package limb

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

const (
	settingsSavedNotice = "The settings are saved. This instance of the service uses them at once, the others within 15 seconds."
	settingsAuditLink   = `href="/admin/audit?action=setting.changed&amp;limit=50"`
)

func (f *peopleFixture) saveSettings(fields url.Values) webResponse {
	f.t.Helper()
	fields.Set("csrf", f.csrfOf(f.get("/settings")))
	return f.post("/settings", fields)
}

func (f *peopleFixture) needsPassword() bool {
	f.t.Helper()
	needed, err := f.a.Admin().PasswordToEndSessions(f.t.Context())
	if err != nil {
		f.t.Fatalf("PasswordToEndSessions failed: %v", err)
	}
	return needed
}

func (f *peopleFixture) canEndOtherSessionsWithoutPassword(login, other Login) bool {
	f.t.Helper()
	err := f.a.TerminateSession(f.t.Context(), login.Principal, other.Principal.SessionID, "")
	var invalid *ValidationError
	switch {
	case err == nil:
		return true
	case errors.As(err, &invalid) && invalid.Field == "password":
		return false
	}
	f.t.Fatalf("TerminateSession failed: %v", err)
	return false
}

func TestTheSettingsPageHasOneSwitchThatShowsWhatHoldsNow(t *testing.T) {
	f := newPeopleFixture(t)
	if r := f.get("/settings"); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/login" || r.has("<h1") || r.has("checkbox") || r.has("csrf") {
		t.Fatalf("the settings for a visitor are %d %q with %.300s", r.StatusCode, r.location(), r.body)
	}
	f.enroll()
	page := f.get("/settings")
	for _, want := range []string{
		`<h1 class="h1">Settings</h1>`, `<form method="post" action="/admin/settings"`, `name="csrf"`, `<legend class="h2">Sessions of the users</legend>`,
		`<input type="checkbox" name="password_to_end_sessions" value="1" aria-describedby="password-to-end-hint">`, "Ask for the password to end sessions",
		`<p id="password-to-end-hint" class="muted">When it is on, a user who ends one of their other sessions`, `<button type="submit" class="btn btn-primary">Save</button>`,
		`<a href="/admin/settings">Settings</a>`, `<p class="aside"><a ` + settingsAuditLink + ">Who changed the settings and when: the audit log</a></p>",
	} {
		if page.StatusCode != http.StatusOK || !page.has(want) {
			t.Errorf("the settings page is %d and lacks %q", page.StatusCode, want)
		}
	}
	if strings.Count(page.body, `name="csrf"`) != 2 {
		t.Errorf("the page has %d tokens, one for the menu to sign out and one for the form", strings.Count(page.body, `name="csrf"`))
	}
	if page.has("checked") || page.has(settingsSavedNotice) || strings.Count(page.body, `type="checkbox"`) != 1 {
		t.Errorf("a page of settings that were not saved shows a switch that is on, a notice or more than one switch: %.900s", page.body)
	}
	if r := f.get("/"); strings.Count(r.body, `href="/admin/settings"`) != 2 || !r.has("Decide whether a user has to give their password to end their other sessions.") {
		t.Errorf("the first page does not link to the settings twice, in the menu and on a card: %.900s", r.body)
	}
	if r := f.get("/users"); !r.has(`<a href="/admin/settings">Settings</a>`) {
		t.Error("the menu of the other pages does not link to the settings")
	}
	russian := f.get("/settings", "Accept-Language", "ru")
	for _, want := range []string{`<html lang="ru">`, `<h1 class="h1">Настройки</h1>`, "Сессии пользователей", "Спрашивать пароль, чтобы завершить сессии", ">Сохранить</button>", "Кто и когда менял настройки"} {
		if !russian.has(want) {
			t.Errorf("the settings page in Russian lacks %q: %.600s", want, russian.body)
		}
	}
}

func TestTheSwitchShowsTheValueThatTheCodeOfTheApplicationGave(t *testing.T) {
	f := newPeopleFixture(t, WithPasswordToEndSessions())
	f.enroll()
	if page := f.get("/settings"); !page.has(`value="1" aria-describedby="password-to-end-hint" checked>`) {
		t.Errorf("the switch is off while the option turned it on: %.900s", page.body)
	}
	if r := f.saveSettings(url.Values{}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("turning it off gave %d", r.StatusCode)
	}
	if page := f.get("/settings"); page.has("checked") || f.needsPassword() {
		t.Error("what the administrator saved does not win over the option")
	}
}

func TestTheSwitchIsSavedTakesEffectAtOnceAndIsWrittenToTheAuditLog(t *testing.T) {
	f := newPeopleFixture(t)
	f.add("ann")
	first, second := f.userLogin("ann", SessionCookie), f.userLogin("ann", SessionCookie)
	f.enroll()
	if f.needsPassword() || !f.canEndOtherSessionsWithoutPassword(first, second) {
		t.Fatal("the password is needed before anyone asked for it")
	}
	second = f.userLogin("ann", SessionCookie)
	f.clock.advance(time.Second)

	r := f.saveSettings(url.Values{"password_to_end_sessions": {"1"}})
	if r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/settings?done=saved" {
		t.Fatalf("turning it on gave %d %q", r.StatusCode, r.location())
	}
	if !f.needsPassword() || f.canEndOtherSessionsWithoutPassword(first, second) {
		t.Error("the setting does not hold on the instance that took it at once")
	}
	page := f.get("/settings?done=saved")
	if !page.has(`<div role="alert" class="alert alert-notice">`+settingsSavedNotice+`</div>`) || !page.has(`aria-describedby="password-to-end-hint" checked>`) {
		t.Errorf("the page after the save shows no notice or a switch that is off: %.1200s", page.body)
	}
	record := f.only(audit.SettingChanged)
	details := detailsOf(t, record)
	if record.ActorKind != store.ActorAdmin || record.ActorID != f.adminID() || record.IP != "127.0.0.1" || record.TargetUserID != "" ||
		details["name"] != "password_to_end_sessions" || details["new"] != "true" || details["old"] != nil {
		t.Errorf("the record of the change is %+v with %v", record, details)
	}

	f.clock.advance(time.Second)
	if r = f.saveSettings(url.Values{"password_to_end_sessions": {"1"}}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("saving the same value gave %d", r.StatusCode)
	}
	if got := f.records(audit.SettingChanged); len(got) != 1 {
		t.Fatalf("saving the same value wrote %d records, want none more", len(got)-1)
	}

	f.clock.advance(time.Second)
	if r = f.saveSettings(url.Values{}); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/settings?done=saved" {
		t.Fatalf("turning it off gave %d %q", r.StatusCode, r.location())
	}
	if f.needsPassword() || !f.canEndOtherSessionsWithoutPassword(first, second) {
		t.Error("turning it off does not hold at once")
	}
	records := f.records(audit.SettingChanged)
	if len(records) != 2 {
		t.Fatalf("%d records of the setting, want 2", len(records))
	}
	var off store.AuditRecord
	for _, found := range records {
		if detailsOf(t, found)["new"] == "false" {
			off = found
		}
	}
	if details = detailsOf(t, off); off.ActorID != f.adminID() || details["old"] != "true" || details["name"] != "password_to_end_sessions" {
		t.Errorf("the record of turning it off is %+v with %v", off, details)
	}
	list := f.get("/audit?action=setting.changed")
	if strings.Count(list.body, "<td>Setting changed</td>") != 2 || strings.Count(list.body, `<td class="break">root</td>`) != 2 || !list.has(`<span class="muted">old</span> true`) {
		t.Errorf("the audit page does not show the two changes made by root: %.1500s", list.body)
	}
	if page = f.get("/settings"); page.has("checked") {
		t.Error("the page shows the switch on after it was turned off")
	}
}

func TestAValueThatIsNotWhatTheSwitchSendsIsRefusedAndChangesNothing(t *testing.T) {
	f := newPeopleFixture(t)
	if err := f.a.Admin().SetPasswordToEndSessions(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	f.enroll()
	for name, values := range map[string][]string{
		"a word": {"yes"}, "on": {"on"}, "zero": {"0"}, "true": {"true"}, "empty": {""}, "twice": {"1", "1"}, "on and off": {"1", "0"}, "a long text": {strings.Repeat("1", 5000)},
	} {
		r := f.saveSettings(url.Values{"password_to_end_sessions": values})
		if r.StatusCode != http.StatusUnprocessableEntity || !r.has(`<div role="alert" class="alert alert-error">The form is not valid. Nothing was changed.</div>`) {
			t.Errorf("%s gave %d: %.500s", name, r.StatusCode, r.body)
		}
		if !r.has(`aria-describedby="password-to-end-hint" checked>`) || strings.Count(r.body, `type="checkbox"`) != 1 {
			t.Errorf("%s: the page that refuses does not show what holds, which is on", name)
		}
	}
	if !f.needsPassword() {
		t.Error("a value that the switch cannot send turned the setting off")
	}
	if got := f.records(audit.SettingChanged); len(got) != 1 {
		t.Errorf("%d records of the setting, want only the one of the code", len(got))
	}
}

func TestTheSettingsNeedASessionTheTokenOfItAndTheOriginOfTheSite(t *testing.T) {
	f := newPeopleFixture(t)
	other := f.newBrowser()
	f.enroll()
	if r := other.signInAgain(); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("a second sign-in gave %d", r.StatusCode)
	}
	foreign, own := other.csrfOf(other.get("/account")), f.csrfOf(f.get("/settings"))
	signedOut := f.newBrowser()
	if r := signedOut.get("/settings"); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/login" {
		t.Errorf("the page for a visitor gave %d %q", r.StatusCode, r.location())
	}
	form := func(token string) url.Values {
		return url.Values{"csrf": {token}, "password_to_end_sessions": {"1"}}
	}
	if r := signedOut.post("/settings", form(own)); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/login" {
		t.Errorf("saving without a session gave %d %q", r.StatusCode, r.location())
	}
	for name, token := range map[string]string{"a wrong token": "wrong", "no token": "", "the token of another session": foreign} {
		if r := f.post("/settings", form(token)); r.StatusCode != http.StatusForbidden {
			t.Errorf("saving with %s gave %d", name, r.StatusCode)
		}
	}
	if r := f.post("/settings", form(own), "Origin", "https://evil.example"); r.StatusCode != http.StatusForbidden {
		t.Errorf("saving from another origin gave %d", r.StatusCode)
	}
	if r := f.post("/settings", form(own), "Sec-Fetch-Site", "cross-site"); r.StatusCode != http.StatusForbidden {
		t.Errorf("saving fetched from another site gave %d", r.StatusCode)
	}
	if r := f.post("/settings", form(own), "Content-Type", "application/json"); r.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("saving as JSON gave %d", r.StatusCode)
	}
	if r := f.request(http.MethodPut, "/settings"); r.StatusCode != http.StatusMethodNotAllowed || r.Header.Get("Allow") != "GET, HEAD, POST" {
		t.Errorf("PUT gave %d with Allow %q", r.StatusCode, r.Header.Get("Allow"))
	}
	if f.needsPassword() || len(f.records(audit.SettingChanged)) != 0 {
		t.Error("a request that was refused changed the setting")
	}
}

func TestThePageShowsWhatWasSavedByAnotherInstanceWithoutWaitingForTheCache(t *testing.T) {
	f := newPeopleFixture(t)
	f.enroll()
	if f.needsPassword() || f.get("/settings").has("checked") {
		t.Fatal("the password is needed before anyone asked for it")
	}
	elsewhere := store.Setting{TenantID: f.a.tenant, Name: settingPasswordToEndSessions, Value: "true", UpdatedAt: f.clock.now()}
	if err := f.a.store.Settings().Set(t.Context(), elsewhere); err != nil {
		t.Fatal(err)
	}
	if f.needsPassword() {
		t.Fatal("the cache of the instance saw the change of another one before it ran out")
	}
	if page := f.get("/settings"); !page.has(`aria-describedby="password-to-end-hint" checked>`) {
		t.Error("the page shows the value of the cache and not the one that is stored")
	}
	f.clock.advance(time.Second)
	if r := f.saveSettings(url.Values{}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("turning it off gave %d", r.StatusCode)
	}
	record := f.only(audit.SettingChanged)
	if details := detailsOf(t, record); details["old"] != "true" || details["new"] != "false" || f.needsPassword() {
		t.Errorf("the change over the one of the other instance is %v and the setting is on: %v", details, f.needsPassword())
	}
}

func TestAFailureOfTheStoreOnTheSettingsIsAnErrorPageThatHidesWhyAndTheLogSaysIt(t *testing.T) {
	f, faults, logs := newFaultyWebFixture(t)
	f.enroll()
	token := f.csrfOf(f.get("/settings"))
	for _, c := range []struct {
		fault, method string
		fields        url.Values
	}{
		{"settings.list", http.MethodGet, nil},
		{"settings.list", http.MethodPost, url.Values{"password_to_end_sessions": {"yes"}}},
		{"settings.get", http.MethodPost, url.Values{"password_to_end_sessions": {"1"}}},
		{"settings.set", http.MethodPost, url.Values{"password_to_end_sessions": {"1"}}},
		{"audit.add", http.MethodPost, url.Values{"password_to_end_sessions": {"1"}}},
	} {
		faults.clear()
		faults.set(c.fault, errors.New("down: "+c.fault))
		var r webResponse
		if c.method == http.MethodGet {
			r = f.get("/settings")
		} else {
			c.fields.Set("csrf", token)
			r = f.post("/settings", c.fields)
		}
		if r.StatusCode != http.StatusInternalServerError || !r.has("Something went wrong") || r.has("down: "+c.fault) {
			t.Errorf("a failure of %s on %s gave %d with %.300s", c.fault, c.method, r.StatusCode, r.body)
		}
		if !strings.Contains(logs.String(), "down: "+c.fault) {
			t.Errorf("the log does not say that %s failed", c.fault)
		}
	}
	faults.clear()
	if needed, err := f.a.Admin().PasswordToEndSessions(t.Context()); err != nil || needed {
		t.Errorf("a save that failed left the setting at %v, %v", needed, err)
	}
	if got := recordsOf(t, f.a, audit.SettingChanged); len(got) != 0 {
		t.Errorf("a save that failed left %d records", len(got))
	}
}
