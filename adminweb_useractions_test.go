package limb

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/internal/admin"
	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

func (f *peopleFixture) act(name, action string, fields url.Values) webResponse {
	f.t.Helper()
	fields.Set("csrf", f.csrfOf(f.card(name)))
	return f.post("/users/"+string(f.ids[name])+"/"+action, fields)
}

func (f *peopleFixture) userLogin(name string, kind SessionKind) Login {
	f.t.Helper()
	login, err := f.a.Login(f.t.Context(), Credentials{Login: name, Password: goodPassword, IP: testIP, UserAgent: "Agent of " + name, Kind: kind})
	if err != nil {
		f.t.Fatalf("the sign-in of %s failed: %v", name, err)
	}
	return login
}

func (f *peopleFixture) authenticated(login Login) bool {
	f.t.Helper()
	r := httptest.NewRequestWithContext(f.t.Context(), http.MethodGet, "/", nil)
	if login.Secret != "" {
		r.AddCookie(&http.Cookie{Name: f.a.cookie, Value: login.Secret}) //nolint:gosec
	} else {
		r.Header.Set("Authorization", "Bearer "+login.Tokens.AccessToken)
	}
	_, err := f.a.Authenticate(r)
	return err == nil
}

func (f *peopleFixture) status(name string) Status {
	f.t.Helper()
	user, err := f.a.Admin().User(f.t.Context(), f.ids[name])
	if err != nil {
		f.t.Fatal(err)
	}
	return user.Status
}

func (f *peopleFixture) only(action string) store.AuditRecord {
	f.t.Helper()
	records := recordsOf(f.t, f.a, action)
	if len(records) != 1 {
		f.t.Fatalf("%d records of %s, want 1", len(records), action)
	}
	return records[0]
}

func (f *peopleFixture) noRecords(actions ...string) {
	f.t.Helper()
	for _, action := range actions {
		if got := recordsOf(f.t, f.a, action); len(got) != 0 {
			f.t.Errorf("%d records of %s, want none: %+v", len(got), action, got)
		}
	}
}

func TestAnAdministratorBlocksAUserWhoLosesAccessAtOnceAndLiftsTheBlockThroughTheBrowser(t *testing.T) {
	f := seedPeople(t)
	id := string(f.ids["ann"])
	cookie, token := f.userLogin("ann", SessionCookie), f.userLogin("ann", SessionToken)
	if !f.authenticated(cookie) || !f.authenticated(token) {
		t.Fatal("the sessions of the user do not work before the block")
	}
	r := f.act("ann", "block", url.Values{"reason": {"  spam wave  "}, "until": {"2026-10-01"}})
	if r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/users/"+id+"?done=blocked" {
		t.Fatalf("the block gave %d %q: %.300s", r.StatusCode, r.location(), r.body)
	}
	if f.authenticated(cookie) || f.authenticated(token) {
		t.Fatal("a user that was blocked keeps a session that works")
	}
	if _, err := f.a.Refresh(t.Context(), token.Tokens.RefreshToken); err == nil {
		t.Fatal("a user that was blocked can refresh the tokens")
	}
	if _, err := f.a.Login(t.Context(), Credentials{Login: "ann", Password: goodPassword, IP: testIP, Kind: SessionCookie}); !errors.Is(err, ErrUserBlocked) {
		t.Fatalf("a user that was blocked signs in: %v", err)
	}
	page := f.get("/users/" + id + "?done=blocked")
	for _, want := range []string{
		"The user is blocked and their sessions ended.", `<span class="badge badge-blocked">Blocked</span>`, `<dd class="break">spam wave</dd>`,
		`<time datetime="2026-10-01T00:00:00Z">2026-10-01 00:00 UTC</time>`, "The user has no session in use.", "Change the block", "Lift the block",
		"<td>User blocked</td>\n<td class=\"break\">root</td>",
	} {
		if !page.has(want) {
			t.Errorf("the card of a blocked user lacks %q", want)
		}
	}
	record := f.only(audit.UserBlocked)
	details := detailsOf(t, record)
	if record.ActorKind != store.ActorAdmin || record.ActorID != f.adminID() || record.IP != "127.0.0.1" || record.TargetUserID != id ||
		details["reason"] != "spam wave" || details["until"] != "2026-10-01T00:00:00Z" || details["sessions"] != float64(2) {
		t.Fatalf("the record of the block is %+v %v", record, details)
	}

	f.clock.advance(time.Minute)
	if r = f.act("ann", "block", url.Values{"reason": {"second reason"}}); r.location() != adminMount+"/users/"+id+"?done=blocked" {
		t.Fatalf("the change of the block gave %d %q", r.StatusCode, r.location())
	}
	changed := f.get("/users/" + id)
	if !changed.has(`<dd class="break">second reason</dd>`) || !changed.has("never, until an administrator lifts it") || changed.has(`<time datetime="2026-10-01T00:00:00Z">`) {
		t.Errorf("a block that was changed is not shown as it is now: %.1500s", changed.body)
	}
	if got := recordsOf(t, f.a, audit.UserBlocked); len(got) != 2 || detailsOf(t, got[0])["previous_reason"] != "spam wave" {
		t.Errorf("the change of the block is recorded as %+v", got)
	}

	f.clock.advance(time.Minute)
	if r = f.act("ann", "unblock", url.Values{}); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/users/"+id+"?done=unblocked" {
		t.Fatalf("lifting the block gave %d %q", r.StatusCode, r.location())
	}
	lifted := f.get("/users/" + id + "?done=unblocked")
	if !lifted.has("The block is lifted.") || !lifted.has(`<span class="badge badge-active">Active</span>`) || lifted.has("Lift the block") || !lifted.has("Block the user") {
		t.Errorf("the card of a user whose block was lifted is wrong: %.800s", lifted.body)
	}
	if record = f.only(audit.UserUnblocked); record.ActorKind != store.ActorAdmin || record.ActorID != f.adminID() || detailsOf(t, record)["previous_reason"] != "second reason" {
		t.Errorf("the record of lifting the block is %+v", record)
	}
	if _, err := f.a.Login(t.Context(), Credentials{Login: "ann", Password: goodPassword, IP: testIP, Kind: SessionCookie}); err != nil {
		t.Errorf("a user whose block was lifted cannot sign in: %v", err)
	}
	if r = f.act("ann", "unblock", url.Values{}); r.StatusCode != http.StatusSeeOther {
		t.Errorf("lifting a block that is not there gave %d", r.StatusCode)
	}
	if got := recordsOf(t, f.a, audit.UserUnblocked); len(got) != 1 {
		t.Errorf("lifting a block that is not there is recorded: %d records", len(got))
	}
}

func TestABlockThatCannotBeMadeIsRefusedAndTheFormKeepsWhatWasTyped(t *testing.T) {
	f := seedPeople(t)
	id := string(f.ids["ann"])
	for _, c := range []struct {
		name   string
		fields url.Values
		text   string
	}{
		{"no reason", url.Values{"reason": {""}}, "Give the reason of the block."},
		{"a reason of spaces", url.Values{"reason": {"   "}}, "Give the reason of the block."},
		{"a reason that is too long", url.Values{"reason": {strings.Repeat("x", store.MaxBlockedReasonLength+1)}}, "at most 512 bytes."},
		{"a reason with a control character", url.Values{"reason": {"bad\x01reason"}}, "without control characters"},
		{"a reason that is not text", url.Values{"reason": {"bad\xffreason"}}, "without control characters"},
		{"a day that is not a day", url.Values{"reason": {"why"}, "until": {"tomorrow"}}, "The day of the end of the block is not valid."},
		{"a day that does not exist", url.Values{"reason": {"why"}, "until": {"2026-02-30"}}, "The day of the end of the block is not valid."},
		{"the first day of the first year", url.Values{"reason": {"why"}, "until": {"0001-01-01"}}, "The day of the end of the block is not valid."},
		{"a year after the last", url.Values{"reason": {"why"}, "until": {"10000-01-01"}}, "The day of the end of the block is not valid."},
		{"a day that has passed", url.Values{"reason": {"why"}, "until": {"2026-09-01"}}, "has to be in the future."},
		{"today, which has begun", url.Values{"reason": {"why"}, "until": {"2026-09-17"}}, "has to be in the future."},
	} {
		r := f.act("ann", "block", c.fields)
		if r.StatusCode != http.StatusUnprocessableEntity || !r.has(c.text) || !r.has(`role="alert" class="alert alert-error"`) {
			t.Errorf("%s: the block gave %d: %.300s", c.name, r.StatusCode, r.body)
		}
		if want := strings.TrimSpace(c.fields.Get("until")); want != "" && c.name != "a day that is not a day" && !r.has(`value="`+want+`"`) {
			t.Errorf("%s: the form lost the day %q", c.name, want)
		}
		if f.status("ann") != StatusActive {
			t.Fatalf("%s: the user was blocked", c.name)
		}
	}
	r := f.act("ann", "block", url.Values{"reason": {"typed <b>reason</b>"}, "until": {"2026-02-30"}})
	if !r.has(`value="typed &lt;b&gt;reason&lt;/b&gt;"`) || !r.has(`value="2026-02-30"`) || r.has("<b>reason") {
		t.Errorf("the form of a refused block does not keep, and escape, what was typed: %.1500s", r.body)
	}
	f.noRecords(audit.UserBlocked)
	if r = f.act("ann", "block", url.Values{"reason": {"é" + strings.Repeat("x", store.MaxBlockedReasonLength-2)}}); r.StatusCode != http.StatusSeeOther {
		t.Errorf("a reason of the longest length gave %d", r.StatusCode)
	}
	if got := f.get("/users/" + id); !got.has(`maxlength="512"`) {
		t.Errorf("the form does not tell the longest reason")
	}
	f.clock.advance(time.Minute)
	if r = f.act("ann", "block", url.Values{"reason": {"why"}, "until": {"2026-09-18"}}); r.StatusCode != http.StatusSeeOther {
		t.Errorf("the day after today gave %d", r.StatusCode)
	}
}

func TestTheSessionsOfAUserAreEndedOneByOneOrAllTogetherThroughTheBrowser(t *testing.T) {
	f := seedPeople(t)
	id := string(f.ids["eve"])
	first, second, third := f.userLogin("eve", SessionCookie), f.userLogin("eve", SessionToken), f.userLogin("eve", SessionCookie)
	other := f.userLogin("ann", SessionCookie)
	sessions, err := f.a.Admin().UserSessions(t.Context(), f.ids["eve"])
	if err != nil || len(sessions) != 3 {
		t.Fatalf("the sessions are %v, %v", sessions, err)
	}
	page := f.card("eve")
	if got := strings.Count(page.body, `action="/admin/users/`+id+`/sessions/end"`); got != 3 || !page.has(`action="/admin/users/`+id+`/sessions/end-all"`) || !page.has("End all sessions") {
		t.Fatalf("the card has %d forms that end a session and %v for all", got, page.has("End all sessions"))
	}
	r := f.act("eve", "sessions/end", url.Values{"session": {first.Principal.SessionID}})
	if r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/users/"+id+"?done=session" {
		t.Fatalf("ending a session gave %d %q", r.StatusCode, r.location())
	}
	if f.authenticated(first) || !f.authenticated(second) || !f.authenticated(third) || !f.authenticated(other) {
		t.Fatal("ending one session did not end that one and only that one")
	}
	if got := f.get("/users/" + id + "?done=session"); !got.has("The session ended.") || strings.Count(got.body, `/sessions/end"`) != 2 {
		t.Errorf("the card after ending a session is wrong: %.600s", got.body)
	}
	if record := f.only(audit.UserSessionEnded); record.ActorKind != store.ActorAdmin || record.ActorID != f.adminID() || detailsOf(t, record)["session"] != first.Principal.SessionID {
		t.Errorf("the record of ending a session is %+v", record)
	}

	for _, session := range []string{other.Principal.SessionID, first.Principal.SessionID, "no-such-session", strings.Repeat("s", store.MaxIDLength+1), ""} {
		if r = f.act("eve", "sessions/end", url.Values{"session": {session}}); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/users/"+id+"?done=session" {
			t.Errorf("ending the session %.10q gave %d %q", session, r.StatusCode, r.location())
		}
	}
	if !f.authenticated(other) || !f.authenticated(second) {
		t.Fatal("a session of another user, or one that was not asked for, ended")
	}
	if got := recordsOf(t, f.a, audit.UserSessionEnded); len(got) != 1 {
		t.Errorf("sessions that could not be ended were recorded as ended: %d records", len(got))
	}

	f.clock.advance(time.Minute)
	if r = f.act("eve", "sessions/end-all", url.Values{}); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/users/"+id+"?done=sessions" {
		t.Fatalf("ending all the sessions gave %d %q", r.StatusCode, r.location())
	}
	if f.authenticated(second) || f.authenticated(third) || !f.authenticated(other) {
		t.Fatal("ending all the sessions of a user did not end theirs, or ended those of another")
	}
	if record := f.only(audit.UserSessionsEnded); detailsOf(t, record)["count"] != float64(2) || record.ActorID != f.adminID() {
		t.Errorf("the record of ending all the sessions is %+v", record)
	}
	if f.status("eve") != StatusActive {
		t.Error("ending the sessions of a user changed their status")
	}
	got := f.get("/users/" + id + "?done=sessions")
	if !got.has("The sessions ended.") || !got.has("The user has no session in use.") || got.has("End all sessions") {
		t.Errorf("the card of a user without sessions is wrong: %.600s", got.body)
	}
	if r = f.act("eve", "sessions/end-all", url.Values{}); r.StatusCode != http.StatusSeeOther {
		t.Errorf("ending the sessions of a user who has none gave %d", r.StatusCode)
	}
	if got := recordsOf(t, f.a, audit.UserSessionsEnded); len(got) != 1 {
		t.Errorf("ending no session is recorded: %d records", len(got))
	}
}

func TestAnAdministratorDeletesAUserWithTheValueTheySignInWithAndRestoresThemThroughTheBrowser(t *testing.T) {
	f := seedPeople(t)
	id := string(f.ids["ann"])
	session := f.userLogin("ann", SessionCookie)
	card := f.card("ann")
	for _, want := range []string{"Delete the user", `action="/admin/users/` + id + `/delete"`, `name="confirm"`, "For example: ann@example.com", "the values they sign in with stay taken"} {
		if !card.has(want) {
			t.Errorf("the card lacks %q", want)
		}
	}
	for _, confirm := range []string{"", "   ", "ann1", "bob@example.com", id, "ann@example.com.", "ann@example.org"} {
		r := f.act("ann", "delete", url.Values{"confirm": {confirm}})
		if r.StatusCode != http.StatusUnprocessableEntity || !r.has("What you typed is not a value that the user signs in with.") {
			t.Errorf("a confirmation of %q gave %d", confirm, r.StatusCode)
		}
	}
	if f.status("ann") != StatusActive || !f.authenticated(session) {
		t.Fatal("a deletion that was not confirmed changed the user")
	}
	f.noRecords(audit.UserDeleted)

	r := f.act("ann", "delete", url.Values{"confirm": {"  ANN@Example.com "}})
	if r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/users/"+id+"?done=deleted" {
		t.Fatalf("the deletion gave %d %q: %.300s", r.StatusCode, r.location(), r.body)
	}
	if f.status("ann") != StatusDeleted || f.authenticated(session) {
		t.Fatal("the user is not deleted or keeps a session")
	}
	if _, err := f.a.Register(t.Context(), Registration{Identifiers: map[string]string{"email": "ann@example.com", "username": "newann"}, Password: goodPassword}); !errors.Is(err, ErrIdentifierTaken) {
		t.Errorf("the value of a deleted user is free: %v", err)
	}
	deleted := f.get("/users/" + id + "?done=deleted")
	for _, want := range []string{
		"The user is deleted.", `<span class="badge badge-deleted">Deleted</span>`, "Removed for good after", `<time datetime="2026-10-17T11:12:`, "Restore the user", `action="/admin/users/` + id + `/restore"`,
		"<td>User deleted</td>", `<span class="muted">mode</span> soft`, "The user has no session in use.",
	} {
		if !deleted.has(want) {
			t.Errorf("the card of a deleted user lacks %q", want)
		}
	}
	for _, unwanted := range []string{"Delete the user", `name="confirm"`, "Block the user", `/block"`} {
		if deleted.has(unwanted) {
			t.Errorf("the card of a deleted user still has %q", unwanted)
		}
	}
	if record := f.only(audit.UserDeleted); record.ActorKind != store.ActorAdmin || record.ActorID != f.adminID() || record.IP != "127.0.0.1" {
		t.Errorf("the record of the deletion is %+v", record)
	}

	f.clock.advance(time.Minute)
	if r = f.act("ann", "delete", url.Values{"confirm": {"ann@example.com"}}); r.StatusCode != http.StatusConflict || !r.has("The user is deleted.") {
		t.Errorf("a second deletion gave %d", r.StatusCode)
	}
	if r = f.act("ann", "block", url.Values{"reason": {"why"}}); r.StatusCode != http.StatusConflict || !r.has("The user is deleted.") {
		t.Errorf("a block of a deleted user gave %d", r.StatusCode)
	}
	if r = f.act("ann", "restore", url.Values{}); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/users/"+id+"?done=restored" {
		t.Fatalf("the restoring gave %d %q", r.StatusCode, r.location())
	}
	restored := f.get("/users/" + id + "?done=restored")
	if !restored.has("The user is restored.") || !restored.has(`<span class="badge badge-active">Active</span>`) || !restored.has("Delete the user") || restored.has("Restore the user") {
		t.Errorf("the card of a restored user is wrong: %.800s", restored.body)
	}
	if record := f.only(audit.UserRestored); record.ActorID != f.adminID() || detailsOf(t, record)["status"] != "active" {
		t.Errorf("the record of restoring is %+v", record)
	}
	if _, err := f.a.Login(t.Context(), Credentials{Login: "ann", Password: goodPassword, IP: testIP, Kind: SessionCookie}); err != nil {
		t.Errorf("a restored user cannot sign in: %v", err)
	}
	if r = f.act("ann", "restore", url.Values{}); r.StatusCode != http.StatusConflict || !r.has("The user is not deleted.") {
		t.Errorf("restoring a user who is not deleted gave %d", r.StatusCode)
	}
}

func TestAUserWhoWasDeletedForLongerThanTheTimeOfKeepingCannotBeRestored(t *testing.T) {
	f := newPeopleFixture(t, WithDeletedUserRetention(time.Hour))
	f.add("ann")
	f.enroll()
	if r := f.act("ann", "delete", url.Values{"confirm": {"ann@example.com"}}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("the deletion gave %d", r.StatusCode)
	}
	f.clock.advance(2 * time.Hour)
	f.signInAgain()
	if r := f.act("ann", "restore", url.Values{}); r.StatusCode != http.StatusConflict || !r.has("The time to restore the user has run out.") {
		t.Errorf("restoring after the time of keeping gave %d: %.300s", r.StatusCode, r.body)
	}
	if f.status("ann") != StatusDeleted {
		t.Error("a user that cannot be restored was restored")
	}
}

func TestWithImmediateDeletionTheUserIsErasedAndTheListSaysSo(t *testing.T) {
	f := newPeopleFixture(t, WithImmediateDeletion())
	f.add("ann")
	f.add("bob")
	f.enroll()
	id := string(f.ids["ann"])
	if card := f.card("ann"); !card.has("The account is erased at once") || card.has("An administrator can restore the account") {
		t.Fatalf("the card does not say that the deletion is immediate: %.600s", card.body)
	}
	r := f.act("ann", "delete", url.Values{"confirm": {"ann@example.com"}})
	if r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/users?done=erased" {
		t.Fatalf("the deletion gave %d %q", r.StatusCode, r.location())
	}
	list := f.get("/users?done=erased")
	if !list.has("The user is erased.") || len(f.namesIn(list)) != 1 || list.has("ann@example.com") {
		t.Errorf("the list after an erasure is wrong: %.600s", list.body)
	}
	if plain := f.get("/users"); plain.has("The user is erased.") {
		t.Errorf("the notice of an erasure is shown without being asked for")
	}
	if gone := f.get("/users/" + id); gone.StatusCode != http.StatusNotFound {
		t.Errorf("the card of an erased user is %d", gone.StatusCode)
	}
	if r = f.post("/users/"+id+"/delete", url.Values{"confirm": {"ann@example.com"}, "csrf": {f.csrfOf(f.get("/users"))}}); r.StatusCode != http.StatusNotFound {
		t.Errorf("deleting an erased user gave %d", r.StatusCode)
	}
	if _, err := f.a.Register(t.Context(), Registration{Identifiers: map[string]string{"email": "ann@example.com", "username": "ann"}, Password: goodPassword}); err != nil {
		t.Errorf("the values of an erased user are not free: %v", err)
	}
	if record := f.only(audit.UserDeleted); detailsOf(t, record)["mode"] != "immediate" || record.ActorID != f.adminID() {
		t.Errorf("the record of the erasure is %+v", record)
	}
}

func TestADeletionThatTheApplicationRefusesIsAnsweredWithoutItsReason(t *testing.T) {
	f := newPeopleFixture(t, WithHooks(Hooks{BeforeDelete: func(context.Context, User) error { return errors.New("owns a subscription of 4242 dollars") }}))
	f.add("ann")
	f.enroll()
	r := f.act("ann", "delete", url.Values{"confirm": {"ann@example.com"}})
	if r.StatusCode != http.StatusConflict || !r.has("The application does not allow this user to be deleted.") || r.has("4242") {
		t.Errorf("a deletion that the application refused gave %d: %.600s", r.StatusCode, r.body)
	}
	if f.status("ann") != StatusActive {
		t.Error("a deletion that the application refused deleted the user")
	}
	f.noRecords(audit.UserDeleted)
}

func TestTheActionsOnTheCardNeedASessionTheTokenOfItAndTheOriginOfTheSite(t *testing.T) {
	f := seedPeople(t)
	id := string(f.ids["ann"])
	session := f.userLogin("ann", SessionCookie)
	other := f.newBrowser()
	if r := other.signInAgain(); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("a second sign-in gave %d", r.StatusCode)
	}
	foreign := other.csrfOf(other.get("/account"))
	own := f.csrfOf(f.card("ann"))
	actions := map[string]url.Values{
		"block": {"reason": {"why"}}, "unblock": {}, "sessions/end": {"session": {session.Principal.SessionID}}, "sessions/end-all": {},
		"delete": {"confirm": {"ann@example.com"}}, "restore": {}, "password/link": {"language": {"en"}}, "password/temporary": {},
		"identifiers/set": {"type": {"email"}, "value": {"other@example.com"}}, "identifiers/remove": {"type": {"username"}}, "identifiers/verify": {"type": {"email"}},
	}
	for action, fields := range actions {
		path := "/users/" + id + "/" + action
		with := func(token string) url.Values {
			values := url.Values{"csrf": {token}}
			for key, list := range fields {
				values[key] = list
			}
			return values
		}
		signedOut := f.newBrowser()
		if r := signedOut.post(path, with(own)); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/login" {
			t.Errorf("%s without a session gave %d %q", action, r.StatusCode, r.location())
		}
		for name, token := range map[string]string{"a wrong token": "wrong", "no token": "", "the token of another session": foreign} {
			if r := f.post(path, with(token)); r.StatusCode != http.StatusForbidden {
				t.Errorf("%s with %s gave %d", action, name, r.StatusCode)
			}
		}
		if r := f.post(path, with(own), "Origin", "https://evil.example"); r.StatusCode != http.StatusForbidden {
			t.Errorf("%s from another origin gave %d", action, r.StatusCode)
		}
		if r := f.post(path, with(own), "Sec-Fetch-Site", "cross-site"); r.StatusCode != http.StatusForbidden {
			t.Errorf("%s fetched from another site gave %d", action, r.StatusCode)
		}
		if r := f.post(path, with(own), "Content-Type", "application/json"); r.StatusCode != http.StatusUnsupportedMediaType {
			t.Errorf("%s as JSON gave %d", action, r.StatusCode)
		}
		if r := f.get(path); r.StatusCode != http.StatusMethodNotAllowed || r.Header.Get("Allow") != "POST" {
			t.Errorf("GET of %s gave %d with Allow %q", action, r.StatusCode, r.Header.Get("Allow"))
		}
	}
	if f.status("ann") != StatusActive || !f.authenticated(session) {
		t.Fatal("a request that was refused changed the user")
	}
	f.noRecords(audit.UserBlocked, audit.UserUnblocked, audit.UserSessionEnded, audit.UserSessionsEnded, audit.UserDeleted, audit.UserRestored, audit.UserPasswordResetSent, audit.UserPasswordTemporary,
		audit.UserIdentifierAdded, audit.UserIdentifierChanged, audit.UserIdentifierRemoved, audit.UserIdentifierVerified)
	for action, fields := range actions {
		values := url.Values{"csrf": {own}}
		for key, list := range fields {
			values[key] = list
		}
		if r := f.post("/users/no-such-user/"+action, values); r.StatusCode != http.StatusNotFound || !r.has("Page not found") {
			t.Errorf("%s for a user that is not there gave %d", action, r.StatusCode)
		}
	}
}

func TestAnAnswerToAnActionOnAUserIsTheOneThatTheFailureCallsFor(t *testing.T) {
	f := seedPeople(t)
	site, ok := f.a.AdminHandler().(*adminSite)
	if !ok {
		t.Fatal("the handler of the administration is not a site")
	}
	user := string(f.ids["ann"])
	cases := []struct {
		name   string
		err    error
		status int
		text   string
	}{
		{"a user that is not there", ErrUserNotFound, http.StatusNotFound, "Page not found"},
		{"a user that is deleted", ErrUserDeleted, http.StatusConflict, "The user is deleted."},
		{"a user that kept changing", ErrConcurrentChange, http.StatusConflict, "The user kept changing meanwhile."},
		{"a refusal of the application", fmt.Errorf("%w: %w", ErrDeletionRefused, errors.New("the secret reason")), http.StatusConflict, "The application does not allow"},
		{"the end of the time of keeping", ErrRetentionOver, http.StatusConflict, "The time to restore the user has run out."},
		{"a user who is not deleted", &ValidationError{Field: "user", Reason: "is not deleted"}, http.StatusConflict, "The user is not deleted."},
		{"a reason that is missing", &ValidationError{Field: "reason", Reason: "required"}, http.StatusUnprocessableEntity, "Give the reason of the block."},
		{"a reason that is wrong", &ValidationError{Field: "reason", Reason: "too long"}, http.StatusUnprocessableEntity, "at most 512 bytes."},
		{"a day in the past", &ValidationError{Field: "until", Reason: "must be in the future"}, http.StatusUnprocessableEntity, "has to be in the future."},
		{"a day that is wrong", &ValidationError{Field: "until", Reason: "must be before the year 10000"}, http.StatusUnprocessableEntity, "is not valid."},
		{"another value", &ValidationError{Field: "other", Reason: "is wrong <b>"}, http.StatusUnprocessableEntity, "The value of other is not accepted: is wrong &lt;b&gt;."},
		{"a value that a type refuses", &ValidationError{Field: "email", Reason: "must be an address"}, http.StatusUnprocessableEntity, "The value of email is not accepted: must be an address."},
		{"the last value to sign in with", &ValidationError{Field: "identifiers", Reason: "at least one value to sign in with is required"}, http.StatusUnprocessableEntity, "keep at least one value to sign in with."},
		{"a value that another user has", fmt.Errorf("%w: email", ErrIdentifierTaken), http.StatusConflict, "Another user has this value."},
		{"a service that cannot send", ErrRecoveryDisabled, http.StatusConflict, "The service has no way to send messages."},
		{"a user without a confirmed value", ErrNoConfirmedChannel, http.StatusConflict, "no confirmed address or phone number"},
		{"a queue of messages that is full", ErrBusy, http.StatusServiceUnavailable, "The queue of messages is full."},
		{"a password that the checks refuse", &PolicyError{Rules: []string{"min_length"}}, http.StatusUnprocessableEntity, "refused the password that was made"},
		{"a failure of the store", errors.New("the store failed"), http.StatusInternalServerError, "Something went wrong"},
	}
	for _, c := range cases {
		recorder := httptest.NewRecorder()
		call := &adminCall{s: site, w: recorder, r: httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/users/"+user+"/block", nil), lang: "en", userID: user}
		if errors.Is(c.err, ErrUserNotFound) {
			call.userID = "no-such-user"
		}
		call.userFailure(admin.Session{ID: "session", AdminID: "admin", Login: "root"}, url.Values{"reason": {"typed"}}, c.err)
		body := recorder.Body.String()
		if c.status == http.StatusServiceUnavailable && recorder.Header().Get("Retry-After") != busyRetryAfter {
			t.Errorf("%s: Retry-After is %q", c.name, recorder.Header().Get("Retry-After"))
		}
		if recorder.Code != c.status || !strings.Contains(body, c.text) || strings.Contains(body, "the secret reason") || strings.Contains(body, "the store failed") {
			t.Errorf("%s: the answer is %d with %.200s", c.name, recorder.Code, body)
		}
	}
}

func TestAFailureOfTheStoreDuringAnActionOnAUserIsAnErrorPageAndChangesNothing(t *testing.T) {
	f, faults, logs := newFaultyWebFixture(t)
	user := mustRegister(t, f.a, map[string]string{"email": "ann@example.com"}, goodPassword)
	f.enroll()
	id := string(user.ID)
	token := f.csrfOf(f.get("/users/" + id))
	for _, fault := range []string{"users.update", "audit.add", "sessions.revoke"} {
		faults.clear()
		faults.set(fault, errors.New("down: "+fault))
		r := f.post("/users/"+id+"/block", url.Values{"reason": {"why"}, "csrf": {token}})
		if r.StatusCode != http.StatusInternalServerError || !r.has("Something went wrong") || r.has("down: "+fault) {
			t.Errorf("a failure of %s gave %d", fault, r.StatusCode)
		}
		if !strings.Contains(logs.String(), "down: "+fault) {
			t.Errorf("the log does not say that %s failed", fault)
		}
		if got, err := f.a.Admin().User(t.Context(), user.ID); err != nil || got.Status != StatusActive {
			t.Fatalf("a block that failed at %s left the user as %+v, %v", fault, got, err)
		}
	}
	if got := recordsOf(t, f.a, audit.UserBlocked); len(got) != 0 {
		t.Errorf("a block that failed is recorded: %+v", got)
	}
	faults.clear()
	if r := f.post("/users/"+id+"/block", url.Values{"reason": {"why"}, "csrf": {token}}); r.StatusCode != http.StatusSeeOther {
		t.Errorf("the block after the failures gave %d", r.StatusCode)
	}
}

func TestADayOfTheEndOfABlockIsTheDayThatStartsItsFirstSecond(t *testing.T) {
	for text, want := range map[string]time.Time{
		"":           {},
		"2026-10-01": time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		"9999-12-31": time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC),
		"0002-01-01": time.Date(2, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		if got, ok := parseBlockDay(text); !ok || !got.Equal(want) {
			t.Errorf("parseBlockDay(%q) = %v, %v, want %v", text, got, ok, want)
		}
	}
	for _, text := range []string{"0001-01-01", "0000-01-01", "10000-01-01", "2026-13-01", "2026-02-30", "2026-1-5", "tomorrow", " 2026-10-01", "2026-10-01 ", "+2026-10-01", "2026/10/01", "01.10.2026"} {
		if got, ok := parseBlockDay(text); ok {
			t.Errorf("parseBlockDay(%q) = %v, want it refused", text, got)
		}
	}
}

func TestTheTypedConfirmationOfADeletionIsAValueThatTheUserSignsInWith(t *testing.T) {
	a := newTestAuth(t, emailAndUsername())
	user := ManagedUser{User: User{ID: "user-1", Identifiers: []UserIdentifier{
		{Type: "email", Value: "ann@example.com", DisplayValue: "Ann@Example.com"},
		{Type: "username", Value: "ann_a", DisplayValue: "Ann_A"},
	}}}
	bare := ManagedUser{User: User{ID: "user-2"}}
	for _, c := range []struct {
		who  ManagedUser
		text string
		want bool
	}{
		{user, "ann@example.com", true}, {user, "Ann@Example.com", true}, {user, "  ANN@EXAMPLE.COM  ", true}, {user, "ann_a", true}, {user, "Ann_A", true},
		{user, " ANN_A ", true}, {user, "", false}, {user, "   ", false}, {user, "ann", false}, {user, "user-1", false}, {user, "ann@example.org", false},
		{user, "ann_a@example.com", false}, {user, "ann@example.com ann_a", false},
		{bare, "user-2", true}, {bare, " user-2 ", true}, {bare, "", false}, {bare, "user-3", false}, {bare, "user", false},
	} {
		if got := a.deletionConfirmed(c.who, c.text); got != c.want {
			t.Errorf("deletionConfirmed(%s, %q) = %v, want %v", c.who.ID, c.text, got, c.want)
		}
	}
}
