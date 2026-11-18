package limb

import (
	"context"
	"encoding/base32"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/internal/admin"
	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/internal/totp"
	"github.com/acneism/limb/store"
)

const changedPassword = "a password with more words"

var (
	sessionIDPattern = regexp.MustCompile(`name="session" value="([^"]+)"`)
	secretPattern    = regexp.MustCompile(`<code class="secret">([^<]+)</code>`)
)

func (f *webFixture) accountToken() string {
	f.t.Helper()
	page := f.get("/account")
	if page.StatusCode != http.StatusOK {
		f.t.Fatalf("the account page is %d", page.StatusCode)
	}
	return f.csrfOf(page)
}

func (f *webFixture) signedInBrowsers(n int) []*browser {
	f.t.Helper()
	var browsers []*browser
	for range n {
		b := f.newBrowser()
		if r := b.signInAgain(); r.StatusCode != http.StatusSeeOther {
			f.t.Fatalf("a sign-in gave %d", r.StatusCode)
		}
		browsers = append(browsers, b)
	}
	return browsers
}

func isSignedOut(b *browser) bool {
	r := b.get("/")
	return r.StatusCode == http.StatusSeeOther && r.location() == adminMount+"/login"
}

func TestTheAccountPageIsForASessionAndListsTheSessionsOfTheAdministrator(t *testing.T) {
	f := newWebFixture(t)
	if r := f.get("/account"); r.StatusCode != http.StatusSeeOther || r.location() != "/admin/login" {
		t.Fatalf("the account page for a visitor is %d %q", r.StatusCode, r.location())
	}
	f.enroll()
	f.signedInBrowsers(1)
	page := f.get("/account")
	for _, want := range []string{
		"Your account", "The account was made on", `action="/admin/account/password"`, `name="current"`, `name="new"`, `name="again"`,
		`autocomplete="new-password"`, `action="/admin/account/recovery"`, `action="/admin/account/authenticator"`, "Recovery codes left: 10.",
		"Where you are signed in", "<strong>This session</strong>", `action="/admin/account/sessions/end"`, "End every other session", "127.0.0.1", "Go-http-client",
	} {
		if page.StatusCode != http.StatusOK || !page.has(want) {
			t.Errorf("the account page is %d and lacks %q", page.StatusCode, want)
		}
	}
	if got := strings.Count(page.body, "<strong>This session</strong>"); got != 1 {
		t.Errorf("%d sessions are marked as the current one", got)
	}
	if got := len(sessionIDPattern.FindAllStringSubmatch(page.body, -1)); got != 1 {
		t.Errorf("%d sessions can be ended from the page, want the one that is not the current", got)
	}
	if r := f.request(http.MethodHead, "/account"); r.StatusCode != http.StatusOK || r.body != "" {
		t.Errorf("HEAD of the account page = %d with %d bytes", r.StatusCode, len(r.body))
	}

	if got := f.get("/account?done=password"); !got.has("The password was changed. Every other session was ended.") || !got.has("alert-notice") {
		t.Error("the notice of a changed password is not shown")
	}
	if got := f.get("/account?done=session"); !got.has("The session was ended.") {
		t.Error("the notice of an ended session is not shown")
	}
	for _, query := range []string{"?done=bogus", "?done=", "?done=<script>alert(1)</script>", "?done=password&done=session", "?done=%00"} {
		if got := f.get("/account" + query); got.StatusCode != http.StatusOK && !strings.Contains(query, "&") || strings.Contains(got.body, "alert-notice") && !strings.Contains(query, "&") || strings.Contains(got.body, "<script>alert") {
			t.Errorf("the query %q gave %d with a notice or an echo", query, got.StatusCode)
		}
	}
	if ru := f.get("/account", "Accept-Language", "ru"); !ru.has("Ваша учётная запись") || !ru.has("Этот сеанс") || !ru.has(`<html lang="ru">`) {
		t.Error("the account page is not in Russian for a Russian browser")
	}
}

func TestAnAdministratorChangesTheirPasswordThroughTheBrowser(t *testing.T) {
	f := newWebFixture(t)
	f.enroll()
	others := f.signedInBrowsers(2)
	token := f.accountToken()
	form := func(current, next, again string) url.Values {
		return url.Values{"current": {current}, "new": {next}, "again": {again}, "csrf": {token}}
	}
	refused := []struct {
		name   string
		form   url.Values
		status int
		text   string
	}{
		{"two new passwords that differ", form(adminPassword, changedPassword, changedPassword+"x"), http.StatusUnprocessableEntity, "The two new passwords are not the same."},
		{"a current password that is wrong", form("not the password", changedPassword, changedPassword), http.StatusUnauthorized, "The current password is wrong."},
		{"a new password that is too short", form(adminPassword, "short", "short"), http.StatusUnprocessableEntity, "The new password is not allowed: it is too short."},
		{"a new password that is common", form(adminPassword, "password1234", "password1234"), http.StatusUnprocessableEntity, "many people use it"},
		{"the current password again", form(adminPassword, adminPassword, adminPassword), http.StatusUnprocessableEntity, "it is the current password"},
		{"a new password that is too long", form(adminPassword, strings.Repeat("a", maxAdminPasswordInput+1), strings.Repeat("a", maxAdminPasswordInput+1)), http.StatusUnprocessableEntity, "it is too long"},
		{"a current password that is too long", form(strings.Repeat("a", maxAdminPasswordInput+1), changedPassword, changedPassword), http.StatusUnauthorized, "The current password is wrong."},
		{"a wrong password and a new one that is too long", form("not the password", strings.Repeat("b", maxAdminPasswordInput+1), strings.Repeat("b", maxAdminPasswordInput+1)), http.StatusUnprocessableEntity, "it is too long"},
	}
	for _, c := range refused {
		r := f.post("/account/password", c.form)
		if r.StatusCode != c.status || !r.has(c.text) || !r.has(`action="/admin/account/password"`) || !r.has(`role="alert"`) {
			t.Errorf("%s: the answer is %d: %.300s", c.name, r.StatusCode, r.body)
		}
		if c.status == http.StatusUnauthorized && r.Header.Get("WWW-Authenticate") == "" {
			t.Errorf("%s: a refusal of the password has no WWW-Authenticate", c.name)
		}
		if strings.Contains(r.body, changedPassword) || strings.Contains(r.body, adminPassword) {
			t.Errorf("%s: the page shows a password", c.name)
		}
	}
	if len(f.records(audit.AdminPasswordChanged)) != 0 {
		t.Fatal("a change that was refused was recorded as made")
	}
	if got := len(f.failures("account", "wrong_password")); got != 1 {
		t.Fatalf("%d wrong passwords of the account page were recorded, want 1", got)
	}
	if got := len(f.failures("account", "too_long")); got != 1 {
		t.Fatalf("%d passwords that are too long were recorded, want 1", got)
	}
	if got := len(f.records(audit.AdminLoginFailed)); got != 2 {
		t.Fatalf("%d failures were recorded, want the wrong password and the one that is too long: a new password that is too long is refused before anything is checked", got)
	}
	for _, b := range others {
		if isSignedOut(b) {
			t.Fatal("a change that was refused ended a session")
		}
	}

	done := f.post("/account/password", form(adminPassword, changedPassword, changedPassword))
	if done.StatusCode != http.StatusSeeOther || done.location() != "/admin/account?done=password" {
		t.Fatalf("the change gave %d %q: %.200s", done.StatusCode, done.location(), done.body)
	}
	if after := f.get(done.location()[len(adminMount):]); after.StatusCode != http.StatusOK || !after.has("The password was changed.") {
		t.Fatalf("the page after the change is %d", after.StatusCode)
	}
	for _, b := range others {
		if !isSignedOut(b) {
			t.Fatal("a session of another browser survived the change of the password")
		}
	}
	records := f.records(audit.AdminPasswordChanged)
	if len(records) != 1 || !strings.Contains(records[0].Details, `"sessions_ended":2`) || records[0].IP != "127.0.0.1" || strings.Contains(records[0].Details, changedPassword) {
		t.Fatalf("the change is recorded as %+v", records)
	}

	fresh := f.newBrowser()
	if r := fresh.post("/login", url.Values{"login": {adminLoginName}, "password": {adminPassword}}); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the old password gave %d", r.StatusCode)
	}
	if r := fresh.post("/login", url.Values{"login": {adminLoginName}, "password": {changedPassword}}); r.StatusCode != http.StatusSeeOther || r.location() != "/admin/login/code" {
		t.Fatalf("the new password gave %d %q", r.StatusCode, r.location())
	}
}

func TestWrongPasswordsOnTheAccountPageCountAgainstTheLimitsOfTheSignIn(t *testing.T) {
	f := newWebFixture(t)
	f.enroll()
	token := f.accountToken()
	wrong := url.Values{"current": {"not the password"}, "new": {changedPassword}, "again": {changedPassword}, "csrf": {token}}
	for i := 1; i <= 5; i++ {
		if r := f.post("/account/password", wrong); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the wrong password %d gave %d", i, r.StatusCode)
		}
	}
	right := url.Values{"current": {adminPassword}, "new": {changedPassword}, "again": {changedPassword}, "csrf": {token}}
	if r := f.post("/account/password", right); r.StatusCode != http.StatusTooManyRequests || r.Header.Get("Retry-After") != "1800" {
		t.Fatalf("the right password after five wrong ones gave %d with Retry-After %q", r.StatusCode, r.Header.Get("Retry-After"))
	}
	for _, path := range []string{"/account/recovery", "/account/authenticator"} {
		if r := f.post(path, url.Values{"password": {adminPassword}, "csrf": {token}}); r.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("%s while the login is paused gave %d", path, r.StatusCode)
		}
	}
	other := f.newBrowser()
	if r := other.post("/login", url.Values{"login": {adminLoginName}, "password": {adminPassword}}); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the sign-in of a login whose account page was guessed at gave %d", r.StatusCode)
	}
	f.clock.advance(31 * time.Minute)
	if r := f.post("/account/password", right); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("the change after the pause gave %d", r.StatusCode)
	}
}

func TestNewRecoveryCodesAreShownOnceThroughTheBrowser(t *testing.T) {
	f := newWebFixture(t)
	codes := f.enroll()
	token := f.accountToken()
	if r := f.post("/account/recovery", url.Values{"password": {"not the password"}, "csrf": {token}}); r.StatusCode != http.StatusUnauthorized || !r.has("The current password is wrong.") {
		t.Fatalf("new codes for a wrong password gave %d", r.StatusCode)
	}
	r := f.post("/account/recovery", url.Values{"password": {adminPassword}, "csrf": {token}})
	if r.StatusCode != http.StatusOK || !r.has("Your recovery codes") || strings.Count(r.body, "<code>") != 10 {
		t.Fatalf("new codes gave %d: %.300s", r.StatusCode, r.body)
	}
	var fresh []string
	for _, m := range recoveryPattern.FindAllStringSubmatch(r.body, -1) {
		fresh = append(fresh, m[1])
	}
	for _, code := range fresh {
		if !recoveryCodeShape.MatchString(code) {
			t.Errorf("the code %q has not the shape of a recovery code", code)
		}
		for _, old := range codes {
			if code == old {
				t.Errorf("a new code is an old one: %s", code)
			}
		}
	}
	if got := f.get("/account"); !got.has("Recovery codes left: 10.") || got.has(fresh[0]) {
		t.Error("the account page does not count the codes, or shows one of them")
	}
	if again := f.get("/account/recovery"); again.StatusCode != http.StatusMethodNotAllowed || again.has(fresh[0]) {
		t.Errorf("the codes can be shown again: %d", again.StatusCode)
	}

	old := f.newBrowser()
	old.password()
	oldPage := old.get("/login/code")
	if r = old.post("/login/code", url.Values{"code": {codes[0]}, "csrf": {old.csrfOf(oldPage)}}); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an old recovery code gave %d", r.StatusCode)
	}
	if r = old.post("/login/code", url.Values{"code": {fresh[0]}, "csrf": {old.csrfOf(oldPage)}}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("a new recovery code gave %d", r.StatusCode)
	}
	if len(f.records(audit.AdminRecoveryCodesRenewed)) != 1 {
		t.Fatal("the renewal was not recorded")
	}
}

func decodeSecret(t *testing.T, page webResponse) []byte {
	t.Helper()
	match := secretPattern.FindStringSubmatch(page.body)
	if match == nil {
		t.Fatalf("the page has no key: %.300s", page.body)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(match[1], " ", ""))
	if err != nil {
		t.Fatalf("the key %q is not base32: %v", match[1], err)
	}
	return seed
}

func TestAnotherAuthenticatorIsBoundThroughTheBrowser(t *testing.T) {
	f := newWebFixture(t, WithAdminSessionTTL(6*time.Hour, 2*time.Hour))
	f.enroll()
	oldSeed := f.seed()
	others := f.signedInBrowsers(1)
	token := f.accountToken()

	if r := f.post("/account/authenticator", url.Values{"password": {"not the password"}, "csrf": {token}}); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a binding for a wrong password gave %d", r.StatusCode)
	}
	begin := f.post("/account/authenticator", url.Values{"password": {adminPassword}, "csrf": {token}})
	for _, want := range []string{"Bind another authenticator", "<svg", `action="/admin/account/authenticator/confirm"`, `name="token"`, `href="otpauth://totp/`} {
		if begin.StatusCode != http.StatusOK || !begin.has(want) {
			t.Errorf("the page of the binding is %d and lacks %q", begin.StatusCode, want)
		}
	}
	newSeed := decodeSecret(t, begin)
	if string(newSeed) == string(oldSeed) || len(newSeed) != totp.SecretLength {
		t.Fatal("the new key is the old one, or has a wrong length")
	}
	bound := f.seed()
	if string(bound) != string(oldSeed) {
		t.Fatal("a binding that waits replaced the authenticator that works")
	}
	tokenOfBinding := regexp.MustCompile(`name="token" value="([^"]+)"`).FindStringSubmatch(begin.body)[1]
	confirm := func(code, bindingToken string) webResponse {
		return f.post("/account/authenticator/confirm", url.Values{"code": {code}, "token": {bindingToken}, "csrf": {token}})
	}

	f.clock.advance(2 * totp.StepSeconds * time.Second)
	wrong := notAnyCodeOf(newSeed, f.clock.now())
	again := confirm(wrong, tokenOfBinding)
	if again.StatusCode != http.StatusUnauthorized || !again.has("The code is wrong.") || again.Header.Get("WWW-Authenticate") == "" || string(decodeSecret(t, again)) != string(newSeed) ||
		!again.has(tokenOfBinding) {
		t.Fatalf("a wrong code gave %d: %.300s", again.StatusCode, again.body)
	}
	if got := len(f.failures("account", "wrong_code")); got != 1 {
		t.Fatalf("%d wrong codes of the binding were recorded, want 1", got)
	}
	if r := confirm(totp.Code(oldSeed, totp.Step(f.clock.now())), tokenOfBinding); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a code of the old authenticator gave %d", r.StatusCode)
	}
	for name, bad := range map[string]string{"a token that was changed": flip(tokenOfBinding), "no token": "", "a token that is long": strings.Repeat("A", 1000)} {
		r := confirm(totp.Code(newSeed, totp.Step(f.clock.now())), bad)
		if r.StatusCode != http.StatusUnprocessableEntity || !r.has("The binding has expired. Start again.") || r.has("Your recovery codes") {
			t.Errorf("%s: the confirmation gave %d", name, r.StatusCode)
		}
	}
	if string(f.seed()) != string(oldSeed) {
		t.Fatal("a confirmation that was refused changed the authenticator")
	}

	done := confirm(totp.Code(newSeed, totp.Step(f.clock.now())), tokenOfBinding)
	if done.StatusCode != http.StatusOK || !done.has("Your recovery codes") || strings.Count(done.body, "<code>") != 10 {
		t.Fatalf("the confirmation gave %d: %.300s", done.StatusCode, done.body)
	}
	if string(f.seed()) != string(newSeed) {
		t.Fatal("the authenticator was not replaced")
	}
	wrongPassword := url.Values{"current": {"not the password"}, "new": {changedPassword}, "again": {changedPassword}, "csrf": {token}}
	for i := 1; i <= 5; i++ {
		if r := f.post("/account/password", wrongPassword); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the wrong password %d after the binding gave %d: the count of failures was not cleared", i, r.StatusCode)
		}
	}
	f.clock.advance(31 * time.Minute)
	if !isSignedOut(others[0]) {
		t.Fatal("a session of another browser survived the binding of another authenticator")
	}
	if f.get("/account").StatusCode != http.StatusOK {
		t.Fatal("the session that bound the authenticator ended")
	}
	if r := confirm(totp.Code(newSeed, totp.Step(f.clock.now())), tokenOfBinding); r.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("a token that was used gave %d, want it to be of no use", r.StatusCode)
	}
	records := f.records(audit.AdminTOTPRebound)
	if len(records) != 1 || !strings.Contains(records[0].Details, `"sessions_ended":1`) || strings.Contains(records[0].Details, tokenOfBinding) {
		t.Fatalf("the binding is recorded as %+v", records)
	}

	f.clock.advance(totp.StepSeconds * time.Second)
	old := f.newBrowser()
	old.password()
	page := old.get("/login/code")
	if r := old.post("/login/code", url.Values{"code": {totp.Code(oldSeed, totp.Step(f.clock.now()))}, "csrf": {old.csrfOf(page)}}); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a code of the old authenticator gave %d at the sign-in", r.StatusCode)
	}
	if r := old.post("/login/code", url.Values{"code": {totp.Code(newSeed, totp.Step(f.clock.now()))}, "csrf": {old.csrfOf(page)}}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("a code of the new authenticator gave %d at the sign-in", r.StatusCode)
	}
}

func notAnyCodeOf(seed []byte, now time.Time) string {
	valid := map[string]bool{}
	step := totp.Step(now)
	for offset := int64(-totp.Window); offset <= totp.Window; offset++ {
		valid[totp.Code(seed, step+offset)] = true
	}
	for _, candidate := range []string{"000000", "111111", "222222", "333333"} {
		if !valid[candidate] {
			return candidate
		}
	}
	return "444444"
}

func flip(token string) string {
	if token == "" {
		return token
	}
	middle := len(token) / 2
	replacement := "A"
	if token[middle] == 'A' {
		replacement = "B"
	}
	return token[:middle] + replacement + token[middle+1:]
}

func TestAnAuthenticatorThatWasNotConfirmedInTimeIsNotBound(t *testing.T) {
	f := newWebFixture(t)
	f.enroll()
	oldSeed := f.seed()
	token := f.accountToken()
	begin := f.post("/account/authenticator", url.Values{"password": {adminPassword}, "csrf": {token}})
	newSeed := decodeSecret(t, begin)
	tokenOfBinding := regexp.MustCompile(`name="token" value="([^"]+)"`).FindStringSubmatch(begin.body)[1]
	f.clock.advance(11 * time.Minute)
	r := f.post("/account/authenticator/confirm", url.Values{"code": {totp.Code(newSeed, totp.Step(f.clock.now()))}, "token": {tokenOfBinding}, "csrf": {token}})
	if r.StatusCode != http.StatusUnprocessableEntity || !r.has("The binding has expired.") {
		t.Fatalf("a binding that ran out gave %d", r.StatusCode)
	}
	if string(f.seed()) != string(oldSeed) {
		t.Fatal("the authenticator was replaced by a binding that ran out")
	}
}

func TestOwnSessionsAreEndedThroughTheBrowser(t *testing.T) {
	f := newWebFixture(t)
	f.enroll()
	others := f.signedInBrowsers(2)
	page := f.get("/account")
	token := f.csrfOf(page)
	var ids []string
	for _, m := range sessionIDPattern.FindAllStringSubmatch(page.body, -1) {
		ids = append(ids, m[1])
	}
	if len(ids) != 2 {
		t.Fatalf("the page offers to end %d sessions, want 2", len(ids))
	}
	post := func(id string) webResponse {
		return f.post("/account/sessions/end", url.Values{"session": {id}, "csrf": {token}})
	}
	if r := post(ids[0]); r.StatusCode != http.StatusSeeOther || r.location() != "/admin/account?done=session" {
		t.Fatalf("ending a session gave %d %q", r.StatusCode, r.location())
	}
	if ended := isSignedOut(others[0]) != isSignedOut(others[1]); !ended {
		t.Fatal("exactly one of the other sessions should have ended")
	}
	for name, id := range map[string]string{"a session that is not there": "no-such-session", "an ID that is too long": strings.Repeat("x", 500), "no ID": ""} {
		if r := post(id); r.StatusCode != http.StatusSeeOther {
			t.Errorf("%s: the answer is %d", name, r.StatusCode)
		}
	}
	own, err := f.a.admins.Resolve(t.Context(), f.cookie(webSessionCookie).Value)
	if err != nil {
		t.Fatal(err)
	}
	if r := post(own.ID); r.StatusCode != http.StatusSeeOther || f.get("/account").StatusCode != http.StatusOK {
		t.Fatalf("the session that asks cannot be ended this way: %d", r.StatusCode)
	}
	if got := len(f.records(audit.AdminSessionEnded)); got != 1 {
		t.Fatalf("%d ends of a session were recorded, want 1", got)
	}

	if r := f.post("/account/sessions/end-others", url.Values{"csrf": {token}}); r.StatusCode != http.StatusSeeOther || r.location() != "/admin/account?done=sessions" {
		t.Fatalf("ending the other sessions gave %d %q", r.StatusCode, r.location())
	}
	if !isSignedOut(others[0]) || !isSignedOut(others[1]) || f.get("/account").StatusCode != http.StatusOK {
		t.Fatal("the other sessions are not all ended, or the one that asks is")
	}
	if got := f.get("/account"); !got.has("There is no other session.") || got.has("End every other session") {
		t.Fatal("the page offers to end sessions that are not there")
	}
	records := f.records(audit.AdminSessionsEnded)
	if len(records) != 1 || !strings.Contains(records[0].Details, `"sessions_ended":1`) {
		t.Fatalf("the end of the sessions is recorded as %+v", records)
	}
}

func TestTheStepsOfTheAccountNeedASessionTheTokenOfItAndTheOriginOfTheSite(t *testing.T) {
	routes := map[string]url.Values{
		"/account/password":              {"current": {adminPassword}, "new": {changedPassword}, "again": {changedPassword}},
		"/account/recovery":              {"password": {adminPassword}},
		"/account/authenticator":         {"password": {adminPassword}},
		"/account/authenticator/confirm": {"code": {"123456"}, "token": {"x"}},
		"/account/sessions/end":          {"session": {"x"}},
		"/account/sessions/end-others":   {},
	}
	f := newWebFixture(t)
	f.enroll()
	token := f.accountToken()
	visitor := f.newBrowser()
	for path, values := range routes {
		with := func(csrf string) url.Values {
			form := url.Values{"csrf": {csrf}}
			for k, v := range values {
				form[k] = v
			}
			return form
		}
		if r := visitor.post(path, with(token)); r.StatusCode != http.StatusSeeOther || r.location() != "/admin/login" {
			t.Errorf("%s for a visitor gave %d %q", path, r.StatusCode, r.location())
		}
		for name, c := range map[string]struct {
			values  url.Values
			headers []string
			status  int
		}{
			"no token":               {values, nil, http.StatusForbidden},
			"another token":          {with(token + "x"), nil, http.StatusForbidden},
			"the token of the login": {with(f.a.keys.CSRFToken("admin:no-such-session")), nil, http.StatusForbidden},
			"another site":           {with(token), []string{"Sec-Fetch-Site", "cross-site"}, http.StatusForbidden},
			"another origin":         {with(token), []string{"Origin", "https://evil.example"}, http.StatusForbidden},
			"no origin":              {with(token), []string{"Origin", ""}, http.StatusForbidden},
		} {
			if r := f.post(path, c.values, c.headers...); r.StatusCode != c.status {
				t.Errorf("%s with %s gave %d, want %d", path, name, r.StatusCode, c.status)
			}
		}
	}
	if got := len(f.records(audit.AdminPasswordChanged)) + len(f.records(audit.AdminSessionEnded)) + len(f.records(audit.AdminRecoveryCodesRenewed)) + len(f.records(audit.AdminTOTPRebound)); got != 0 {
		t.Fatalf("%d changes were made by requests that were refused", got)
	}
	if f.get("/account").StatusCode != http.StatusOK {
		t.Fatal("a request that was refused ended the session")
	}
}

func TestWithoutTheSecondFactorTheAccountHasOnlyThePasswordAndTheSessions(t *testing.T) {
	f := newWebFixture(t, WithoutAdminTOTP())
	f.password()
	page := f.get("/account")
	if !page.has(`action="/admin/account/password"`) || page.has(`action="/admin/account/recovery"`) || page.has(`action="/admin/account/authenticator"`) || page.has("Recovery codes left") {
		t.Fatalf("the account page without a second factor is wrong: %.600s", page.body)
	}
	token := f.csrfOf(page)
	for _, path := range []string{"/account/recovery", "/account/authenticator"} {
		if r := f.post(path, url.Values{"password": {adminPassword}, "csrf": {token}}); r.StatusCode != http.StatusNotFound {
			t.Errorf("%s without a second factor gave %d", path, r.StatusCode)
		}
	}
	if r := f.post("/account/authenticator/confirm", url.Values{"code": {"123456"}, "token": {"x"}, "csrf": {token}}); r.StatusCode != http.StatusNotFound {
		t.Errorf("the confirmation without a second factor gave %d", r.StatusCode)
	}
	if r := f.post("/account/password", url.Values{"current": {adminPassword}, "new": {changedPassword}, "again": {changedPassword}, "csrf": {token}}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("the change of the password gave %d", r.StatusCode)
	}
}

func TestAnAccountThatChangedMeanwhileSendsToTheSignIn(t *testing.T) {
	f := newWebFixture(t)
	f.enroll()
	token := f.accountToken()
	if err := f.a.Admin().ResetAdminPassword(t.Context(), adminLoginName, changedPassword); err != nil {
		t.Fatal(err)
	}
	if r := f.get("/account"); r.StatusCode != http.StatusSeeOther || r.location() != "/admin/login" {
		t.Fatalf("the account page after a reset of the password gave %d %q", r.StatusCode, r.location())
	}
	if r := f.post("/account/password", url.Values{"current": {changedPassword}, "new": {adminPassword}, "again": {adminPassword}, "csrf": {token}}); r.StatusCode != http.StatusSeeOther || r.location() != "/admin/login" {
		t.Fatalf("a change with a session that ended gave %d %q", r.StatusCode, r.location())
	}
}

func TestAFailureOfTheStoreDuringAChangeOfThePasswordIsAnErrorPageAndChangesNothing(t *testing.T) {
	f, faults, logs := newFaultyWebFixture(t)
	f.enroll()
	token := f.accountToken()
	before, err := f.a.store.Admins().FindByLogin(t.Context(), f.a.tenant, adminLoginName)
	if err != nil {
		t.Fatal(err)
	}
	faults.set("audit.add", errors.New("the audit log is down"))
	r := f.post("/account/password", url.Values{"current": {adminPassword}, "new": {changedPassword}, "again": {changedPassword}, "csrf": {token}})
	if r.StatusCode != http.StatusInternalServerError || !r.has("Something went wrong") || r.has("audit log is down") {
		t.Fatalf("a change that cannot be recorded gave %d", r.StatusCode)
	}
	if !strings.Contains(logs.String(), "the audit log is down") {
		t.Fatalf("the log does not say why: %q", logs.String())
	}
	found, err := f.a.store.Admins().FindByLogin(t.Context(), f.a.tenant, adminLoginName)
	if err != nil || found.Version != before.Version || found.PasswordHash != before.PasswordHash {
		t.Fatalf("the account is %+v, %v: a change that failed must leave it as it was", found, err)
	}
	faults.clear()
	if r = f.post("/account/password", url.Values{"current": {adminPassword}, "new": {changedPassword}, "again": {changedPassword}, "csrf": {token}}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("the change after the failure gave %d", r.StatusCode)
	}
	if got := f.records(audit.AdminPasswordChanged); len(got) != 1 || got[0].ActorKind != store.ActorAdmin {
		t.Fatalf("the change is recorded as %+v", got)
	}
}

func TestASuccessfulStepOfTheAccountClearsTheCountOfWrongPasswords(t *testing.T) {
	f := newWebFixture(t)
	f.enroll()
	token := f.accountToken()
	wrong := url.Values{"password": {"not the password"}, "csrf": {token}}
	for range 4 {
		if r := f.post("/account/recovery", wrong); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("a wrong password gave %d", r.StatusCode)
		}
	}
	if r := f.post("/account/recovery", url.Values{"password": {adminPassword}, "csrf": {token}}); r.StatusCode != http.StatusOK {
		t.Fatalf("the right password gave %d", r.StatusCode)
	}
	for i := 1; i <= 5; i++ {
		if r := f.post("/account/recovery", wrong); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the wrong password %d after the success gave %d: the count was not cleared", i, r.StatusCode)
		}
	}
	if r := f.post("/account/recovery", wrong); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the sixth wrong password after the success gave %d", r.StatusCode)
	}
}

func TestAPasswordThatChecksOfTheApplicationRefuseIsRefusedWithoutTheTextOfTheChecks(t *testing.T) {
	refuse := func(word, code string) func(context.Context, string) error {
		return func(_ context.Context, password string) error {
			if strings.Contains(password, word) {
				return errors.New(code)
			}
			return nil
		}
	}
	f := newWebFixture(t, WithPasswordPolicy(PasswordPolicy{Checks: []func(context.Context, string) error{refuse("alpha", "leaked-code"), refuse("beta", "other-code")}}))
	f.enroll()
	token := f.accountToken()
	change := func(next string) webResponse {
		return f.post("/account/password", url.Values{"current": {adminPassword}, "new": {next}, "again": {next}, "csrf": {token}})
	}
	both := change("alpha and beta words together")
	if both.StatusCode != http.StatusUnprocessableEntity || strings.Count(both.body, "it breaks a rule of the service") != 1 || both.has("leaked-code") || both.has("other-code") {
		t.Fatalf("two checks that refuse gave %d: %.400s", both.StatusCode, both.body)
	}
	mixed := change("alpha")
	if mixed.StatusCode != http.StatusUnprocessableEntity || !mixed.has("it is too short, it breaks a rule of the service") {
		t.Fatalf("a rule of the service and a rule of the check gave %d: %.400s", mixed.StatusCode, mixed.body)
	}
}

func TestAFailureOfAStepOfTheAccountIsAnsweredAsItShouldBe(t *testing.T) {
	a, _ := newLimitedAuth(t, WithAdminMountPath(adminMount), WithDevelopmentMode())
	site, ok := a.AdminHandler().(*adminSite)
	if !ok {
		t.Fatal("the handler of the administration is not a site")
	}
	cases := []struct {
		name     string
		err      error
		status   int
		location string
		text     string
	}{
		{"a pause", &RateLimitError{RetryAfter: 90 * time.Second}, http.StatusTooManyRequests, "", "Try again in 2 min."},
		{"a session that ended", admin.ErrNoSession, http.StatusSeeOther, adminMount + "/login", ""},
		{"a service without a second factor", admin.ErrNoSecondFactor, http.StatusNotFound, "", "Page not found"},
		{"another error", errors.New("the store failed"), http.StatusInternalServerError, "", "Something went wrong"},
	}
	for _, c := range cases {
		recorder := httptest.NewRecorder()
		call := &adminCall{s: site, w: recorder, r: httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/account/password", nil), lang: "en"}
		call.accountFailure(admin.Session{ID: "session", AdminID: "admin", Login: "root"}, c.err)
		if recorder.Code != c.status || recorder.Header().Get("Location") != c.location || !strings.Contains(recorder.Body.String(), c.text) {
			t.Errorf("%s: the answer is %d %q with %.100s", c.name, recorder.Code, recorder.Header().Get("Location"), recorder.Body.String())
		}
		if c.status == http.StatusSeeOther && !strings.Contains(strings.Join(recorder.Header().Values("Set-Cookie"), ";"), "limb_admin=;") {
			t.Errorf("%s: the cookie of the session was not cleared: %v", c.name, recorder.Header().Values("Set-Cookie"))
		}
	}
}
