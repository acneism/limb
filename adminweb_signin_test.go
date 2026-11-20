package limb

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/internal/memstore"
	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/internal/totp"
	"github.com/acneism/limb/store"
)

var recoveryCodeShape = regexp.MustCompile(`^[A-Z2-7]{5}(-[A-Z2-7]{5}){4}$`)

var signedInSentence = regexp.MustCompile(`<p class="muted">You signed in at \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC\.</p>`)

func newFaultyWebFixture(t *testing.T) (*webFixture, *faultSet, *logBuffer) {
	t.Helper()
	faults := newFaults()
	logger, logs := capturingLogger()
	a, err := NewWithStore(faultStore{Store: memstore.New(), faults: faults}, []byte(testKey),
		WithAutoMigrate(), WithLogger(logger), WithAdminMountPath(adminMount), WithDevelopmentMode())
	if err != nil {
		t.Fatalf("NewWithStore failed: %v", err)
	}
	a.hasher = newHasher(t, weakParams)
	clock := newFakeClock()
	a.now = clock.now
	return startWebFixture(t, a, clock), faults, logs
}

func TestAnAdministratorBindsAnAuthenticatorAndSignsInAndOutThroughTheBrowser(t *testing.T) {
	f := newWebFixture(t)
	login := f.get("/login")
	for _, want := range []string{`<html lang="en">`, `<h1 class="h1">Sign in</h1>`, `action="/admin/login"`, `name="login"`, `name="password"`, `autocomplete="current-password"`} {
		if !login.has(want) {
			t.Errorf("the sign-in page lacks %s", want)
		}
	}
	if login.StatusCode != http.StatusOK || login.has(`name="csrf"`) {
		t.Fatalf("the sign-in page is %d: %.400s", login.StatusCode, login.body)
	}
	if got := f.get("/"); got.StatusCode != http.StatusSeeOther || got.location() != "/admin/login" {
		t.Fatalf("the first page for a visitor is %d %q, want a redirect to the sign-in", got.StatusCode, got.location())
	}

	first := f.password()
	if first.StatusCode != http.StatusSeeOther || first.location() != "/admin/login/totp" {
		t.Fatalf("the password gave %d %q", first.StatusCode, first.location())
	}
	pending := f.cookie(webPendingCookie)
	if pending == nil || len(pending.Value) != secret.TextLen || f.cookie(webSessionCookie) != nil {
		t.Fatalf("the cookies are %+v and %+v: the password gives only the cookie of the second step", pending, f.cookie(webSessionCookie))
	}

	enrollment := f.get("/login/totp")
	seed := f.seed()
	grouped := groupSecret(totp.EncodeSecret(seed))
	for _, want := range []string{grouped, "<svg", `href="otpauth://totp/`, "secret=" + totp.EncodeSecret(seed), "QR code of the key of the authenticator", `action="/admin/login/totp"`, `name="csrf"`} {
		if enrollment.StatusCode != http.StatusOK || !enrollment.has(want) {
			t.Errorf("the page of the binding is %d and lacks %q", enrollment.StatusCode, want)
		}
	}
	if again := f.get("/login/totp"); !again.has(grouped) {
		t.Fatal("the page that is shown again has another key")
	}
	token := f.csrfOf(enrollment)
	typed := f.wrongCode()
	refused := f.post("/login/totp", url.Values{"code": {typed}, "csrf": {token}})
	if refused.StatusCode != http.StatusUnauthorized || !refused.has(`role="alert"`) || !refused.has("The code is wrong.") || !refused.has(grouped) ||
		refused.Header.Get("WWW-Authenticate") == "" || f.cookie(webSessionCookie) != nil {
		t.Fatalf("a wrong code gave %d: %.400s", refused.StatusCode, refused.body)
	}
	if got := f.failures("second_factor", "wrong_code"); len(got) != 1 || got[0].ActorKind != store.ActorAdmin || got[0].ActorID == "" || strings.Contains(got[0].Details, typed) {
		t.Fatalf("a wrong code of the binding is recorded as %+v", got)
	}
	done := f.post("/login/totp", url.Values{"code": {f.code()}, "csrf": {token}})
	if done.StatusCode != http.StatusOK || !done.has("Your recovery codes") || !done.has(`action="/admin/logout"`) || strings.Count(done.body, "<code>") != 10 {
		t.Fatalf("the binding gave %d: %.600s", done.StatusCode, done.body)
	}
	seen := map[string]bool{}
	for _, m := range recoveryPattern.FindAllStringSubmatch(done.body, -1) {
		if !recoveryCodeShape.MatchString(m[1]) || seen[m[1]] {
			t.Errorf("the recovery code %q is not of the form of five groups of five characters, or is a copy", m[1])
		}
		seen[m[1]] = true
	}
	session := f.cookie(webSessionCookie)
	if session == nil || len(session.Value) != secret.TextLen || session.Value == pending.Value || f.cookie(webPendingCookie) != nil {
		t.Fatal("the session has the secret of the sign-in, or the cookie of the sign-in stayed")
	}
	if set := done.cookie(webSessionCookie); set == nil || !set.HttpOnly || set.SameSite != http.SameSiteStrictMode || set.Path != adminMount+"/" || set.MaxAge != 0 {
		t.Fatalf("the cookie of the session that the binding set is %+v", set)
	}

	home := f.get("/")
	for _, want := range []string{"Welcome, root.", "Signed in as root", `action="/admin/logout"`} {
		if home.StatusCode != http.StatusOK || !home.has(want) {
			t.Errorf("the first page is %d and lacks %q", home.StatusCode, want)
		}
	}
	if !signedInSentence.MatchString(home.body) || home.has("&lt;time") || home.has("<time") {
		t.Errorf("the first page does not say when the administrator signed in, in words: %.600s", home.body)
	}
	if home.has("recovery codes left") {
		t.Error("the first page warns about the recovery codes although there are ten")
	}
	if got := f.get("/login"); got.StatusCode != http.StatusSeeOther || got.location() != "/admin/" {
		t.Fatalf("the sign-in page of an administrator who is signed in is %d %q", got.StatusCode, got.location())
	}
	enrolled, signedIn := f.records(audit.AdminTOTPEnrolled), f.records(audit.AdminLogin)
	if len(enrolled) != 1 || len(signedIn) != 1 || signedIn[0].ActorKind != store.ActorAdmin || signedIn[0].ActorID == "" || signedIn[0].IP != "127.0.0.1" {
		t.Fatalf("the audit log holds %+v and %+v", enrolled, signedIn)
	}

	out := f.post("/logout", url.Values{"csrf": {f.csrfOf(home)}})
	if out.StatusCode != http.StatusSeeOther || out.location() != "/admin/login" || f.cookie(webSessionCookie) != nil {
		t.Fatalf("signing out gave %d %q", out.StatusCode, out.location())
	}
	if got := f.get("/"); got.StatusCode != http.StatusSeeOther || got.location() != "/admin/login" {
		t.Fatalf("the first page after signing out is %d %q", got.StatusCode, got.location())
	}
	copied := f.newBrowser()
	copied.setCookie(webSessionCookie, session.Value, adminMount+"/")
	if got := copied.get("/"); got.StatusCode != http.StatusSeeOther {
		t.Fatalf("a copy of the cookie of a session that was ended gave %d: the end of a session is the business of the server", got.StatusCode)
	}
	if len(f.records(audit.AdminLogout)) != 1 {
		t.Fatal("the sign-out was not recorded")
	}
}

func TestTheSecondStepTakesAOneTimePasswordOnceAndARecoveryCodeOnce(t *testing.T) {
	t.Run("a one-time password works once", func(t *testing.T) {
		f := newWebFixture(t)
		f.enroll()
		f.browser = f.newBrowser()
		if r := f.password(); r.StatusCode != http.StatusSeeOther || r.location() != "/admin/login/code" {
			t.Fatalf("the password gave %d %q", r.StatusCode, r.location())
		}
		page := f.get("/login/code")
		for _, want := range []string{"Confirm it is you", "Signing in as root", `autocomplete="one-time-code"`, `action="/admin/login/code"`, `href="/admin/login"`} {
			if !page.has(want) {
				t.Errorf("the page of the second step lacks %q", want)
			}
		}
		token := f.csrfOf(page)
		typed := f.wrongCode()
		wrong := f.post("/login/code", url.Values{"code": {typed}, "csrf": {token}})
		if wrong.StatusCode != http.StatusUnauthorized || !wrong.has("The code is wrong") || !wrong.has(`role="alert"`) || wrong.Header.Get("WWW-Authenticate") == "" || f.cookie(webSessionCookie) != nil {
			t.Fatalf("a wrong code gave %d: %.300s", wrong.StatusCode, wrong.body)
		}
		if got := f.failures("second_factor", "wrong_code"); len(got) != 1 || got[0].ActorKind != store.ActorAdmin || got[0].ActorID == "" || got[0].IP != "127.0.0.1" ||
			strings.Contains(got[0].Details, typed) || detailsOf(t, got[0])["login"] != adminLoginName {
			t.Fatalf("a wrong code is recorded as %+v", got)
		}
		code := f.code()
		ok := f.post("/login/code", url.Values{"code": {code}, "csrf": {token}})
		if ok.StatusCode != http.StatusSeeOther || ok.location() != "/admin/" || f.cookie(webSessionCookie) == nil || f.cookie(webPendingCookie) != nil {
			t.Fatalf("the right code gave %d %q", ok.StatusCode, ok.location())
		}
		if f.get("/").StatusCode != http.StatusOK {
			t.Fatal("the session does not work")
		}
		if r := f.post("/login/code", url.Values{"code": {code}, "csrf": {token}}); r.StatusCode != http.StatusSeeOther || r.location() != "/admin/login" {
			t.Fatalf("a sign-in that has ended and is used again gave %d %q", r.StatusCode, r.location())
		}

		f.browser = f.newBrowser()
		f.password()
		again := f.get("/login/code")
		if replay := f.post("/login/code", url.Values{"code": {code}, "csrf": {f.csrfOf(again)}}); replay.StatusCode != http.StatusUnauthorized || f.cookie(webSessionCookie) != nil {
			t.Fatalf("a one-time password that was used gave %d", replay.StatusCode)
		}
		for _, shape := range []func(code string) string{
			func(code string) string { return " " + code[:3] + " " + code[3:] + " " },
			func(code string) string { return "\t" + code + "\r\n" },
			func(code string) string { return code[:3] + "-" + code[3:] },
		} {
			f.clock.advance(totp.StepSeconds * time.Second)
			f.browser = f.newBrowser()
			f.password()
			page := f.get("/login/code")
			typed := shape(f.code())
			if r := f.post("/login/code", url.Values{"code": {typed}, "csrf": {f.csrfOf(page)}}); r.StatusCode != http.StatusSeeOther {
				t.Errorf("a one-time password typed as %q gave %d", typed, r.StatusCode)
			}
		}
	})

	t.Run("a recovery code works once", func(t *testing.T) {
		f := newWebFixture(t)
		codes := f.enroll()
		f.browser = f.newBrowser()
		f.password()
		page := f.get("/login/code")
		typed := " " + strings.ToLower(codes[0]) + " "
		if r := f.post("/login/code", url.Values{"code": {typed}, "csrf": {f.csrfOf(page)}}); r.StatusCode != http.StatusSeeOther || r.location() != "/admin/" || f.cookie(webSessionCookie) == nil {
			t.Fatalf("a recovery code typed in lower case with spaces gave %d", r.StatusCode)
		}
		used := f.records(audit.AdminRecoveryCodeUsed)
		if len(used) != 1 || !strings.Contains(used[0].Details, `"left":9`) || strings.Contains(used[0].Details, codes[0]) {
			t.Fatalf("the use of the recovery code is recorded as %+v", used)
		}

		f.browser = f.newBrowser()
		f.password()
		again := f.get("/login/code")
		if reuse := f.post("/login/code", url.Values{"code": {codes[0]}, "csrf": {f.csrfOf(again)}}); reuse.StatusCode != http.StatusUnauthorized || f.cookie(webSessionCookie) != nil {
			t.Fatalf("a recovery code that was used gave %d", reuse.StatusCode)
		}
		padded := "\t" + codes[1] + "\u00a0"
		if other := f.post("/login/code", url.Values{"code": {padded}, "csrf": {f.csrfOf(again)}}); other.StatusCode != http.StatusSeeOther {
			t.Fatalf("another recovery code padded with a tab and a no-break space gave %d", other.StatusCode)
		}
	})

	t.Run("what is no code is a wrong code", func(t *testing.T) {
		f := newWebFixture(t)
		f.enroll()
		for _, input := range []string{"", " ", "12345", "1234567", "abcdef", "ÄÖÜ", strings.Repeat("9", 4096), "00000\x00"} {
			f.browser = f.newBrowser()
			f.password()
			r := f.post("/login/code", url.Values{"code": {input}, "csrf": {f.csrfOf(f.get("/login/code"))}})
			if r.StatusCode != http.StatusUnauthorized || !r.has("The code is wrong") {
				t.Errorf("the input %.20q gave %d", input, r.StatusCode)
			}
			f.clock.advance(time.Hour)
		}
	})

	t.Run("a sign-in lives five minutes", func(t *testing.T) {
		f := newWebFixture(t)
		f.enroll()
		f.browser = f.newBrowser()
		f.password()
		page := f.get("/login/code")
		f.clock.advance(5*time.Minute + time.Second)
		r := f.post("/login/code", url.Values{"code": {f.code()}, "csrf": {f.csrfOf(page)}})
		if r.StatusCode != http.StatusUnauthorized || !r.has("The sign-in has expired") || f.cookie(webPendingCookie) != nil || f.cookie(webSessionCookie) != nil {
			t.Fatalf("a sign-in that was left for five minutes gave %d", r.StatusCode)
		}
	})

	t.Run("three guesses end the sign-in", func(t *testing.T) {
		f := newWebFixture(t)
		f.enroll()
		f.browser = f.newBrowser()
		f.password()
		page := f.get("/login/code")
		token := f.csrfOf(page)
		for i := 1; i <= 3; i++ {
			if r := f.post("/login/code", url.Values{"code": {f.wrongCode()}, "csrf": {token}}); r.StatusCode != http.StatusUnauthorized || !r.has("The code is wrong") {
				t.Fatalf("the guess %d gave %d: %.200s", i, r.StatusCode, r.body)
			}
		}
		r := f.post("/login/code", url.Values{"code": {f.code()}, "csrf": {token}})
		if r.StatusCode != http.StatusUnauthorized || !r.has("The sign-in has expired") || f.cookie(webPendingCookie) != nil || f.cookie(webSessionCookie) != nil {
			t.Fatalf("the right code after three wrong ones gave %d: the sign-in must be over", r.StatusCode)
		}
		if again := f.get("/login/code"); again.StatusCode != http.StatusSeeOther || again.location() != "/admin/login" {
			t.Fatalf("the page of the second step after the end of the sign-in is %d %q", again.StatusCode, again.location())
		}
	})
}

func TestOneOneTimePasswordOpensOneSessionWhateverTheNumberOfRequests(t *testing.T) {
	f := newWebFixture(t)
	f.enroll()
	const clients = 4
	browsers := make([]*browser, clients)
	tokens := make([]string, clients)
	for i := range browsers {
		browsers[i] = f.newBrowser()
		browsers[i].password()
		tokens[i] = browsers[i].csrfOf(browsers[i].get("/login/code"))
	}
	code := f.code()
	statuses := make([]int, clients)
	errs := make([]error, clients)
	var wg sync.WaitGroup
	for i := range browsers {
		wg.Go(func() {
			statuses[i], errs[i] = browsers[i].postStatus("/login/code", url.Values{"code": {code}, "csrf": {tokens[i]}})
		})
	}
	wg.Wait()
	opened := 0
	for i := range statuses {
		if errs[i] != nil {
			t.Fatalf("the request %d failed: %v", i, errs[i])
		}
		switch statuses[i] {
		case http.StatusSeeOther:
			opened++
		case http.StatusUnauthorized:
		default:
			t.Errorf("the request %d gave %d", i, statuses[i])
		}
	}
	if opened != 1 {
		t.Fatalf("%d sign-ins used the same one-time password, want exactly one", opened)
	}
	if got := len(f.records(audit.AdminLogin)); got != 2 {
		t.Fatalf("%d sign-ins were recorded, want the one of the binding and the one that won", got)
	}
}

func TestAStepThatChangesSomethingNeedsTheTokenOfItsPage(t *testing.T) {
	f := newWebFixture(t)
	f.enroll()
	f.browser = f.newBrowser()
	f.password()
	signInToken := f.csrfOf(f.get("/login/code"))
	other := f.newBrowser()
	other.password()
	otherToken := other.csrfOf(other.get("/login/code"))
	if signInToken == otherToken {
		t.Fatal("two sign-ins have the same token")
	}

	code := f.code()
	attempts := []struct {
		name, path string
		values     url.Values
	}{
		{"no token", "/login/code", url.Values{"code": {code}}},
		{"an empty token", "/login/code", url.Values{"code": {code}, "csrf": {""}}},
		{"a token that is longer", "/login/code", url.Values{"code": {code}, "csrf": {signInToken + "x"}}},
		{"a token that is shorter", "/login/code", url.Values{"code": {code}, "csrf": {signInToken[:len(signInToken)-1]}}},
		{"the token of another sign-in", "/login/code", url.Values{"code": {code}, "csrf": {otherToken}}},
		{"a token in the query and not in the form", "/login/code?csrf=" + url.QueryEscape(signInToken), url.Values{"code": {code}}},
	}
	for _, c := range attempts {
		if r := f.post(c.path, c.values); r.StatusCode != http.StatusForbidden {
			t.Errorf("%s: the step gave %d", c.name, r.StatusCode)
		}
	}
	waiting, err := f.a.admins.Pending(t.Context(), f.cookie(webPendingCookie).Value)
	if err != nil || waiting.Session.Attempts != 0 {
		t.Fatalf("the sign-in is %+v, %v: a request that was refused counted a guess", waiting.Session, err)
	}
	if r := f.post("/login/code", url.Values{"code": {code}, "csrf": {signInToken}}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("the step with its token gave %d", r.StatusCode)
	}

	home := f.get("/")
	sessionToken := f.csrfOf(home)
	if sessionToken == signInToken {
		t.Fatal("the session has the token of the sign-in")
	}
	logouts := []struct {
		name    string
		values  url.Values
		headers []string
	}{
		{"no token", url.Values{}, nil},
		{"another token", url.Values{"csrf": {sessionToken + "x"}}, nil},
		{"the token of the sign-in", url.Values{"csrf": {signInToken}}, nil},
		{"the right token from another site", url.Values{"csrf": {sessionToken}}, []string{"Sec-Fetch-Site", "cross-site"}},
		{"the right token from another origin", url.Values{"csrf": {sessionToken}}, []string{"Origin", "https://evil.example"}},
	}
	for _, c := range logouts {
		if r := f.post("/logout", c.values, c.headers...); r.StatusCode != http.StatusForbidden {
			t.Errorf("signing out with %s gave %d", c.name, r.StatusCode)
		}
	}
	if f.get("/").StatusCode != http.StatusOK {
		t.Fatal("a request that was refused signed the administrator out")
	}
}

func TestTheTokenOfASessionIsBoundToTheAdministration(t *testing.T) {
	f := newWebFixture(t)
	f.enroll()
	token := f.csrfOf(f.get("/"))
	ses, err := f.a.admins.Resolve(t.Context(), f.cookie(webSessionCookie).Value)
	if err != nil {
		t.Fatal(err)
	}
	if token != f.a.keys.CSRFToken("admin:"+ses.ID) || token == f.a.keys.CSRFToken(ses.ID) {
		t.Fatal("the token of an administrator is not bound to the administration: a session of a user with the same ID would have it")
	}
}

func TestAWrongPasswordIsTheSameAnswerWhetherTheLoginExistsOrNot(t *testing.T) {
	f := newWebFixture(t)
	if _, err := f.a.Admin().CreateAdmin(t.Context(), "gone", adminPassword); err != nil {
		t.Fatal(err)
	}
	if err := f.a.Admin().DisableAdmin(t.Context(), "gone"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		form url.Values
	}{
		{"a login that does not exist", url.Values{"login": {"nobody"}, "password": {adminPassword}}},
		{"a wrong password", url.Values{"login": {adminLoginName}, "password": {"a password that is not it"}}},
		{"a disabled account", url.Values{"login": {"gone"}, "password": {adminPassword}}},
		{"a login that is no login", url.Values{"login": {"r o o t!"}, "password": {adminPassword}}},
		{"no login", url.Values{"login": {""}, "password": {""}}},
		{"a password that is too long", url.Values{"login": {adminLoginName}, "password": {strings.Repeat("a", maxAdminPasswordInput+1)}}},
		{"a login that is too long", url.Values{"login": {strings.Repeat("a", maxAdminLoginInput+1)}, "password": {"x"}}},
	}
	value := regexp.MustCompile(`value="[^"]*"`)
	var bodies []string
	for _, c := range cases {
		r := f.post("/login", c.form)
		if r.StatusCode != http.StatusUnauthorized || !r.has("The login or the password is wrong.") || r.Header.Get("WWW-Authenticate") == "" {
			t.Errorf("%s: the answer is %d: %.300s", c.name, r.StatusCode, r.body)
		}
		if f.cookie(webPendingCookie) != nil || f.cookie(webSessionCookie) != nil {
			t.Errorf("%s: a cookie was set", c.name)
		}
		bodies = append(bodies, value.ReplaceAllString(r.body, `value=""`))
		f.clock.advance(time.Hour)
	}
	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Errorf("the answer to %q differs from the answer to %q", cases[i].name, cases[0].name)
		}
	}

	failures := f.records(audit.AdminLoginFailed)
	if len(failures) != len(cases) {
		t.Fatalf("%d failures were recorded, want %d", len(failures), len(cases))
	}
	reasons := map[string]int{}
	for _, r := range failures {
		details := detailsOf(t, r)
		reasons[fmt.Sprint(details["reason"])]++
		if details["stage"] != "password" || r.ActorKind != store.ActorAdmin || r.IP != "127.0.0.1" {
			t.Errorf("the failure is %+v", r)
		}
		if details["reason"] == "unknown_login" && details["login"] != "n***" {
			t.Errorf("a login that does not exist is written as %q, want it masked", details["login"])
		}
		for _, typed := range []string{adminPassword, "a password that is not it", "nobody"} {
			if strings.Contains(r.Details, typed) {
				t.Errorf("a failure holds what was typed: %s", r.Details)
			}
		}
	}
	want := map[string]int{"unknown_login": 1, "wrong_password": 1, "disabled": 1, "invalid_login": 2, "too_long": 2}
	for reason, n := range want {
		if reasons[reason] != n {
			t.Errorf("the reasons are %v, want %v", reasons, want)
			break
		}
	}
}

func TestWhatWasTypedIsShownBackEscapedAndThePasswordNever(t *testing.T) {
	f := newWebFixture(t)
	evil := `"><script>alert(1)</script>`
	r := f.post("/login", url.Values{"login": {evil}, "password": {"secret typed here"}})
	if strings.Contains(r.body, "<script>") || !strings.Contains(r.body, "&#34;&gt;&lt;script&gt;") {
		t.Fatalf("what was typed is not escaped: %.500s", r.body)
	}
	if strings.Contains(r.body, "secret typed here") {
		t.Fatal("the password was shown again")
	}
	long := f.post("/login", url.Values{"login": {strings.Repeat("я", maxAdminLoginInput)}, "password": {"x"}})
	if !long.has(`value="` + strings.Repeat("я", maxAdminLoginInput/2) + `"`) {
		t.Fatal("a login that is too long was not cut where a character ends")
	}
}

func TestAnAdministratorWhoWasChangedHasNoSessionAndBindsAgainAfterAReset(t *testing.T) {
	f := newWebFixture(t)
	codes := f.enroll()
	oldSeed := f.seed()
	f.browser = f.newBrowser()
	if signed := f.signIn(); signed.StatusCode != http.StatusSeeOther {
		t.Fatalf("the sign-in gave %d", signed.StatusCode)
	}
	if f.get("/").StatusCode != http.StatusOK {
		t.Fatal("the session does not work")
	}

	changed := adminPassword + " and more words"
	if err := f.a.Admin().ResetAdminPassword(t.Context(), adminLoginName, changed); err != nil {
		t.Fatal(err)
	}
	if got := f.get("/"); got.StatusCode != http.StatusSeeOther || got.location() != "/admin/login" || f.cookie(webSessionCookie) != nil {
		t.Fatalf("a session of an administrator whose password was reset gave %d %q", got.StatusCode, got.location())
	}

	f.browser = f.newBrowser()
	if r := f.password(); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the old password gave %d", r.StatusCode)
	}
	if r := f.post("/login", url.Values{"login": {adminLoginName}, "password": {changed}}); r.StatusCode != http.StatusSeeOther || r.location() != "/admin/login/code" {
		t.Fatalf("the new password gave %d %q", r.StatusCode, r.location())
	}
	page := f.get("/login/code")
	if err := f.a.Admin().ResetAdminTOTP(t.Context(), adminLoginName); err != nil {
		t.Fatal(err)
	}
	if r := f.post("/login/code", url.Values{"code": {"123456"}, "csrf": {f.csrfOf(page)}}); r.StatusCode != http.StatusUnauthorized || !r.has("The sign-in has expired") || f.cookie(webPendingCookie) != nil {
		t.Fatalf("a sign-in of an administrator whose authenticator was reset between the steps gave %d", r.StatusCode)
	}

	if err := f.a.Admin().ResetAdminPassword(t.Context(), adminLoginName, adminPassword); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(time.Hour)
	f.browser = f.newBrowser()
	fresh := f.enroll()
	if bytes.Equal(f.seed(), oldSeed) {
		t.Fatal("the authenticator that was bound again has the key of the one that was reset")
	}
	f.browser = f.newBrowser()
	f.password()
	second := f.get("/login/code")
	if r := f.post("/login/code", url.Values{"code": {codes[0]}, "csrf": {f.csrfOf(second)}}); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a recovery code of the authenticator that was reset gave %d", r.StatusCode)
	}
	if r := f.post("/login/code", url.Values{"code": {fresh[0]}, "csrf": {f.csrfOf(second)}}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("a recovery code of the authenticator that was bound again gave %d", r.StatusCode)
	}
}

func TestADisabledAdministratorLosesTheSessionForGood(t *testing.T) {
	f := newWebFixture(t)
	f.enroll()
	f.browser = f.newBrowser()
	f.signIn()
	if f.get("/").StatusCode != http.StatusOK {
		t.Fatal("the session does not work")
	}
	if err := f.a.Admin().DisableAdmin(t.Context(), adminLoginName); err != nil {
		t.Fatal(err)
	}
	if got := f.get("/"); got.StatusCode != http.StatusSeeOther || got.location() != "/admin/login" {
		t.Fatalf("the session of an administrator who was disabled gave %d %q", got.StatusCode, got.location())
	}
	if err := f.a.Admin().EnableAdmin(t.Context(), adminLoginName); err != nil {
		t.Fatal(err)
	}
	if got := f.get("/"); got.StatusCode != http.StatusSeeOther {
		t.Fatalf("the session of an administrator who was disabled and enabled again came back: %d", got.StatusCode)
	}
	f.clock.advance(totp.StepSeconds * time.Second)
	f.browser = f.newBrowser()
	if signed := f.signIn(); signed.StatusCode != http.StatusSeeOther {
		t.Fatalf("a new sign-in after the account was enabled again gave %d", signed.StatusCode)
	}
}

func TestAnAdministratorWhoMustBindAnAuthenticatorCannotGoToTheCodeStep(t *testing.T) {
	f := newWebFixture(t)
	f.password()
	page := f.get("/login/totp")
	if got := f.get("/login/code"); got.StatusCode != http.StatusSeeOther || got.location() != "/admin/login/totp" {
		t.Fatalf("the code page gave %d %q", got.StatusCode, got.location())
	}
	if got := f.post("/login/code", url.Values{"code": {"123456"}, "csrf": {f.csrfOf(page)}}); got.StatusCode != http.StatusSeeOther || got.location() != "/admin/login/totp" {
		t.Fatalf("a code before the binding gave %d %q", got.StatusCode, got.location())
	}
	waiting, err := f.a.admins.Pending(t.Context(), f.cookie(webPendingCookie).Value)
	if err != nil || waiting.Session.Attempts != 0 {
		t.Fatalf("the sign-in is %+v, %v: a code before the binding counted a guess", waiting.Session, err)
	}

	f.browser = f.newBrowser()
	f.enroll()
	f.browser = f.newBrowser()
	f.password()
	second := f.get("/login/code")
	if got := f.get("/login/totp"); got.StatusCode != http.StatusSeeOther || got.location() != "/admin/login/code" {
		t.Fatalf("the page of the binding for an administrator who has an authenticator gave %d %q", got.StatusCode, got.location())
	}
	if got := f.post("/login/totp", url.Values{"code": {f.code()}, "csrf": {f.csrfOf(second)}}); got.StatusCode != http.StatusSeeOther || got.location() != "/admin/login/code" {
		t.Fatalf("a binding for one who has an authenticator gave %d %q", got.StatusCode, got.location())
	}
}

func TestTheCookiesOfTheTwoStepsAreNotInterchangeable(t *testing.T) {
	f := newWebFixture(t)
	f.enroll()
	session := f.cookie(webSessionCookie).Value

	asPending := f.newBrowser()
	asPending.setCookie(webPendingCookie, session, adminMount+"/login")
	if got := asPending.get("/login/code"); got.StatusCode != http.StatusUnauthorized || !got.has("The sign-in has expired") {
		t.Fatalf("the secret of a session as the cookie of the second step gave %d", got.StatusCode)
	}

	f.browser = f.newBrowser()
	f.password()
	waiting := f.cookie(webPendingCookie).Value
	asSession := f.newBrowser()
	asSession.setCookie(webSessionCookie, waiting, adminMount+"/")
	if got := asSession.get("/"); got.StatusCode != http.StatusSeeOther || got.location() != "/admin/login" {
		t.Fatalf("the secret of a sign-in as the cookie of a session gave %d %q", got.StatusCode, got.location())
	}

	junk := map[string]string{
		"a value that is no secret":     "x",
		"a value that is too long":      strings.Repeat("a", 10_000),
		"a value that is not base64":    strings.Repeat("!", secret.TextLen),
		"a secret that nobody has made": strings.Repeat("A", secret.TextLen),
	}
	for name, value := range junk {
		for _, path := range []string{"/", "/login/code"} {
			b := f.newBrowser()
			b.setCookie(webSessionCookie, value, adminMount+"/")
			b.setCookie(webPendingCookie, value, adminMount+"/login")
			if got := b.get(path); got.StatusCode >= http.StatusInternalServerError || got.StatusCode == http.StatusOK {
				t.Errorf("%s on %s gave %d", name, path, got.StatusCode)
			}
		}
	}
}

func TestASessionEndsAtItsTimeAndWhenItIsIdle(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		f := newWebFixture(t)
		f.enroll()
		for range 2 {
			f.clock.advance(29 * time.Minute)
			if f.get("/").StatusCode != http.StatusOK {
				t.Fatal("a session that is used every half an hour does not work")
			}
		}
		f.clock.advance(31 * time.Minute)
		if got := f.get("/"); got.StatusCode != http.StatusSeeOther || got.location() != "/admin/login" || f.cookie(webSessionCookie) != nil {
			t.Fatalf("a session that was idle gave %d %q", got.StatusCode, got.location())
		}
	})

	t.Run("absolute", func(t *testing.T) {
		f := newWebFixture(t, WithAdminSessionTTL(2*time.Hour, time.Hour))
		f.enroll()
		for range 2 {
			f.clock.advance(50 * time.Minute)
			if f.get("/").StatusCode != http.StatusOK {
				t.Fatal("a session that is used before its end does not work")
			}
		}
		f.clock.advance(50 * time.Minute)
		if got := f.get("/"); got.StatusCode != http.StatusSeeOther || got.location() != "/admin/login" {
			t.Fatalf("a session after its absolute time gave %d %q although it was used", got.StatusCode, got.location())
		}
	})
}

func TestFiveWrongPasswordsOfOneLoginFromOneAddressPauseIt(t *testing.T) {
	f := newWebFixture(t)
	wrong := url.Values{"login": {adminLoginName}, "password": {"not the password"}}
	for i := 1; i <= 5; i++ {
		if r := f.post("/login", wrong); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the wrong password %d gave %d", i, r.StatusCode)
		}
	}
	paused := f.password()
	if paused.StatusCode != http.StatusTooManyRequests || paused.Header.Get("Retry-After") != "1800" || !paused.has("Try again in 30 min.") || f.cookie(webPendingCookie) != nil {
		t.Fatalf("the right password after five wrong ones gave %d with Retry-After %q", paused.StatusCode, paused.Header.Get("Retry-After"))
	}
	if other := f.post("/login", url.Values{"login": {"someone"}, "password": {"x"}}); other.StatusCode != http.StatusUnauthorized {
		t.Fatalf("another login from the same address gave %d: the pause belongs to one login", other.StatusCode)
	}
	f.clock.advance(29 * time.Minute)
	if r := f.password(); r.StatusCode != http.StatusTooManyRequests || r.Header.Get("Retry-After") != "60" {
		t.Fatalf("a minute before the end of the pause the password gave %d with Retry-After %q", r.StatusCode, r.Header.Get("Retry-After"))
	}
	f.clock.advance(2 * time.Minute)
	if r := f.password(); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("the right password after the pause gave %d", r.StatusCode)
	}
}

func TestTwentyWrongPasswordsFromOneAddressPauseTheAddress(t *testing.T) {
	f := newWebFixture(t)
	for i := range 20 {
		form := url.Values{"login": {"user" + strconv.Itoa(i)}, "password": {"x"}}
		if r := f.post("/login", form); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the wrong password %d gave %d", i+1, r.StatusCode)
		}
	}
	if r := f.password(); r.StatusCode != http.StatusTooManyRequests || r.Header.Get("Retry-After") != "1800" {
		t.Fatalf("the right password from an address that failed twenty times gave %d with Retry-After %q", r.StatusCode, r.Header.Get("Retry-After"))
	}
}

func TestWrongCodesCountAgainstTheSameLimitAsWrongPasswords(t *testing.T) {
	f := newWebFixture(t)
	f.enroll()
	f.browser = f.newBrowser()
	f.password()
	token := f.csrfOf(f.get("/login/code"))
	for i := 1; i <= 3; i++ {
		if r := f.post("/login/code", url.Values{"code": {f.wrongCode()}, "csrf": {token}}); r.StatusCode != http.StatusUnauthorized || !r.has("The code is wrong") {
			t.Fatalf("the wrong code %d gave %d", i, r.StatusCode)
		}
	}
	if r := f.post("/login/code", url.Values{"code": {f.code()}, "csrf": {token}}); r.StatusCode != http.StatusUnauthorized || !r.has("The sign-in has expired") {
		t.Fatalf("the code after three guesses gave %d", r.StatusCode)
	}
	if r := f.password(); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("the password gave %d", r.StatusCode)
	}
	token = f.csrfOf(f.get("/login/code"))
	for i := 4; i <= 5; i++ {
		if r := f.post("/login/code", url.Values{"code": {f.wrongCode()}, "csrf": {token}}); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the wrong code %d gave %d", i, r.StatusCode)
		}
	}
	paused := f.post("/login/code", url.Values{"code": {f.code()}, "csrf": {token}})
	if paused.StatusCode != http.StatusTooManyRequests || paused.Header.Get("Retry-After") != "1800" || f.cookie(webSessionCookie) != nil {
		t.Fatalf("the right code after five wrong ones gave %d with Retry-After %q", paused.StatusCode, paused.Header.Get("Retry-After"))
	}
	if r := f.password(); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the password of a login whose codes were guessed gave %d", r.StatusCode)
	}
	f.clock.advance(31 * time.Minute)
	f.browser = f.newBrowser()
	if signed := f.signIn(); signed.StatusCode != http.StatusSeeOther {
		t.Fatalf("the sign-in after the pause gave %d", signed.StatusCode)
	}
}

func TestASuccessfulSignInClearsTheCountOfWrongAttempts(t *testing.T) {
	f := newWebFixture(t)
	f.enroll()
	f.browser = f.newBrowser()
	wrong := url.Values{"login": {adminLoginName}, "password": {"not the password"}}
	for range 4 {
		if r := f.post("/login", wrong); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("a wrong password gave %d", r.StatusCode)
		}
	}
	if signed := f.signIn(); signed.StatusCode != http.StatusSeeOther {
		t.Fatalf("the sign-in gave %d", signed.StatusCode)
	}
	f.browser = f.newBrowser()
	for i := 1; i <= 5; i++ {
		if r := f.post("/login", wrong); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the wrong password %d after the sign-in gave %d: the count was not cleared", i, r.StatusCode)
		}
	}
	if r := f.post("/login", wrong); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the sixth wrong password after the sign-in gave %d", r.StatusCode)
	}
}

func TestASuccessfulBindingClearsTheCountOfWrongAttempts(t *testing.T) {
	f := newWebFixture(t)
	wrong := url.Values{"login": {adminLoginName}, "password": {"not the password"}}
	for range 4 {
		if r := f.post("/login", wrong); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("a wrong password gave %d", r.StatusCode)
		}
	}
	f.enroll()
	f.browser = f.newBrowser()
	for i := 1; i <= 5; i++ {
		if r := f.post("/login", wrong); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the wrong password %d after the binding gave %d: the count was not cleared", i, r.StatusCode)
		}
	}
	if r := f.post("/login", wrong); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the sixth wrong password after the binding gave %d", r.StatusCode)
	}
}

func TestTheBindingNeedsTheTokenOfItsPage(t *testing.T) {
	f := newWebFixture(t)
	f.password()
	token := f.csrfOf(f.get("/login/totp"))
	code := f.code()
	attempts := []struct {
		name   string
		values url.Values
	}{
		{"no token", url.Values{"code": {code}}},
		{"an empty token", url.Values{"code": {code}, "csrf": {""}}},
		{"a token that is longer", url.Values{"code": {code}, "csrf": {token + "x"}}},
		{"a token that is shorter", url.Values{"code": {code}, "csrf": {token[:len(token)-1]}}},
	}
	for _, c := range attempts {
		if r := f.post("/login/totp", c.values); r.StatusCode != http.StatusForbidden {
			t.Errorf("%s: the binding gave %d", c.name, r.StatusCode)
		}
	}
	waiting, err := f.a.admins.Pending(t.Context(), f.cookie(webPendingCookie).Value)
	if err != nil || waiting.Session.Attempts != 0 || !waiting.NeedsEnrollment() {
		t.Fatalf("the sign-in is %+v, %v: a binding that was refused counted a guess or bound the authenticator", waiting.Session, err)
	}
	if f.cookie(webSessionCookie) != nil {
		t.Fatal("a binding that was refused opened a session")
	}
	if r := f.post("/login/totp", url.Values{"code": {"\t" + code + "\r\n"}, "csrf": {token}}); r.StatusCode != http.StatusOK || !r.has("Your recovery codes") {
		t.Fatalf("the binding with its token gave %d", r.StatusCode)
	}
}

func TestSigningOutWithoutASessionSendsToTheSignInPage(t *testing.T) {
	f := newWebFixture(t)
	r := f.post("/logout", url.Values{})
	if r.StatusCode != http.StatusSeeOther || r.location() != "/admin/login" {
		t.Fatalf("signing out without a session gave %d %q", r.StatusCode, r.location())
	}
	if len(f.records(audit.AdminLogout)) != 0 {
		t.Fatal("a sign-out that ended nothing was recorded")
	}
}

func TestWithoutTheSecondFactorThePasswordOpensTheSession(t *testing.T) {
	f := newWebFixture(t, WithoutAdminTOTP())
	r := f.password()
	if r.StatusCode != http.StatusSeeOther || r.location() != "/admin/" || f.cookie(webSessionCookie) == nil || f.cookie(webPendingCookie) != nil {
		t.Fatalf("the password gave %d %q", r.StatusCode, r.location())
	}
	home := f.get("/")
	if home.StatusCode != http.StatusOK || !home.has("Welcome, root.") || home.has("recovery codes left") || home.has("no recovery codes") {
		t.Fatalf("the first page is %d: %.400s", home.StatusCode, home.body)
	}
	if got := f.get("/login/totp"); got.StatusCode != http.StatusSeeOther || got.location() != "/admin/login" {
		t.Fatalf("the page of the binding gave %d %q", got.StatusCode, got.location())
	}
	if len(f.records(audit.AdminLogin)) != 1 {
		t.Fatal("the sign-in was not recorded")
	}
}

func TestTheFirstPageWarnsWhenFewRecoveryCodesAreLeft(t *testing.T) {
	f := newWebFixture(t)
	codes := f.enroll()
	for i, code := range codes {
		f.browser = f.newBrowser()
		f.password()
		page := f.get("/login/code")
		if r := f.post("/login/code", url.Values{"code": {code}, "csrf": {f.csrfOf(page)}}); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("the recovery code %d gave %d", i+1, r.StatusCode)
		}
		left := len(codes) - i - 1
		home := f.get("/")
		switch {
		case left == 0:
			if !home.has("You have no recovery codes left.") {
				t.Errorf("with none left the first page says %.600s", home.body)
			}
		case left < 4:
			if !home.has(fmt.Sprintf("You have %d recovery codes left.", left)) {
				t.Errorf("with %d left the first page says %.600s", left, home.body)
			}
		default:
			if home.has("recovery codes left") || home.has("no recovery codes") {
				t.Errorf("with %d left the first page warns", left)
			}
		}
	}
}

func TestThePagesRunNoScriptAskNothingOfAnotherSiteAndStyleNothingInline(t *testing.T) {
	f := newWebFixture(t)
	wrong := url.Values{"login": {adminLoginName}, "password": {"x"}}
	pages := map[string]webResponse{}
	pages["the sign-in"] = f.get("/login")
	pages["a failure"] = f.post("/login", wrong)
	pages["a page that is not there"] = f.get("/nowhere")
	f.browser = f.newBrowser()
	f.password()
	binding := f.get("/login/totp")
	pages["the binding"] = binding
	pages["the recovery codes"] = f.post("/login/totp", url.Values{"code": {f.code()}, "csrf": {f.csrfOf(binding)}})
	pages["the first page"] = f.get("/")
	f.clock.advance(totp.StepSeconds * time.Second)
	f.browser = f.newBrowser()
	f.password()
	pages["the second step"] = f.get("/login/code")
	f.clock.advance(time.Hour)
	for range 5 {
		f.post("/login", wrong)
	}
	pages["a pause"] = f.password()

	handler := regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	remote := regexp.MustCompile(`(?i)\b(?:src|href|action|formaction|poster|data)\s*=\s*"(?:[a-z][a-z0-9+.-]*:|//)`)
	for name, page := range pages {
		lower := strings.ToLower(page.body)
		if page.body == "" {
			t.Errorf("%s: the page is empty", name)
			continue
		}
		for _, forbidden := range []string{"<script", "<iframe", "<object", "<embed", "<style", "<link rel=\"preload", "javascript:", " style=", "<base", "<meta http-equiv"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("%s: the page has %q", name, forbidden)
			}
		}
		if handler.MatchString(page.body) {
			t.Errorf("%s: the page has the attribute of an event handler", name)
		}
		for _, m := range remote.FindAllString(page.body, -1) {
			if !strings.Contains(m, "otpauth:") {
				t.Errorf("%s: the page reaches for %s", name, m)
			}
		}
		for _, form := range regexp.MustCompile(`<form[^>]*>`).FindAllString(page.body, -1) {
			if !strings.Contains(form, `method="post"`) || !strings.Contains(form, `action="/admin/`) {
				t.Errorf("%s: the form %s does not post to the administration", name, form)
			}
		}
		if strings.Count(lower, "<h1") != 1 || !strings.Contains(lower, `<main id="main"`) || !strings.Contains(lower, "<title>") || !strings.Contains(lower, `lang="en"`) {
			t.Errorf("%s: the page lacks its title, its single heading, its main part or its language", name)
		}
		for _, input := range regexp.MustCompile(`<input[^>]*type="password"[^>]*>`).FindAllString(page.body, -1) {
			if !strings.Contains(input, "autocomplete=") {
				t.Errorf("%s: the field %s does not say what a password manager may do", name, input)
			}
		}
	}
}

func TestASignInThatCannotBeRecordedDoesNotHappen(t *testing.T) {
	f, faults, logs := newFaultyWebFixture(t)
	f.enroll()
	f.browser = f.newBrowser()
	f.password()
	token := f.csrfOf(f.get("/login/code"))
	faults.set("audit.add", errors.New("the audit log is down"))
	code := f.code()
	r := f.post("/login/code", url.Values{"code": {code}, "csrf": {token}})
	if r.StatusCode != http.StatusInternalServerError || !r.has("Something went wrong") || r.has("audit log is down") || f.cookie(webSessionCookie) != nil {
		t.Fatalf("a sign-in that cannot be recorded gave %d: %.300s", r.StatusCode, r.body)
	}
	if !strings.Contains(logs.String(), "the audit log is down") {
		t.Fatalf("the log does not say why: %q", logs.String())
	}
	faults.clear()
	if r := f.post("/login/code", url.Values{"code": {code}, "csrf": {token}}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("the same code after the failure gave %d: a sign-in that failed must not use the code up", r.StatusCode)
	}
}

func TestAFailureThatCannotBeRecordedStillGetsItsAnswerAndALogLine(t *testing.T) {
	f, faults, logs := newFaultyWebFixture(t)
	faults.set("audit.add", errors.New("the audit log is down"))
	r := f.post("/login", url.Values{"login": {adminLoginName}, "password": {"wrong"}})
	if r.StatusCode != http.StatusUnauthorized || !r.has("The login or the password is wrong.") {
		t.Fatalf("a failed sign-in that cannot be recorded gave %d", r.StatusCode)
	}
	if text := logs.String(); !strings.Contains(text, "a failed sign-in to the administration cannot be recorded") || !strings.Contains(text, "the audit log is down") {
		t.Fatalf("the log of the failure is %q", text)
	}
}
