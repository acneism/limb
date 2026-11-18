package limb

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/internal/totp"
)

type webInstances struct {
	*instances
	a, b *webFixture
}

func newWebInstances(t *testing.T, d *database) *webInstances {
	t.Helper()
	in := newInstancesWith(t, d, WithAdminMountPath(adminMount), WithDevelopmentMode())
	if _, err := in.a.Admin().CreateAdmin(t.Context(), adminLoginName, adminPassword); err != nil {
		t.Fatalf("CreateAdmin failed: %v", err)
	}
	return &webInstances{instances: in, a: serveWeb(t, in.a, in.clock), b: serveWeb(t, in.b, in.clock)}
}

func (b *browser) adopt(from *browser) {
	b.f.t.Helper()
	cookie := from.cookie(webSessionCookie)
	if cookie == nil {
		b.f.t.Fatal("the other browser has no session")
	}
	b.setCookie(webSessionCookie, cookie.Value, adminMount+"/")
}

func TestTheWebAdministrationSharesItsSessionsBetweenInstancesOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		w := newWebInstances(t, d)
		onA := w.a.newBrowser()
		onA.enroll()
		onB := w.b.newBrowser()
		onB.adopt(onA)
		if home := onB.get("/"); home.StatusCode != http.StatusOK || !home.has("Welcome, root.") {
			t.Fatalf("a session that the first instance made gave %d on the second", home.StatusCode)
		}
		if out := onB.post("/logout", url.Values{"csrf": {onB.csrfOf(onB.get("/"))}}); out.StatusCode != http.StatusSeeOther {
			t.Fatalf("signing out on the second instance gave %d", out.StatusCode)
		}
		if !isSignedOut(onA) {
			t.Fatal("a session that the second instance ended works on the first")
		}

		first, second := w.a.newBrowser(), w.b.newBrowser()
		if r := first.signInAgain(); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("a sign-in on the first instance gave %d", r.StatusCode)
		}
		if r := second.signInAgain(); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("a sign-in on the second instance gave %d", r.StatusCode)
		}
		page := first.get("/account")
		if got := len(sessionIDPattern.FindAllStringSubmatch(page.body, -1)); got != 1 || !page.has("<strong>This session</strong>") {
			t.Fatalf("the first instance lists %d other sessions, want the one of the second", got)
		}
		if r := first.post("/account/sessions/end-others", url.Values{"csrf": {first.csrfOf(page)}}); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("ending the other sessions gave %d", r.StatusCode)
		}
		if !isSignedOut(second) || first.get("/account").StatusCode != http.StatusOK {
			t.Fatal("the session of the second instance was not ended, or the one that asked was")
		}
	})
}

func TestOneOneTimePasswordOpensOneSessionOnTwoInstancesOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		w := newWebInstances(t, d)
		w.a.newBrowser().enroll()
		for round := range 3 {
			w.clock.advance(time.Hour)
			pending := []*browser{w.a.newBrowser(), w.b.newBrowser()}
			tokens := make([]string, len(pending))
			for i, b := range pending {
				if r := b.password(); r.StatusCode != http.StatusSeeOther {
					t.Fatalf("the password gave %d", r.StatusCode)
				}
				tokens[i] = b.csrfOf(b.get("/login/code"))
			}
			code := w.a.code()
			statuses := make([]int, len(pending))
			errs := make([]error, len(pending))
			var wg sync.WaitGroup
			for i, b := range pending {
				wg.Go(func() {
					statuses[i], errs[i] = b.postStatus("/login/code", url.Values{"code": {code}, "csrf": {tokens[i]}})
				})
			}
			wg.Wait()
			opened := 0
			for i, status := range statuses {
				if errs[i] != nil {
					t.Fatalf("round %d: the request %d failed: %v", round, i, errs[i])
				}
				switch status {
				case http.StatusSeeOther:
					opened++
				case http.StatusUnauthorized:
				default:
					t.Errorf("round %d: the request %d gave %d", round, i, status)
				}
			}
			if opened != 1 {
				t.Fatalf("round %d: %d of the two instances opened a session with the same one-time password, want exactly one", round, opened)
			}
		}
	})
}

func TestTheLimitsOnTheSignInOfAdministratorsAreSharedBetweenInstancesOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		w := newWebInstances(t, d)
		wrong := url.Values{"login": {adminLoginName}, "password": {"not the password"}}
		for i, instance := range []*webFixture{w.a, w.b, w.a, w.b, w.a} {
			if r := instance.newBrowser().post("/login", wrong); r.StatusCode != http.StatusUnauthorized {
				t.Fatalf("the wrong password %d gave %d", i+1, r.StatusCode)
			}
		}
		for name, instance := range map[string]*webFixture{"the first instance": w.a, "the second instance": w.b} {
			r := instance.newBrowser().post("/login", url.Values{"login": {adminLoginName}, "password": {adminPassword}})
			if r.StatusCode != http.StatusTooManyRequests || r.Header.Get("Retry-After") != "1800" {
				t.Errorf("%s gave %d with Retry-After %q after five failures that were spread over the two", name, r.StatusCode, r.Header.Get("Retry-After"))
			}
		}
		w.clock.advance(31 * time.Minute)
		if r := w.b.newBrowser().password(); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("the sign-in after the pause gave %d", r.StatusCode)
		}
	})
}

func TestTheAccountOfAnAdministratorIsKeptByEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		w := newWebInstances(t, d)
		codes := w.a.newBrowser().enroll()
		oldSeed := w.a.seed()
		first := w.a.newBrowser()
		first.signInAgain()
		second := w.b.newBrowser()
		second.signInAgain()
		token := first.csrfOf(first.get("/account"))

		renewed := first.post("/account/recovery", url.Values{"password": {adminPassword}, "csrf": {token}})
		if renewed.StatusCode != http.StatusOK || strings.Count(renewed.body, "<code>") != 10 {
			t.Fatalf("new recovery codes gave %d", renewed.StatusCode)
		}
		fresh := recoveryPattern.FindAllStringSubmatch(renewed.body, -1)[0][1]
		if r := second.get("/account"); r.StatusCode != http.StatusOK || !r.has("Recovery codes left: 10.") {
			t.Fatal("the second instance does not see the new recovery codes, or the renewal ended its session")
		}

		if r := first.post("/account/sessions/end", url.Values{"session": {strings.Repeat("x", 500)}, "csrf": {token}}); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("ending a session by an ID that is far too long gave %d", r.StatusCode)
		}
		changed := first.post("/account/password", url.Values{"current": {adminPassword}, "new": {changedPassword}, "again": {changedPassword}, "csrf": {token}})
		if changed.StatusCode != http.StatusSeeOther {
			t.Fatalf("the change of the password gave %d: %.200s", changed.StatusCode, changed.body)
		}
		if !isSignedOut(second) || first.get("/account").StatusCode != http.StatusOK {
			t.Fatal("the change of the password did not end the session of the other instance, or ended the one that made it")
		}

		begin := first.post("/account/authenticator", url.Values{"password": {changedPassword}, "csrf": {token}})
		if begin.StatusCode != http.StatusOK {
			t.Fatalf("the binding gave %d: %.300s", begin.StatusCode, begin.body)
		}
		newSeed := decodeSecret(t, begin)
		bindingToken := regexp.MustCompile(`name="token" value="([^"]+)"`).FindStringSubmatch(begin.body)[1]
		w.clock.advance(2 * totp.StepSeconds * time.Second)
		done := first.post("/account/authenticator/confirm", url.Values{"code": {totp.Code(newSeed, totp.Step(w.clock.now()))}, "token": {bindingToken}, "csrf": {token}})
		if done.StatusCode != http.StatusOK || strings.Count(done.body, "<code>") != 10 {
			t.Fatalf("the confirmation gave %d: %.300s", done.StatusCode, done.body)
		}

		w.clock.advance(totp.StepSeconds * time.Second)
		signIn := func(instance *webFixture, code string) webResponse {
			b := instance.newBrowser()
			if r := b.post("/login", url.Values{"login": {adminLoginName}, "password": {changedPassword}}); r.StatusCode != http.StatusSeeOther {
				t.Fatalf("the new password gave %d", r.StatusCode)
			}
			return b.post("/login/code", url.Values{"code": {code}, "csrf": {b.csrfOf(b.get("/login/code"))}})
		}
		if r := signIn(w.b, totp.Code(oldSeed, totp.Step(w.clock.now()))); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("a one-time password of the old authenticator gave %d on the other instance", r.StatusCode)
		}
		if r := signIn(w.b, codes[0]); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("a recovery code of before the renewal gave %d on the other instance", r.StatusCode)
		}
		if r := signIn(w.b, fresh); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("a recovery code that the binding replaced gave %d on the other instance", r.StatusCode)
		}
		if r := signIn(w.b, totp.Code(newSeed, totp.Step(w.clock.now()))); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("a one-time password of the new authenticator gave %d on the other instance", r.StatusCode)
		}

		for _, action := range []string{audit.AdminRecoveryCodesRenewed, audit.AdminPasswordChanged, audit.AdminTOTPRebound} {
			if got := recordsOf(t, w.a.a, action); len(got) != 1 {
				t.Errorf("%d records of %s, want 1", len(got), action)
			}
		}
	})
}
