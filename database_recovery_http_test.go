package limb

import (
	"net/http"
	"testing"
	"time"

	"github.com/acneism/limb/identifier"
)

func newRecoveryInstances(t *testing.T, d *database) (*apiFixture, *apiFixture, *recordingSender, *fakeClock) {
	t.Helper()
	sender := &recordingSender{}
	clock := newFakeClock()
	prefix := d.Prefix(t)
	build := func() *apiFixture {
		a, err := New(d.DB, d.dialect, []byte(testKey), WithTablePrefix(prefix), WithAutoMigrate(), WithLogger(discardingLogger()),
			WithIdentifiers(identifier.Email(identifier.Required()), identifier.Username()),
			WithSender(sender), WithSignup(), WithServiceName("Acme"),
			WithVerifyURL("https://app.example.com/verify"), WithResetURL("https://app.example.com/reset"))
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		a.hasher = newHasher(t, weakParams)
		a.now = clock.now
		return &apiFixture{handler: a.Handler()}
	}
	first, second := build(), build()
	return first, second, sender, clock
}

func TestRegistrationAndRecoveryOverHTTPAreSharedBetweenInstancesOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		a, b, sender, clock := newRecoveryInstances(t, d)
		credentials := map[string]string{"login": "olga_o", "password": goodPassword}

		if rec := a.send(t, http.MethodPost, "/register", registration("olga@example.com", "olga_o")); rec.Code != http.StatusAccepted {
			t.Fatalf("POST /register = %d: %s", rec.Code, rec.Body.String())
		}
		confirm := waitForMessage(t, sender, 0, MessageVerification, "olga@example.com")
		b.expectError(t, b.send(t, http.MethodPost, "/login", credentials, sameOrigin()), http.StatusForbidden, "verification_required")
		if rec := b.send(t, http.MethodPost, "/verify/confirm", map[string]string{"token": tokenOf(confirm.Link)}); rec.Code != http.StatusNoContent {
			t.Fatalf("POST /verify/confirm on the other instance = %d: %s", rec.Code, rec.Body.String())
		}
		a.expectError(t, a.send(t, http.MethodPost, "/verify/confirm", map[string]string{"token": tokenOf(confirm.Link)}), http.StatusBadRequest, "invalid_secret")
		signedIn := a.send(t, http.MethodPost, "/login", credentials, sameOrigin())
		if signedIn.Code != http.StatusOK {
			t.Fatalf("POST /login = %d: %s", signedIn.Code, signedIn.Body.String())
		}
		session := cookieNamed(signedIn, "__Host-limb_session")
		if session == nil {
			session = cookieNamed(signedIn, "limb_session")
		}
		if session == nil {
			t.Fatal("POST /login set no session cookie")
		}

		from := len(sender.sent())
		if rec := b.send(t, http.MethodPost, "/password/reset", map[string]string{"login": "olga@example.com"}); rec.Code != http.StatusAccepted {
			t.Fatalf("POST /password/reset = %d: %s", rec.Code, rec.Body.String())
		}
		reset := waitForMessage(t, sender, from, MessagePasswordReset, "olga@example.com")
		clock.advance(time.Minute)
		body := map[string]string{"token": tokenOf(reset.Link), "password": recoveredPassword}
		if rec := a.send(t, http.MethodPost, "/password/reset/confirm", body); rec.Code != http.StatusNoContent {
			t.Fatalf("POST /password/reset/confirm on the other instance = %d: %s", rec.Code, rec.Body.String())
		}
		b.expectError(t, b.send(t, http.MethodPost, "/password/reset/confirm", body), http.StatusBadRequest, "invalid_secret")
		b.expectError(t, b.send(t, http.MethodGet, "/sessions/current", nil, withCookie(session.Name, session.Value)), http.StatusUnauthorized, "unauthenticated")
		b.expectError(t, b.send(t, http.MethodPost, "/login", credentials, sameOrigin()), http.StatusUnauthorized, "invalid_credentials")
		credentials["password"] = recoveredPassword
		if rec := b.send(t, http.MethodPost, "/login", credentials, sameOrigin()); rec.Code != http.StatusOK {
			t.Fatalf("POST /login with the new password = %d: %s", rec.Code, rec.Body.String())
		}

		from = len(sender.sent())
		if rec := a.send(t, http.MethodPost, "/password/reset", map[string]string{"login": "olga_o"}); rec.Code != http.StatusAccepted {
			t.Fatalf("POST /password/reset = %d", rec.Code)
		}
		late := waitForMessage(t, sender, from, MessagePasswordReset, "olga@example.com")
		clock.advance(31 * time.Minute)
		lateBody := map[string]string{"token": tokenOf(late.Link), "password": recoveredPassword + "2"}
		b.expectError(t, b.send(t, http.MethodPost, "/password/reset/confirm", lateBody), http.StatusBadRequest, "invalid_secret")
	})
}

func TestTheLimitsOfRecoveryAreSharedBetweenInstancesOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		a, b, _, clock := newRecoveryInstances(t, d)
		if rec := a.send(t, http.MethodPost, "/register", registration("olga@example.com", "olga_o")); rec.Code != http.StatusAccepted {
			t.Fatalf("POST /register = %d: %s", rec.Code, rec.Body.String())
		}
		for i, instance := range []*apiFixture{b, a} {
			if rec := instance.send(t, http.MethodPost, "/verify", map[string]string{"login": "olga@example.com"}); rec.Code != http.StatusAccepted {
				t.Fatalf("request %d = %d: %s", i, rec.Code, rec.Body.String())
			}
		}
		refused := b.send(t, http.MethodPost, "/verify", map[string]string{"login": " OLGA@example.com "})
		b.expectError(t, refused, http.StatusTooManyRequests, "rate_limited")
		if refused.Header().Get("Retry-After") == "" {
			t.Fatal("no Retry-After")
		}
		clock.advance(time.Hour + time.Second)
		if rec := a.send(t, http.MethodPost, "/verify", map[string]string{"login": "olga@example.com"}); rec.Code != http.StatusAccepted {
			t.Fatalf("after the hour = %d: %s", rec.Code, rec.Body.String())
		}
		for range 2 {
			a.expectError(t, a.send(t, http.MethodPost, "/verify/confirm", map[string]string{"login": "olga_o", "code": "000000"}), http.StatusBadRequest, "invalid_secret")
		}
	})
}
