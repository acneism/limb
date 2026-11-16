package limb

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/store"
)

func TestLoginOpensACookieSession(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	now := f.clock.now().UTC().Truncate(time.Microsecond)

	if _, err := uuid.Parse(login.Principal.SessionID); err != nil {
		t.Fatalf("the session ID %q is not a UUID: %v", login.Principal.SessionID, err)
	}
	want := Principal{UserID: f.user.ID, SessionID: login.Principal.SessionID, SessionKind: SessionCookie}
	if login.Principal != want {
		t.Fatalf("Principal = %+v, want %+v", login.Principal, want)
	}
	if len(login.Secret) != secret.TextLen || login.CSRFToken != f.a.keys.CSRFToken(login.Principal.SessionID) {
		t.Fatalf("Secret has %d characters and CSRFToken is %q", len(login.Secret), login.CSRFToken)
	}
	if login.Tokens != (Tokens{}) || !login.ExpiresAt.Equal(now.Add(30*24*time.Hour)) {
		t.Fatalf("Tokens = %+v, ExpiresAt = %v", login.Tokens, login.ExpiresAt)
	}

	stored := f.session(t, login.Principal.SessionID)
	sum := sha256.Sum256([]byte(login.Secret))
	s := stored.Session
	if s.TenantID != store.DefaultTenant || s.Kind != store.SessionCookie || s.UserID != string(f.user.ID) ||
		string(s.SecretHash) != string(sum[:]) || s.IP != "203.0.113.7" || s.UserAgent != testAgent ||
		!s.CreatedAt.Equal(now) || !s.LastSeenAt.Equal(now) || !s.ExpiresAt.Equal(login.ExpiresAt) || !s.RevokedAt.IsZero() {
		t.Fatalf("stored session = %+v", s)
	}
	if got := f.stored(t); !got.LastLoginAt.Equal(now) {
		t.Fatalf("LastLoginAt = %v, want %v", got.LastLoginAt, now)
	}
}

func TestEverySignInGetsANewSecretAndKeepsTheOthers(t *testing.T) {
	f := newSessionFixture(t)
	first, second := f.login(t), f.login(t)
	if first.Secret == second.Secret || first.Principal.SessionID == second.Principal.SessionID || first.CSRFToken == second.CSRFToken {
		t.Fatal("a sign-in must not reuse a secret, a session or a CSRF token")
	}
	for _, login := range []Login{first, second} {
		if _, err := f.a.Authenticate(f.request(t, "GET", login, nil)); err != nil {
			t.Fatalf("the session %s must stay valid: %v", login.Principal.SessionID, err)
		}
	}
}

func TestLoginAcceptsEveryFormOfTheLogin(t *testing.T) {
	f := newSessionFixture(t)
	for _, name := range []string{"nina@example.com", "  NINA@example.com ", "nina_n", "NINA_N"} {
		c := f.credentials()
		c.Login = name
		if _, err := f.a.Login(t.Context(), c); err != nil {
			t.Errorf("Login(%q) failed: %v", name, err)
		}
	}
}

func TestLoginRejectsWrongCredentialsTheSameWay(t *testing.T) {
	f := newSessionFixture(t)
	cases := map[string]Credentials{
		"wrong password": {Login: "nina@example.com", Password: "wrong password", Kind: SessionCookie},
		"unknown login":  {Login: "nobody@example.com", Password: goodPassword, Kind: SessionCookie},
		"invalid login":  {Login: "not a login!", Password: goodPassword, Kind: SessionCookie},
		"empty login":    {Login: "", Password: goodPassword, Kind: SessionCookie},
	}
	for name, c := range cases {
		before := f.counting.verifies.Load() + f.counting.dummies.Load()
		login, err := f.a.Login(t.Context(), c)
		if err != ErrInvalidCredentials || login != (Login{}) { //nolint:errorlint
			t.Errorf("%s: Login = %+v, %v; want ErrInvalidCredentials exactly", name, login, err)
		}
		if f.counting.verifies.Load()+f.counting.dummies.Load() != before+1 {
			t.Errorf("%s: the password must be checked once, with the same work for every case", name)
		}
	}
}

func TestLoginCountsOnlyWrongPasswords(t *testing.T) {
	f := newSessionFixture(t)
	keys := f.a.loginAttemptKeys("nina@example.com", testIP)
	counted := func() int {
		t.Helper()
		counters, err := f.a.store.Attempts().Get(t.Context(), keys.accountIP, keys.ip, keys.account)
		if err != nil {
			t.Fatal(err)
		}
		return len(counters)
	}
	f.login(t)
	if counted() != 0 {
		t.Fatal("a successful sign-in must not be counted")
	}
	c := f.credentials()
	c.Password = "wrong password"
	if _, err := f.a.Login(t.Context(), c); err != ErrInvalidCredentials { //nolint:errorlint
		t.Fatal(err)
	}
	if counted() != 3 {
		t.Fatalf("a failure must be counted on all three counters, got %d", counted())
	}
	f.login(t)
	counters, err := f.a.store.Attempts().Get(t.Context(), keys.accountIP, keys.ip, keys.account)
	if err != nil || len(counters) != 2 {
		t.Fatalf("a successful sign-in clears the pair counter only: %v, %v", counters, err)
	}
	for _, counter := range counters {
		if counter.Key == keys.accountIP {
			t.Fatal("the pair counter must be cleared")
		}
	}
}

func TestLoginIsTurnedDownBeforeThePasswordIsChecked(t *testing.T) {
	f := newSessionFixture(t)
	c := f.credentials()
	c.Password = "wrong password"
	for range 5 {
		if _, err := f.a.Login(t.Context(), c); err != ErrInvalidCredentials { //nolint:errorlint
			t.Fatal(err)
		}
	}
	checks := f.counting.verifies.Load() + f.counting.dummies.Load()
	_, err := f.a.Login(t.Context(), f.credentials())
	var limit *RateLimitError
	if !errors.As(err, &limit) || limit.RetryAfter != 15*time.Minute {
		t.Fatalf("Login = %v, want a *RateLimitError with a pause of 15 minutes, even for the right password", err)
	}
	if got := f.counting.verifies.Load() + f.counting.dummies.Load(); got != checks {
		t.Fatal("a turned down attempt must not reach the password check")
	}
	f.clock.advance(15*time.Minute + time.Second)
	f.login(t)
}

func TestLoginReportsABlockedAccountOnlyAfterTheRightPassword(t *testing.T) {
	f := newSessionFixture(t)
	f.change(t, func(u *store.User) { u.Status = store.StatusBlocked })
	c := f.credentials()
	c.Password = "wrong password"
	if _, err := f.a.Login(t.Context(), c); err != ErrInvalidCredentials { //nolint:errorlint
		t.Fatalf("a wrong password for a blocked account = %v, want ErrInvalidCredentials", err)
	}
	if _, err := f.a.Login(t.Context(), f.credentials()); err != ErrUserBlocked { //nolint:errorlint
		t.Fatalf("the right password for a blocked account = %v, want ErrUserBlocked", err)
	}
	keys := f.a.loginAttemptKeys("nina@example.com", testIP)
	counters, err := f.a.store.Attempts().Get(t.Context(), keys.accountIP)
	if err != nil || len(counters) != 1 || counters[0].Count != 1 {
		t.Fatalf("only the wrong password counts: %v, %v", counters, err)
	}
	f.change(t, func(u *store.User) { u.Status = store.StatusDeleted })
	if _, err = f.a.Login(t.Context(), f.credentials()); err != ErrInvalidCredentials { //nolint:errorlint
		t.Fatalf("a deleted account = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginOfAUserWhoMustChangeThePassword(t *testing.T) {
	f := newSessionFixture(t)
	f.change(t, func(u *store.User) { u.MustChangePassword = true })
	login := f.login(t)
	if !login.Principal.MustChangePassword {
		t.Fatal("the sign-in must say that the password has to be changed")
	}
	p, err := f.a.Authenticate(f.request(t, "GET", login, nil))
	if !errors.Is(err, ErrPasswordChangeRequired) || p != login.Principal {
		t.Fatalf("Authenticate = %+v, %v; want the principal with ErrPasswordChangeRequired", p, err)
	}
}

func TestLoginRejectsAnUnknownKind(t *testing.T) {
	f := newSessionFixture(t)
	for _, kind := range []SessionKind{"", "other", "COOKIE"} {
		c := f.credentials()
		c.Kind = kind
		var invalid *ValidationError
		if _, err := f.a.Login(t.Context(), c); !errors.As(err, &invalid) || invalid.Field != "kind" {
			t.Errorf("kind %q: Login = %v, want a *ValidationError about the kind", kind, err)
		}
	}
	if f.counting.verifies.Load() != 0 {
		t.Fatal("a request with a wrong kind must not reach the password check")
	}
}

func TestLoginStoresACleanUserAgentAndAddress(t *testing.T) {
	f := newSessionFixture(t)
	cases := []struct {
		name, agent string
		ip          netip.Addr
		wantAgent   string
		wantIP      string
	}{
		{"plain", "Firefox/130", netip.MustParseAddr("2001:db8::1"), "Firefox/130", "2001:db8::1"},
		{"no address", "Firefox/130", netip.Addr{}, "Firefox/130", ""},
		{"mapped address", "x", netip.MustParseAddr("::ffff:203.0.113.9"), "x", "203.0.113.9"},
		{"zone", "x", netip.MustParseAddr("fe80::1%eth0"), "x", "fe80::1"},
		{"control characters", "a\x00b\r\nc\x7fd\te", testIP, "abcde", "203.0.113.7"},
		{"invalid UTF-8", "a\xffb\xc3", testIP, "ab", "203.0.113.7"},
		{"empty", "", testIP, "", "203.0.113.7"},
		{"long", strings.Repeat("a", 600), testIP, strings.Repeat("a", store.MaxUserAgentLength), "203.0.113.7"},
		{"long and multibyte", strings.Repeat("é", 300), testIP, strings.Repeat("é", store.MaxUserAgentLength/2), "203.0.113.7"},
		{"cut inside a character", strings.Repeat("a", 511) + "é", testIP, strings.Repeat("a", 511), "203.0.113.7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := f.credentials()
			c.UserAgent, c.IP = tc.agent, tc.ip
			login, err := f.a.Login(t.Context(), c)
			if err != nil {
				t.Fatal(err)
			}
			s := f.session(t, login.Principal.SessionID).Session
			if s.UserAgent != tc.wantAgent || s.IP != tc.wantIP {
				t.Fatalf("stored user agent %q and address %q, want %q and %q", s.UserAgent, s.IP, tc.wantAgent, tc.wantIP)
			}
		})
	}
}

func TestLoginSurvivesAProblemWithTheTimeOfTheLastSignIn(t *testing.T) {
	for name, updateErr := range map[string]error{"a concurrent change": store.ErrStale, "a store failure": errors.New("database is down")} {
		t.Run(name, func(t *testing.T) {
			logger, logs := capturingLogger()
			f := newSessionFixture(t, WithLogger(logger))
			f.a.store = &faultyStore{Store: f.a.store, updateErr: updateErr}
			login, err := f.a.Login(t.Context(), f.credentials())
			if err != nil || login.Secret == "" {
				t.Fatalf("Login = %+v, %v; the session is already open and must be returned", login, err)
			}
			warned := strings.Contains(logs.String(), "cannot be saved")
			if warned != !errors.Is(updateErr, store.ErrStale) {
				t.Fatalf("warned = %v for %v; only a real failure is worth a warning:\n%s", warned, updateErr, logs.String())
			}
		})
	}
}

func TestLoginReportsAFailureToOpenTheSession(t *testing.T) {
	f := newSessionFixture(t)
	boom := errors.New("database is down")
	f.breakSessions(func(s *sessionsFault) { s.createErr = boom })
	if _, err := f.a.Login(t.Context(), f.credentials()); !errors.Is(err, boom) || errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login = %v, want the failure of the store and not a wrong password", err)
	}
	f.breakSessions(func(s *sessionsFault) { s.createErr = store.ErrNotFound })
	if _, err := f.a.Login(t.Context(), f.credentials()); err != ErrInvalidCredentials { //nolint:errorlint
		t.Fatalf("a user who vanished meanwhile = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginReportsAFailureOfTheRandomSource(t *testing.T) {
	f := newSessionFixture(t)
	boom := errors.New("no ID")
	f.a.newID = func() (string, error) { return "", boom }
	if _, err := f.a.Login(t.Context(), f.credentials()); !errors.Is(err, boom) {
		t.Fatalf("Login = %v, want %v", err, boom)
	}
}

func TestLoginStopsWhenTheContextIsCanceled(t *testing.T) {
	f := newSessionFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.a.Login(ctx, f.credentials()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Login = %v, want context.Canceled", err)
	}
}

func TestConcurrentSignInsOpenSeparateSessions(t *testing.T) {
	f := newSessionFixture(t)
	const racers = 12
	logins := make([]Login, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Go(func() {
			login, err := f.a.Login(t.Context(), f.credentials())
			if err != nil {
				t.Errorf("Login %d failed: %v", i, err)
			}
			logins[i] = login
		})
	}
	wg.Wait()
	secrets, ids := map[string]bool{}, map[string]bool{}
	for _, login := range logins {
		secrets[login.Secret], ids[login.Principal.SessionID] = true, true
	}
	if len(secrets) != racers || len(ids) != racers {
		t.Fatalf("%d secrets and %d sessions for %d sign-ins", len(secrets), len(ids), racers)
	}
}
