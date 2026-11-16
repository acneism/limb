package limb

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type instances struct {
	a, b  *Auth
	clock *fakeClock
	db    *sql.DB
}

func newInstances(t *testing.T, d *database) *instances {
	t.Helper()
	db := d.DB
	prefix := d.Prefix(t)
	clock := newFakeClock()
	build := func() *Auth {
		a, err := New(db, d.dialect, []byte(testKey), WithTablePrefix(prefix), WithAutoMigrate(), WithLogger(discardingLogger()), emailAndUsername())
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		a.hasher = newHasher(t, weakParams)
		a.now = clock.now
		return a
	}
	first := build()
	return &instances{a: first, b: build(), clock: clock, db: db}
}

func (i *instances) bearer(t *testing.T, token string) *http.Request {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://app.example.com/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func (i *instances) cookie(t *testing.T, a *Auth, secret string) *http.Request {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://app.example.com/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Cookie", a.cookie+"="+secret)
	return r
}

func TestSessionsAreSharedBetweenInstances(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstances(t, d)
		ctx := t.Context()
		user := mustRegister(t, in.a, map[string]string{"email": "nina@example.com", "username": "nina_n"}, goodPassword)
		credentials := Credentials{Login: "nina@example.com", Password: goodPassword, IP: testIP, UserAgent: testAgent, Kind: SessionCookie}

		cookie, err := in.a.Login(ctx, credentials)
		if err != nil {
			t.Fatalf("Login failed: %v", err)
		}
		if p, authErr := in.b.Authenticate(in.cookie(t, in.b, cookie.Secret)); authErr != nil || p != cookie.Principal {
			t.Fatalf("another instance must know the session: %+v, %v", p, authErr)
		}
		credentials.Kind = SessionToken
		tokens, err := in.b.Login(ctx, credentials)
		if err != nil {
			t.Fatalf("Login failed: %v", err)
		}
		for name, instance := range map[string]*Auth{"a": in.a, "b": in.b} {
			if p, authErr := instance.Authenticate(in.bearer(t, tokens.Tokens.AccessToken)); authErr != nil || p.UserID != user.ID {
				t.Fatalf("instance %s: %+v, %v; every instance must accept the token of the other", name, p, authErr)
			}
		}
		keys, err := in.a.store.SigningKeys().List(ctx)
		if err != nil || len(keys) != 1 {
			t.Fatalf("the instances must share one signing key: %v, %v", keys, err)
		}

		listed, err := in.a.Sessions(ctx, cookie.Principal)
		if err != nil || len(listed) != 2 {
			t.Fatalf("Sessions = %v, %v; both sessions of the user must be listed", listed, err)
		}
		if err = in.b.TerminateSession(ctx, tokens.Principal, cookie.Principal.SessionID, ""); err != nil {
			t.Fatalf("TerminateSession failed: %v", err)
		}
		if _, authErr := in.a.Authenticate(in.cookie(t, in.a, cookie.Secret)); authErr != ErrUnauthenticated { //nolint:errorlint
			t.Fatalf("a session ended on one instance must end on the other at once: %v", authErr)
		}

		changed, err := in.a.ChangePassword(ctx, tokens.Principal, goodPassword, newPassword)
		if err != nil {
			t.Fatalf("ChangePassword failed: %v", err)
		}
		if _, authErr := in.b.Authenticate(in.bearer(t, tokens.Tokens.AccessToken)); authErr != ErrUnauthenticated { //nolint:errorlint
			t.Fatalf("the old token must stop working on every instance: %v", authErr)
		}
		if _, authErr := in.b.Authenticate(in.bearer(t, changed.Tokens.AccessToken)); authErr != nil {
			t.Fatalf("the new token must work on every instance: %v", authErr)
		}
		if err = in.b.LogoutAll(ctx, changed.Principal, ""); err != nil {
			t.Fatalf("LogoutAll failed: %v", err)
		}
		if _, authErr := in.a.Authenticate(in.bearer(t, changed.Tokens.AccessToken)); authErr != ErrUnauthenticated { //nolint:errorlint
			t.Fatalf("every session must be ended: %v", authErr)
		}
	})
}

func TestRefreshTokensAreUsedOnceAcrossInstances(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstances(t, d)
		ctx := t.Context()
		mustRegister(t, in.a, map[string]string{"email": "nina@example.com"}, goodPassword)
		login, err := in.a.Login(ctx, Credentials{Login: "nina@example.com", Password: goodPassword, Kind: SessionToken})
		if err != nil {
			t.Fatal(err)
		}
		const racers = 16
		var wins, refused atomic.Int32
		var wg sync.WaitGroup
		for i := range racers {
			instance := in.a
			if i%2 == 1 {
				instance = in.b
			}
			wg.Go(func() {
				switch _, refreshErr := instance.Refresh(ctx, login.Tokens.RefreshToken); {
				case refreshErr == nil:
					wins.Add(1)
				case errors.Is(refreshErr, ErrUnauthenticated):
					refused.Add(1)
				default:
					t.Errorf("unexpected error: %v", refreshErr)
				}
			})
		}
		wg.Wait()
		if wins.Load() != 1 || refused.Load() != racers-1 {
			t.Fatalf("%d refreshes won and %d were refused across two instances, want exactly 1 and %d", wins.Load(), refused.Load(), racers-1)
		}
		if _, authErr := in.a.Authenticate(in.bearer(t, login.Tokens.AccessToken)); authErr != nil {
			t.Fatalf("a race of one client must not end the session: %v", authErr)
		}
		in.clock.advance(11 * time.Second)
		if _, refreshErr := in.b.Refresh(ctx, login.Tokens.RefreshToken); refreshErr != ErrUnauthenticated { //nolint:errorlint
			t.Fatalf("Refresh = %v, want ErrUnauthenticated", refreshErr)
		}
		if _, authErr := in.a.Authenticate(in.bearer(t, login.Tokens.AccessToken)); authErr != ErrUnauthenticated { //nolint:errorlint
			t.Fatalf("a token that is replayed later must end the session on every instance: %v", authErr)
		}
	})
}

func TestFailedAttemptsAreCountedAcrossInstances(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstances(t, d)
		ctx := t.Context()
		mustRegister(t, in.a, map[string]string{"email": "nina@example.com"}, goodPassword)
		wrong := Credentials{Login: "nina@example.com", Password: "wrong password", IP: testIP, Kind: SessionCookie}
		for i := range 5 {
			instance := in.a
			if i%2 == 1 {
				instance = in.b
			}
			if _, err := instance.Login(ctx, wrong); err != ErrInvalidCredentials { //nolint:errorlint
				t.Fatalf("attempt %d: %v", i+1, err)
			}
		}
		right := wrong
		right.Password = goodPassword
		for name, instance := range map[string]*Auth{"a": in.a, "b": in.b} {
			var limit *RateLimitError
			if _, err := instance.Login(ctx, right); !errors.As(err, &limit) || limit.RetryAfter != 15*time.Minute {
				t.Fatalf("instance %s: Login = %v, want a pause of 15 minutes: the failures of both instances count together", name, err)
			}
		}
		in.clock.advance(15*time.Minute + time.Second)
		if _, err := in.b.Login(ctx, right); err != nil {
			t.Fatalf("after the pause the user can sign in: %v", err)
		}
	})
}

func TestInstancesShareTheSigningKeys(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstances(t, d)
		ctx := t.Context()
		var wg sync.WaitGroup
		tokens := make([]string, 8)
		for i := range tokens {
			instance := in.a
			if i%2 == 1 {
				instance = in.b
			}
			wg.Go(func() {
				token, _, err := instance.issueAccessToken(ctx, "user-"+strconv.Itoa(i), "session", false, in.clock.now())
				if err != nil {
					t.Errorf("issueAccessToken failed: %v", err)
				}
				tokens[i] = token
			})
		}
		wg.Wait()
		keys, err := in.a.store.SigningKeys().List(ctx)
		if err != nil || len(keys) != 1 {
			t.Fatalf("the instances that started at once made %d keys, want 1: %v", len(keys), err)
		}
		for i, token := range tokens {
			for _, instance := range []*Auth{in.a, in.b} {
				if _, verifyErr := instance.verifyAccessToken(ctx, token); verifyErr != nil {
					t.Fatalf("token %d is not accepted by every instance: %v", i, verifyErr)
				}
			}
		}
		in.clock.advance(keyRotation - publishDelay + time.Minute)
		for _, instance := range []*Auth{in.a, in.b, in.a, in.b} {
			wg.Go(func() {
				if _, _, signErr := instance.issueAccessToken(ctx, "user", "session", false, in.clock.now()); signErr != nil {
					t.Errorf("issueAccessToken failed: %v", signErr)
				}
			})
		}
		wg.Wait()
		if keys, err = in.a.store.SigningKeys().List(ctx); err != nil || len(keys) != 2 || keys[0].RetireAfter.IsZero() {
			t.Fatalf("rotation by several instances gave %+v, %v; want exactly one new key and the old one retired", keys, err)
		}
	})
}

func TestCleanup(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstances(t, d)
		ctx := t.Context()
		mustRegister(t, in.a, map[string]string{"email": "nina@example.com"}, goodPassword)
		login, err := in.a.Login(ctx, Credentials{Login: "nina@example.com", Password: goodPassword, IP: testIP, Kind: SessionToken})
		if err != nil {
			t.Fatal(err)
		}
		wrong := Credentials{Login: "nina@example.com", Password: "wrong", IP: testIP, Kind: SessionCookie}
		if _, loginErr := in.a.Login(ctx, wrong); loginErr != ErrInvalidCredentials { //nolint:errorlint
			t.Fatal(loginErr)
		}
		in.clock.advance(60 * 24 * time.Hour)
		if err = in.b.Cleanup(ctx); err != nil {
			t.Fatalf("Cleanup failed: %v", err)
		}
		if _, resolveErr := in.a.store.Sessions().ResolveByID(ctx, in.a.tenant, login.Principal.SessionID); resolveErr == nil {
			t.Fatal("an expired session must be removed")
		}
		keys := in.a.loginAttemptKeys(wrong.Login, wrong.IP)
		left, err := in.a.store.Attempts().Get(ctx, keys.accountIP, keys.ip, keys.account)
		if err != nil || len(left) != 0 {
			t.Fatalf("counters left = %v, %v", left, err)
		}
		if err = in.a.Cleanup(ctx); err != nil {
			t.Fatalf("a second Cleanup failed: %v", err)
		}
	})
}
