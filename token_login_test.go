package limb

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/store"
)

func (f *sessionFixture) tokenCredentials() Credentials {
	c := f.credentials()
	c.Kind = SessionToken
	return c
}

func (f *sessionFixture) tokenLogin(t *testing.T) Login {
	t.Helper()
	login, err := f.a.Login(t.Context(), f.tokenCredentials())
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	return login
}

func (f *sessionFixture) bearer(t *testing.T, method, token string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, "http://app.example.com/api", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func (f *sessionFixture) authenticateToken(t *testing.T, login Login) (Principal, error) {
	t.Helper()
	return f.a.Authenticate(f.bearer(t, http.MethodGet, login.Tokens.AccessToken))
}

type noSessionsStore struct {
	store.Store
	t *testing.T
}

func (s noSessionsStore) Sessions() store.Sessions {
	s.t.Helper()
	s.t.Error("the database must not be asked for a session")
	return s.Store.Sessions()
}

func TestLoginOpensATokenSession(t *testing.T) {
	f := newSessionFixture(t)
	login := f.tokenLogin(t)
	now := f.clock.now().UTC().Truncate(time.Microsecond)

	want := Principal{UserID: f.user.ID, SessionID: login.Principal.SessionID, SessionKind: SessionToken}
	if login.Principal != want || login.Secret != "" || login.CSRFToken != "" {
		t.Fatalf("Login = %+v, want the principal %+v and no cookie secret or CSRF token", login, want)
	}
	if !login.ExpiresAt.Equal(now.Add(30*24*time.Hour)) || !login.Tokens.RefreshExpiresAt.Equal(now.Add(7*24*time.Hour)) ||
		!login.Tokens.AccessExpiresAt.Equal(now.Truncate(time.Second).Add(10*time.Minute)) {
		t.Fatalf("session ends %v, refresh token %v, access token %v", login.ExpiresAt, login.Tokens.RefreshExpiresAt, login.Tokens.AccessExpiresAt)
	}
	if len(login.Tokens.RefreshToken) != secret.TextLen || login.Tokens.AccessToken == "" || login.Tokens.AccessToken == login.Tokens.RefreshToken {
		t.Fatalf("Tokens = %+v", login.Tokens)
	}

	s := f.session(t, login.Principal.SessionID).Session
	if s.Kind != store.SessionToken || len(s.SecretHash) != 0 || s.UserID != string(f.user.ID) || s.IP != "203.0.113.7" ||
		s.UserAgent != testAgent || !s.CreatedAt.Equal(now) || !s.ExpiresAt.Equal(login.ExpiresAt) {
		t.Fatalf("stored session = %+v", s)
	}
	hash := sha256.Sum256([]byte(login.Tokens.RefreshToken))
	use, err := f.a.store.RefreshTokens().Use(t.Context(), f.a.tenant, hash[:], now)
	if err != nil {
		t.Fatalf("the refresh token must be stored by its hash: %v", err)
	}
	if use.Token.SessionID != login.Principal.SessionID || !use.Token.ExpiresAt.Equal(login.Tokens.RefreshExpiresAt) || use.Reused {
		t.Fatalf("stored refresh token = %+v", use)
	}
	claims, err := f.a.verifyAccessToken(t.Context(), login.Tokens.AccessToken)
	if err != nil || claims.Subject != string(f.user.ID) || claims.SessionID != login.Principal.SessionID || claims.ChangePassword {
		t.Fatalf("the access token carries %+v, %v", claims, err)
	}
	if got := f.stored(t); !got.LastLoginAt.Equal(now) {
		t.Fatalf("LastLoginAt = %v, want %v", got.LastLoginAt, now)
	}
}

func TestEveryTokenSignInGetsNewTokens(t *testing.T) {
	f := newSessionFixture(t)
	first, second := f.tokenLogin(t), f.tokenLogin(t)
	if first.Tokens.RefreshToken == second.Tokens.RefreshToken || first.Principal.SessionID == second.Principal.SessionID ||
		first.Tokens.AccessToken == second.Tokens.AccessToken {
		t.Fatal("a sign-in must not reuse a session or a token")
	}
	for _, login := range []Login{first, second} {
		if _, err := f.authenticateToken(t, login); err != nil {
			t.Fatalf("both sessions must work: %v", err)
		}
	}
}

func TestATokenSessionOfARestrictedUserCarriesTheServiceClaim(t *testing.T) {
	for _, mode := range []RevocationMode{RevocationInstant, RevocationAfterTTL} {
		f := newSessionFixture(t, WithRevocation(mode))
		f.change(t, func(u *store.User) { u.MustChangePassword = true })
		login := f.tokenLogin(t)
		if !login.Principal.MustChangePassword {
			t.Fatalf("mode %d: the sign-in must say that the password has to be changed", mode)
		}
		claims, err := f.a.verifyAccessToken(t.Context(), login.Tokens.AccessToken)
		if err != nil || !claims.ChangePassword {
			t.Fatalf("mode %d: claims = %+v, %v; want cpw", mode, claims, err)
		}
		p, err := f.authenticateToken(t, login)
		if !errors.Is(err, ErrPasswordChangeRequired) || p != login.Principal {
			t.Fatalf("mode %d: Authenticate = %+v, %v; want the principal with ErrPasswordChangeRequired", mode, p, err)
		}
	}
}

func TestAnInstantTokenIsCheckedAgainstTheDatabase(t *testing.T) {
	f := newSessionFixture(t, WithSessionTTL(time.Hour, 20*time.Minute))
	login := f.tokenLogin(t)
	p, err := f.authenticateToken(t, login)
	if err != nil || p != login.Principal {
		t.Fatalf("Authenticate = %+v, %v; want %+v", p, err, login.Principal)
	}
	if p.SessionKind != SessionToken || p.UserID != f.user.ID {
		t.Fatalf("Principal = %+v", p)
	}

	gone := func(name string, login Login) {
		t.Helper()
		if _, authErr := f.authenticateToken(t, login); authErr != ErrUnauthenticated { //nolint:errorlint
			t.Fatalf("%s: Authenticate = %v, want ErrUnauthenticated", name, authErr)
		}
	}
	ended := f.tokenLogin(t)
	if err = f.a.Logout(t.Context(), ended.Principal); err != nil {
		t.Fatal(err)
	}
	gone("a session that was ended at once, whatever the token says", ended)

	for name, edit := range map[string]func(*store.User){
		"a blocked user":      func(u *store.User) { u.Status = store.StatusBlocked },
		"a deleted user":      func(u *store.User) { u.Status = store.StatusDeleted },
		"a user blocked till": func(u *store.User) { u.Status, u.BlockedUntil = store.StatusBlocked, f.clock.now().Add(time.Hour) },
	} {
		fresh := f.tokenLogin(t)
		f.change(t, edit)
		gone(name, fresh)
		f.change(t, func(u *store.User) { u.Status, u.BlockedUntil = store.StatusActive, time.Time{} })
	}

	idle := f.tokenLogin(t)
	f.clock.advance(20 * time.Minute)
	gone("a session idle for the idle lifetime", idle)
}

func TestATokenOfAnotherUserOrKindOrSessionIsRefused(t *testing.T) {
	f := newSessionFixture(t)
	mine := f.tokenLogin(t)
	cookie := f.login(t)
	other := mustRegister(t, f.a, map[string]string{"email": "olga@example.com"}, goodPassword)
	cases := map[string]string{
		"the session of another user": a2token(t, f.a, string(other.ID), mine.Principal.SessionID),
		"a cookie session":            a2token(t, f.a, string(f.user.ID), cookie.Principal.SessionID),
		"an unknown session":          a2token(t, f.a, string(f.user.ID), "00000000-0000-7000-8000-00000000dead"),
	}
	for name, token := range cases {
		if _, err := f.a.Authenticate(f.bearer(t, http.MethodGet, token)); err != ErrUnauthenticated { //nolint:errorlint
			t.Errorf("%s: Authenticate = %v, want ErrUnauthenticated", name, err)
		}
	}
}

func a2token(t *testing.T, a *Auth, userID, sessionID string) string {
	t.Helper()
	token, _, err := a.issueAccessToken(t.Context(), userID, sessionID, false, a.now())
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestATokenSessionIsMarkedAsUsed(t *testing.T) {
	f := newSessionFixture(t)
	login := f.tokenLogin(t)
	start := f.session(t, login.Principal.SessionID).Session.LastSeenAt
	f.clock.advance(touchInterval)
	if _, err := f.authenticateToken(t, login); err != nil {
		t.Fatal(err)
	}
	if got := f.session(t, login.Principal.SessionID).Session.LastSeenAt; !got.Equal(start.Add(touchInterval)) {
		t.Fatalf("LastSeenAt = %v, want %v", got, start.Add(touchInterval))
	}
}

func TestAnExpiredTokenIsRefusedWhateverTheSessionIs(t *testing.T) {
	f := newSessionFixture(t)
	login := f.tokenLogin(t)
	f.clock.advance(10*time.Minute + tokenLeeway - time.Second)
	if _, err := f.authenticateToken(t, login); err != nil {
		t.Fatalf("a token within the tolerance after its expiry still works: %v", err)
	}
	f.clock.advance(2 * time.Second)
	if _, err := f.authenticateToken(t, login); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("an expired token = %v, want ErrUnauthenticated", err)
	}
}

func TestATokenCheckedAfterItsLifetimeNeverAsksTheDatabase(t *testing.T) {
	f := newSessionFixture(t, WithRevocation(RevocationAfterTTL))
	login := f.tokenLogin(t)
	if err := f.a.Logout(t.Context(), login.Principal); err != nil {
		t.Fatal(err)
	}
	f.change(t, func(u *store.User) { u.Status = store.StatusBlocked })
	f.a.store = noSessionsStore{Store: f.a.store, t: t}

	p, err := f.authenticateToken(t, login)
	if err != nil || p != login.Principal {
		t.Fatalf("Authenticate = %+v, %v; want %+v: the token works until it expires", p, err, login.Principal)
	}
	f.clock.advance(10*time.Minute + tokenLeeway)
	if _, err = f.authenticateToken(t, login); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("an expired token = %v, want ErrUnauthenticated", err)
	}
}

func TestACookieSessionIsAlwaysCheckedAgainstTheDatabase(t *testing.T) {
	f := newSessionFixture(t, WithRevocation(RevocationAfterTTL))
	login := f.login(t)
	if err := f.a.Logout(t.Context(), login.Principal); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.Authenticate(f.request(t, http.MethodGet, login, nil)); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("a cookie session that was ended = %v, want ErrUnauthenticated", err)
	}
}

func TestABearerTokenNeedsNoCrossSiteCheck(t *testing.T) {
	f := newSessionFixture(t)
	login := f.tokenLogin(t)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		r := f.bearer(t, method, login.Tokens.AccessToken)
		r.Header.Set("Origin", "https://evil.example")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		if _, err := f.a.Authenticate(r); err != nil {
			t.Errorf("%s with a token: %v; a token is not sent by the browser on its own, so there is nothing to forge", method, err)
		}
	}
}

func TestABearerTokenWinsOverTheCookie(t *testing.T) {
	f := newSessionFixture(t)
	token, cookie := f.tokenLogin(t), f.login(t)
	r := f.request(t, http.MethodGet, cookie, map[string]string{"Authorization": "Bearer " + token.Tokens.AccessToken})
	p, err := f.a.Authenticate(r)
	if err != nil || p != token.Principal {
		t.Fatalf("Authenticate = %+v, %v; want the principal of the token", p, err)
	}
	r = f.request(t, http.MethodGet, f.login(t), map[string]string{"Authorization": "Bearer " + token.Tokens.AccessToken + "x"})
	if _, err = f.a.Authenticate(r); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("a wrong token with a good cookie = %v, want ErrUnauthenticated", err)
	}
}

func TestTokenSignInStopsWhenTheKeysCannotBeUsed(t *testing.T) {
	f := newSessionFixture(t)
	boom := errors.New("database is down")
	healthy := f.a.store
	f.a.store = &keysFaultStore{Store: healthy, listErr: boom}
	if _, err := f.a.Login(t.Context(), f.tokenCredentials()); !errors.Is(err, boom) {
		t.Fatalf("Login = %v, want %v", err, boom)
	}
	f.a.store = healthy
	list, err := f.a.store.Sessions().ListByUser(t.Context(), f.a.tenant, string(f.user.ID), f.clock.now())
	if err != nil || len(list) != 0 {
		t.Fatalf("a sign-in that cannot sign a token must not leave a session: %v, %v", list, err)
	}
}

func TestTokenSignInReportsAFailureToOpenTheSession(t *testing.T) {
	f := newSessionFixture(t)
	f.tokenLogin(t)
	boom := errors.New("database is down")
	healthy := f.a.store
	f.a.store = &faultyStore{Store: healthy, txErr: boom}
	if _, err := f.a.Login(t.Context(), f.tokenCredentials()); !errors.Is(err, boom) || errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login = %v, want the failure of the store", err)
	}
	f.a.store = healthy
	f.a.newID = func() (string, error) { return "", boom }
	if _, err := f.a.Login(t.Context(), f.tokenCredentials()); !errors.Is(err, boom) {
		t.Fatalf("Login = %v, want %v", err, boom)
	}
}

func TestAUserWhoVanishedDuringATokenSignInIsAWrongLogin(t *testing.T) {
	f := newSessionFixture(t)
	f.tokenLogin(t)
	f.a.store = &faultyStore{Store: f.a.store, txErr: store.ErrNotFound}
	if _, err := f.a.Login(t.Context(), f.tokenCredentials()); err != ErrInvalidCredentials { //nolint:errorlint
		t.Fatalf("Login = %v, want ErrInvalidCredentials", err)
	}
}

func TestTheRefreshTokenOfASessionNeverOutlivesIt(t *testing.T) {
	f := newSessionFixture(t, WithSessionTTL(time.Hour, time.Hour))
	login := f.tokenLogin(t)
	if !login.Tokens.RefreshExpiresAt.Equal(login.ExpiresAt) {
		t.Fatalf("refresh token ends %v, session ends %v; they are equal when the lifetimes are", login.Tokens.RefreshExpiresAt, login.ExpiresAt)
	}
	stored, err := newTestAuthWithTTL(t, 2*time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := stored.Tokens.RefreshExpiresAt.Sub(f.clock.now()); got > time.Hour || got < time.Hour-time.Second {
		t.Fatalf("a refresh token lives for the idle lifetime, got %v", got)
	}
}

func newTestAuthWithTTL(t *testing.T, absolute, idle time.Duration) (Login, error) {
	t.Helper()
	f := newSessionFixture(t, WithSessionTTL(absolute, idle))
	return f.a.Login(t.Context(), f.tokenCredentials())
}

func TestNoTokenTextLooksLikeAnotherSecret(t *testing.T) {
	f := newSessionFixture(t)
	login := f.tokenLogin(t)
	if strings.Contains(login.Tokens.AccessToken, login.Tokens.RefreshToken) || login.Tokens.RefreshToken == login.Principal.SessionID {
		t.Fatal("tokens must be independent of each other")
	}
	if _, err := secret.Hash(login.Tokens.AccessToken); err == nil {
		t.Fatal("an access token must not pass for a secret")
	}
	if _, err := f.a.verifyAccessToken(t.Context(), login.Tokens.RefreshToken); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("a refresh token must not pass for an access token: %v", err)
	}
}
