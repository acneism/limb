package limb

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/store"
)

func (f *sessionFixture) refresh(t *testing.T, token string) (Tokens, error) {
	t.Helper()
	return f.a.Refresh(t.Context(), token)
}

func (f *sessionFixture) mustRefresh(t *testing.T, token string) Tokens {
	t.Helper()
	tokens, err := f.refresh(t, token)
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}
	return tokens
}

func (f *sessionFixture) refused(t *testing.T, name, token string) {
	t.Helper()
	if tokens, err := f.refresh(t, token); err != ErrUnauthenticated || tokens != (Tokens{}) { //nolint:errorlint
		t.Fatalf("%s: Refresh = %+v, %v; want ErrUnauthenticated exactly and no tokens", name, tokens, err)
	}
}

func (f *sessionFixture) sessionWorks(t *testing.T, id string) bool {
	t.Helper()
	resolved, err := f.a.store.Sessions().ResolveByID(t.Context(), f.a.tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	return resolved.Session.RevokedAt.IsZero()
}

func TestRefreshGivesANewPairForTheSameSession(t *testing.T) {
	f := newSessionFixture(t)
	login := f.tokenLogin(t)
	f.clock.advance(5 * time.Minute)
	now := f.clock.now().UTC().Truncate(time.Microsecond)

	tokens := f.mustRefresh(t, login.Tokens.RefreshToken)
	if tokens.AccessToken == "" || tokens.AccessToken == login.Tokens.AccessToken || tokens.RefreshToken == "" || tokens.RefreshToken == login.Tokens.RefreshToken {
		t.Fatalf("Refresh = %+v, want new tokens", tokens)
	}
	if !tokens.RefreshExpiresAt.Equal(now.Add(7*24*time.Hour)) || !tokens.AccessExpiresAt.Equal(now.Truncate(time.Second).Add(10*time.Minute)) {
		t.Fatalf("the new refresh token ends %v and the access token %v", tokens.RefreshExpiresAt, tokens.AccessExpiresAt)
	}
	claims, err := f.a.verifyAccessToken(t.Context(), tokens.AccessToken)
	if err != nil || claims.SessionID != login.Principal.SessionID || claims.Subject != string(f.user.ID) || claims.ChangePassword {
		t.Fatalf("the new access token carries %+v, %v; it must name the same session and user", claims, err)
	}
	p, err := f.a.Authenticate(f.bearer(t, http.MethodGet, tokens.AccessToken))
	if err != nil || p != login.Principal {
		t.Fatalf("Authenticate = %+v, %v; want %+v", p, err, login.Principal)
	}
	if got := f.session(t, login.Principal.SessionID).Session.LastSeenAt; !got.Equal(now) {
		t.Fatalf("LastSeenAt = %v, want %v: a refresh counts as use", got, now)
	}
	hash := sha256.Sum256([]byte(tokens.RefreshToken))
	stored, err := f.a.store.RefreshTokens().Use(t.Context(), f.a.tenant, hash[:], now)
	if err != nil || stored.Reused || stored.Token.SessionID != login.Principal.SessionID {
		t.Fatalf("the new refresh token must be stored by its hash: %+v, %v", stored, err)
	}
}

func TestRefreshCanBeChained(t *testing.T) {
	f := newSessionFixture(t)
	login := f.tokenLogin(t)
	token := login.Tokens.RefreshToken
	seen := map[string]bool{token: true}
	for range 6 {
		f.clock.advance(time.Hour)
		next := f.mustRefresh(t, token)
		if seen[next.RefreshToken] {
			t.Fatal("a refresh token was handed out twice")
		}
		seen[next.RefreshToken] = true
		token = next.RefreshToken
	}
	if !f.sessionWorks(t, login.Principal.SessionID) {
		t.Fatal("the session must survive its refreshes")
	}
}

func TestAUsedRefreshTokenIsRefusedWithoutHarmInsideTheWindow(t *testing.T) {
	f := newSessionFixture(t)
	login := f.tokenLogin(t)
	next := f.mustRefresh(t, login.Tokens.RefreshToken)
	f.clock.advance(10 * time.Second)
	f.refused(t, "the old token at the edge of the window", login.Tokens.RefreshToken)
	if !f.sessionWorks(t, login.Principal.SessionID) {
		t.Fatal("a repeat inside the window is a race of the client and must not end the session")
	}
	if _, err := f.a.Authenticate(f.bearer(t, http.MethodGet, next.AccessToken)); err != nil {
		t.Fatalf("the winner of the race must keep working: %v", err)
	}
	f.mustRefresh(t, next.RefreshToken)
}

func TestAUsedRefreshTokenEndsTheSessionOutsideTheWindow(t *testing.T) {
	logger, logs := capturingLogger()
	f := newSessionFixture(t, WithLogger(logger))
	login := f.tokenLogin(t)
	next := f.mustRefresh(t, login.Tokens.RefreshToken)
	f.clock.advance(10*time.Second + time.Microsecond)
	f.refused(t, "a stolen token", login.Tokens.RefreshToken)
	if f.sessionWorks(t, login.Principal.SessionID) {
		t.Fatal("a token that is used again after the window must end the whole session")
	}
	f.refused(t, "the token that was handed out later", next.RefreshToken)
	if _, err := f.a.Authenticate(f.bearer(t, http.MethodGet, next.AccessToken)); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("the access token of the ended session = %v, want ErrUnauthenticated", err)
	}
	text := logs.String()
	if !strings.Contains(text, "level=WARN") || !strings.Contains(text, "user_id="+string(f.user.ID)) ||
		!strings.Contains(text, "session_id="+login.Principal.SessionID) {
		t.Fatalf("the reuse must be logged as a warning with the user and the session:\n%s", text)
	}
	for _, secret := range []string{login.Tokens.RefreshToken, next.RefreshToken, login.Tokens.AccessToken, next.AccessToken} {
		if strings.Contains(text, secret) || strings.Contains(text, secret[:20]) {
			t.Fatalf("the log must not contain a token:\n%s", text)
		}
	}
	hash := sha256.Sum256([]byte(login.Tokens.RefreshToken))
	if strings.Contains(text, string(hash[:8])) {
		t.Fatalf("the log must not contain a hash:\n%s", text)
	}
	before := strings.Count(logs.String(), "used again")
	f.refused(t, "the stolen token once more", login.Tokens.RefreshToken)
	if strings.Count(logs.String(), "used again") != before {
		t.Fatal("a session that is ended already must not be reported again")
	}
}

func TestParallelRefreshesOfOneTokenGiveOneWinner(t *testing.T) {
	f := newSessionFixture(t)
	login := f.tokenLogin(t)
	const racers = 12
	var wins, refused atomic.Int32
	var wg sync.WaitGroup
	for range racers {
		wg.Go(func() {
			switch _, err := f.a.Refresh(t.Context(), login.Tokens.RefreshToken); {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrUnauthenticated):
				refused.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 || refused.Load() != racers-1 {
		t.Fatalf("%d refreshes won and %d were refused, want exactly 1 and %d", wins.Load(), refused.Load(), racers-1)
	}
	if !f.sessionWorks(t, login.Principal.SessionID) {
		t.Fatal("a race of one client must not end the session")
	}
}

func TestRefreshRefusesEverythingThatIsNotAGoodToken(t *testing.T) {
	f := newSessionFixture(t)
	login := f.tokenLogin(t)
	cookie := f.login(t)
	cases := map[string]string{
		"nothing":               "",
		"junk":                  "junk",
		"an unknown token":      strings.Repeat("A", 43),
		"the token cut short":   login.Tokens.RefreshToken[:42],
		"the token extended":    login.Tokens.RefreshToken + "A",
		"the access token":      login.Tokens.AccessToken,
		"the cookie secret":     cookie.Secret,
		"the session ID":        login.Principal.SessionID,
		"padding":               login.Tokens.RefreshToken + "=",
		"whitespace":            " " + login.Tokens.RefreshToken,
		"a huge value":          strings.Repeat("A", 1<<20),
		"a NUL byte":            "\x00" + login.Tokens.RefreshToken[1:],
		"invalid UTF-8":         "\xff" + login.Tokens.RefreshToken[1:],
		"the token in capitals": strings.ToUpper(login.Tokens.RefreshToken),
	}
	for name, token := range cases {
		f.refused(t, name, token)
	}
	f.mustRefresh(t, login.Tokens.RefreshToken)
}

func TestRefreshChecksTheSessionAndTheUser(t *testing.T) {
	f := newSessionFixture(t, WithSessionTTL(24*time.Hour, 2*time.Hour))
	ended := f.tokenLogin(t)
	if err := f.a.Logout(t.Context(), ended.Principal); err != nil {
		t.Fatal(err)
	}
	f.refused(t, "an ended session", ended.Tokens.RefreshToken)

	for name, edit := range map[string]func(*store.User){
		"a blocked user": func(u *store.User) { u.Status = store.StatusBlocked },
		"a deleted user": func(u *store.User) { u.Status = store.StatusDeleted },
		"a user blocked for a while": func(u *store.User) {
			u.Status, u.BlockedUntil = store.StatusBlocked, f.clock.now().Add(time.Hour)
		},
	} {
		login := f.tokenLogin(t)
		f.change(t, edit)
		f.refused(t, name, login.Tokens.RefreshToken)
		f.change(t, func(u *store.User) { u.Status, u.BlockedUntil = store.StatusActive, time.Time{} })
		f.mustRefresh(t, login.Tokens.RefreshToken)
	}

	idle := f.tokenLogin(t)
	f.clock.advance(2 * time.Hour)
	f.refused(t, "a session that went idle", idle.Tokens.RefreshToken)

	atEdge := f.tokenLogin(t)
	f.clock.advance(2*time.Hour - time.Microsecond)
	f.mustRefresh(t, atEdge.Tokens.RefreshToken)
}

func TestARefreshTokenExpiresOnItsOwn(t *testing.T) {
	f := newSessionFixture(t, WithSessionTTL(24*time.Hour, 2*time.Hour))
	login := f.tokenLogin(t)
	f.clock.advance(2*time.Hour - time.Microsecond)
	if _, err := f.a.Authenticate(f.bearer(t, http.MethodGet, f.a.mustIssueFor(t, login))); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(time.Microsecond)
	f.refused(t, "a token at the end of its lifetime", login.Tokens.RefreshToken)
}

func (a *Auth) mustIssueFor(t *testing.T, login Login) string {
	t.Helper()
	token, _, err := a.issueAccessToken(t.Context(), string(login.Principal.UserID), login.Principal.SessionID, false, a.now())
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestTheNewRefreshTokenNeverOutlivesTheSession(t *testing.T) {
	f := newSessionFixture(t, WithSessionTTL(3*time.Hour, 2*time.Hour))
	login := f.tokenLogin(t)
	f.clock.advance(90 * time.Minute)
	tokens := f.mustRefresh(t, login.Tokens.RefreshToken)
	if !tokens.RefreshExpiresAt.Equal(login.ExpiresAt) {
		t.Fatalf("the refresh token ends %v, the session ends %v: after 90 minutes only 90 minutes are left", tokens.RefreshExpiresAt, login.ExpiresAt)
	}
	f.clock.advance(90*time.Minute - time.Microsecond)
	last := f.mustRefresh(t, tokens.RefreshToken)
	if !last.RefreshExpiresAt.Equal(login.ExpiresAt) {
		t.Fatalf("the refresh token ends %v, want the end of the session %v", last.RefreshExpiresAt, login.ExpiresAt)
	}
	f.clock.advance(time.Microsecond)
	f.refused(t, "a session at the end of its life", last.RefreshToken)
}

func TestARestrictedSessionKeepsItsRestrictionWhenRefreshed(t *testing.T) {
	f := newSessionFixture(t)
	f.change(t, func(u *store.User) { u.MustChangePassword = true })
	login := f.tokenLogin(t)
	tokens := f.mustRefresh(t, login.Tokens.RefreshToken)
	claims, err := f.a.verifyAccessToken(t.Context(), tokens.AccessToken)
	if err != nil || !claims.ChangePassword {
		t.Fatalf("claims = %+v, %v; the new token of a restricted session must carry cpw", claims, err)
	}
	f.change(t, func(u *store.User) { u.MustChangePassword = false })
	tokens = f.mustRefresh(t, tokens.RefreshToken)
	if claims, err = f.a.verifyAccessToken(t.Context(), tokens.AccessToken); err != nil || claims.ChangePassword {
		t.Fatalf("claims = %+v, %v; once the password is changed the restriction goes", claims, err)
	}
}

func TestARefreshThatCannotSignLeavesTheTokenUsable(t *testing.T) {
	f := newSessionFixture(t)
	login := f.tokenLogin(t)
	boom := errors.New("database is down")
	healthy := f.a.store
	f.a.ring = newKeyring(f.a)
	f.a.store = &keysFaultStore{Store: healthy, listErr: boom}
	if _, err := f.refresh(t, login.Tokens.RefreshToken); !errors.Is(err, boom) || errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Refresh = %v, want the failure of the store", err)
	}
	f.a.store = healthy
	f.mustRefresh(t, login.Tokens.RefreshToken)
}

func TestARefreshThatFailsHalfwayLeavesTheTokenUsable(t *testing.T) {
	f := newSessionFixture(t)
	login := f.tokenLogin(t)
	boom := errors.New("database is down")
	healthy := f.a.store
	f.a.store = &tokensFaultStore{Store: healthy, addErr: boom}
	if _, err := f.refresh(t, login.Tokens.RefreshToken); !errors.Is(err, boom) || errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Refresh = %v, want the failure of the store and not ErrUnauthenticated", err)
	}
	f.a.store = healthy
	f.mustRefresh(t, login.Tokens.RefreshToken)
}

type tokensFaultStore struct {
	store.Store
	addErr error
}

func (s *tokensFaultStore) InTx(ctx context.Context, fn func(ctx context.Context, tx store.Repositories) error) error {
	return s.Store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		return fn(ctx, tokensFaultRepositories{Repositories: tx, s: s})
	})
}

type tokensFaultRepositories struct {
	store.Repositories
	s *tokensFaultStore
}

func (r tokensFaultRepositories) RefreshTokens() store.RefreshTokens {
	return tokensFault{RefreshTokens: r.Repositories.RefreshTokens(), s: r.s}
}

type tokensFault struct {
	store.RefreshTokens
	s *tokensFaultStore
}

func (r tokensFault) Add(ctx context.Context, t store.RefreshToken) error {
	if r.s.addErr != nil {
		return r.s.addErr
	}
	return r.RefreshTokens.Add(ctx, t)
}

func TestRefreshStopsWhenTheContextIsCanceled(t *testing.T) {
	f := newSessionFixture(t)
	login := f.tokenLogin(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.a.Refresh(ctx, login.Tokens.RefreshToken); !errors.Is(err, context.Canceled) || errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Refresh = %v, want context.Canceled", err)
	}
	f.mustRefresh(t, login.Tokens.RefreshToken)
}

func TestACookieSessionHasNoRefreshToken(t *testing.T) {
	f := newSessionFixture(t)
	cookie := f.login(t)
	if cookie.Tokens != (Tokens{}) {
		t.Fatalf("a cookie session has no tokens: %+v", cookie.Tokens)
	}
	f.refused(t, "the secret of a cookie session", cookie.Secret)
}

func TestARefreshTokenOfACookieSessionIsRefused(t *testing.T) {
	f := newSessionFixture(t)
	cookie := f.login(t)
	text := strings.Repeat("B", 42) + "A"
	if _, err := secret.Hash(text); err != nil {
		t.Fatalf("test setup: %v", err)
	}
	hash := sha256.Sum256([]byte(text))
	err := f.a.store.RefreshTokens().Add(t.Context(), store.RefreshToken{
		TenantID: f.a.tenant, Hash: hash[:], SessionID: cookie.Principal.SessionID, ExpiresAt: f.clock.now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.refused(t, "a refresh token of a cookie session", text)
}
