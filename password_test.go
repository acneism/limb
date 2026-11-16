package limb

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

const newPassword = "a much better password than that"

func (f *sessionFixture) change(t *testing.T, edit func(*store.User)) {
	t.Helper()
	f.fixture.change(t, edit)
}

func (f *sessionFixture) works(t *testing.T, login Login) bool {
	t.Helper()
	var err error
	if login.Secret != "" {
		_, err = f.a.Authenticate(f.request(t, http.MethodGet, login, nil))
	} else {
		_, err = f.authenticateToken(t, login)
	}
	if err != nil && !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unexpected error: %v", err)
	}
	return err == nil
}

func (f *sessionFixture) canSignInWith(t *testing.T, password string) bool {
	t.Helper()
	c := f.credentials()
	c.Password = password
	c.IP = netip.Addr{}
	_, err := f.a.Login(t.Context(), c)
	return err == nil
}

func TestChangePasswordReplacesACookieSession(t *testing.T) {
	f := newSessionFixture(t)
	mine, other := f.login(t), f.login(t)
	f.clock.advance(time.Hour)
	changed, err := f.a.ChangePassword(t.Context(), mine.Principal, goodPassword, newPassword)
	if err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}
	if f.works(t, mine) || f.works(t, other) {
		t.Fatal("every session of the user must end, the current one too")
	}
	if !f.works(t, changed) {
		t.Fatal("the new session must work")
	}
	if changed.Principal.SessionID == mine.Principal.SessionID || changed.Secret == mine.Secret || changed.CSRFToken == mine.CSRFToken || changed.Secret == "" {
		t.Fatalf("a new session needs a new ID, secret and CSRF token: %+v", changed)
	}
	if changed.Principal.UserID != f.user.ID || changed.Principal.SessionKind != SessionCookie || changed.Principal.MustChangePassword {
		t.Fatalf("Principal = %+v", changed.Principal)
	}
	if changed.CSRFToken != f.a.keys.CSRFToken(changed.Principal.SessionID) || changed.Tokens != (Tokens{}) {
		t.Fatalf("Login = %+v", changed)
	}
	old, fresh := f.session(t, mine.Principal.SessionID).Session, f.session(t, changed.Principal.SessionID).Session
	if !fresh.CreatedAt.Equal(old.CreatedAt) || !fresh.ExpiresAt.Equal(old.ExpiresAt) || fresh.IP != old.IP || fresh.UserAgent != old.UserAgent ||
		!changed.ExpiresAt.Equal(old.ExpiresAt) || !fresh.LastSeenAt.Equal(f.clock.now().UTC().Truncate(time.Microsecond)) {
		t.Fatalf("the new session must inherit the sign-in and the end of the old one: old %+v, new %+v", old, fresh)
	}
	if old.RevokedAt.IsZero() || !fresh.RevokedAt.IsZero() {
		t.Fatalf("old %+v, new %+v", old, fresh)
	}
	if f.canSignInWith(t, goodPassword) || !f.canSignInWith(t, newPassword) {
		t.Fatal("the new password must replace the old one")
	}
}

func TestChangePasswordReplacesATokenSession(t *testing.T) {
	f := newSessionFixture(t)
	mine := f.tokenLogin(t)
	changed, err := f.a.ChangePassword(t.Context(), mine.Principal, goodPassword, newPassword)
	if err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}
	if f.works(t, mine) {
		t.Fatal("the old access token must stop working at once")
	}
	if _, err = f.a.Refresh(t.Context(), mine.Tokens.RefreshToken); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("the old refresh token = %v, want ErrUnauthenticated", err)
	}
	if !f.works(t, changed) || changed.Secret != "" || changed.CSRFToken != "" || changed.Principal.SessionKind != SessionToken {
		t.Fatalf("Login = %+v", changed)
	}
	if changed.Principal.SessionID == mine.Principal.SessionID || changed.Tokens.RefreshExpiresAt.IsZero() || changed.Tokens.AccessExpiresAt.IsZero() {
		t.Fatalf("Login = %+v", changed)
	}
	next, err := f.a.Refresh(t.Context(), changed.Tokens.RefreshToken)
	if err != nil {
		t.Fatalf("the new refresh token must work: %v", err)
	}
	claims, err := f.a.verifyAccessToken(t.Context(), next.AccessToken)
	if err != nil || claims.SessionID != changed.Principal.SessionID {
		t.Fatalf("claims = %+v, %v", claims, err)
	}
}

func TestChangePasswordEndsTheRestrictionOfATemporaryPassword(t *testing.T) {
	for _, tc := range []struct {
		kind SessionKind
		mode RevocationMode
	}{{SessionCookie, RevocationInstant}, {SessionToken, RevocationInstant}, {SessionToken, RevocationAfterTTL}} {
		kind := tc.kind
		f := newSessionFixture(t, WithRevocation(tc.mode))
		f.change(t, func(u *store.User) { u.MustChangePassword = true })
		c := f.credentials()
		c.Kind = kind
		login, err := f.a.Login(t.Context(), c)
		if err != nil || !login.Principal.MustChangePassword {
			t.Fatalf("%s: Login = %+v, %v", kind, login, err)
		}
		changed, err := f.a.ChangePassword(t.Context(), login.Principal, goodPassword, newPassword)
		if err != nil || changed.Principal.MustChangePassword {
			t.Fatalf("%s: ChangePassword = %+v, %v; the new session must not be restricted", kind, changed, err)
		}
		if !f.works(t, changed) || f.stored(t).MustChangePassword {
			t.Fatalf("%s: the user must be free to use the service", kind)
		}
		if kind == SessionToken {
			claims, claimsErr := f.a.verifyAccessToken(t.Context(), changed.Tokens.AccessToken)
			if claimsErr != nil || claims.ChangePassword {
				t.Fatalf("%s: the new access token = %+v, %v; it must not carry cpw", kind, claims, claimsErr)
			}
			if _, authErr := f.authenticateToken(t, changed); authErr != nil {
				t.Fatalf("%s mode %d: Authenticate = %v", kind, tc.mode, authErr)
			}
		}
	}
}

func TestChangePasswordRefusesAWrongCurrentPassword(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	if _, err := f.a.ChangePassword(t.Context(), login.Principal, "not the password", newPassword); err != ErrInvalidCredentials { //nolint:errorlint
		t.Fatalf("ChangePassword = %v, want ErrInvalidCredentials", err)
	}
	if !f.works(t, login) || !f.canSignInWith(t, goodPassword) {
		t.Fatal("a refused change must leave the session and the password as they were")
	}
	keys := f.a.userAttemptKeys(string(f.user.ID))
	counters, err := f.a.store.Attempts().Get(t.Context(), keys.account)
	if err != nil || len(counters) != 1 || counters[0].Count != 1 {
		t.Fatalf("the failure must be counted: %v, %v", counters, err)
	}
}

func TestTheCurrentPasswordIsCheckedUnderTheLimits(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	for range 20 {
		_, _ = f.a.ChangePassword(t.Context(), login.Principal, "not the password", newPassword)
	}
	_, err := f.a.ChangePassword(t.Context(), login.Principal, goodPassword, newPassword)
	var limit *RateLimitError
	if !errors.As(err, &limit) || limit.RetryAfter != time.Second {
		t.Fatalf("ChangePassword = %v, want a *RateLimitError with a second to wait even for the right password", err)
	}
	f.clock.advance(time.Second)
	if _, err = f.a.ChangePassword(t.Context(), login.Principal, goodPassword, newPassword); err != nil {
		t.Fatalf("after the delay the owner can go on: %v", err)
	}
}

func TestChangePasswordKeepsThePasswordPolicy(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	cases := map[string]struct {
		password string
		rule     string
	}{
		"too short":        {"short", "min_length"},
		"a common one":     {"password1234", "common_password"},
		"the e-mail":       {"nina@example.com", "login_identifier"},
		"upper case login": {"NINA@EXAMPLE.COM", "login_identifier"},
		"empty":            {"", "min_length"},
	}
	for name, tc := range cases {
		_, err := f.a.ChangePassword(t.Context(), login.Principal, goodPassword, tc.password)
		var policy *PolicyError
		if !errors.As(err, &policy) || !containsRule(policy.Rules, tc.rule) {
			t.Errorf("%s: ChangePassword = %v, want a *PolicyError with %s", name, err, tc.rule)
		}
	}
	if !f.works(t, login) || !f.canSignInWith(t, goodPassword) {
		t.Fatal("a refused change must leave everything as it was")
	}
	if _, err := f.a.ChangePassword(t.Context(), login.Principal, "wrong", "short"); err != ErrInvalidCredentials { //nolint:errorlint
		t.Fatalf("a wrong current password must be reported before the policy: %v", err)
	}
}

func containsRule(rules []string, rule string) bool {
	for _, r := range rules {
		if r == rule {
			return true
		}
	}
	return false
}

func TestChangePasswordNeedsALiveSessionOfTheSameUser(t *testing.T) {
	f := newSessionFixture(t)
	olga := mustRegister(t, f.a, map[string]string{"email": "olga@example.com"}, newPassword)
	login := f.login(t)
	stranger := Principal{UserID: olga.ID, SessionID: login.Principal.SessionID, SessionKind: SessionCookie}
	if _, err := f.a.ChangePassword(t.Context(), stranger, newPassword, "yet another password 42"); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("the session of another user = %v, want ErrUnauthenticated", err)
	}
	if err := f.a.Logout(t.Context(), login.Principal); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.ChangePassword(t.Context(), login.Principal, goodPassword, newPassword); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("an ended session = %v, want ErrUnauthenticated", err)
	}
	missing := Principal{UserID: f.user.ID, SessionID: "00000000-0000-7000-8000-00000000dead"}
	if _, err := f.a.ChangePassword(t.Context(), missing, goodPassword, newPassword); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("an unknown session = %v, want ErrUnauthenticated", err)
	}
	if !f.canSignInWith(t, goodPassword) {
		t.Fatal("a refused change must not change the password")
	}
}

func TestChangePasswordForAUserWhoIsBlockedOrGone(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	f.change(t, func(u *store.User) { u.Status = store.StatusBlocked })
	if _, err := f.a.ChangePassword(t.Context(), login.Principal, goodPassword, newPassword); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("a blocked user = %v, want ErrUnauthenticated", err)
	}
	ghost := Principal{UserID: "00000000-0000-7000-8000-0000000000ff", SessionID: login.Principal.SessionID}
	dummies := f.counting.dummies.Load()
	if _, err := f.a.ChangePassword(t.Context(), ghost, goodPassword, newPassword); err != ErrInvalidCredentials { //nolint:errorlint
		t.Fatalf("an unknown user = %v, want ErrInvalidCredentials, the same as a wrong password", err)
	}
	if f.counting.dummies.Load() != dummies+1 {
		t.Fatal("an unknown user must cost the same hashing work as a wrong password")
	}
}

func TestOnlyOneOfTwoParallelChangesWins(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	const racers = 6
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := range racers {
		wg.Go(func() {
			next := newPassword + strconv.Itoa(i)
			_, err := f.a.ChangePassword(t.Context(), login.Principal, goodPassword, next)
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrInvalidCredentials), errors.Is(err, ErrUnauthenticated):
			default:
				t.Errorf("racer %d: %v", i, err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d changes succeeded, want exactly 1", wins.Load())
	}
	list, err := f.a.Sessions(t.Context(), Principal{UserID: f.user.ID})
	if err != nil || len(list) != 1 {
		t.Fatalf("Sessions = %v, %v; exactly the one new session must be left", list, err)
	}
}

type staleOnceStore struct {
	store.Store
	stale *atomic.Int32
}

func (s staleOnceStore) InTx(ctx context.Context, fn func(ctx context.Context, tx store.Repositories) error) error {
	return s.Store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		return fn(ctx, staleRepositories{Repositories: tx, s: s})
	})
}

type staleRepositories struct {
	store.Repositories
	s staleOnceStore
}

func (r staleRepositories) Users() store.Users {
	return staleUsers{Users: r.Repositories.Users(), s: r.s}
}

type staleUsers struct {
	store.Users
	s staleOnceStore
}

func (u staleUsers) Update(ctx context.Context, user store.User) (store.User, error) {
	if u.s.stale.Add(-1) >= 0 {
		return store.User{}, store.ErrStale
	}
	return u.Users.Update(ctx, user)
}

func TestAConcurrentChangeOfTheUserIsRetried(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	stale := &atomic.Int32{}
	stale.Store(2)
	f.a.store = staleOnceStore{Store: f.a.store, stale: stale}
	if _, err := f.a.ChangePassword(t.Context(), login.Principal, goodPassword, newPassword); err != nil {
		t.Fatalf("ChangePassword = %v, want success after two retries", err)
	}
	stale.Store(1000)
	c := f.credentials()
	c.Password = newPassword
	again, err := f.a.Login(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.ChangePassword(t.Context(), again.Principal, newPassword, goodPassword); !errors.Is(err, store.ErrStale) {
		t.Fatalf("ChangePassword = %v, want the error of a user that keeps changing", err)
	}
}

func TestChangePasswordReportsFailures(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	boom := errors.New("database is down")
	f.counting.hashErr = boom
	if _, err := f.a.ChangePassword(t.Context(), login.Principal, goodPassword, newPassword); !errors.Is(err, boom) {
		t.Fatalf("ChangePassword = %v, want the failure of hashing", err)
	}
	f.counting.hashErr = nil
	healthy := f.a.store
	f.a.store = &faultyStore{Store: healthy, txErr: boom}
	if _, err := f.a.ChangePassword(t.Context(), login.Principal, goodPassword, newPassword); !errors.Is(err, boom) || errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("ChangePassword = %v, want the failure of the store", err)
	}
	f.a.store = healthy
	if !f.works(t, login) || !f.canSignInWith(t, goodPassword) {
		t.Fatal("a failed change must leave everything as it was")
	}
}

func TestLogoutAllWithoutThePasswordOption(t *testing.T) {
	f := newSessionFixture(t)
	first, second, third := f.login(t), f.login(t), f.tokenLogin(t)
	olga := mustRegister(t, f.a, map[string]string{"email": "olga@example.com"}, newPassword)
	c := f.credentials()
	c.Login, c.Password = "olga@example.com", newPassword
	foreign, err := f.a.Login(t.Context(), c)
	if err != nil || foreign.Principal.UserID != olga.ID {
		t.Fatal(err)
	}
	if err = f.a.LogoutAll(t.Context(), first.Principal, ""); err != nil {
		t.Fatalf("LogoutAll = %v, the password is not needed without the option", err)
	}
	for name, login := range map[string]Login{"first": first, "second": second, "token": third} {
		if f.works(t, login) {
			t.Errorf("the %s session must end, the current one too", name)
		}
	}
	if !f.works(t, foreign) {
		t.Fatal("the sessions of another user must stay")
	}
	if err = f.a.LogoutAll(t.Context(), first.Principal, "ignored anyway"); err != nil {
		t.Fatalf("a second LogoutAll = %v, nothing left is not an error", err)
	}
}

func TestTerminateSessionWithoutThePasswordOption(t *testing.T) {
	f := newSessionFixture(t)
	mine, other := f.login(t), f.login(t)
	if err := f.a.TerminateSession(t.Context(), mine.Principal, other.Principal.SessionID, ""); err != nil {
		t.Fatalf("TerminateSession = %v", err)
	}
	if f.works(t, other) || !f.works(t, mine) {
		t.Fatal("only the chosen session must end")
	}
	if err := f.a.TerminateSession(t.Context(), mine.Principal, other.Principal.SessionID, ""); err != ErrSessionNotFound { //nolint:errorlint
		t.Fatalf("an ended session = %v, want ErrSessionNotFound", err)
	}
	if err := f.a.TerminateSession(t.Context(), mine.Principal, mine.Principal.SessionID, ""); err != nil {
		t.Fatalf("the current session = %v", err)
	}
	if f.works(t, mine) {
		t.Fatal("the current session must end")
	}
}

func TestTerminateSessionCannotReachSessionsOfOthers(t *testing.T) {
	f := newSessionFixture(t)
	mine := f.login(t)
	olga := mustRegister(t, f.a, map[string]string{"email": "olga@example.com"}, newPassword)
	c := f.credentials()
	c.Login, c.Password = "olga@example.com", newPassword
	theirs, err := f.a.Login(t.Context(), c)
	if err != nil || theirs.Principal.UserID != olga.ID {
		t.Fatal(err)
	}
	for name, id := range map[string]string{
		"a session of someone else": theirs.Principal.SessionID, "a missing session": "00000000-0000-7000-8000-00000000dead",
		"an empty ID": "", "a NUL byte": "a\x00b", "junk": "not an id",
	} {
		if err = f.a.TerminateSession(t.Context(), mine.Principal, id, ""); err != ErrSessionNotFound { //nolint:errorlint
			t.Errorf("%s: TerminateSession = %v, want ErrSessionNotFound, the same for all of them", name, err)
		}
	}
	if !f.works(t, theirs) || !f.works(t, mine) {
		t.Fatal("no session may end")
	}
}

func TestEndingSessionsAsksForThePasswordWhenTheOptionIsOn(t *testing.T) {
	f := newSessionFixture(t, WithPasswordToEndSessions())
	mine, other := f.login(t), f.login(t)

	var invalid *ValidationError
	if err := f.a.TerminateSession(t.Context(), mine.Principal, other.Principal.SessionID, ""); !errors.As(err, &invalid) || invalid.Field != "password" {
		t.Fatalf("TerminateSession without a password = %v, want a *ValidationError about the password", err)
	}
	if err := f.a.LogoutAll(t.Context(), mine.Principal, ""); !errors.As(err, &invalid) || invalid.Field != "password" {
		t.Fatalf("LogoutAll without a password = %v, want a *ValidationError about the password", err)
	}
	if err := f.a.TerminateSession(t.Context(), mine.Principal, other.Principal.SessionID, "wrong"); err != ErrInvalidCredentials { //nolint:errorlint
		t.Fatalf("TerminateSession with a wrong password = %v, want ErrInvalidCredentials", err)
	}
	if err := f.a.LogoutAll(t.Context(), mine.Principal, "wrong"); err != ErrInvalidCredentials { //nolint:errorlint
		t.Fatalf("LogoutAll with a wrong password = %v, want ErrInvalidCredentials", err)
	}
	if !f.works(t, mine) || !f.works(t, other) {
		t.Fatal("a refused request must end nothing")
	}
	keys := f.a.userAttemptKeys(string(f.user.ID))
	counters, err := f.a.store.Attempts().Get(t.Context(), keys.account)
	if err != nil || len(counters) != 1 || counters[0].Count != 2 {
		t.Fatalf("both wrong passwords must be counted like those of a password change: %v, %v", counters, err)
	}

	if err = f.a.TerminateSession(t.Context(), mine.Principal, "00000000-0000-7000-8000-00000000dead", "wrong"); err != ErrInvalidCredentials { //nolint:errorlint
		t.Fatalf("a missing session with a wrong password = %v, want ErrInvalidCredentials: the password comes first", err)
	}
	if err = f.a.TerminateSession(t.Context(), mine.Principal, "00000000-0000-7000-8000-00000000dead", goodPassword); err != ErrSessionNotFound { //nolint:errorlint
		t.Fatalf("a missing session with the right password = %v, want ErrSessionNotFound", err)
	}
	if err = f.a.TerminateSession(t.Context(), mine.Principal, other.Principal.SessionID, goodPassword); err != nil {
		t.Fatalf("TerminateSession with the password = %v", err)
	}
	if f.works(t, other) {
		t.Fatal("the session must end")
	}
	third := f.login(t)
	if err = f.a.TerminateSession(t.Context(), third.Principal, third.Principal.SessionID, ""); err != nil {
		t.Fatalf("the current session never needs the password: %v", err)
	}
	if err = f.a.LogoutAll(t.Context(), mine.Principal, goodPassword); err != nil {
		t.Fatalf("LogoutAll with the password = %v", err)
	}
	if f.works(t, mine) {
		t.Fatal("every session must end")
	}
}

func TestTheSettingThatAsksForThePasswordIsReadInOnePlace(t *testing.T) {
	f := newSessionFixture(t)
	if f.a.passwordToEndSessions(t.Context()) {
		t.Fatal("the password must not be needed by default")
	}
	on := newSessionFixture(t, WithPasswordToEndSessions())
	if !on.a.passwordToEndSessions(t.Context()) {
		t.Fatal("WithPasswordToEndSessions must turn it on")
	}
}

func TestEndingSessionsReportsStoreFailures(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	boom := errors.New("database is down")
	f.breakSessions(func(s *sessionsFault) { s.revokeErr = boom })
	if err := f.a.TerminateSession(t.Context(), login.Principal, "00000000-0000-7000-8000-00000000dead", ""); !errors.Is(err, boom) || errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("TerminateSession = %v, want the failure of the store", err)
	}
	other := newSessionFixture(t)
	otherLogin := other.login(t)
	other.a.store = &faultyStore{Store: other.a.store, getErr: boom}
	other.a.endNeeds = true
	if err := other.a.LogoutAll(t.Context(), otherLogin.Principal, goodPassword); !errors.Is(err, boom) {
		t.Fatalf("LogoutAll = %v, want the failure of the store", err)
	}
}

type beforeTxStore struct {
	store.Store
	before func()
	once   sync.Once
}

func (s *beforeTxStore) InTx(ctx context.Context, fn func(ctx context.Context, tx store.Repositories) error) error {
	s.once.Do(s.before)
	return s.Store.InTx(ctx, fn)
}

func TestAPasswordThatChangedMeanwhileIsNotOverwritten(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	winner, err := f.a.hasher.Hash(t.Context(), "the winner password 42")
	if err != nil {
		t.Fatal(err)
	}
	f.a.store = &beforeTxStore{Store: f.a.store, before: func() {
		f.change(t, func(u *store.User) { u.PasswordHash = winner })
	}}
	if _, err = f.a.ChangePassword(t.Context(), login.Principal, goodPassword, newPassword); err != ErrInvalidCredentials { //nolint:errorlint
		t.Fatalf("ChangePassword = %v, want ErrInvalidCredentials: the password it checked is not the current one any more", err)
	}
	if !f.canSignInWith(t, "the winner password 42") || f.canSignInWith(t, newPassword) {
		t.Fatal("the change that came first must stand")
	}
	if !f.works(t, login) {
		t.Fatal("a refused change must end no session")
	}
}
