package limb

import (
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func sessionIDs(list []Session) []string {
	ids := make([]string, 0, len(list))
	for _, s := range list {
		ids = append(ids, s.ID)
	}
	return ids
}

func TestSessionsListsTheSessionsInUse(t *testing.T) {
	f := newSessionFixture(t, WithSessionTTL(24*time.Hour, 2*time.Hour))
	first := f.login(t)
	f.clock.advance(time.Minute)
	c := f.credentials()
	c.IP, c.UserAgent = netip.MustParseAddr("198.51.100.4"), "Safari"
	second, err := f.a.Login(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}

	list, err := f.a.Sessions(t.Context(), second.Principal)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sessionIDs(list), []string{first.Principal.SessionID, second.Principal.SessionID}; !slices.Equal(got, want) {
		t.Fatalf("Sessions = %v, want %v, the oldest first", got, want)
	}
	older, newer := list[0], list[1]
	if older.Current || !newer.Current {
		t.Fatalf("Current = %v and %v, want only the session of the principal", older.Current, newer.Current)
	}
	if older.Kind != SessionCookie || older.IP != "203.0.113.7" || older.UserAgent != testAgent ||
		!older.CreatedAt.Equal(f.session(t, older.ID).Session.CreatedAt) || older.ExpiresAt.Sub(older.CreatedAt) != 24*time.Hour {
		t.Fatalf("session = %+v", older)
	}
	if newer.IP != "198.51.100.4" || newer.UserAgent != "Safari" || !newer.LastSeenAt.Equal(newer.CreatedAt) {
		t.Fatalf("session = %+v", newer)
	}
	if got, err := f.a.Sessions(t.Context(), first.Principal); err != nil || !got[0].Current || got[1].Current {
		t.Fatalf("Current must follow the principal: %+v, %v", got, err)
	}
}

func TestSessionsHidesEndedExpiredAndIdleSessions(t *testing.T) {
	f := newSessionFixture(t, WithSessionTTL(24*time.Hour, time.Hour))
	ended, idle, busy := f.login(t), f.login(t), f.login(t)
	if err := f.a.Logout(t.Context(), ended.Principal); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(time.Hour - time.Microsecond)
	if _, err := f.a.Authenticate(f.request(t, http.MethodGet, busy, nil)); err != nil {
		t.Fatal(err)
	}
	list, err := f.a.Sessions(t.Context(), busy.Principal)
	if err != nil || !slices.Equal(sessionIDs(list), []string{idle.Principal.SessionID, busy.Principal.SessionID}) {
		t.Fatalf("Sessions = %v, %v; want the idle one still shown a microsecond before the limit", sessionIDs(list), err)
	}
	f.clock.advance(time.Microsecond)
	list, err = f.a.Sessions(t.Context(), busy.Principal)
	if err != nil || !slices.Equal(sessionIDs(list), []string{busy.Principal.SessionID}) {
		t.Fatalf("Sessions = %v, %v; want only the session that is used: one that is idle for the idle lifetime is hidden", sessionIDs(list), err)
	}
	f.clock.advance(24 * time.Hour)
	if list, err = f.a.Sessions(t.Context(), busy.Principal); err != nil || len(list) != 0 {
		t.Fatalf("Sessions = %v, %v; want none after the absolute lifetime", sessionIDs(list), err)
	}
}

func TestSessionsDoesNotShowTheSessionsOfOthers(t *testing.T) {
	f := newSessionFixture(t)
	mine := f.login(t)
	other := mustRegister(t, f.a, map[string]string{"email": "olga@example.com"}, goodPassword)
	c := f.credentials()
	c.Login = "olga@example.com"
	theirs, err := f.a.Login(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	list, err := f.a.Sessions(t.Context(), mine.Principal)
	if err != nil || !slices.Equal(sessionIDs(list), []string{mine.Principal.SessionID}) {
		t.Fatalf("Sessions = %v, %v", sessionIDs(list), err)
	}
	if theirs.Principal.UserID != other.ID {
		t.Fatalf("test setup: %v", theirs.Principal)
	}
}

func TestSessionsReportsAStoreFailure(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	boom := errors.New("database is down")
	f.breakSessions(func(s *sessionsFault) { s.listErr = boom })
	if _, err := f.a.Sessions(t.Context(), login.Principal); !errors.Is(err, boom) {
		t.Fatalf("Sessions = %v, want %v", err, boom)
	}
}

func TestLogoutEndsOnlyTheSessionOfThePrincipal(t *testing.T) {
	f := newSessionFixture(t)
	first, second := f.login(t), f.login(t)
	if err := f.a.Logout(t.Context(), first.Principal); err != nil {
		t.Fatalf("Logout = %v", err)
	}
	if _, err := f.a.Authenticate(f.request(t, http.MethodGet, first, nil)); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("an ended session must not work: %v", err)
	}
	if _, err := f.a.Authenticate(f.request(t, http.MethodGet, second, nil)); err != nil {
		t.Fatalf("the other session must keep working: %v", err)
	}
	if got := f.session(t, first.Principal.SessionID).Session.RevokedAt; !got.Equal(f.clock.now().UTC().Truncate(time.Microsecond)) {
		t.Fatalf("RevokedAt = %v", got)
	}
	if err := f.a.Logout(t.Context(), first.Principal); err != nil {
		t.Fatalf("a second Logout = %v, ending an ended session is not an error", err)
	}
}

func TestLogoutCannotEndTheSessionOfAnotherUser(t *testing.T) {
	f := newSessionFixture(t)
	mine := f.login(t)
	stranger := mine.Principal
	stranger.UserID = "00000000-0000-7000-8000-000000000999"
	if err := f.a.Logout(t.Context(), stranger); err != nil {
		t.Fatalf("Logout = %v", err)
	}
	if _, err := f.a.Authenticate(f.request(t, http.MethodGet, mine, nil)); err != nil {
		t.Fatalf("the session was ended by someone who does not own it: %v", err)
	}
}

func TestLogoutReportsAStoreFailure(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	boom := errors.New("database is down")
	f.breakSessions(func(s *sessionsFault) { s.revokeErr = boom })
	if err := f.a.Logout(t.Context(), login.Principal); !errors.Is(err, boom) {
		t.Fatalf("Logout = %v, want %v", err, boom)
	}
}

func TestEndingASessionAlsoEndsItsHoldOnTheUserState(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	f.change(t, func(u *store.User) { u.Status = store.StatusBlocked })
	if _, err := f.a.Authenticate(f.request(t, http.MethodGet, login, nil)); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("a blocked user takes effect at once: %v", err)
	}
	if err := f.a.Logout(t.Context(), login.Principal); err != nil {
		t.Fatalf("a blocked user can still be logged out: %v", err)
	}
}
