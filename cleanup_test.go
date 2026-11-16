package limb

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

type cleanupSetup struct {
	f   *sessionFixture
	now time.Time
}

func newCleanupSetup(t *testing.T, opts ...Option) *cleanupSetup {
	t.Helper()
	f := newSessionFixture(t, append([]Option{WithSessionTTL(10*24*time.Hour, 2*24*time.Hour)}, opts...)...)
	return &cleanupSetup{f: f, now: f.clock.now().UTC().Truncate(time.Microsecond)}
}

func (c *cleanupSetup) session(t *testing.T, id string, mutate func(*store.Session)) {
	t.Helper()
	s := store.Session{
		TenantID: c.f.a.tenant, ID: id, Kind: store.SessionToken, UserID: string(c.f.user.ID),
		CreatedAt: c.now.Add(-20 * 24 * time.Hour), LastSeenAt: c.now.Add(-time.Hour), ExpiresAt: c.now.Add(10 * 24 * time.Hour),
	}
	mutate(&s)
	revoked := s.RevokedAt
	s.RevokedAt = time.Time{}
	if err := c.f.a.store.Sessions().Create(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	if !revoked.IsZero() {
		if err := c.f.a.store.Sessions().Revoke(t.Context(), s.TenantID, s.UserID, s.ID, revoked); err != nil {
			t.Fatal(err)
		}
	}
}

func (c *cleanupSetup) exists(t *testing.T, id string) bool {
	t.Helper()
	return c.f.sessionExists(t, id)
}

func (c *cleanupSetup) token(t *testing.T, session string, label uint16, expires time.Time) []byte {
	t.Helper()
	hash := hashFor(label)
	err := c.f.a.store.RefreshTokens().Add(t.Context(), store.RefreshToken{
		TenantID: c.f.a.tenant, Hash: hash, SessionID: session, ExpiresAt: expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func hashFor(label uint16) []byte {
	hash := make([]byte, store.SecretHashLength)
	binary.BigEndian.PutUint16(hash, label)
	return hash
}

func (c *cleanupSetup) tokenExists(t *testing.T, hash []byte) bool {
	t.Helper()
	_, err := c.f.a.store.RefreshTokens().Use(t.Context(), c.f.a.tenant, hash, c.now)
	switch {
	case err == nil:
		return true
	case errors.Is(err, store.ErrNotFound):
		return false
	}
	t.Fatal(err)
	return false
}

func sid(n int) string {
	return fmt.Sprintf("00000000-0000-7000-8000-%012d", 4000+n)
}

func TestCleanupRemovesOnlyWhatIsOldEnough(t *testing.T) {
	c := newCleanupSetup(t)
	day := 24 * time.Hour
	now := c.now
	c.session(t, sid(1), func(*store.Session) {})
	c.session(t, sid(2), func(s *store.Session) { s.ExpiresAt = now.Add(-6 * day) })
	c.session(t, sid(3), func(s *store.Session) { s.ExpiresAt = now.Add(-8 * day) })
	c.session(t, sid(4), func(s *store.Session) { s.LastSeenAt = now.Add(-8 * day) })
	c.session(t, sid(5), func(s *store.Session) { s.LastSeenAt = now.Add(-10 * day) })
	c.session(t, sid(6), func(s *store.Session) { s.RevokedAt = now.Add(-6 * day) })
	c.session(t, sid(7), func(s *store.Session) { s.RevokedAt = now.Add(-8 * day) })
	c.session(t, sid(8), func(s *store.Session) { s.ExpiresAt = now.Add(-7 * day) })

	tokens := map[string][]byte{
		"a token of a live session that expired long ago":    c.token(t, sid(1), 1, now.Add(-25*time.Hour)),
		"a token of a live session that expires at the edge": c.token(t, sid(1), 2, now.Add(-24*time.Hour)),
		"a token of a live session that is valid":            c.token(t, sid(1), 3, now.Add(time.Hour)),
		"a token of a removed session":                       c.token(t, sid(3), 4, now.Add(time.Hour)),
	}
	wantTokens := map[string]bool{
		"a token of a live session that expired long ago":    false,
		"a token of a live session that expires at the edge": true,
		"a token of a live session that is valid":            true,
		"a token of a removed session":                       false,
	}

	if err := c.f.a.Cleanup(t.Context()); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
	wantSessions := map[int]bool{1: true, 2: true, 3: false, 4: true, 5: false, 6: true, 7: false, 8: true}
	for n, want := range wantSessions {
		if got := c.exists(t, sid(n)); got != want {
			t.Errorf("session %d: present = %v, want %v", n, got, want)
		}
	}
	for name, hash := range tokens {
		if got := c.tokenExists(t, hash); got != wantTokens[name] {
			t.Errorf("%s: present = %v, want %v", name, got, wantTokens[name])
		}
	}
	if err := c.f.a.Cleanup(t.Context()); err != nil {
		t.Fatalf("a second Cleanup failed: %v", err)
	}
	for n, want := range wantSessions {
		if got := c.exists(t, sid(n)); got != want {
			t.Errorf("after a second Cleanup, session %d: present = %v, want %v", n, got, want)
		}
	}
}

func TestCleanupRemovesCountersOnlyWhenTheirWindowsAreOver(t *testing.T) {
	c := newCleanupSetup(t)
	ctx, a, now := t.Context(), c.f.a, c.now
	hit := func(key string, at time.Time) {
		t.Helper()
		if _, err := a.store.Attempts().Hit(ctx, key, at, 15*time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	hit("old", now.Add(-3*time.Hour))
	hit("edge", now.Add(-75*time.Minute))
	hit("recent", now.Add(-10*time.Minute))
	hit("paused", now.Add(-3*time.Hour))
	hit("delayed", now.Add(-3*time.Hour))
	if err := a.store.Attempts().Hold(ctx, "paused", store.Hold{BlockedUntil: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := a.store.Attempts().Hold(ctx, "delayed", store.Hold{NextAllowedAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := a.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	left, err := a.store.Attempts().Get(ctx, "old", "edge", "recent", "paused", "delayed")
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, counter := range left {
		keys = append(keys, counter.Key)
	}
	got := strings.Join(sortedCopy(keys), ",")
	if got != "delayed,edge,paused,recent" {
		t.Fatalf("counters left = %s, want delayed,edge,paused,recent", got)
	}
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestCleanupKeepsCountersOfLongerWindows(t *testing.T) {
	c := newCleanupSetup(t, WithLoginLimits(LoginLimits{IP: Limit{Window: 6 * time.Hour}}))
	ctx, a := t.Context(), c.f.a
	if _, err := a.store.Attempts().Hit(ctx, "long", c.now.Add(-5*time.Hour), 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := a.store.Attempts().Hit(ctx, "too old", c.now.Add(-8*time.Hour), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := a.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	left, err := a.store.Attempts().Get(ctx, "long", "too old")
	if err != nil || len(left) != 1 || left[0].Key != "long" {
		t.Fatalf("counters left = %+v, %v; a counter that may still be inside its window must stay", left, err)
	}
}

func TestCleanupRemovesRetiredKeysOnly(t *testing.T) {
	c := newCleanupSetup(t)
	ctx, a, now := t.Context(), c.f.a, c.now
	for i, retire := range []time.Time{now.Add(-time.Hour), now.Add(time.Hour), {}} {
		key := store.SigningKey{
			KID: string(rune('a' + i)), Algorithm: "EdDSA", Generation: int64(i + 1), PrivateKey: []byte{1}, PublicKey: []byte{2},
			CreatedAt: now.Add(-100 * 24 * time.Hour),
		}
		if err := a.store.SigningKeys().Add(ctx, key); err != nil {
			t.Fatal(err)
		}
		if !retire.IsZero() {
			if err := a.store.SigningKeys().Retire(ctx, key.KID, retire); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := a.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	left, err := a.store.SigningKeys().List(ctx)
	if err != nil || len(left) != 2 || left[0].KID != "b" || left[1].KID != "c" {
		t.Fatalf("keys left = %+v, %v; only the retired one must go", left, err)
	}
}

func TestCleanupDoesNotTouchAnotherTenant(t *testing.T) {
	c := newCleanupSetup(t)
	ctx, a := t.Context(), c.f.a
	user := store.User{TenantID: otherTenant, ID: "00000000-0000-7000-8000-0000000000e1", Status: store.StatusActive, CreatedAt: c.now}
	if err := a.store.Users().Create(ctx, user); err != nil {
		t.Fatal(err)
	}
	old := store.Session{
		TenantID: otherTenant, ID: sid(9), Kind: store.SessionToken, UserID: user.ID,
		CreatedAt: c.now.Add(-100 * 24 * time.Hour), LastSeenAt: c.now.Add(-100 * 24 * time.Hour), ExpiresAt: c.now.Add(-50 * 24 * time.Hour),
	}
	if err := a.store.Sessions().Create(ctx, old); err != nil {
		t.Fatal(err)
	}
	hash := hashFor(77)
	if err := a.store.RefreshTokens().Add(ctx, store.RefreshToken{TenantID: otherTenant, Hash: hash, SessionID: old.ID, ExpiresAt: c.now.Add(-50 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := a.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := a.store.Sessions().ResolveByID(ctx, otherTenant, old.ID); err != nil {
		t.Fatalf("a session of another tenant was removed: %v", err)
	}
	if _, err := a.store.RefreshTokens().Use(ctx, otherTenant, hash, c.now); err != nil {
		t.Fatalf("a token of another tenant was removed: %v", err)
	}
}

type cleanupFailures struct {
	store.Store
	sessionsErr, tokensErr, attemptsErr, keysErr error
}

func (s cleanupFailures) Sessions() store.Sessions {
	return cleanupSessions{Sessions: s.Store.Sessions(), err: s.sessionsErr}
}

func (s cleanupFailures) RefreshTokens() store.RefreshTokens {
	return cleanupTokens{RefreshTokens: s.Store.RefreshTokens(), err: s.tokensErr}
}

func (s cleanupFailures) Attempts() store.Attempts {
	return cleanupAttempts{Attempts: s.Store.Attempts(), err: s.attemptsErr}
}

func (s cleanupFailures) SigningKeys() store.SigningKeys {
	return cleanupKeys{SigningKeys: s.Store.SigningKeys(), err: s.keysErr}
}

type cleanupSessions struct {
	store.Sessions
	err error
}

func (s cleanupSessions) DeleteInactive(ctx context.Context, tenantID string, a, b, c time.Time) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	return s.Sessions.DeleteInactive(ctx, tenantID, a, b, c)
}

type cleanupTokens struct {
	store.RefreshTokens
	err error
}

func (s cleanupTokens) DeleteExpired(ctx context.Context, tenantID string, before time.Time) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	return s.RefreshTokens.DeleteExpired(ctx, tenantID, before)
}

type cleanupAttempts struct {
	store.Attempts
	err error
}

func (s cleanupAttempts) DeleteStale(ctx context.Context, before time.Time) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	return s.Attempts.DeleteStale(ctx, before)
}

type cleanupKeys struct {
	store.SigningKeys
	err error
}

func (s cleanupKeys) DeleteRetired(ctx context.Context, before time.Time) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	return s.SigningKeys.DeleteRetired(ctx, before)
}

func TestAFailureOfOneKindOfDataDoesNotStopTheOthers(t *testing.T) {
	c := newCleanupSetup(t)
	ctx, a := t.Context(), c.f.a
	c.session(t, sid(1), func(s *store.Session) { s.ExpiresAt = c.now.Add(-30 * 24 * time.Hour) })
	c.session(t, sid(2), func(*store.Session) {})
	old := c.token(t, sid(2), 5, c.now.Add(-48*time.Hour))
	if _, err := a.store.Attempts().Hit(ctx, "old", c.now.Add(-5*time.Hour), time.Minute); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("database is down")
	healthy := a.store
	a.store = cleanupFailures{Store: healthy, sessionsErr: boom, keysErr: errors.New("keys are down")}
	err := a.Cleanup(ctx)
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "old sessions") || !strings.Contains(err.Error(), "old signing keys") ||
		strings.Contains(err.Error(), "refresh tokens") {
		t.Fatalf("Cleanup = %v, want the failures of sessions and keys, and only those", err)
	}
	a.store = healthy
	if c.tokenExists(t, old) {
		t.Fatal("the tokens must be removed although the sessions could not be")
	}
	if left, _ := a.store.Attempts().Get(ctx, "old"); len(left) != 0 {
		t.Fatal("the counters must be removed although the sessions could not be")
	}
	if !c.exists(t, sid(1)) {
		t.Fatal("the session whose removal failed must still be there")
	}
	for _, failing := range []cleanupFailures{{tokensErr: boom}, {attemptsErr: boom}} {
		failing.Store = healthy
		a.store = failing
		if err = a.Cleanup(ctx); !errors.Is(err, boom) {
			t.Fatalf("Cleanup = %v, want %v", err, boom)
		}
	}
	a.store = healthy
	if err = a.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup = %v", err)
	}
	if c.exists(t, sid(1)) {
		t.Fatal("the session must be removed once the store works")
	}
}

func TestCleanupReportsWhatItRemoved(t *testing.T) {
	logger, logs := capturingLogger()
	c := newCleanupSetup(t, WithLogger(logger))
	if err := c.f.a.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "old data") {
		t.Fatalf("nothing was removed and nothing must be logged:\n%s", logs.String())
	}
	c.session(t, sid(1), func(s *store.Session) { s.ExpiresAt = c.now.Add(-30 * 24 * time.Hour) })
	if err := c.f.a.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if text := logs.String(); !strings.Contains(text, "old data was removed") || !strings.Contains(text, "sessions=1") {
		t.Fatalf("the removal must be logged:\n%s", text)
	}
}
