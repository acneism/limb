package storetest

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

var sessionBase = time.Date(2026, 5, 6, 7, 8, 9, 123456789, time.UTC)

func hashOf(label string, n int) []byte {
	sum := sha256.Sum256(fmt.Appendf(nil, "storetest %s %d", label, n))
	return sum[:]
}

func newCookieSession(tenant, sessionID, userID string, n int) store.Session {
	return store.Session{
		TenantID:   tenant,
		ID:         sessionID,
		Kind:       store.SessionCookie,
		SecretHash: hashOf("cookie", n),
		UserID:     userID,
		IP:         "203.0.113.7",
		UserAgent:  "storetest/1.0",
		CreatedAt:  sessionBase,
		LastSeenAt: sessionBase.Add(time.Minute),
		ExpiresAt:  sessionBase.Add(30 * 24 * time.Hour),
	}
}

func newTokenSession(tenant, sessionID, userID string) store.Session {
	s := newCookieSession(tenant, sessionID, userID, 0)
	s.Kind = store.SessionToken
	s.SecretHash = nil
	return s
}

func mustCreateSession(t *testing.T, s store.Store, sess store.Session) {
	t.Helper()
	if err := s.Sessions().Create(t.Context(), sess); err != nil {
		t.Fatalf("Create(session %s) failed: %v", sess.ID, err)
	}
}

func checkSession(t *testing.T, got, want store.Session) {
	t.Helper()
	switch {
	case got.TenantID != want.TenantID, got.ID != want.ID, got.Kind != want.Kind, got.UserID != want.UserID,
		got.IP != want.IP, got.UserAgent != want.UserAgent, !bytes.Equal(got.SecretHash, want.SecretHash):
		t.Fatalf("session differs:\n got %+v\nwant %+v", got, want)
	case !sameTime(got.CreatedAt, want.CreatedAt), !sameTime(got.LastSeenAt, want.LastSeenAt),
		!sameTime(got.ExpiresAt, want.ExpiresAt), !sameTime(got.RevokedAt, want.RevokedAt):
		t.Fatalf("session times differ, they must be UTC with microsecond precision:\n got %+v\nwant %+v", got, want)
	}
}

func testSessionLifecycle(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	cookie := newCookieSession(tenantA, id(10), id(1), 1)
	token := newTokenSession(tenantA, id(11), id(1))
	token.IP, token.UserAgent = "", ""
	mustCreateSession(t, s, cookie)
	mustCreateSession(t, s, token)

	byID, err := s.Sessions().ResolveByID(ctx, tenantA, cookie.ID)
	if err != nil {
		t.Fatalf("ResolveByID failed: %v", err)
	}
	checkSession(t, byID.Session, cookie)
	want := store.UserState{Status: store.StatusActive}
	if byID.User != want {
		t.Fatalf("user state = %+v, want %+v", byID.User, want)
	}
	bySecret, err := s.Sessions().ResolveBySecret(ctx, tenantA, cookie.SecretHash)
	if err != nil {
		t.Fatalf("ResolveBySecret failed: %v", err)
	}
	checkSession(t, bySecret.Session, cookie)

	gotToken, err := s.Sessions().ResolveByID(ctx, tenantA, token.ID)
	if err != nil {
		t.Fatalf("ResolveByID of a token session failed: %v", err)
	}
	checkSession(t, gotToken.Session, token)
	if len(gotToken.Session.SecretHash) != 0 {
		t.Fatalf("a token session must have no secret hash, got %x", gotToken.Session.SecretHash)
	}
}

func testSessionTimes(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	local := time.FixedZone("UTC+7", 7*3600)
	sess := newCookieSession(tenantA, id(10), id(1), 1)
	sess.CreatedAt = time.Date(2026, 5, 6, 14, 8, 9, 123456789, local)
	sess.LastSeenAt = time.Date(2026, 5, 6, 14, 9, 9, 999999999, local)
	sess.ExpiresAt = time.Date(2026, 6, 6, 14, 8, 9, 5000, local)
	mustCreateSession(t, s, sess)
	got, err := s.Sessions().ResolveByID(ctx, tenantA, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	checkSession(t, got.Session, sess)
	if got.Session.CreatedAt.Nanosecond() != 123456000 || got.Session.LastSeenAt.Nanosecond() != 999999000 {
		t.Fatalf("times must be truncated to microseconds: %+v", got.Session)
	}
	if err = s.Sessions().Revoke(ctx, tenantA, id(1), sess.ID, time.Date(2026, 5, 7, 1, 2, 3, 456789999, local)); err != nil {
		t.Fatal(err)
	}
	got, err = s.Sessions().ResolveByID(ctx, tenantA, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !sameTime(got.Session.RevokedAt, time.Date(2026, 5, 6, 18, 2, 3, 456789000, time.UTC)) {
		t.Fatalf("RevokedAt = %v, want UTC with microseconds", got.Session.RevokedAt)
	}
}

func testSessionConflictsAndMissingUsers(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	mustCreate(t, s, newUser(tenantB, id(1)))
	first := newCookieSession(tenantA, id(10), id(1), 1)
	mustCreateSession(t, s, first)

	if err := s.Sessions().Create(ctx, first); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Create of the same session = %v, want ErrConflict", err)
	}
	sameID := newCookieSession(tenantA, id(10), id(1), 2)
	if err := s.Sessions().Create(ctx, sameID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Create with a taken ID = %v, want ErrConflict", err)
	}
	sameSecret := newCookieSession(tenantA, id(11), id(1), 1)
	if err := s.Sessions().Create(ctx, sameSecret); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Create with a taken secret = %v, want ErrConflict", err)
	}
	otherTenantSameSecret := newCookieSession(tenantB, id(12), id(1), 1)
	if err := s.Sessions().Create(ctx, otherTenantSameSecret); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a secret hash is unique across tenants, Create = %v, want ErrConflict", err)
	}
	if _, err := s.Sessions().ResolveByID(ctx, tenantA, id(11)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a rejected session must not be stored, ResolveByID = %v", err)
	}
	noUser := newCookieSession(tenantA, id(13), id(99), 3)
	if err := s.Sessions().Create(ctx, noUser); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Create for a missing user = %v, want ErrNotFound", err)
	}
	foreignUser := newCookieSession(tenantA, id(14), id(1), 4)
	foreignUser.TenantID = "third"
	if err := s.Sessions().Create(ctx, foreignUser); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Create for a user of no such tenant = %v, want ErrNotFound", err)
	}
	two := newTokenSession(tenantA, id(15), id(1))
	three := newTokenSession(tenantA, id(16), id(1))
	mustCreateSession(t, s, two)
	mustCreateSession(t, s, three)
}

func testSessionInvalidRecords(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	valid := newCookieSession(tenantA, id(10), id(1), 1)
	edits := map[string]func(*store.Session){
		"no tenant":             func(x *store.Session) { x.TenantID = "" },
		"no id":                 func(x *store.Session) { x.ID = "" },
		"no user":               func(x *store.Session) { x.UserID = "" },
		"unknown kind":          func(x *store.Session) { x.Kind = "other" },
		"cookie without secret": func(x *store.Session) { x.SecretHash = nil },
		"short secret":          func(x *store.Session) { x.SecretHash = x.SecretHash[:31] },
		"token with a secret":   func(x *store.Session) { x.Kind = store.SessionToken },
		"NUL byte in the agent": func(x *store.Session) { x.UserAgent = "a\x00b" },
		"invalid UTF-8":         func(x *store.Session) { x.IP = "\xff" },
		"long agent":            func(x *store.Session) { x.UserAgent = strings.Repeat("a", store.MaxUserAgentLength+1) },
		"long address":          func(x *store.Session) { x.IP = strings.Repeat("1", store.MaxIPLength+1) },
		"no creation time":      func(x *store.Session) { x.CreatedAt = time.Time{} },
		"no last seen time":     func(x *store.Session) { x.LastSeenAt = time.Time{} },
		"no expiry":             func(x *store.Session) { x.ExpiresAt = time.Time{} },
		"revoked":               func(x *store.Session) { x.RevokedAt = sessionBase },
	}
	for name, edit := range edits {
		sess := valid
		sess.SecretHash = bytes.Clone(valid.SecretHash)
		edit(&sess)
		if err := s.Sessions().Create(ctx, sess); err == nil || isDomainError(err) {
			t.Errorf("Create with %s = %v, want a validation error", name, err)
		}
	}
	longest := newCookieSession(tenantA, id(11), id(1), 2)
	longest.UserAgent = strings.Repeat("a", store.MaxUserAgentLength)
	longest.IP = strings.Repeat("1", store.MaxIPLength)
	mustCreateSession(t, s, longest)
	if _, err := s.Sessions().ResolveByID(ctx, tenantA, id(10)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a rejected session must not be stored, ResolveByID = %v", err)
	}
	if err := s.Sessions().Touch(ctx, tenantA, id(11), time.Time{}); err == nil || isDomainError(err) {
		t.Errorf("Touch without a time = %v, want a validation error", err)
	}
	if err := s.Sessions().Revoke(ctx, tenantA, id(1), id(11), time.Time{}); err == nil || isDomainError(err) {
		t.Errorf("Revoke without a time = %v, want a validation error", err)
	}
	if _, err := s.Sessions().RevokeAllForUser(ctx, tenantA, id(1), "", time.Time{}); err == nil || isDomainError(err) {
		t.Errorf("RevokeAllForUser without a time = %v, want a validation error", err)
	}
}

func testSessionLookups(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	sess := newCookieSession(tenantA, id(10), id(1), 1)
	mustCreateSession(t, s, sess)

	notFound := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s = %v, want ErrNotFound", name, err)
		}
	}
	_, err := s.Sessions().ResolveByID(ctx, tenantA, id(99))
	notFound("ResolveByID of a missing session", err)
	_, err = s.Sessions().ResolveByID(ctx, tenantB, sess.ID)
	notFound("ResolveByID in another tenant", err)
	_, err = s.Sessions().ResolveByID(ctx, tenantA, "a\x00b")
	notFound("ResolveByID with a NUL byte", err)
	_, err = s.Sessions().ResolveByID(ctx, tenantA, "\xff")
	notFound("ResolveByID with invalid UTF-8", err)
	_, err = s.Sessions().ResolveByID(ctx, tenantA, "")
	notFound("ResolveByID with an empty ID", err)
	_, err = s.Sessions().ResolveBySecret(ctx, tenantA, hashOf("cookie", 99))
	notFound("ResolveBySecret of an unknown secret", err)
	_, err = s.Sessions().ResolveBySecret(ctx, tenantB, sess.SecretHash)
	notFound("ResolveBySecret in another tenant", err)
	_, err = s.Sessions().ResolveBySecret(ctx, tenantA, nil)
	notFound("ResolveBySecret without a hash", err)
	_, err = s.Sessions().ResolveBySecret(ctx, tenantA, sess.SecretHash[:31])
	notFound("ResolveBySecret with a short hash", err)
	_, err = s.Sessions().ResolveBySecret(ctx, "a\x00", sess.SecretHash)
	notFound("ResolveBySecret with a NUL byte in the tenant", err)
	notFound("Revoke of a missing session", s.Sessions().Revoke(ctx, tenantA, id(1), id(99), sessionBase))
	notFound("Revoke with a NUL byte", s.Sessions().Revoke(ctx, tenantA, id(1), "a\x00", sessionBase))
	if err = s.Sessions().Touch(ctx, tenantA, id(99), sessionBase); err != nil {
		t.Errorf("Touch of a missing session = %v, want nil", err)
	}
	if err = s.Sessions().Touch(ctx, tenantA, "a\x00", sessionBase); err != nil {
		t.Errorf("Touch with a NUL byte = %v, want nil", err)
	}
	if list, listErr := s.Sessions().ListByUser(ctx, tenantA, "a\x00", sessionBase); listErr != nil || len(list) != 0 {
		t.Errorf("ListByUser with a NUL byte = %v, %v; want an empty list", list, listErr)
	}
}

func testSessionResolveShowsTheUser(t *testing.T, s store.Store) {
	ctx := t.Context()
	user := mustCreate(t, s, newUser(tenantA, id(1)))
	sess := newCookieSession(tenantA, id(10), id(1), 1)
	mustCreateSession(t, s, sess)

	until := sessionBase.Add(48 * time.Hour)
	user.Status = store.StatusBlocked
	user.BlockedUntil = until
	user.MustChangePassword = true
	if _, err := s.Users().Update(ctx, user); err != nil {
		t.Fatal(err)
	}
	for name, resolve := range map[string]func() (store.ResolvedSession, error){
		"by ID": func() (store.ResolvedSession, error) { return s.Sessions().ResolveByID(ctx, tenantA, sess.ID) },
		"by secret": func() (store.ResolvedSession, error) {
			return s.Sessions().ResolveBySecret(ctx, tenantA, sess.SecretHash)
		},
	} {
		got, err := resolve()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.User.Status != store.StatusBlocked || !got.User.MustChangePassword || !sameTime(got.User.BlockedUntil, until) {
			t.Fatalf("%s: user state = %+v, want blocked until %v and a password change", name, got.User, until)
		}
	}
	user, err := s.Users().Get(ctx, tenantA, id(1))
	if err != nil {
		t.Fatal(err)
	}
	user.Status = store.StatusDeleted
	user.BlockedUntil = time.Time{}
	user.MustChangePassword = false
	if _, err = s.Users().Update(ctx, user); err != nil {
		t.Fatal(err)
	}
	got, err := s.Sessions().ResolveByID(ctx, tenantA, sess.ID)
	if err != nil || got.User.Status != store.StatusDeleted || got.User.MustChangePassword || !got.User.BlockedUntil.IsZero() {
		t.Fatalf("user state = %+v, %v; want a deleted user with no block", got.User, err)
	}
}

func testSessionTouch(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	sess := newCookieSession(tenantA, id(10), id(1), 1)
	mustCreateSession(t, s, sess)

	lastSeen := func() time.Time {
		t.Helper()
		got, err := s.Sessions().ResolveByID(ctx, tenantA, sess.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got.Session.LastSeenAt
	}
	later := sess.LastSeenAt.Add(5 * time.Minute)
	if err := s.Sessions().Touch(ctx, tenantA, sess.ID, later); err != nil {
		t.Fatal(err)
	}
	if got := lastSeen(); !sameTime(got, later) {
		t.Fatalf("LastSeenAt = %v, want %v", got, later)
	}
	if err := s.Sessions().Touch(ctx, tenantA, sess.ID, sess.LastSeenAt); err != nil {
		t.Fatal(err)
	}
	if got := lastSeen(); !sameTime(got, later) {
		t.Fatalf("Touch must not move LastSeenAt back: got %v, want %v", got, later)
	}
	if err := s.Sessions().Touch(ctx, tenantB, sess.ID, later.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := lastSeen(); !sameTime(got, later) {
		t.Fatalf("Touch in another tenant changed the session: %v", got)
	}
}

func testSessionRevoke(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	mustCreate(t, s, newUser(tenantA, id(2)))
	sess := newCookieSession(tenantA, id(10), id(1), 1)
	mustCreateSession(t, s, sess)
	at := sessionBase.Add(time.Hour)

	if err := s.Sessions().Revoke(ctx, tenantA, id(2), sess.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Revoke of the session of another user = %v, want ErrNotFound", err)
	}
	if err := s.Sessions().Revoke(ctx, tenantB, id(1), sess.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Revoke in another tenant = %v, want ErrNotFound", err)
	}
	if got, err := s.Sessions().ResolveByID(ctx, tenantA, sess.ID); err != nil || !got.Session.RevokedAt.IsZero() {
		t.Fatalf("a refused Revoke changed the session: %+v, %v", got.Session, err)
	}
	if err := s.Sessions().Revoke(ctx, tenantA, id(1), sess.ID, at); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	got, err := s.Sessions().ResolveByID(ctx, tenantA, sess.ID)
	if err != nil || !sameTime(got.Session.RevokedAt, at) {
		t.Fatalf("a revoked session must still resolve with RevokedAt %v: %+v, %v", at, got.Session, err)
	}
	if _, err = s.Sessions().ResolveBySecret(ctx, tenantA, sess.SecretHash); err != nil {
		t.Fatalf("a revoked session must still resolve by its secret: %v", err)
	}
	if err = s.Sessions().Revoke(ctx, tenantA, id(1), sess.ID, at.Add(time.Hour)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Revoke of a revoked session = %v, want ErrNotFound", err)
	}
	again, err := s.Sessions().ResolveByID(ctx, tenantA, sess.ID)
	if err != nil || !sameTime(again.Session.RevokedAt, at) {
		t.Fatalf("a second Revoke must keep the first time %v: %+v, %v", at, again.Session, err)
	}
}

func testSessionRevokeAll(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	mustCreate(t, s, newUser(tenantA, id(2)))
	mustCreate(t, s, newUser(tenantB, id(1)))
	for n := range 4 {
		mustCreateSession(t, s, newCookieSession(tenantA, id(10+n), id(1), 10+n))
	}
	mustCreateSession(t, s, newTokenSession(tenantA, id(20), id(1)))
	mustCreateSession(t, s, newCookieSession(tenantA, id(30), id(2), 30))
	mustCreateSession(t, s, newCookieSession(tenantB, id(40), id(1), 40))
	at := sessionBase.Add(time.Hour)
	if err := s.Sessions().Revoke(ctx, tenantA, id(1), id(13), at.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	revokedAt := func(tenant, session string) time.Time {
		t.Helper()
		got, err := s.Sessions().ResolveByID(ctx, tenant, session)
		if err != nil {
			t.Fatal(err)
		}
		return got.Session.RevokedAt
	}
	count, err := s.Sessions().RevokeAllForUser(ctx, tenantA, id(1), id(11), at)
	if err != nil || count != 3 {
		t.Fatalf("RevokeAllForUser = %d, %v; want 3: the user has 5 live sessions and one is kept", count, err)
	}
	if !revokedAt(tenantA, id(11)).IsZero() {
		t.Fatal("RevokeAllForUser ended the session it was told to keep")
	}
	for _, session := range []string{id(10), id(12), id(20)} {
		if got := revokedAt(tenantA, session); !sameTime(got, at) {
			t.Fatalf("session %s: RevokedAt = %v, want %v", session, got, at)
		}
	}
	if got := revokedAt(tenantA, id(13)); !sameTime(got, at.Add(-time.Minute)) {
		t.Fatalf("an already revoked session keeps its time, got %v", got)
	}
	if !revokedAt(tenantA, id(30)).IsZero() || !revokedAt(tenantB, id(40)).IsZero() {
		t.Fatal("RevokeAllForUser touched the sessions of another user or tenant")
	}

	count, err = s.Sessions().RevokeAllForUser(ctx, tenantA, id(1), "", at.Add(time.Hour))
	if err != nil || count != 1 {
		t.Fatalf("RevokeAllForUser without an exception = %d, %v; want the one remaining session", count, err)
	}
	if count, err = s.Sessions().RevokeAllForUser(ctx, tenantA, id(1), "", at.Add(2*time.Hour)); err != nil || count != 0 {
		t.Fatalf("RevokeAllForUser with nothing left = %d, %v; want 0", count, err)
	}
	if count, err = s.Sessions().RevokeAllForUser(ctx, tenantA, id(77), id(11), at); err != nil || count != 0 {
		t.Fatalf("RevokeAllForUser of an unknown user = %d, %v; want 0", count, err)
	}
}

func testSessionList(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	mustCreate(t, s, newUser(tenantA, id(2)))
	now := sessionBase.Add(24 * time.Hour)
	mk := func(session string, n int, created time.Time, expires time.Time) store.Session {
		sess := newCookieSession(tenantA, session, id(1), n)
		sess.CreatedAt = created
		sess.LastSeenAt = created
		sess.ExpiresAt = expires
		mustCreateSession(t, s, sess)
		return sess
	}
	late := mk(id(14), 4, sessionBase.Add(3*time.Hour), now.Add(time.Hour))
	tieHigh := mk("b-"+id(12), 2, sessionBase.Add(time.Hour), now.Add(time.Hour))
	tieLow := mk("A-"+id(11), 1, sessionBase.Add(time.Hour), now.Add(time.Hour))
	first := mk(id(10), 5, sessionBase, now.Add(time.Hour))
	mk(id(15), 6, sessionBase, now)
	mk(id(16), 7, sessionBase, now.Add(-time.Second))
	revoked := mk(id(17), 8, sessionBase.Add(time.Minute), now.Add(time.Hour))
	if err := s.Sessions().Revoke(ctx, tenantA, id(1), revoked.ID, now); err != nil {
		t.Fatal(err)
	}
	other := newCookieSession(tenantA, id(20), id(2), 9)
	other.ExpiresAt = now.Add(time.Hour)
	mustCreateSession(t, s, other)

	list, err := s.Sessions().ListByUser(ctx, tenantA, id(1), now)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, sess := range list {
		ids = append(ids, sess.ID)
	}
	want := []string{first.ID, tieLow.ID, tieHigh.ID, late.ID}
	if !slices.Equal(ids, want) {
		t.Fatalf("ListByUser = %v, want %v: live sessions by creation time and then by ID in byte order", ids, want)
	}
	checkSession(t, list[0], first)
	if list, err = s.Sessions().ListByUser(ctx, tenantB, id(1), now); err != nil || len(list) != 0 {
		t.Fatalf("ListByUser in another tenant = %v, %v; want an empty list", list, err)
	}
	if list, err = s.Sessions().ListByUser(ctx, tenantA, id(3), now); err != nil || len(list) != 0 {
		t.Fatalf("ListByUser of an unknown user = %v, %v; want an empty list", list, err)
	}
}

func testSessionDeleteInactive(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	mustCreate(t, s, newUser(tenantB, id(1)))
	now := sessionBase.Add(100 * 24 * time.Hour)
	mk := func(tenant, session string, n int, seen, expires time.Time) store.Session {
		sess := newCookieSession(tenant, session, id(1), n)
		sess.CreatedAt = sessionBase
		sess.LastSeenAt = seen
		sess.ExpiresAt = expires
		mustCreateSession(t, s, sess)
		return sess
	}
	live := mk(tenantA, id(10), 1, now.Add(-time.Hour), now.Add(time.Hour))
	expired := mk(tenantA, id(11), 2, now.Add(-time.Hour), now.Add(-48*time.Hour))
	idle := mk(tenantA, id(12), 3, now.Add(-10*24*time.Hour), now.Add(time.Hour))
	revokedOld := mk(tenantA, id(13), 4, now.Add(-time.Hour), now.Add(time.Hour))
	revokedNew := mk(tenantA, id(14), 5, now.Add(-time.Hour), now.Add(time.Hour))
	otherTenant := mk(tenantB, id(15), 6, now.Add(-10*24*time.Hour), now.Add(-48*time.Hour))
	if err := s.Sessions().Revoke(ctx, tenantA, id(1), revokedOld.ID, now.Add(-72*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Sessions().Revoke(ctx, tenantA, id(1), revokedNew.ID, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	mustAddToken(t, s, tenantA, expired.ID, 1, now.Add(time.Hour))

	removed, err := s.Sessions().DeleteInactive(ctx, tenantA, now.Add(-24*time.Hour), now.Add(-7*24*time.Hour), now.Add(-24*time.Hour))
	if err != nil || removed != 3 {
		t.Fatalf("DeleteInactive = %d, %v; want 3: one expired, one idle, one revoked long ago", removed, err)
	}
	for _, kept := range []store.Session{live, revokedNew, otherTenant} {
		if _, err = s.Sessions().ResolveByID(ctx, kept.TenantID, kept.ID); err != nil {
			t.Fatalf("DeleteInactive removed session %s that must stay: %v", kept.ID, err)
		}
	}
	for _, gone := range []store.Session{expired, idle, revokedOld} {
		if _, err = s.Sessions().ResolveByID(ctx, gone.TenantID, gone.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("session %s must be removed, ResolveByID = %v", gone.ID, err)
		}
	}
	if _, err = s.RefreshTokens().Use(ctx, tenantA, hashOf("refresh", 1), now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the refresh tokens of a removed session must go with it, Use = %v", err)
	}
	if removed, err = s.Sessions().DeleteInactive(ctx, tenantA, time.Time{}, time.Time{}, time.Time{}); err != nil || removed != 0 {
		t.Fatalf("DeleteInactive with zero times = %d, %v; want 0", removed, err)
	}
	if removed, err = s.Sessions().DeleteInactive(ctx, "a\x00", now, now, now); err != nil || removed != 0 {
		t.Fatalf("DeleteInactive with a NUL byte = %d, %v; want 0", removed, err)
	}
}

func testSessionsFollowTheUser(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	mustCreate(t, s, newUser(tenantA, id(2)))
	mustCreateSession(t, s, newCookieSession(tenantA, id(10), id(1), 1))
	mustCreateSession(t, s, newTokenSession(tenantA, id(11), id(1)))
	mustCreateSession(t, s, newCookieSession(tenantA, id(12), id(2), 2))
	mustAddToken(t, s, tenantA, id(11), 1, sessionBase.Add(time.Hour))
	mustAddToken(t, s, tenantA, id(12), 2, sessionBase.Add(time.Hour))

	if err := s.Users().Delete(ctx, tenantA, id(1)); err != nil {
		t.Fatal(err)
	}
	for _, session := range []string{id(10), id(11)} {
		if _, err := s.Sessions().ResolveByID(ctx, tenantA, session); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("session %s must go with its user, ResolveByID = %v", session, err)
		}
	}
	if _, err := s.Sessions().ResolveBySecret(ctx, tenantA, hashOf("cookie", 1)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a deleted session must not resolve by its secret: %v", err)
	}
	if _, err := s.RefreshTokens().Use(ctx, tenantA, hashOf("refresh", 1), sessionBase); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the refresh token of a removed session must go with it, Use = %v", err)
	}
	if _, err := s.Sessions().ResolveByID(ctx, tenantA, id(12)); err != nil {
		t.Fatalf("the session of another user was removed: %v", err)
	}
	if use, err := s.RefreshTokens().Use(ctx, tenantA, hashOf("refresh", 2), sessionBase); err != nil || use.Reused {
		t.Fatalf("the refresh token of another user was affected: %+v, %v", use, err)
	}
	mustCreate(t, s, newUser(tenantA, id(1)))
	mustCreateSession(t, s, newCookieSession(tenantA, id(13), id(1), 1))
}

func testSessionTenantIsolation(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	mustCreate(t, s, newUser(tenantB, id(1)))
	mustCreateSession(t, s, newCookieSession(tenantA, id(10), id(1), 1))
	mustCreateSession(t, s, newCookieSession(tenantB, id(10), id(1), 2))
	for tenant, n := range map[string]int{tenantA: 1, tenantB: 2} {
		got, err := s.Sessions().ResolveByID(ctx, tenant, id(10))
		if err != nil || got.Session.TenantID != tenant || !bytes.Equal(got.Session.SecretHash, hashOf("cookie", n)) {
			t.Fatalf("tenant %s: ResolveByID = %+v, %v", tenant, got.Session, err)
		}
	}
	if err := s.Sessions().Revoke(ctx, tenantA, id(1), id(10), sessionBase); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Sessions().ResolveByID(ctx, tenantB, id(10)); err != nil || !got.Session.RevokedAt.IsZero() {
		t.Fatalf("Revoke in one tenant changed the other: %+v, %v", got.Session, err)
	}
	if count, err := s.Sessions().RevokeAllForUser(ctx, tenantA, id(1), "", sessionBase.Add(time.Hour)); err != nil || count != 0 {
		t.Fatalf("RevokeAllForUser = %d, %v; the only session of tenant A was revoked already", count, err)
	}
	if got, err := s.Sessions().ResolveByID(ctx, tenantB, id(10)); err != nil || !got.Session.RevokedAt.IsZero() {
		t.Fatalf("RevokeAllForUser in one tenant changed the other: %+v, %v", got.Session, err)
	}
}

func testConcurrentSessionCreate(t *testing.T, s store.Store) {
	ctx := t.Context()
	const racers = 8
	for n := range racers {
		mustCreate(t, s, newUser(tenantA, id(n+1)))
	}
	var wins, conflicts atomic.Int32
	parallel(racers, func(i int) {
		err := s.Sessions().Create(ctx, newCookieSession(tenantA, id(100+i), id(i+1), 1))
		switch {
		case err == nil:
			wins.Add(1)
		case errors.Is(err, store.ErrConflict):
			conflicts.Add(1)
		default:
			t.Errorf("racer %d: unexpected error %v", i, err)
		}
	})
	if wins.Load() != 1 || conflicts.Load() != racers-1 {
		t.Fatalf("%d creations succeeded and %d conflicted; want exactly 1 and %d, the secret is unique", wins.Load(), conflicts.Load(), racers-1)
	}
}

func testSessionReturnedSlicesAreCopies(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	sess := newCookieSession(tenantA, id(10), id(1), 1)
	given := bytes.Clone(sess.SecretHash)
	mustCreateSession(t, s, sess)
	sess.SecretHash[0] ^= 0xff
	got, err := s.Sessions().ResolveByID(ctx, tenantA, id(10))
	if err != nil || !bytes.Equal(got.Session.SecretHash, given) {
		t.Fatalf("the store kept the slice it was given: %x, %v", got.Session.SecretHash, err)
	}
	got.Session.SecretHash[0] ^= 0xff
	again, err := s.Sessions().ResolveBySecret(ctx, tenantA, given)
	if err != nil || !bytes.Equal(again.Session.SecretHash, given) {
		t.Fatalf("the store returned a slice it still uses: %x, %v", again.Session.SecretHash, err)
	}
}
