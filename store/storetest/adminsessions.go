package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

var adminSessionBase = time.Date(2026, 11, 13, 14, 15, 16, 123456789, time.UTC)

func newAdminSession(tenant, sessionID, adminID string, n int) store.AdminSession {
	return store.AdminSession{
		TenantID:     tenant,
		ID:           sessionID,
		AdminID:      adminID,
		Stage:        store.AdminStageFull,
		SecretHash:   hashOf("admin-cookie", n),
		AdminVersion: 1,
		IP:           "203.0.113.9",
		UserAgent:    "Mozilla/5.0 (test)",
		CreatedAt:    adminSessionBase,
		LastSeenAt:   adminSessionBase.Add(time.Minute),
		ExpiresAt:    adminSessionBase.Add(12 * time.Hour),
	}
}

func mustCreateAdminSession(t *testing.T, s store.Store, a store.AdminSession) {
	t.Helper()
	if err := s.AdminSessions().Create(t.Context(), a); err != nil {
		t.Fatalf("Create(%s) failed: %v", a.ID, err)
	}
}

func resolveAdminSession(t *testing.T, s store.Store, tenant string, hash []byte) store.ResolvedAdminSession {
	t.Helper()
	resolved, err := s.AdminSessions().ResolveBySecret(t.Context(), tenant, hash)
	if err != nil {
		t.Fatalf("ResolveBySecret failed: %v", err)
	}
	return resolved
}

func checkAdminSession(t *testing.T, got, want store.AdminSession) {
	t.Helper()
	switch {
	case got.TenantID != want.TenantID, got.ID != want.ID, got.AdminID != want.AdminID, got.Stage != want.Stage,
		!bytes.Equal(got.SecretHash, want.SecretHash), got.AdminVersion != want.AdminVersion, got.Attempts != want.Attempts,
		got.IP != want.IP, got.UserAgent != want.UserAgent:
		t.Fatalf("admin session differs:\n got %+v\nwant %+v", got, want)
	case !sameTime(got.CreatedAt, want.CreatedAt), !sameTime(got.LastSeenAt, want.LastSeenAt), !sameTime(got.ExpiresAt, want.ExpiresAt):
		t.Fatalf("admin session times differ, they must be UTC with microsecond precision:\n got %+v\nwant %+v", got, want)
	}
}

func adminSessionIDs(list []store.AdminSession) []string {
	ids := make([]string, 0, len(list))
	for _, s := range list {
		ids = append(ids, s.ID)
	}
	return ids
}

func testAdminSessionLifecycle(t *testing.T, s store.Store) {
	ctx := t.Context()
	admin := mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	plus3 := time.FixedZone("UTC+3", 3*3600)
	want := newAdminSession(tenantA, id(10), id(1), 1)
	want.CreatedAt = want.CreatedAt.In(plus3)
	want.ExpiresAt = want.ExpiresAt.In(plus3)
	mustCreateAdminSession(t, s, want)
	resolved := resolveAdminSession(t, s, tenantA, want.SecretHash)
	checkAdminSession(t, resolved.Session, want)
	if state := resolved.Admin; state.Login != "root" || state.Status != store.AdminActive || state.Version != 1 || state.TOTPConfirmed {
		t.Fatalf("the state of the administrator = %+v", state)
	}

	changed := admin
	changed.TOTPSecret = sealedSecretOf(1)
	changed.TOTPConfirmedAt = adminBase
	changed.Status = store.AdminDisabled
	if _, err := s.Admins().Update(ctx, changed); err != nil {
		t.Fatal(err)
	}
	resolved = resolveAdminSession(t, s, tenantA, want.SecretHash)
	checkAdminSession(t, resolved.Session, want)
	if state := resolved.Admin; state.Status != store.AdminDisabled || state.Version != 2 || !state.TOTPConfirmed {
		t.Fatalf("the state of the administrator must be the current one: %+v", state)
	}

	later := want.LastSeenAt.Add(time.Hour)
	if err := s.AdminSessions().Touch(ctx, tenantA, id(10), later); err != nil {
		t.Fatalf("Touch failed: %v", err)
	}
	want.LastSeenAt = later
	checkAdminSession(t, resolveAdminSession(t, s, tenantA, want.SecretHash).Session, want)
	if err := s.AdminSessions().Touch(ctx, tenantA, id(10), adminSessionBase); err != nil {
		t.Fatalf("Touch with an earlier time failed: %v", err)
	}
	checkAdminSession(t, resolveAdminSession(t, s, tenantA, want.SecretHash).Session, want)
	if err := s.AdminSessions().Touch(ctx, tenantA, id(99), later); err != nil {
		t.Fatalf("Touch of a session that does not exist = %v, want nil", err)
	}
	if err := s.AdminSessions().Touch(ctx, tenantA, id(10), time.Time{}); err == nil || isDomainError(err) {
		t.Fatalf("Touch without a time = %v, want a validation error", err)
	}

	pending := newAdminSession(tenantA, id(11), id(1), 2)
	pending.Stage = store.AdminStagePassword
	pending.IP, pending.UserAgent = "", ""
	mustCreateAdminSession(t, s, pending)
	got := resolveAdminSession(t, s, tenantA, pending.SecretHash).Session
	checkAdminSession(t, got, pending)
	if got.IP != "" || got.UserAgent != "" {
		t.Fatalf("fields that are not set must come back empty: %+v", got)
	}

	if err := s.AdminSessions().Delete(ctx, tenantA, id(1), id(10)); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := s.AdminSessions().ResolveBySecret(ctx, tenantA, want.SecretHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ResolveBySecret after Delete = %v, want ErrNotFound", err)
	}
	if err := s.AdminSessions().Delete(ctx, tenantA, id(1), id(10)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete of a deleted session = %v, want ErrNotFound", err)
	}
	if err := s.AdminSessions().Delete(ctx, tenantA, id(2), id(11)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete of the session of another administrator = %v, want ErrNotFound", err)
	}
	resolveAdminSession(t, s, tenantA, pending.SecretHash)
}

func testAdminSessionConflictsAndMissingAdmins(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	mustCreateAdmin(t, s, newAdmin(tenantB, id(1), "root"))
	first := newAdminSession(tenantA, id(10), id(1), 1)
	mustCreateAdminSession(t, s, first)
	if err := s.AdminSessions().Create(ctx, first); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Create of the same session = %v, want ErrConflict", err)
	}
	sameID := newAdminSession(tenantA, id(10), id(1), 2)
	if err := s.AdminSessions().Create(ctx, sameID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Create with a taken ID = %v, want ErrConflict", err)
	}
	sameSecret := newAdminSession(tenantA, id(11), id(1), 1)
	if err := s.AdminSessions().Create(ctx, sameSecret); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Create with a taken secret hash = %v, want ErrConflict", err)
	}
	otherTenant := newAdminSession(tenantB, id(12), id(1), 1)
	if err := s.AdminSessions().Create(ctx, otherTenant); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Create with a secret hash that another tenant has = %v, want ErrConflict: the hash is unique", err)
	}
	missing := newAdminSession(tenantA, id(13), id(99), 3)
	if err := s.AdminSessions().Create(ctx, missing); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Create for a missing administrator = %v, want ErrNotFound", err)
	}
	crossTenant := newAdminSession(tenantA, id(14), id(1), 4)
	crossTenant.TenantID = "third"
	if err := s.AdminSessions().Create(ctx, crossTenant); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Create for an administrator of another tenant = %v, want ErrNotFound", err)
	}
	if list, err := s.AdminSessions().ListByAdmin(ctx, tenantA, id(1), adminSessionBase); err != nil || len(list) != 1 {
		t.Fatalf("a rejected session was stored: %v, %v", list, err)
	}
	sameIDElsewhere := newAdminSession(tenantB, id(10), id(1), 5)
	mustCreateAdminSession(t, s, sameIDElsewhere)
}

func testAdminSessionInvalidRecords(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	edits := map[string]func(*store.AdminSession){
		"no tenant":                func(a *store.AdminSession) { a.TenantID = "" },
		"no ID":                    func(a *store.AdminSession) { a.ID = "" },
		"no administrator":         func(a *store.AdminSession) { a.AdminID = "" },
		"no stage":                 func(a *store.AdminSession) { a.Stage = "" },
		"an unknown stage":         func(a *store.AdminSession) { a.Stage = "half" },
		"no hash":                  func(a *store.AdminSession) { a.SecretHash = nil },
		"a short hash":             func(a *store.AdminSession) { a.SecretHash = a.SecretHash[:31] },
		"a long hash":              func(a *store.AdminSession) { a.SecretHash = append(bytes.Clone(a.SecretHash), 0) },
		"no version":               func(a *store.AdminSession) { a.AdminVersion = 0 },
		"a negative version":       func(a *store.AdminSession) { a.AdminVersion = -3 },
		"attempts":                 func(a *store.AdminSession) { a.Attempts = 1 },
		"no creation time":         func(a *store.AdminSession) { a.CreatedAt = time.Time{} },
		"no time of the last use":  func(a *store.AdminSession) { a.LastSeenAt = time.Time{} },
		"no expiry":                func(a *store.AdminSession) { a.ExpiresAt = time.Time{} },
		"NUL in the agent":         func(a *store.AdminSession) { a.UserAgent = "a\x00b" },
		"invalid UTF-8 in the IP":  func(a *store.AdminSession) { a.IP = "a\xffb" },
		"invalid UTF-8 in the tag": func(a *store.AdminSession) { a.ID = "a\xffb" },
	}
	fields := map[string]struct {
		limit int
		set   func(*store.AdminSession, string)
	}{
		"tenant": {store.MaxTenantIDLength, func(a *store.AdminSession, v string) { a.TenantID = v }},
		"ID":     {store.MaxIDLength, func(a *store.AdminSession, v string) { a.ID = v }},
		"admin":  {store.MaxIDLength, func(a *store.AdminSession, v string) { a.AdminID = v }},
		"IP":     {store.MaxIPLength, func(a *store.AdminSession, v string) { a.IP = v }},
		"agent":  {store.MaxUserAgentLength, func(a *store.AdminSession, v string) { a.UserAgent = v }},
	}
	for field, f := range fields {
		for label, text := range overTheLimit(f.limit) {
			edits[fmt.Sprintf("a %s %s", field, label)] = func(a *store.AdminSession) { f.set(a, text) }
		}
	}
	for name, edit := range edits {
		a := newAdminSession(tenantA, id(10), id(1), 1)
		edit(&a)
		if err := s.AdminSessions().Create(ctx, a); err == nil || isDomainError(err) {
			t.Errorf("Create with %s = %v, want a validation error", name, err)
		}
	}
	if list, err := s.AdminSessions().ListByAdmin(ctx, tenantA, id(1), adminSessionBase); err != nil || len(list) != 0 {
		t.Fatalf("a rejected session must not be stored: %v, %v", list, err)
	}
}

func testAdminSessionLongestValues(t *testing.T, s store.Store) {
	for _, c := range characters {
		t.Run(c.name, func(t *testing.T) {
			tenant := fill(c.unit, store.MaxTenantIDLength)
			adminID := fill(c.unit, store.MaxIDLength)
			mustCreateAdmin(t, s, newAdmin(tenant, adminID, fill(c.unit, store.MaxAdminLoginLength)))
			a := newAdminSession(tenant, fill(c.unit, store.MaxIDLength), adminID, 1)
			a.IP = fill(c.unit, store.MaxIPLength)
			a.UserAgent = fill(c.unit, store.MaxUserAgentLength)
			mustCreateAdminSession(t, s, a)
			checkAdminSession(t, resolveAdminSession(t, s, tenant, a.SecretHash).Session, a)
			list, err := s.AdminSessions().ListByAdmin(t.Context(), tenant, adminID, adminSessionBase)
			if err != nil || len(list) != 1 {
				t.Fatalf("ListByAdmin = %v, %v; want the longest session", list, err)
			}
			checkAdminSession(t, list[0], a)
			if err = s.AdminSessions().Delete(t.Context(), tenant, adminID, a.ID); err != nil {
				t.Fatalf("Delete of the longest session failed: %v", err)
			}
		})
	}
}

func testAdminSessionLookupsThatFindNothing(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	a := newAdminSession(tenantA, id(10), id(1), 1)
	mustCreateAdminSession(t, s, a)
	for name, hash := range map[string][]byte{"no hash": nil, "a short hash": a.SecretHash[:31], "a long hash": append(bytes.Clone(a.SecretHash), 0), "another hash": hashOf("admin-cookie", 2)} {
		if _, err := s.AdminSessions().ResolveBySecret(ctx, tenantA, hash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ResolveBySecret with %s = %v, want ErrNotFound", name, err)
		}
	}
	if _, err := s.AdminSessions().ResolveBySecret(ctx, tenantB, a.SecretHash); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("ResolveBySecret in another tenant = %v, want ErrNotFound", err)
	}
	for _, bad := range []string{"", "a\x00b", "a\xffb", strings.Repeat("a", store.MaxIdentifierValueLength+1)} {
		if _, err := s.AdminSessions().ResolveBySecret(ctx, bad, a.SecretHash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ResolveBySecret with tenant %q = %v, want ErrNotFound", bad, err)
		}
		if err := s.AdminSessions().Delete(ctx, tenantA, id(1), bad); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete with ID %q = %v, want ErrNotFound", bad, err)
		}
		if err := s.AdminSessions().Rebind(ctx, tenantA, id(1), bad, 2); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Rebind with ID %q = %v, want ErrNotFound", bad, err)
		}
		if ok, err := s.AdminSessions().TryAttempt(ctx, tenantA, bad, 3); err != nil || ok {
			t.Errorf("TryAttempt with ID %q = %v, %v; want false", bad, ok, err)
		}
		if removed, err := s.AdminSessions().DeleteForAdmin(ctx, tenantA, bad, ""); err != nil || removed != 0 {
			t.Errorf("DeleteForAdmin with admin %q = %d, %v; want nothing", bad, removed, err)
		}
		if list, err := s.AdminSessions().ListByAdmin(ctx, tenantA, bad, adminSessionBase); err != nil || len(list) != 0 {
			t.Errorf("ListByAdmin with admin %q = %v, %v; want nothing", bad, list, err)
		}
		if removed, err := s.AdminSessions().DeleteStale(ctx, bad, adminSessionBase, adminSessionBase); err != nil || removed != 0 {
			t.Errorf("DeleteStale with tenant %q = %d, %v; want nothing", bad, removed, err)
		}
	}
	resolveAdminSession(t, s, tenantA, a.SecretHash)
}

func testAdminSessionHashesAreExact(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	odd := []byte{0, 0, 255, 1, 0, 128, 0, 0, 7, 0, 0, 0, 255, 255, 0, 3, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255}
	a := newAdminSession(tenantA, id(10), id(1), 1)
	a.SecretHash = odd
	mustCreateAdminSession(t, s, a)
	near := bytes.Clone(odd)
	near[31] = 254
	other := bytes.Clone(odd)
	other[0] = 1
	for name, hash := range map[string][]byte{"a hash that differs in the last byte": near, "a hash that differs in the first byte": other} {
		if _, err := s.AdminSessions().ResolveBySecret(ctx, tenantA, hash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ResolveBySecret with %s = %v, want ErrNotFound: hashes are compared byte for byte", name, err)
		}
	}
	if got := resolveAdminSession(t, s, tenantA, odd).Session; !bytes.Equal(got.SecretHash, odd) {
		t.Fatalf("the hash must be stored byte for byte: %v", got.SecretHash)
	}
}

func testAdminSessionTryAttempt(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	pending := newAdminSession(tenantA, id(10), id(1), 1)
	pending.Stage = store.AdminStagePassword
	mustCreateAdminSession(t, s, pending)
	other := newAdminSession(tenantA, id(11), id(1), 2)
	other.Stage = store.AdminStagePassword
	mustCreateAdminSession(t, s, other)
	full := newAdminSession(tenantA, id(12), id(1), 3)
	mustCreateAdminSession(t, s, full)

	for n := 1; n <= 3; n++ {
		ok, err := s.AdminSessions().TryAttempt(ctx, tenantA, id(10), 3)
		if err != nil || !ok {
			t.Fatalf("TryAttempt %d = %v, %v; want true", n, ok, err)
		}
		if got := resolveAdminSession(t, s, tenantA, pending.SecretHash).Session; got.Attempts != n {
			t.Fatalf("after %d attempts the session has %d", n, got.Attempts)
		}
	}
	for range 2 {
		if ok, err := s.AdminSessions().TryAttempt(ctx, tenantA, id(10), 3); err != nil || ok {
			t.Fatalf("TryAttempt over the limit = %v, %v; want false", ok, err)
		}
	}
	if got := resolveAdminSession(t, s, tenantA, pending.SecretHash).Session; got.Attempts != 3 {
		t.Fatalf("a refused attempt must not be counted, the session has %d", got.Attempts)
	}
	if ok, err := s.AdminSessions().TryAttempt(ctx, tenantA, id(10), 4); err != nil || !ok {
		t.Fatalf("TryAttempt with a greater limit = %v, %v; want true", ok, err)
	}
	if ok, err := s.AdminSessions().TryAttempt(ctx, tenantA, id(11), 3); err != nil || !ok {
		t.Fatalf("TryAttempt on another session = %v, %v; want true: the counters are apart", ok, err)
	}
	if ok, err := s.AdminSessions().TryAttempt(ctx, tenantA, id(12), 3); err != nil || ok {
		t.Fatalf("TryAttempt on a complete session = %v, %v; want false", ok, err)
	}
	if ok, err := s.AdminSessions().TryAttempt(ctx, tenantA, id(99), 3); err != nil || ok {
		t.Fatalf("TryAttempt on a session that does not exist = %v, %v; want false", ok, err)
	}
	if ok, err := s.AdminSessions().TryAttempt(ctx, tenantB, id(11), 3); err != nil || ok {
		t.Fatalf("TryAttempt in another tenant = %v, %v; want false", ok, err)
	}
	for _, limit := range []int{0, -1} {
		if _, err := s.AdminSessions().TryAttempt(ctx, tenantA, id(10), limit); err == nil || isDomainError(err) {
			t.Fatalf("TryAttempt with a limit of %d = %v, want a validation error", limit, err)
		}
	}
}

func testConcurrentAdminSessionTryAttempt(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	pending := newAdminSession(tenantA, id(10), id(1), 1)
	pending.Stage = store.AdminStagePassword
	mustCreateAdminSession(t, s, pending)
	const racers, limit = 12, 3
	var counted atomic.Int32
	parallel(racers, func(i int) {
		ok, err := s.AdminSessions().TryAttempt(ctx, tenantA, id(10), limit)
		if err != nil {
			t.Errorf("racer %d: %v", i, err)
			return
		}
		if ok {
			counted.Add(1)
		}
	})
	if counted.Load() != limit {
		t.Fatalf("%d attempts were counted by %d calls at once, want exactly %d: a guess is checked only when it is counted", counted.Load(), racers, limit)
	}
	if got := resolveAdminSession(t, s, tenantA, pending.SecretHash).Session; got.Attempts != limit {
		t.Fatalf("the session has %d attempts, want %d", got.Attempts, limit)
	}
}

func testAdminSessionRebind(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	mustCreateAdmin(t, s, newAdmin(tenantA, id(2), "second"))
	a := newAdminSession(tenantA, id(10), id(1), 1)
	mustCreateAdminSession(t, s, a)
	if err := s.AdminSessions().Rebind(ctx, tenantA, id(1), id(10), 5); err != nil {
		t.Fatalf("Rebind failed: %v", err)
	}
	a.AdminVersion = 5
	checkAdminSession(t, resolveAdminSession(t, s, tenantA, a.SecretHash).Session, a)
	if err := s.AdminSessions().Rebind(ctx, tenantA, id(2), id(10), 6); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Rebind of the session of another administrator = %v, want ErrNotFound", err)
	}
	if err := s.AdminSessions().Rebind(ctx, tenantA, id(1), id(99), 6); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Rebind of a session that does not exist = %v, want ErrNotFound", err)
	}
	if err := s.AdminSessions().Rebind(ctx, tenantB, id(1), id(10), 6); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Rebind in another tenant = %v, want ErrNotFound", err)
	}
	checkAdminSession(t, resolveAdminSession(t, s, tenantA, a.SecretHash).Session, a)
}

func testAdminSessionList(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	mustCreateAdmin(t, s, newAdmin(tenantA, id(2), "second"))
	now := adminSessionBase.Add(time.Hour)
	mk := func(n int, adminID string, created time.Time, expires time.Time, stage store.AdminSessionStage) {
		a := newAdminSession(tenantA, id(n), adminID, n)
		a.CreatedAt, a.LastSeenAt, a.ExpiresAt, a.Stage = created, created, expires, stage
		mustCreateAdminSession(t, s, a)
	}
	mk(13, id(1), adminSessionBase.Add(3*time.Minute), now.Add(time.Hour), store.AdminStageFull)
	mk(11, id(1), adminSessionBase.Add(time.Minute), now.Add(time.Hour), store.AdminStageFull)
	mk(12, id(1), adminSessionBase.Add(time.Minute), now.Add(time.Minute), store.AdminStageFull)
	mk(14, id(1), adminSessionBase.Add(4*time.Minute), now, store.AdminStageFull)
	mk(15, id(1), adminSessionBase.Add(5*time.Minute), now.Add(-time.Second), store.AdminStageFull)
	mk(16, id(1), adminSessionBase.Add(6*time.Minute), now.Add(time.Hour), store.AdminStagePassword)
	mk(17, id(2), adminSessionBase.Add(7*time.Minute), now.Add(time.Hour), store.AdminStageFull)
	list, err := s.AdminSessions().ListByAdmin(ctx, tenantA, id(1), now)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{id(11), id(12), id(13)}
	if got := adminSessionIDs(list); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("ListByAdmin = %v, want %v: complete sessions that expire after now, by creation time and then by ID", got, want)
	}
	if list, err = s.AdminSessions().ListByAdmin(ctx, tenantB, id(1), now); err != nil || len(list) != 0 {
		t.Fatalf("ListByAdmin in another tenant = %v, %v; want nothing", list, err)
	}
}

func testAdminSessionDeleteForAdmin(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	mustCreateAdmin(t, s, newAdmin(tenantA, id(2), "second"))
	mustCreateAdmin(t, s, newAdmin(tenantB, id(1), "root"))
	for n := 1; n <= 4; n++ {
		a := newAdminSession(tenantA, id(10+n), id(1), n)
		if n == 3 {
			a.Stage = store.AdminStagePassword
		}
		mustCreateAdminSession(t, s, a)
	}
	mustCreateAdminSession(t, s, newAdminSession(tenantA, id(20), id(2), 5))
	mustCreateAdminSession(t, s, newAdminSession(tenantB, id(21), id(1), 6))

	removed, err := s.AdminSessions().DeleteForAdmin(ctx, tenantA, id(1), id(12))
	if err != nil || removed != 3 {
		t.Fatalf("DeleteForAdmin except one = %d, %v; want 3", removed, err)
	}
	list, err := s.AdminSessions().ListByAdmin(ctx, tenantA, id(1), adminSessionBase)
	if err != nil || strings.Join(adminSessionIDs(list), "|") != id(12) {
		t.Fatalf("the sessions that are left = %v, %v; want only the one that was kept", adminSessionIDs(list), err)
	}
	if removed, err = s.AdminSessions().DeleteForAdmin(ctx, tenantA, id(1), id(99)); err != nil || removed != 1 {
		t.Fatalf("DeleteForAdmin except a session that is not there = %d, %v; want 1", removed, err)
	}
	if removed, err = s.AdminSessions().DeleteForAdmin(ctx, tenantA, id(1), ""); err != nil || removed != 0 {
		t.Fatalf("DeleteForAdmin of nothing = %d, %v; want 0", removed, err)
	}
	for _, still := range []struct {
		tenant, admin string
		id            string
	}{{tenantA, id(2), id(20)}, {tenantB, id(1), id(21)}} {
		list, listErr := s.AdminSessions().ListByAdmin(ctx, still.tenant, still.admin, adminSessionBase)
		if listErr != nil || strings.Join(adminSessionIDs(list), "|") != still.id {
			t.Fatalf("the session %s of another administrator or tenant must stay: %v, %v", still.id, adminSessionIDs(list), listErr)
		}
	}
}

func testAdminSessionDeleteStale(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	mustCreateAdmin(t, s, newAdmin(tenantB, id(1), "root"))
	cutoff := adminSessionBase.Add(24 * time.Hour)
	mk := func(tenant string, n int, seen, expires time.Time) {
		a := newAdminSession(tenant, id(n), id(1), n)
		a.CreatedAt, a.LastSeenAt, a.ExpiresAt = adminSessionBase, seen, expires
		mustCreateAdminSession(t, s, a)
	}
	mk(tenantA, 10, cutoff, cutoff.Add(time.Hour))
	mk(tenantA, 11, cutoff, cutoff)
	mk(tenantA, 12, cutoff, cutoff.Add(-time.Microsecond))
	mk(tenantA, 13, cutoff.Add(-time.Microsecond), cutoff.Add(time.Hour))
	mk(tenantA, 14, cutoff.Add(-time.Hour), cutoff.Add(-time.Hour))
	mk(tenantB, 15, cutoff.Add(-time.Hour), cutoff.Add(-time.Hour))
	removed, err := s.AdminSessions().DeleteStale(ctx, tenantA, cutoff, cutoff)
	if err != nil || removed != 3 {
		t.Fatalf("DeleteStale = %d, %v; want 3", removed, err)
	}
	for n, wantFound := range map[int]bool{10: true, 11: true, 12: false, 13: false, 14: false} {
		_, err = s.AdminSessions().ResolveBySecret(ctx, tenantA, hashOf("admin-cookie", n))
		if (err == nil) != wantFound {
			t.Errorf("session %d found = %v (%v), want %v: a session that expired or was last seen exactly at the cutoff stays", n, err == nil, err, wantFound)
		}
	}
	if _, err = s.AdminSessions().ResolveBySecret(ctx, tenantB, hashOf("admin-cookie", 15)); err != nil {
		t.Fatalf("a stale session of another tenant must stay: %v", err)
	}
	if removed, err = s.AdminSessions().DeleteStale(ctx, tenantA, cutoff, cutoff); err != nil || removed != 0 {
		t.Fatalf("a second DeleteStale = %d, %v; want 0", removed, err)
	}
}

func testAdminSessionsFollowTheAdmin(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	a := newAdminSession(tenantA, id(10), id(1), 1)
	mustCreateAdminSession(t, s, a)
	pending := newAdminSession(tenantA, id(11), id(1), 2)
	pending.Stage = store.AdminStagePassword
	mustCreateAdminSession(t, s, pending)
	if err := s.Admins().Delete(ctx, tenantA, id(1)); err != nil {
		t.Fatal(err)
	}
	for _, hash := range [][]byte{a.SecretHash, pending.SecretHash} {
		if _, err := s.AdminSessions().ResolveBySecret(ctx, tenantA, hash); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a session of an administrator that was deleted still resolves: %v", err)
		}
	}
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	if list, err := s.AdminSessions().ListByAdmin(ctx, tenantA, id(1), adminSessionBase); err != nil || len(list) != 0 {
		t.Fatalf("the sessions of an administrator that was deleted came back: %v, %v", list, err)
	}
	mustCreateAdminSession(t, s, a)
}

func testAdminSessionTenantIsolation(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	mustCreateAdmin(t, s, newAdmin(tenantB, id(1), "other"))
	a := newAdminSession(tenantA, id(10), id(1), 1)
	b := newAdminSession(tenantB, id(10), id(1), 2)
	mustCreateAdminSession(t, s, a)
	mustCreateAdminSession(t, s, b)
	for _, c := range []struct {
		tenant string
		hash   []byte
		login  string
	}{{tenantA, a.SecretHash, "root"}, {tenantB, b.SecretHash, "other"}} {
		if got := resolveAdminSession(t, s, c.tenant, c.hash).Admin.Login; got != c.login {
			t.Fatalf("the session of the tenant %s resolved the administrator %q, want %q: the administrator is the one of the same tenant", c.tenant, got, c.login)
		}
	}
	if err := s.AdminSessions().Touch(ctx, tenantA, id(10), adminSessionBase.Add(5*time.Hour)); err != nil {
		t.Fatal(err)
	}
	checkAdminSession(t, resolveAdminSession(t, s, tenantB, b.SecretHash).Session, b)
	if err := s.AdminSessions().Delete(ctx, tenantA, id(1), id(10)); err != nil {
		t.Fatal(err)
	}
	checkAdminSession(t, resolveAdminSession(t, s, tenantB, b.SecretHash).Session, b)
}

func testAdminSessionRollback(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	kept := newAdminSession(tenantA, id(10), id(1), 1)
	mustCreateAdminSession(t, s, kept)
	added := newAdminSession(tenantA, id(11), id(1), 2)
	err := s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if err := tx.AdminSessions().Create(ctx, added); err != nil {
			return err
		}
		if err := tx.AdminSessions().Delete(ctx, tenantA, id(1), id(10)); err != nil {
			return err
		}
		if _, err := tx.AdminSessions().ResolveBySecret(ctx, tenantA, added.SecretHash); err != nil {
			return fmt.Errorf("the transaction must see its own session: %w", err)
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatalf("InTx = %v, want the error of the function", err)
	}
	if _, resolveErr := s.AdminSessions().ResolveBySecret(ctx, tenantA, added.SecretHash); !errors.Is(resolveErr, store.ErrNotFound) {
		t.Fatalf("a rolled back session must not exist: %v", resolveErr)
	}
	checkAdminSession(t, resolveAdminSession(t, s, tenantA, kept.SecretHash).Session, kept)
	err = s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		return tx.AdminSessions().Create(ctx, added)
	})
	if err != nil {
		t.Fatalf("InTx failed: %v", err)
	}
	resolveAdminSession(t, s, tenantA, added.SecretHash)
}

func testAdminLoginIsAllOrNothing(t *testing.T, s store.Store) {
	ctx := t.Context()
	admin := mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	pending := newAdminSession(tenantA, id(10), id(1), 1)
	pending.Stage = store.AdminStagePassword
	mustCreateAdminSession(t, s, pending)
	full := newAdminSession(tenantA, id(11), id(1), 2)
	finish := func(version int64) error {
		return s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
			if err := tx.Admins().AcceptStep(ctx, tenantA, id(1), version, 5, adminSessionBase); err != nil {
				return err
			}
			if err := tx.AdminSessions().Delete(ctx, tenantA, id(1), id(10)); err != nil {
				return err
			}
			return tx.AdminSessions().Create(ctx, full)
		})
	}
	changed := admin
	changed.PasswordHash = passwordHashOf(7)
	if _, err := s.Admins().Update(ctx, changed); err != nil {
		t.Fatal(err)
	}
	if err := finish(admin.Version); !errors.Is(err, store.ErrStale) {
		t.Fatalf("a sign-in that began before a change of the account = %v, want ErrStale", err)
	}
	if _, err := s.AdminSessions().ResolveBySecret(ctx, tenantA, full.SecretHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a session of a refused sign-in must not exist: %v", err)
	}
	resolveAdminSession(t, s, tenantA, pending.SecretHash)
	if err := finish(admin.Version + 1); err != nil {
		t.Fatalf("a sign-in that began after the change failed: %v", err)
	}
	if _, err := s.AdminSessions().ResolveBySecret(ctx, tenantA, pending.SecretHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the sign-in that was finished must be gone: %v", err)
	}
	resolveAdminSession(t, s, tenantA, full.SecretHash)
	if err := finish(admin.Version + 1); err == nil {
		t.Fatal("a sign-in cannot be finished twice")
	}
}
