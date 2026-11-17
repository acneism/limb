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

var adminBase = time.Date(2026, 11, 12, 13, 14, 15, 123456789, time.UTC)

func passwordHashOf(n int) string {
	return "$argon2id$v=19$m=19456,t=2,p=1$" + strings.Repeat("s", 22) + "$" + strings.Repeat(string(rune('a'+n%26)), 43)
}

func sealedSecretOf(n int) []byte {
	return append(hashOf("totp", n), hashOf("tail", n)[:17]...)
}

func newAdmin(tenant, adminID, login string) store.Admin {
	return store.Admin{TenantID: tenant, ID: adminID, Login: login, PasswordHash: passwordHashOf(1), Status: store.AdminActive, CreatedAt: adminBase}
}

func mustCreateAdmin(t *testing.T, s store.Store, a store.Admin) store.Admin {
	t.Helper()
	if err := s.Admins().Create(t.Context(), a); err != nil {
		t.Fatalf("Create(%s) failed: %v", a.Login, err)
	}
	got, err := s.Admins().Get(t.Context(), a.TenantID, a.ID)
	if err != nil {
		t.Fatalf("Get(%s) failed: %v", a.ID, err)
	}
	return got
}

func checkAdmin(t *testing.T, got, want store.Admin) {
	t.Helper()
	switch {
	case got.TenantID != want.TenantID, got.ID != want.ID, got.Login != want.Login, got.PasswordHash != want.PasswordHash,
		got.Status != want.Status, got.TOTPLastStep != want.TOTPLastStep, got.Version != want.Version,
		!bytes.Equal(got.TOTPSecret, want.TOTPSecret):
		t.Fatalf("admin differs:\n got %+v\nwant %+v", got, want)
	case !sameTime(got.TOTPConfirmedAt, want.TOTPConfirmedAt), !sameTime(got.CreatedAt, want.CreatedAt), !sameTime(got.LastLoginAt, want.LastLoginAt):
		t.Fatalf("admin times differ, they must be UTC with microsecond precision:\n got %+v\nwant %+v", got, want)
	}
}

func adminWithVersion(a store.Admin, version int64) store.Admin {
	a.Version = version
	return a
}

func recoveryHashes(n int) [][]byte {
	hashes := make([][]byte, n)
	for i := range hashes {
		hashes[i] = hashOf("recovery", i)
	}
	return hashes
}

func testAdminLifecycle(t *testing.T, s store.Store) {
	ctx := t.Context()
	want := newAdmin(tenantA, id(1), "root")
	got := mustCreateAdmin(t, s, want)
	want.Version = 1
	checkAdmin(t, got, want)
	byLogin, err := s.Admins().FindByLogin(ctx, tenantA, "root")
	if err != nil {
		t.Fatalf("FindByLogin failed: %v", err)
	}
	checkAdmin(t, byLogin, want)

	plus3 := time.FixedZone("UTC+3", 3*3600)
	bound := got
	bound.PasswordHash = passwordHashOf(2)
	bound.TOTPSecret = sealedSecretOf(1)
	bound.TOTPConfirmedAt = time.Date(2026, 12, 1, 2, 3, 4, 987654321, plus3)
	bound.Status = store.AdminDisabled
	updated, err := s.Admins().Update(ctx, bound)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	bound.Version = 2
	checkAdmin(t, updated, bound)
	reread, err := s.Admins().Get(ctx, tenantA, id(1))
	if err != nil {
		t.Fatal(err)
	}
	checkAdmin(t, reread, bound)

	cleared := reread
	cleared.TOTPSecret = nil
	cleared.TOTPConfirmedAt = time.Time{}
	cleared.Status = store.AdminActive
	if _, err = s.Admins().Update(ctx, cleared); err != nil {
		t.Fatalf("Update that clears the authenticator failed: %v", err)
	}
	cleared.Version = 3
	if reread, err = s.Admins().Get(ctx, tenantA, id(1)); err != nil {
		t.Fatal(err)
	}
	checkAdmin(t, reread, cleared)
	if reread.TOTPSecret != nil {
		t.Fatalf("a secret that was cleared must come back empty: %v", reread.TOTPSecret)
	}

	if err = s.Admins().Delete(ctx, tenantA, id(1)); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err = s.Admins().Get(ctx, tenantA, id(1)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
	if _, err = s.Admins().FindByLogin(ctx, tenantA, "root"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindByLogin after Delete = %v, want ErrNotFound", err)
	}
	mustCreateAdmin(t, s, newAdmin(tenantA, id(2), "root"))
}

func testAdminNotFound(t *testing.T, s store.Store) {
	ctx := t.Context()
	if _, err := s.Admins().Get(ctx, tenantA, id(1)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get = %v, want ErrNotFound", err)
	}
	if _, err := s.Admins().FindByLogin(ctx, tenantA, "root"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("FindByLogin = %v, want ErrNotFound", err)
	}
	missing := newAdmin(tenantA, id(1), "root")
	missing.Version = 1
	if _, err := s.Admins().Update(ctx, missing); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Update = %v, want ErrNotFound", err)
	}
	if err := s.Admins().Delete(ctx, tenantA, id(1)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Delete = %v, want ErrNotFound", err)
	}
	if err := s.Admins().AcceptStep(ctx, tenantA, id(1), 1, 5, adminBase); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("AcceptStep = %v, want ErrNotFound", err)
	}
	if err := s.Admins().RecordLogin(ctx, tenantA, id(1), 1, adminBase); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("RecordLogin = %v, want ErrNotFound", err)
	}
	if err := s.Admins().UseRecoveryCode(ctx, tenantA, id(1), hashOf("recovery", 1), adminBase); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("UseRecoveryCode = %v, want ErrNotFound", err)
	}
	for _, hashes := range [][][]byte{nil, recoveryHashes(3)} {
		if err := s.Admins().ReplaceRecoveryCodes(ctx, tenantA, id(1), hashes); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ReplaceRecoveryCodes of %d codes = %v, want ErrNotFound", len(hashes), err)
		}
	}
	if list, err := s.Admins().List(ctx, tenantA); err != nil || len(list) != 0 {
		t.Errorf("List = %v, %v; want nothing", list, err)
	}
	if count, err := s.Admins().CountRecoveryCodes(ctx, tenantA, id(1)); err != nil || count != 0 {
		t.Errorf("CountRecoveryCodes = %d, %v; want 0", count, err)
	}
}

func testAdminConflicts(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	if err := s.Admins().Create(ctx, newAdmin(tenantA, id(1), "other")); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Create with a taken ID = %v, want ErrConflict", err)
	}
	if err := s.Admins().Create(ctx, newAdmin(tenantA, id(2), "root")); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Create with a taken login = %v, want ErrConflict", err)
	}
	if list, err := s.Admins().List(ctx, tenantA); err != nil || len(list) != 1 {
		t.Fatalf("a rejected administrator was stored: %v, %v", list, err)
	}
	mustCreateAdmin(t, s, newAdmin(tenantB, id(1), "root"))
	mustCreateAdmin(t, s, newAdmin(tenantB, id(2), "elsewhere"))
	if _, err := s.Admins().FindByLogin(ctx, tenantA, "elsewhere"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindByLogin of the login of another tenant = %v, want ErrNotFound", err)
	}
	for _, tenant := range []string{tenantA, tenantB} {
		if got, err := s.Admins().FindByLogin(ctx, tenant, "root"); err != nil || got.TenantID != tenant {
			t.Fatalf("FindByLogin(%s, root) = %+v, %v, want the administrator of that tenant", tenant, got, err)
		}
	}
	for n, login := range []string{"Root", "ROOT", "root ", " root", "rööt", "roöt"} {
		mustCreateAdmin(t, s, newAdmin(tenantA, id(10+n), login))
	}
	for _, login := range []string{"Root", "ROOT", "root ", " root", "rööt"} {
		got, err := s.Admins().FindByLogin(ctx, tenantA, login)
		if err != nil || got.Login != login {
			t.Fatalf("FindByLogin(%q) = %+v, %v; logins are compared byte by byte", login, got, err)
		}
	}
	if _, err := s.Admins().FindByLogin(ctx, tenantA, "rOOt"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindByLogin(rOOt) = %v, want ErrNotFound: only the exact login matches", err)
	}
}

func testAdminOptionalFields(t *testing.T, s store.Store) {
	bare := newAdmin(tenantA, id(1), "root")
	got := mustCreateAdmin(t, s, bare)
	if got.TOTPSecret != nil || !got.TOTPConfirmedAt.IsZero() || !got.LastLoginAt.IsZero() || got.TOTPLastStep != 0 {
		t.Fatalf("unset fields must come back unset: %+v", got)
	}
	binary := newAdmin(tenantA, id(2), "binary")
	binary.TOTPSecret = []byte{0, 1, 2, 0, 255, 0}
	binary.TOTPConfirmedAt = adminBase
	binary.TOTPLastStep = 9
	binary.LastLoginAt = adminBase.Add(time.Hour)
	got = mustCreateAdmin(t, s, binary)
	binary.Version = 1
	checkAdmin(t, got, binary)
	if !bytes.Equal(got.TOTPSecret, []byte{0, 1, 2, 0, 255, 0}) {
		t.Fatalf("the secret must be stored byte for byte: %v", got.TOTPSecret)
	}
	got.TOTPSecret[0] = 99
	if again, err := s.Admins().Get(t.Context(), tenantA, id(2)); err != nil || again.TOTPSecret[0] != 0 {
		t.Fatalf("a changed copy must not change the stored secret: %v, %v", again.TOTPSecret, err)
	}
}

func testAdminUpdateWritesOnlyItsFields(t *testing.T, s store.Store) {
	ctx := t.Context()
	stale := mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	signedIn := adminBase.Add(time.Hour)
	if err := s.Admins().AcceptStep(ctx, tenantA, id(1), stale.Version, 7, signedIn); err != nil {
		t.Fatalf("AcceptStep failed: %v", err)
	}
	changed := stale
	changed.Login = "renamed"
	changed.CreatedAt = adminBase.Add(-time.Hour)
	changed.LastLoginAt = adminBase.Add(5 * time.Hour)
	changed.TOTPLastStep = 99
	changed.PasswordHash = passwordHashOf(3)
	if _, err := s.Admins().Update(ctx, changed); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	got, err := s.Admins().Get(ctx, tenantA, id(1))
	if err != nil {
		t.Fatal(err)
	}
	want := newAdmin(tenantA, id(1), "root")
	want.PasswordHash = passwordHashOf(3)
	want.TOTPLastStep = 7
	want.LastLoginAt = signedIn
	want.Version = 2
	checkAdmin(t, got, want)
}

func testAdminVersions(t *testing.T, s store.Store) {
	ctx := t.Context()
	first := mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	if first.Version != 1 {
		t.Fatalf("a new administrator must have version 1, got %d", first.Version)
	}
	changed := first
	changed.PasswordHash = passwordHashOf(2)
	second, err := s.Admins().Update(ctx, changed)
	if err != nil || second.Version != 2 {
		t.Fatalf("Update = version %d, %v; want version 2", second.Version, err)
	}
	if _, err = s.Admins().Update(ctx, changed); !errors.Is(err, store.ErrStale) {
		t.Fatalf("Update with an old version = %v, want ErrStale", err)
	}
	third, err := s.Admins().Update(ctx, second)
	if err != nil || third.Version != 3 {
		t.Fatalf("Update = version %d, %v; want version 3", third.Version, err)
	}
	forced := third
	forced.Version = 1
	if _, err = s.Admins().Update(ctx, forced); !errors.Is(err, store.ErrStale) {
		t.Fatalf("Update with a made up version = %v, want ErrStale", err)
	}
	created := newAdmin(tenantA, id(2), "second")
	created.Version = 41
	if got := mustCreateAdmin(t, s, created); got.Version != 1 {
		t.Fatalf("Create must store version 1 whatever the record says, got %d", got.Version)
	}
	if err = s.Admins().AcceptStep(ctx, tenantA, id(1), 3, 5, adminBase); err != nil {
		t.Fatalf("AcceptStep does not change the version: %v", err)
	}
	if again, getErr := s.Admins().Get(ctx, tenantA, id(1)); getErr != nil || again.Version != 3 {
		t.Fatalf("version after AcceptStep = %d, %v; want 3", again.Version, getErr)
	}
	if err = s.Admins().RecordLogin(ctx, tenantA, id(1), 3, adminBase.Add(time.Hour)); err != nil {
		t.Fatalf("RecordLogin does not change the version: %v", err)
	}
	if again, getErr := s.Admins().Get(ctx, tenantA, id(1)); getErr != nil || again.Version != 3 {
		t.Fatalf("version after RecordLogin = %d, %v; want 3", again.Version, getErr)
	}
}

func testConcurrentAdminUpdates(t *testing.T, s store.Store) {
	ctx := t.Context()
	base := mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	const writers = 8
	var wins, stale atomic.Int32
	parallel(writers, func(i int) {
		a := base
		a.PasswordHash = passwordHashOf(i)
		_, err := s.Admins().Update(ctx, a)
		switch {
		case err == nil:
			wins.Add(1)
		case errors.Is(err, store.ErrStale):
			stale.Add(1)
		default:
			t.Errorf("writer %d: unexpected error %v", i, err)
		}
	})
	if wins.Load() != 1 || stale.Load() != writers-1 {
		t.Fatalf("%d updates succeeded and %d were stale; want exactly 1 and %d", wins.Load(), stale.Load(), writers-1)
	}
	if got, err := s.Admins().Get(ctx, tenantA, id(1)); err != nil || got.Version != 2 {
		t.Fatalf("version = %d, %v; want 2", got.Version, err)
	}
}

func testAdminInvalidRecords(t *testing.T, s store.Store) {
	ctx := t.Context()
	edits := map[string]func(*store.Admin){
		"no tenant":                       func(a *store.Admin) { a.TenantID = "" },
		"no ID":                           func(a *store.Admin) { a.ID = "" },
		"no login":                        func(a *store.Admin) { a.Login = "" },
		"no password":                     func(a *store.Admin) { a.PasswordHash = "" },
		"no status":                       func(a *store.Admin) { a.Status = "" },
		"an unknown status":               func(a *store.Admin) { a.Status = "frozen" },
		"no creation time":                func(a *store.Admin) { a.CreatedAt = time.Time{} },
		"a negative step":                 func(a *store.Admin) { a.TOTPLastStep = -1 },
		"NUL in the login":                func(a *store.Admin) { a.Login = "a\x00b" },
		"invalid UTF-8 in the login":      func(a *store.Admin) { a.Login = "a\xffb" },
		"NUL in the password":             func(a *store.Admin) { a.PasswordHash = "a\x00b" },
		"a confirmation without a secret": func(a *store.Admin) { a.TOTPConfirmedAt = adminBase },
		"a secret over the limit":         func(a *store.Admin) { a.TOTPSecret = make([]byte, store.MaxSealedSecretLength+1) },
	}
	fields := map[string]struct {
		limit int
		set   func(*store.Admin, string)
	}{
		"tenant":   {store.MaxTenantIDLength, func(a *store.Admin, v string) { a.TenantID = v }},
		"id":       {store.MaxIDLength, func(a *store.Admin, v string) { a.ID = v }},
		"login":    {store.MaxAdminLoginLength, func(a *store.Admin, v string) { a.Login = v }},
		"password": {store.MaxPasswordHashLength, func(a *store.Admin, v string) { a.PasswordHash = v }},
	}
	for field, f := range fields {
		for label, text := range overTheLimit(f.limit) {
			edits[fmt.Sprintf("a %s %s", field, label)] = func(a *store.Admin) { f.set(a, text) }
		}
	}
	for name, edit := range edits {
		a := newAdmin(tenantA, id(1), "root")
		edit(&a)
		if err := s.Admins().Create(ctx, a); err == nil || isDomainError(err) {
			t.Errorf("Create with %s = %v, want a validation error", name, err)
		}
	}
	if list, err := s.Admins().List(ctx, tenantA); err != nil || len(list) != 0 {
		t.Fatalf("a rejected administrator must not be stored: %v, %v", list, err)
	}
	good := mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	for name, edit := range edits {
		if name == "no creation time" || name == "a negative step" {
			continue
		}
		a := good
		edit(&a)
		if _, err := s.Admins().Update(ctx, a); err == nil || isDomainError(err) {
			t.Errorf("Update with %s = %v, want a validation error", name, err)
		}
	}
	if got, err := s.Admins().Get(ctx, tenantA, id(1)); err != nil || got.Version != 1 {
		t.Fatalf("a rejected update must change nothing: %+v, %v", got, err)
	}
}

func testAdminLongestValues(t *testing.T, s store.Store) {
	for _, c := range characters {
		t.Run(c.name, func(t *testing.T) {
			a := store.Admin{
				TenantID:        fill(c.unit, store.MaxTenantIDLength),
				ID:              fill(c.unit, store.MaxIDLength),
				Login:           fill(c.unit, store.MaxAdminLoginLength),
				PasswordHash:    fill(c.unit, store.MaxPasswordHashLength),
				TOTPSecret:      bytes.Repeat([]byte{0xA5}, store.MaxSealedSecretLength),
				TOTPConfirmedAt: adminBase,
				Status:          store.AdminActive,
				CreatedAt:       adminBase,
			}
			created := mustCreateAdmin(t, s, a)
			a.Version = 1
			checkAdmin(t, created, a)
			byLogin, err := s.Admins().FindByLogin(t.Context(), a.TenantID, a.Login)
			if err != nil {
				t.Fatalf("FindByLogin of the longest login failed: %v", err)
			}
			checkAdmin(t, byLogin, a)
			a.PasswordHash = fill("z", store.MaxPasswordHashLength)
			updated, err := s.Admins().Update(t.Context(), adminWithVersion(a, 1))
			if err != nil {
				t.Fatalf("Update with the longest values failed: %v", err)
			}
			a.Version = 2
			checkAdmin(t, updated, a)
			if list, listErr := s.Admins().List(t.Context(), a.TenantID); listErr != nil || len(list) != 1 {
				t.Fatalf("List = %v, %v; want the longest administrator", list, listErr)
			}
		})
	}
}

func testAdminList(t *testing.T, s store.Store) {
	ctx := t.Context()
	logins := []string{"b", "a-c", "B", "ab", "я", "a", "é", "Z", "a_b"}
	for n, login := range logins {
		mustCreateAdmin(t, s, newAdmin(tenantA, id(n+1), login))
	}
	mustCreateAdmin(t, s, newAdmin(tenantB, id(50), "other"))
	list, err := s.Admins().List(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(list))
	for _, a := range list {
		got = append(got, a.Login)
	}
	want := []string{"B", "Z", "a", "a-c", "a_b", "ab", "b", "é", "я"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("List must return the administrators of the tenant in byte order, whatever the collation of the database is:\n got %q\nwant %q", got, want)
	}
	if list, err = s.Admins().List(ctx, tenantB); err != nil || len(list) != 1 || list[0].Login != "other" {
		t.Fatalf("List of the other tenant = %v, %v", list, err)
	}
}

func testAdminLookupsThatFindNothing(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	for _, bad := range []string{"", "a\x00b", "a\xffb", strings.Repeat("a", store.MaxIdentifierValueLength+1)} {
		if _, err := s.Admins().Get(ctx, bad, id(1)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get with tenant %q = %v, want ErrNotFound", bad, err)
		}
		if _, err := s.Admins().Get(ctx, tenantA, bad); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get with ID %q = %v, want ErrNotFound", bad, err)
		}
		if _, err := s.Admins().FindByLogin(ctx, tenantA, bad); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("FindByLogin with %q = %v, want ErrNotFound", bad, err)
		}
		if err := s.Admins().Delete(ctx, tenantA, bad); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete with ID %q = %v, want ErrNotFound", bad, err)
		}
		if list, err := s.Admins().List(ctx, bad); err != nil || len(list) != 0 {
			t.Errorf("List with tenant %q = %v, %v; want nothing", bad, list, err)
		}
		if err := s.Admins().AcceptStep(ctx, tenantA, bad, 1, 5, adminBase); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AcceptStep with ID %q = %v, want ErrNotFound", bad, err)
		}
		if err := s.Admins().RecordLogin(ctx, bad, id(1), 1, adminBase); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RecordLogin with tenant %q = %v, want ErrNotFound", bad, err)
		}
		if err := s.Admins().ReplaceRecoveryCodes(ctx, tenantA, bad, nil); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ReplaceRecoveryCodes with ID %q = %v, want ErrNotFound", bad, err)
		}
		if err := s.Admins().UseRecoveryCode(ctx, tenantA, bad, hashOf("recovery", 1), adminBase); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UseRecoveryCode with ID %q = %v, want ErrNotFound", bad, err)
		}
		if count, err := s.Admins().CountRecoveryCodes(ctx, tenantA, bad); err != nil || count != 0 {
			t.Errorf("CountRecoveryCodes with ID %q = %d, %v; want 0", bad, count, err)
		}
	}
}

func testAdminTenantIsolation(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	mustCreateAdmin(t, s, newAdmin(tenantB, id(1), "root"))
	if err := s.Admins().ReplaceRecoveryCodes(ctx, tenantA, id(1), recoveryHashes(2)); err != nil {
		t.Fatal(err)
	}
	if count, err := s.Admins().CountRecoveryCodes(ctx, tenantB, id(1)); err != nil || count != 0 {
		t.Fatalf("a recovery code of one tenant is counted in another: %d, %v", count, err)
	}
	if err := s.Admins().UseRecoveryCode(ctx, tenantB, id(1), recoveryHashes(1)[0], adminBase); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a recovery code of one tenant works in another: %v", err)
	}
	if err := s.Admins().AcceptStep(ctx, tenantA, id(1), 1, 5, adminBase); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Admins().Get(ctx, tenantB, id(1)); err != nil || got.TOTPLastStep != 0 || !got.LastLoginAt.IsZero() {
		t.Fatalf("a step accepted in one tenant touched another: %+v, %v", got, err)
	}
	if err := s.Admins().Delete(ctx, tenantA, id(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Admins().Get(ctx, tenantB, id(1)); err != nil {
		t.Fatalf("Delete in one tenant removed an administrator of another: %v", err)
	}
}

func testAdminAcceptStep(t *testing.T, s store.Store) {
	ctx := t.Context()
	a := mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	local := time.FixedZone("UTC+3", 3*3600)
	first := time.Date(2026, 12, 1, 2, 3, 4, 987654321, local)
	if err := s.Admins().AcceptStep(ctx, tenantA, id(1), a.Version, 100, first); err != nil {
		t.Fatalf("AcceptStep failed: %v", err)
	}
	got, err := s.Admins().Get(ctx, tenantA, id(1))
	if err != nil {
		t.Fatal(err)
	}
	want := a
	want.TOTPLastStep = 100
	want.LastLoginAt = first
	checkAdmin(t, got, want)

	for _, step := range []int64{100, 99, 1, 0, -5} {
		if err = s.Admins().AcceptStep(ctx, tenantA, id(1), a.Version, step, adminBase); !errors.Is(err, store.ErrConflict) {
			t.Errorf("AcceptStep of the step %d after 100 = %v, want ErrConflict: a password is used once", step, err)
		}
	}
	if err = s.Admins().AcceptStep(ctx, tenantA, id(1), a.Version+1, 101, adminBase); !errors.Is(err, store.ErrStale) {
		t.Errorf("AcceptStep with a version that is not the stored one = %v, want ErrStale", err)
	}
	if err = s.Admins().AcceptStep(ctx, tenantA, id(1), a.Version-1, 101, adminBase); !errors.Is(err, store.ErrStale) {
		t.Errorf("AcceptStep with an old version = %v, want ErrStale", err)
	}
	for _, step := range []int64{100, 50} {
		if err = s.Admins().AcceptStep(ctx, tenantA, id(1), a.Version+1, step, adminBase); !errors.Is(err, store.ErrStale) {
			t.Errorf("AcceptStep of the step %d with a version that is not the stored one = %v, want ErrStale: the version is judged first", step, err)
		}
	}
	if got, err = s.Admins().Get(ctx, tenantA, id(1)); err != nil || got.TOTPLastStep != 100 || !sameTime(got.LastLoginAt, first) {
		t.Fatalf("a refused step must change nothing: %+v, %v", got, err)
	}
	second := first.Add(30 * time.Second)
	if err = s.Admins().AcceptStep(ctx, tenantA, id(1), a.Version, 101, second); err != nil {
		t.Fatalf("AcceptStep of the next step failed: %v", err)
	}
	if got, err = s.Admins().Get(ctx, tenantA, id(1)); err != nil || got.TOTPLastStep != 101 || !sameTime(got.LastLoginAt, second) {
		t.Fatalf("the next step must be recorded: %+v, %v", got, err)
	}
	if err = s.Admins().AcceptStep(ctx, tenantA, id(1), a.Version, 200, time.Time{}); err == nil || isDomainError(err) {
		t.Errorf("AcceptStep without a time = %v, want a validation error", err)
	}

	changed := got
	changed.PasswordHash = passwordHashOf(5)
	if _, err = s.Admins().Update(ctx, changed); err != nil {
		t.Fatal(err)
	}
	if err = s.Admins().AcceptStep(ctx, tenantA, id(1), a.Version, 300, adminBase); !errors.Is(err, store.ErrStale) {
		t.Fatalf("AcceptStep after a change of the administrator = %v, want ErrStale: the sign-in began before the change", err)
	}
}

func testConcurrentAdminAcceptStep(t *testing.T, s store.Store) {
	ctx := t.Context()
	a := mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	const racers = 8
	var wins, conflicts atomic.Int32
	parallel(racers, func(i int) {
		err := s.Admins().AcceptStep(ctx, tenantA, id(1), a.Version, 42, adminBase.Add(time.Duration(i)*time.Second))
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
		t.Fatalf("%d accepts succeeded and %d conflicted; want exactly 1 and %d: one password, one sign-in", wins.Load(), conflicts.Load(), racers-1)
	}
	var accepted atomic.Int32
	parallel(racers, func(i int) {
		err := s.Admins().AcceptStep(ctx, tenantA, id(1), a.Version, int64(50+i), adminBase.Add(time.Hour))
		switch {
		case err == nil:
			accepted.Add(1)
		case errors.Is(err, store.ErrConflict):
		default:
			t.Errorf("step %d: unexpected error %v", 50+i, err)
		}
	})
	got, err := s.Admins().Get(ctx, tenantA, id(1))
	if err != nil || got.TOTPLastStep != 50+racers-1 || accepted.Load() < 1 {
		t.Fatalf("after steps 50 to %d at once the last step is %d (%v), %d accepted; want the greatest to stay", 50+racers-1, got.TOTPLastStep, err, accepted.Load())
	}
}

func testAdminAcceptStepWaitsForAChangeInProgress(t *testing.T, s store.Store) {
	ctx := t.Context()
	a := mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	changing := make(chan struct{})
	release := make(chan struct{})
	changed := make(chan error, 1)
	go func() {
		changed <- s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
			next := a
			next.PasswordHash = passwordHashOf(2)
			if _, err := tx.Admins().Update(ctx, next); err != nil {
				return err
			}
			close(changing)
			<-release
			return nil
		})
	}()
	select {
	case <-changing:
	case err := <-changed:
		t.Fatalf("the change ended before it was in progress: %v", err)
	}
	accepted := make(chan error, 1)
	go func() {
		accepted <- s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
			return tx.Admins().AcceptStep(ctx, tenantA, id(1), a.Version, 5, adminBase)
		})
	}()
	select {
	case err := <-accepted:
		close(release)
		t.Fatalf("AcceptStep did not wait for the change of the administrator that was in progress: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	if err := <-changed; err != nil {
		t.Fatalf("the change failed: %v", err)
	}
	if err := <-accepted; !errors.Is(err, store.ErrStale) {
		t.Fatalf("AcceptStep after the change was committed = %v, want ErrStale", err)
	}
	if got, err := s.Admins().Get(ctx, tenantA, id(1)); err != nil || got.TOTPLastStep != 0 || got.PasswordHash != passwordHashOf(2) {
		t.Fatalf("the change must stand and the step must not: %+v, %v", got, err)
	}
}

func testAdminRecordLogin(t *testing.T, s store.Store) {
	ctx := t.Context()
	a := mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	local := time.FixedZone("UTC+3", 3*3600)
	first := time.Date(2026, 12, 1, 2, 3, 4, 987654321, local)
	for n := range 3 {
		if err := s.Admins().RecordLogin(ctx, tenantA, id(1), a.Version, first); err != nil {
			t.Fatalf("RecordLogin %d at the time the administrator has = %v, want nil", n+1, err)
		}
	}
	got, err := s.Admins().Get(ctx, tenantA, id(1))
	if err != nil {
		t.Fatal(err)
	}
	want := a
	want.LastLoginAt = first
	checkAdmin(t, got, want)
	if err = s.Admins().RecordLogin(ctx, tenantA, id(1), a.Version+1, adminBase); !errors.Is(err, store.ErrStale) {
		t.Fatalf("RecordLogin with a version that is not the stored one = %v, want ErrStale", err)
	}
	if got, err = s.Admins().Get(ctx, tenantA, id(1)); err != nil || !sameTime(got.LastLoginAt, first) {
		t.Fatalf("a refused sign-in must change nothing: %+v, %v", got, err)
	}
	if err = s.Admins().RecordLogin(ctx, tenantA, id(1), a.Version, time.Time{}); err == nil || isDomainError(err) {
		t.Fatalf("RecordLogin without a time = %v, want a validation error", err)
	}
	later := first.Add(time.Hour)
	if err = s.Admins().RecordLogin(ctx, tenantA, id(1), a.Version, later); err != nil {
		t.Fatal(err)
	}
	if got, err = s.Admins().Get(ctx, tenantA, id(1)); err != nil || !sameTime(got.LastLoginAt, later) || got.TOTPLastStep != 0 {
		t.Fatalf("a later sign-in must replace the time and leave the step: %+v, %v", got, err)
	}
}

func testAdminRecoveryCodes(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	mustCreateAdmin(t, s, newAdmin(tenantA, id(2), "second"))
	codes := recoveryHashes(10)
	if err := s.Admins().ReplaceRecoveryCodes(ctx, tenantA, id(1), codes); err != nil {
		t.Fatalf("ReplaceRecoveryCodes failed: %v", err)
	}
	if count, err := s.Admins().CountRecoveryCodes(ctx, tenantA, id(1)); err != nil || count != 10 {
		t.Fatalf("CountRecoveryCodes = %d, %v; want 10", count, err)
	}
	at := adminBase.Add(time.Hour).In(time.FixedZone("UTC+3", 3*3600))
	if err := s.Admins().UseRecoveryCode(ctx, tenantA, id(1), codes[3], at); err != nil {
		t.Fatalf("UseRecoveryCode failed: %v", err)
	}
	if err := s.Admins().UseRecoveryCode(ctx, tenantA, id(1), codes[3], at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UseRecoveryCode of a used code = %v, want ErrNotFound", err)
	}
	if err := s.Admins().UseRecoveryCode(ctx, tenantA, id(1), hashOf("recovery", 99), at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UseRecoveryCode of an unknown code = %v, want ErrNotFound", err)
	}
	if err := s.Admins().UseRecoveryCode(ctx, tenantA, id(2), codes[4], at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UseRecoveryCode of the code of another administrator = %v, want ErrNotFound", err)
	}
	if count, err := s.Admins().CountRecoveryCodes(ctx, tenantA, id(1)); err != nil || count != 9 {
		t.Fatalf("CountRecoveryCodes after a use = %d, %v; want 9", count, err)
	}
	if count, err := s.Admins().CountRecoveryCodes(ctx, tenantA, id(2)); err != nil || count != 0 {
		t.Fatalf("the other administrator has no codes: %d, %v", count, err)
	}

	fresh := append(recoveryHashes(2), hashOf("recovery", 50), hashOf("recovery", 51))
	if err := s.Admins().ReplaceRecoveryCodes(ctx, tenantA, id(1), fresh); err != nil {
		t.Fatalf("second ReplaceRecoveryCodes failed: %v", err)
	}
	if count, err := s.Admins().CountRecoveryCodes(ctx, tenantA, id(1)); err != nil || count != 4 {
		t.Fatalf("CountRecoveryCodes after a replacement = %d, %v; want 4", count, err)
	}
	if err := s.Admins().UseRecoveryCode(ctx, tenantA, id(1), codes[5], at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a code that was replaced still works: %v", err)
	}
	if err := s.Admins().UseRecoveryCode(ctx, tenantA, id(1), fresh[0], at); err != nil {
		t.Fatalf("a code that was in the old and is in the new set must work, because the replacement is new: %v", err)
	}
	if err := s.Admins().ReplaceRecoveryCodes(ctx, tenantA, id(1), nil); err != nil {
		t.Fatalf("ReplaceRecoveryCodes with no codes failed: %v", err)
	}
	if count, err := s.Admins().CountRecoveryCodes(ctx, tenantA, id(1)); err != nil || count != 0 {
		t.Fatalf("CountRecoveryCodes after the removal = %d, %v; want 0", count, err)
	}
	if err := s.Admins().UseRecoveryCode(ctx, tenantA, id(1), fresh[1], at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a code that was removed still works: %v", err)
	}
	if err := s.Admins().UseRecoveryCode(ctx, tenantA, id(1), codes[0], time.Time{}); err == nil || isDomainError(err) {
		t.Fatalf("UseRecoveryCode without a time = %v, want a validation error", err)
	}
}

func testAdminRecoveryCodesInvalidInput(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	kept := recoveryHashes(3)
	if err := s.Admins().ReplaceRecoveryCodes(ctx, tenantA, id(1), kept); err != nil {
		t.Fatal(err)
	}
	bad := map[string][][]byte{
		"a short hash":    {hashOf("recovery", 1)[:31]},
		"a long hash":     {append(hashOf("recovery", 1), 0)},
		"an empty hash":   {nil},
		"a repeated hash": {hashOf("recovery", 1), hashOf("recovery", 2), hashOf("recovery", 1)},
		"too many hashes": recoveryHashes(store.MaxRecoveryCodes + 1),
		"one bad of many": {hashOf("recovery", 1), hashOf("recovery", 2)[:5]},
	}
	for name, hashes := range bad {
		if err := s.Admins().ReplaceRecoveryCodes(ctx, tenantA, id(1), hashes); err == nil || isDomainError(err) {
			t.Errorf("ReplaceRecoveryCodes with %s = %v, want a validation error", name, err)
		}
	}
	if count, err := s.Admins().CountRecoveryCodes(ctx, tenantA, id(1)); err != nil || count != 3 {
		t.Fatalf("a rejected replacement must keep the codes: %d, %v", count, err)
	}
	if err := s.Admins().UseRecoveryCode(ctx, tenantA, id(1), kept[0], adminBase); err != nil {
		t.Fatalf("a code that was kept must work: %v", err)
	}
	if err := s.Admins().ReplaceRecoveryCodes(ctx, tenantA, id(1), recoveryHashes(store.MaxRecoveryCodes)); err != nil {
		t.Fatalf("the most codes that are allowed were rejected: %v", err)
	}
	for _, short := range [][]byte{nil, hashOf("recovery", 0)[:31]} {
		if err := s.Admins().UseRecoveryCode(ctx, tenantA, id(1), short, adminBase); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UseRecoveryCode with a hash of %d bytes = %v, want ErrNotFound", len(short), err)
		}
	}
}

func testAdminRecoveryCodeHashesAreExact(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	odd := []byte{0, 0, 255, 1, 0, 128, 0, 0, 7, 0, 0, 0, 255, 255, 0, 3, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255}
	near := bytes.Clone(odd)
	near[31] = 254
	other := bytes.Clone(odd)
	other[0] = 1
	if err := s.Admins().ReplaceRecoveryCodes(ctx, tenantA, id(1), [][]byte{odd}); err != nil {
		t.Fatal(err)
	}
	for name, hash := range map[string][]byte{"a hash that differs in the last byte": near, "a hash that differs in the first byte": other} {
		if err := s.Admins().UseRecoveryCode(ctx, tenantA, id(1), hash, adminBase); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UseRecoveryCode with %s = %v, want ErrNotFound: hashes are compared byte for byte", name, err)
		}
	}
	if err := s.Admins().UseRecoveryCode(ctx, tenantA, id(1), odd, adminBase); err != nil {
		t.Fatalf("UseRecoveryCode with the exact hash failed: %v", err)
	}
}

func testConcurrentRecoveryCodeUse(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	codes := recoveryHashes(3)
	if err := s.Admins().ReplaceRecoveryCodes(ctx, tenantA, id(1), codes); err != nil {
		t.Fatal(err)
	}
	const racers = 8
	var wins, misses atomic.Int32
	parallel(racers, func(i int) {
		err := s.Admins().UseRecoveryCode(ctx, tenantA, id(1), codes[1], adminBase.Add(time.Duration(i)*time.Second))
		switch {
		case err == nil:
			wins.Add(1)
		case errors.Is(err, store.ErrNotFound):
			misses.Add(1)
		default:
			t.Errorf("racer %d: unexpected error %v", i, err)
		}
	})
	if wins.Load() != 1 || misses.Load() != racers-1 {
		t.Fatalf("%d uses succeeded and %d failed; want exactly 1 and %d: a code is used once", wins.Load(), misses.Load(), racers-1)
	}
	if count, err := s.Admins().CountRecoveryCodes(ctx, tenantA, id(1)); err != nil || count != 2 {
		t.Fatalf("CountRecoveryCodes = %d, %v; want 2", count, err)
	}
}

func testAdminRecoveryCodesFollowTheAdmin(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	if err := s.Admins().ReplaceRecoveryCodes(ctx, tenantA, id(1), recoveryHashes(5)); err != nil {
		t.Fatal(err)
	}
	if err := s.Admins().Delete(ctx, tenantA, id(1)); err != nil {
		t.Fatal(err)
	}
	mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	if count, err := s.Admins().CountRecoveryCodes(ctx, tenantA, id(1)); err != nil || count != 0 {
		t.Fatalf("the codes of an administrator that was deleted came back: %d, %v", count, err)
	}
	if err := s.Admins().UseRecoveryCode(ctx, tenantA, id(1), recoveryHashes(1)[0], adminBase); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a code of an administrator that was deleted works: %v", err)
	}
}

func testAdminRollback(t *testing.T, s store.Store) {
	ctx := t.Context()
	kept := mustCreateAdmin(t, s, newAdmin(tenantA, id(1), "root"))
	if err := s.Admins().ReplaceRecoveryCodes(ctx, tenantA, id(1), recoveryHashes(3)); err != nil {
		t.Fatal(err)
	}
	err := s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if err := tx.Admins().Create(ctx, newAdmin(tenantA, id(2), "second")); err != nil {
			return err
		}
		changed := kept
		changed.PasswordHash = passwordHashOf(9)
		if _, err := tx.Admins().Update(ctx, changed); err != nil {
			return err
		}
		if err := tx.Admins().ReplaceRecoveryCodes(ctx, tenantA, id(1), recoveryHashes(1)); err != nil {
			return err
		}
		if err := tx.Admins().AcceptStep(ctx, tenantA, id(1), 2, 5, adminBase); err != nil {
			return err
		}
		got, err := tx.Admins().Get(ctx, tenantA, id(1))
		if err != nil || got.PasswordHash != passwordHashOf(9) || got.TOTPLastStep != 5 {
			return fmt.Errorf("the transaction must see its own writes: %+v, %w", got, err)
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatalf("InTx = %v, want the error of the function", err)
	}
	if _, getErr := s.Admins().Get(ctx, tenantA, id(2)); !errors.Is(getErr, store.ErrNotFound) {
		t.Fatalf("a rolled back administrator must not exist: %v", getErr)
	}
	got, getErr := s.Admins().Get(ctx, tenantA, id(1))
	if getErr != nil {
		t.Fatal(getErr)
	}
	checkAdmin(t, got, kept)
	if count, countErr := s.Admins().CountRecoveryCodes(ctx, tenantA, id(1)); countErr != nil || count != 3 {
		t.Fatalf("a rolled back replacement must keep the codes: %d, %v", count, countErr)
	}
	err = s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		changed := kept
		changed.PasswordHash = passwordHashOf(8)
		_, updateErr := tx.Admins().Update(ctx, changed)
		return updateErr
	})
	if err != nil {
		t.Fatalf("InTx failed: %v", err)
	}
	if got, getErr = s.Admins().Get(ctx, tenantA, id(1)); getErr != nil || got.PasswordHash != passwordHashOf(8) || got.Version != 2 {
		t.Fatalf("a committed change must be visible: %+v, %v", got, getErr)
	}
}
