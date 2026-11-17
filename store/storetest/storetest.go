// Package storetest holds the compatibility tests of the store interface. The
// built-in stores pass them, and so should every store written by an
// application: run Run from a test and give it a function that returns a new,
// empty store.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

const (
	tenantA = store.DefaultTenant
	tenantB = "second"
)

type testCase struct {
	name  string
	fresh bool
	run   func(t *testing.T, s store.Store)
}

var cases = []testCase{
	{name: "Schema/Migrate is idempotent", run: testMigrateIsIdempotent},
	{name: "Schema/concurrent Migrate", fresh: true, run: testConcurrentMigrate},
	{name: "Users/lifecycle", run: testUserLifecycle},
	{name: "Users/not found", run: testUserNotFound},
	{name: "Users/conflict", run: testUserConflict},
	{name: "Lookups/invalid text is not found", run: testInvalidLookups},
	{name: "Users/optional fields", run: testUserOptionalFields},
	{name: "Users/times are UTC with microseconds", run: testUserTimes},
	{name: "Users/versions", run: testUserVersions},
	{name: "Users/invalid records", run: testInvalidRecords},
	{name: "Users/concurrent updates of one version", run: testConcurrentUpdates},
	{name: "Users/no lost updates", run: testNoLostUpdates},
	{name: "Identifiers/lifecycle", run: testIdentifierLifecycle},
	{name: "Identifiers/errors", run: testIdentifierErrors},
	{name: "Identifiers/MarkVerified at the time it has", run: testMarkVerifiedAtTheTimeItHas},
	{name: "Identifiers/listed in byte order", run: testListByUserIsInByteOrder},
	{name: "Identifiers/values are compared byte by byte", run: testBytewiseValues},
	{name: "Identifiers/deleted with the user", run: testIdentifiersFollowTheUser},
	{name: "Identifiers/concurrent Add of one value", run: testConcurrentAdd},
	{name: "Tenants/isolation", run: testTenantIsolation},
	{name: "Limits/the longest values are stored", run: testLongestValuesAreStored},
	{name: "Limits/the longest Argon2id hash is stored", run: testLongestArgon2idHash},
	{name: "Limits/values over the limit are invalid", run: testValuesOverTheLimitAreInvalid},
	{name: "Limits/signing keys over the limit are invalid", run: testSigningKeyMaterialLimit},
	{name: "Limits/long values are not found", run: testLongValuesAreNotFound},
	{name: "Lookups/empty values are not found", run: testEmptyValuesAreNotFound},
	{name: "Bytes/keys are compared byte by byte", run: testKeysAreComparedByteByByte},
	{name: "Bytes/signing keys are stored exactly", run: testBinaryValuesAreExact},
	{name: "Bytes/hashes are stored exactly", run: testHashesAreExact},
	{name: "Sessions/lifecycle", run: testSessionLifecycle},
	{name: "Sessions/times are UTC with microseconds", run: testSessionTimes},
	{name: "Sessions/conflicts and missing users", run: testSessionConflictsAndMissingUsers},
	{name: "Sessions/invalid records", run: testSessionInvalidRecords},
	{name: "Sessions/lookups that find nothing", run: testSessionLookups},
	{name: "Sessions/resolve shows the current user", run: testSessionResolveShowsTheUser},
	{name: "Sessions/Touch", run: testSessionTouch},
	{name: "Sessions/Revoke", run: testSessionRevoke},
	{name: "Sessions/RevokeAllForUser", run: testSessionRevokeAll},
	{name: "Sessions/ListByUser", run: testSessionList},
	{name: "Sessions/DeleteInactive", run: testSessionDeleteInactive},
	{name: "Sessions/deleted with the user", run: testSessionsFollowTheUser},
	{name: "Sessions/tenant isolation", run: testSessionTenantIsolation},
	{name: "Sessions/concurrent Create with one secret", run: testConcurrentSessionCreate},
	{name: "Sessions/slices are copies", run: testSessionReturnedSlicesAreCopies},
	{name: "RefreshTokens/Use", run: testRefreshTokenUse},
	{name: "RefreshTokens/errors", run: testRefreshTokenErrors},
	{name: "RefreshTokens/concurrent Use of one token", run: testConcurrentRefreshTokenUse},
	{name: "RefreshTokens/concurrent rotation in transactions", run: testConcurrentRefreshTokenRotation},
	{name: "RefreshTokens/rollback", run: testRefreshTokenRollback},
	{name: "RefreshTokens/DeleteExpired", run: testRefreshTokenDeleteExpired},
	{name: "Secrets/link", run: testSecretLink},
	{name: "Secrets/links that are refused", run: testSecretLinkRefusals},
	{name: "Secrets/Add errors", run: testSecretAddErrors},
	{name: "Secrets/TryCodes counts attempts", run: testSecretTryCodes},
	{name: "Secrets/TryCodes refusals", run: testSecretTryCodesRefusals},
	{name: "Secrets/concurrent TryCodes", run: testConcurrentSecretTryCodes},
	{name: "Secrets/UseCode", run: testSecretUseCode},
	{name: "Secrets/concurrent use", run: testConcurrentSecretUse},
	{name: "Secrets/End", run: testSecretEnd},
	{name: "Secrets/DeleteStale", run: testSecretDeleteStale},
	{name: "Secrets/deleted with the user and the channel", run: testSecretsFollowTheirOwners},
	{name: "Secrets/tenant isolation", run: testSecretTenantIsolation},
	{name: "Secrets/rollback", run: testSecretRollback},
	{name: "Secrets/the longest values are stored", run: testSecretLongestValues},
	{name: "Secrets/values over the limit are invalid", run: testSecretValuesOverTheLimit},
	{name: "Secrets/channels are compared byte by byte", run: testSecretChannelsAreComparedByByte},
	{name: "Secrets/hashes are stored exactly", run: testSecretHashesAreExact},
	{name: "Attempts/counting in a window", run: testAttemptsCountInAWindow},
	{name: "Attempts/the window ends", run: testAttemptsWindowEnds},
	{name: "Attempts/holds survive a new window", run: testAttemptsKeepHoldsAcrossWindows},
	{name: "Attempts/Hold", run: testAttemptsHold},
	{name: "Attempts/Get", run: testAttemptsGet},
	{name: "Attempts/Reset", run: testAttemptsReset},
	{name: "Attempts/DeleteStale", run: testAttemptsDeleteStale},
	{name: "Attempts/invalid input", run: testAttemptsInvalidInput},
	{name: "Attempts/concurrent hits count exactly", run: testConcurrentAttemptHits},
	{name: "Attempts/concurrent hits that open a window", run: testConcurrentAttemptWindowRestart},
	{name: "Attempts/concurrent first hits", run: testConcurrentFirstAttemptHits},
	{name: "Attempts/concurrent first hits in transactions", run: testConcurrentFirstAttemptHitsInTransactions},
	{name: "Attempts/rollback", run: testAttemptsRollback},
	{name: "Attempts/hits racing with resets", run: testAttemptHitsAndResets},
	{name: "SigningKeys/lifecycle", run: testSigningKeyLifecycle},
	{name: "SigningKeys/conflicts", run: testSigningKeyConflicts},
	{name: "SigningKeys/invalid records", run: testSigningKeyInvalidRecords},
	{name: "SigningKeys/Retire", run: testSigningKeyRetire},
	{name: "SigningKeys/DeleteRetired", run: testSigningKeyDeleteRetired},
	{name: "SigningKeys/concurrent rotation", run: testConcurrentSigningKeyRotation},
	{name: "SigningKeys/rotation in a transaction", run: testSigningKeyRotationInTransaction},
	{name: "SigningKeys/slices are copies", run: testSigningKeySlicesAreCopies},
	{name: "Settings/lifecycle", run: testSettingLifecycle},
	{name: "Settings/listed in byte order", run: testSettingList},
	{name: "Settings/names are compared byte by byte", run: testSettingNamesAreComparedByteByByte},
	{name: "Settings/invalid records", run: testSettingInvalidRecords},
	{name: "Settings/the longest values are stored", run: testSettingLongestValues},
	{name: "Settings/lookups that find nothing", run: testSettingLookupsThatFindNothing},
	{name: "Settings/tenant isolation", run: testSettingTenantIsolation},
	{name: "Settings/concurrent Set of one name", run: testConcurrentSettingSets},
	{name: "Settings/rollback", run: testSettingRollback},
	{name: "InTx/commit", run: testTxCommit},
	{name: "InTx/rollback on error", run: testTxRollbackOnError},
	{name: "InTx/rollback on panic", run: testTxRollbackOnPanic},
	{name: "InTx/rollback after a conflict", run: testTxRollbackAfterConflict},
	{name: "InTx/concurrent registrations of one identifier", run: testConcurrentTransactions},
	{name: "InTx/Use sees a commit made after the first read", run: testUseSeesACommitAfterTheFirstRead},
	{name: "InTx/Hit sees a commit made after the first read", run: testHitSeesACommitAfterTheFirstRead},
	{name: "InTx/Update tells a missing user from a stale one", run: testUpdateTellsAMissingUserFromAStaleOne},
	{name: "InTx/crossing transactions all succeed", run: testCrossingTransactionsAllSucceed},
	{name: "Context/canceled", run: testCanceledContext},
}

// Run executes the compatibility tests. newStore is called once for every test
// and must return a store that is empty and not shared with other tests.
func Run(t *testing.T, newStore func(t *testing.T) store.Store) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			if !tc.fresh {
				if err := s.Migrate(t.Context()); err != nil {
					t.Fatalf("Migrate failed: %v", err)
				}
			}
			tc.run(t, s)
		})
	}
}

func id(n int) string {
	return fmt.Sprintf("00000000-0000-7000-8000-%012d", n)
}

func newUser(tenant, userID string) store.User {
	return store.User{ //nolint:gosec
		TenantID:     tenant,
		ID:           userID,
		Status:       store.StatusActive,
		PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
		CreatedAt:    time.Date(2026, 3, 4, 5, 6, 7, 123456789, time.UTC),
	}
}

func newIdentifier(tenant, typ, value, userID string) store.Identifier {
	return store.Identifier{TenantID: tenant, Type: typ, Value: value, DisplayValue: value, UserID: userID}
}

func stored(at time.Time) time.Time {
	if at.IsZero() {
		return time.Time{}
	}
	return at.UTC().Truncate(time.Microsecond)
}

func sameTime(got, want time.Time) bool {
	want = stored(want)
	if want.IsZero() {
		return got.IsZero()
	}
	return got.Equal(want) && got.Location() == time.UTC
}

func checkUser(t *testing.T, got, want store.User) {
	t.Helper()
	switch {
	case got.TenantID != want.TenantID, got.ID != want.ID, got.Status != want.Status,
		got.PasswordHash != want.PasswordHash, got.MustChangePassword != want.MustChangePassword,
		got.BlockedReason != want.BlockedReason, got.Version != want.Version:
		t.Fatalf("user differs:\n got %+v\nwant %+v", got, want)
	case !sameTime(got.BlockedUntil, want.BlockedUntil), !sameTime(got.DeletedAt, want.DeletedAt),
		!sameTime(got.PurgeAfter, want.PurgeAfter), !sameTime(got.CreatedAt, want.CreatedAt),
		!sameTime(got.LastLoginAt, want.LastLoginAt):
		t.Fatalf("user times differ, they must be UTC with microsecond precision:\n got %+v\nwant %+v", got, want)
	}
}

func checkIdentifier(t *testing.T, got, want store.Identifier) {
	t.Helper()
	if got.TenantID != want.TenantID || got.Type != want.Type || got.Value != want.Value ||
		got.DisplayValue != want.DisplayValue || got.UserID != want.UserID || !sameTime(got.VerifiedAt, want.VerifiedAt) {
		t.Fatalf("identifier differs:\n got %+v\nwant %+v", got, want)
	}
}

func mustCreate(t *testing.T, s store.Store, u store.User) store.User {
	t.Helper()
	if err := s.Users().Create(t.Context(), u); err != nil {
		t.Fatalf("Create(%s) failed: %v", u.ID, err)
	}
	got, err := s.Users().Get(t.Context(), u.TenantID, u.ID)
	if err != nil {
		t.Fatalf("Get(%s) failed: %v", u.ID, err)
	}
	return got
}

func mustAdd(t *testing.T, s store.Store, i store.Identifier) {
	t.Helper()
	if err := s.Identifiers().Add(t.Context(), i); err != nil {
		t.Fatalf("Add(%s %q) failed: %v", i.Type, i.Value, err)
	}
}

func isDomainError(err error) bool {
	return errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrStale)
}

func parallel(n int, fn func(i int)) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Go(func() {
			<-start
			fn(i)
		})
	}
	close(start)
	wg.Wait()
}

func testMigrateIsIdempotent(t *testing.T, s store.Store) {
	ctx := t.Context()
	first, err := s.SchemaVersion(ctx)
	if err != nil || first < 1 {
		t.Fatalf("SchemaVersion after Migrate = %d, %v; want a positive version and no error", first, err)
	}
	if err = s.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate failed: %v", err)
	}
	second, err := s.SchemaVersion(ctx)
	if err != nil || second != first {
		t.Fatalf("SchemaVersion changed from %d to %d (%v)", first, second, err)
	}
}

func testConcurrentMigrate(t *testing.T, s store.Store) {
	ctx := t.Context()
	version, err := s.SchemaVersion(ctx)
	if version != 0 || !errors.Is(err, store.ErrSchemaOutdated) {
		t.Fatalf("SchemaVersion of an empty database = %d, %v; want 0 and ErrSchemaOutdated", version, err)
	}
	errs := make([]error, 8)
	parallel(len(errs), func(i int) {
		errs[i] = s.Migrate(ctx)
	})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Migrate #%d failed: %v", i, err)
		}
	}
	if version, err = s.SchemaVersion(ctx); err != nil || version < 1 {
		t.Fatalf("SchemaVersion after concurrent Migrate = %d, %v", version, err)
	}
	mustCreate(t, s, newUser(tenantA, id(1)))
}

func testUserLifecycle(t *testing.T, s store.Store) {
	ctx := t.Context()
	users := s.Users()
	want := newUser(tenantA, id(1))
	got := mustCreate(t, s, want)
	want.Version = 1
	checkUser(t, got, want)

	plus3 := time.FixedZone("UTC+3", 3*60*60)
	blocked := got
	blocked.Status = store.StatusBlocked
	blocked.PasswordHash = "$changed$"
	blocked.MustChangePassword = true
	blocked.BlockedReason = "repeated abuse reports"
	blocked.BlockedUntil = time.Date(2027, 1, 2, 3, 4, 5, 987654321, plus3)
	blocked.LastLoginAt = time.Date(2026, 5, 6, 7, 8, 9, 555555555, plus3)
	updated, err := users.Update(ctx, blocked)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	blocked.Version = 2
	checkUser(t, updated, blocked)
	reread, err := users.Get(ctx, tenantA, id(1))
	if err != nil {
		t.Fatal(err)
	}
	checkUser(t, reread, blocked)

	deleted := reread
	deleted.Status = store.StatusDeleted
	deleted.BlockedReason = ""
	deleted.BlockedUntil = time.Time{}
	deleted.DeletedAt = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	deleted.PurgeAfter = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if _, err = users.Update(ctx, deleted); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	deleted.Version = 3
	reread, err = users.Get(ctx, tenantA, id(1))
	if err != nil {
		t.Fatal(err)
	}
	checkUser(t, reread, deleted)

	if err = users.Delete(ctx, tenantA, id(1)); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err = users.Get(ctx, tenantA, id(1)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
}

func testUserNotFound(t *testing.T, s store.Store) {
	ctx := t.Context()
	if _, err := s.Users().Get(ctx, tenantA, id(1)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get = %v, want ErrNotFound", err)
	}
	missing := newUser(tenantA, id(1))
	missing.Version = 1
	if _, err := s.Users().Update(ctx, missing); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Update = %v, want ErrNotFound", err)
	}
	if err := s.Users().Delete(ctx, tenantA, id(1)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete = %v, want ErrNotFound", err)
	}
}

func testInvalidLookups(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	for _, bad := range []string{"a\x00b", "a\xffb"} {
		if _, err := s.Users().Get(ctx, bad, id(1)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get with tenant %q = %v, want ErrNotFound", bad, err)
		}
		if _, err := s.Users().Get(ctx, tenantA, bad); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get with id %q = %v, want ErrNotFound", bad, err)
		}
		if err := s.Users().Delete(ctx, tenantA, bad); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete with id %q = %v, want ErrNotFound", bad, err)
		}
		if _, err := s.Identifiers().Find(ctx, tenantA, "email", bad); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Find with value %q = %v, want ErrNotFound", bad, err)
		}
		if _, err := s.Identifiers().Find(ctx, tenantA, bad, "a@example.com"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Find with type %q = %v, want ErrNotFound", bad, err)
		}
		if err := s.Identifiers().Remove(ctx, tenantA, "email", bad); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Remove with value %q = %v, want ErrNotFound", bad, err)
		}
		if err := s.Identifiers().MarkVerified(ctx, tenantA, "email", bad, time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("MarkVerified with value %q = %v, want ErrNotFound", bad, err)
		}
		if list, err := s.Identifiers().ListByUser(ctx, tenantA, bad); err != nil || len(list) != 0 {
			t.Errorf("ListByUser with user %q = %v, %v; want an empty list", bad, list, err)
		}
	}
}

func testUserConflict(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	if err := s.Users().Create(ctx, newUser(tenantA, id(1))); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second Create = %v, want ErrConflict", err)
	}
	mustCreate(t, s, newUser(tenantB, id(1)))
}

func testUserOptionalFields(t *testing.T, s store.Store) {
	bare := store.User{
		TenantID:  tenantA,
		ID:        id(1),
		Status:    store.StatusActive,
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	got := mustCreate(t, s, bare)
	bare.Version = 1
	checkUser(t, got, bare)
	if got.PasswordHash != "" || got.BlockedReason != "" || !got.BlockedUntil.IsZero() || !got.DeletedAt.IsZero() ||
		!got.PurgeAfter.IsZero() || !got.LastLoginAt.IsZero() || got.MustChangePassword {
		t.Fatalf("unset fields must come back unset: %+v", got)
	}
}

func testUserTimes(t *testing.T, s store.Store) {
	west := time.FixedZone("UTC-7", -7*60*60)
	u := newUser(tenantA, id(1))
	u.CreatedAt = time.Date(2026, 12, 31, 23, 59, 59, 999999999, west)
	u.LastLoginAt = time.Date(2026, 2, 28, 12, 0, 0, 1500, time.UTC)
	got := mustCreate(t, s, u)
	if !got.CreatedAt.Equal(time.Date(2027, 1, 1, 6, 59, 59, 999999000, time.UTC)) || got.CreatedAt.Location() != time.UTC {
		t.Fatalf("CreatedAt = %v (%v), want the same instant in UTC cut to microseconds", got.CreatedAt, got.CreatedAt.Location())
	}
	if !got.LastLoginAt.Equal(time.Date(2026, 2, 28, 12, 0, 0, 1000, time.UTC)) {
		t.Fatalf("LastLoginAt = %v, want nanoseconds below one microsecond dropped", got.LastLoginAt)
	}
	i := newIdentifier(tenantA, "email", "a@example.com", id(1))
	i.VerifiedAt = time.Date(2026, 4, 5, 6, 7, 8, 123456789, west)
	mustAdd(t, s, i)
	found, err := s.Identifiers().Find(t.Context(), tenantA, "email", "a@example.com")
	if err != nil {
		t.Fatal(err)
	}
	checkIdentifier(t, found, i)
}

func testUserVersions(t *testing.T, s store.Store) {
	ctx := t.Context()
	first := mustCreate(t, s, newUser(tenantA, id(1)))
	if first.Version != 1 {
		t.Fatalf("a new user must have version 1, got %d", first.Version)
	}
	changed := first
	changed.LastLoginAt = time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC)
	second, err := s.Users().Update(ctx, changed)
	if err != nil || second.Version != 2 {
		t.Fatalf("Update = version %d, %v; want version 2", second.Version, err)
	}
	if _, err = s.Users().Update(ctx, changed); !errors.Is(err, store.ErrStale) {
		t.Fatalf("Update with an old version = %v, want ErrStale", err)
	}
	third, err := s.Users().Update(ctx, second)
	if err != nil || third.Version != 3 {
		t.Fatalf("Update = version %d, %v; want version 3", third.Version, err)
	}
	moved := third
	moved.CreatedAt = third.CreatedAt.Add(24 * time.Hour)
	if _, err = s.Users().Update(ctx, moved); err != nil {
		t.Fatal(err)
	}
	reread, err := s.Users().Get(ctx, tenantA, id(1))
	if err != nil {
		t.Fatal(err)
	}
	if !sameTime(reread.CreatedAt, first.CreatedAt) {
		t.Fatalf("Update must not change CreatedAt: %v became %v", first.CreatedAt, reread.CreatedAt)
	}
	if reread.Version != 4 {
		t.Fatalf("version = %d, want 4", reread.Version)
	}
	forced := reread
	forced.Version = 1
	if _, err = s.Users().Update(ctx, forced); !errors.Is(err, store.ErrStale) {
		t.Fatalf("Update with a made up version = %v, want ErrStale", err)
	}
	created := newUser(tenantA, id(2))
	created.Version = 41
	if got := mustCreate(t, s, created); got.Version != 1 {
		t.Fatalf("Create must store version 1 whatever the record says, got %d", got.Version)
	}
}

func testInvalidRecords(t *testing.T, s store.Store) {
	ctx := t.Context()
	noTenant := newUser("", id(1))
	noID := newUser(tenantA, "")
	badStatus := newUser(tenantA, id(1))
	badStatus.Status = "frozen"
	noCreated := newUser(tenantA, id(1))
	noCreated.CreatedAt = time.Time{}
	nulByte := newUser(tenantA, id(1))
	nulByte.PasswordHash = "a\x00b"
	badUTF8 := newUser(tenantA, id(1))
	badUTF8.BlockedReason = "a\xffb"
	for name, u := range map[string]store.User{
		"no tenant": noTenant, "no id": noID, "unknown status": badStatus,
		"no creation time": noCreated, "NUL byte": nulByte, "invalid UTF-8": badUTF8,
	} {
		if err := s.Users().Create(ctx, u); err == nil || isDomainError(err) {
			t.Errorf("Create with %s = %v, want a validation error", name, err)
		}
	}
	if _, err := s.Users().Get(ctx, tenantA, id(1)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a rejected user must not be stored, Get = %v", err)
	}
	mustCreate(t, s, newUser(tenantA, id(1)))
	for name, i := range map[string]store.Identifier{
		"no tenant": newIdentifier("", "email", "a@x", id(1)),
		"no type":   newIdentifier(tenantA, "", "a@x", id(1)),
		"no value":  newIdentifier(tenantA, "email", "", id(1)),
		"no user":   newIdentifier(tenantA, "email", "a@x", ""),
		"NUL byte":  newIdentifier(tenantA, "email", "a\x00@x", id(1)),
	} {
		if err := s.Identifiers().Add(ctx, i); err == nil || isDomainError(err) {
			t.Errorf("Add with %s = %v, want a validation error", name, err)
		}
	}
	noDisplay := newIdentifier(tenantA, "email", "a@x", id(1))
	noDisplay.DisplayValue = ""
	if err := s.Identifiers().Add(ctx, noDisplay); err == nil || isDomainError(err) {
		t.Errorf("Add without a display value = %v, want a validation error", err)
	}
	if list, err := s.Identifiers().ListByUser(ctx, tenantA, id(1)); err != nil || len(list) != 0 {
		t.Fatalf("rejected identifiers must not be stored: %v, %v", list, err)
	}
}

func testConcurrentUpdates(t *testing.T, s store.Store) {
	ctx := t.Context()
	base := mustCreate(t, s, newUser(tenantA, id(1)))
	const writers = 8
	var wins, stale atomic.Int32
	var mu sync.Mutex
	winner := -1
	parallel(writers, func(i int) {
		u := base
		u.BlockedReason = fmt.Sprintf("writer %d", i)
		_, err := s.Users().Update(ctx, u)
		switch {
		case err == nil:
			wins.Add(1)
			mu.Lock()
			winner = i
			mu.Unlock()
		case errors.Is(err, store.ErrStale):
			stale.Add(1)
		default:
			t.Errorf("writer %d: unexpected error %v", i, err)
		}
	})
	if wins.Load() != 1 || stale.Load() != writers-1 {
		t.Fatalf("%d updates succeeded and %d were stale; want exactly 1 and %d", wins.Load(), stale.Load(), writers-1)
	}
	got, err := s.Users().Get(ctx, tenantA, id(1))
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 2 || got.BlockedReason != fmt.Sprintf("writer %d", winner) {
		t.Fatalf("stored %q at version %d, want the result of writer %d at version 2", got.BlockedReason, got.Version, winner)
	}
}

func testNoLostUpdates(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	const writers = 6
	parallel(writers, func(int) {
		for range 200 {
			current, err := s.Users().Get(ctx, tenantA, id(1))
			if err != nil {
				t.Errorf("Get failed: %v", err)
				return
			}
			current.BlockedReason += "x"
			if _, err = s.Users().Update(ctx, current); err == nil {
				return
			} else if !errors.Is(err, store.ErrStale) {
				t.Errorf("Update failed: %v", err)
				return
			}
		}
		t.Errorf("an update kept being stale")
	})
	got, err := s.Users().Get(ctx, tenantA, id(1))
	if err != nil {
		t.Fatal(err)
	}
	if got.BlockedReason != strings.Repeat("x", writers) || got.Version != writers+1 {
		t.Fatalf("got %d appended characters at version %d, want %d at version %d", len(got.BlockedReason), got.Version, writers, writers+1)
	}
}

func testIdentifierLifecycle(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	email := store.Identifier{TenantID: tenantA, Type: "email", Value: "alice@example.com", DisplayValue: "Alice@Example.com", UserID: id(1)}
	phone := newIdentifier(tenantA, "phone", "+79261234567", id(1))
	nick := newIdentifier(tenantA, "email", "alice@work.example", id(1))
	for _, i := range []store.Identifier{phone, email, nick} {
		mustAdd(t, s, i)
	}
	found, err := s.Identifiers().Find(ctx, tenantA, "email", "alice@example.com")
	if err != nil {
		t.Fatalf("Find failed: %v", err)
	}
	checkIdentifier(t, found, email)

	list, err := s.Identifiers().ListByUser(ctx, tenantA, id(1))
	if err != nil || len(list) != 3 {
		t.Fatalf("ListByUser = %v, %v; want 3 identifiers", list, err)
	}
	for n, want := range []store.Identifier{email, nick, phone} {
		checkIdentifier(t, list[n], want)
	}

	verifiedAt := time.Date(2026, 8, 9, 10, 11, 12, 345678901, time.FixedZone("UTC+5", 5*60*60))
	if err = s.Identifiers().MarkVerified(ctx, tenantA, "email", "alice@example.com", verifiedAt); err != nil {
		t.Fatalf("MarkVerified failed: %v", err)
	}
	email.VerifiedAt = verifiedAt
	if found, err = s.Identifiers().Find(ctx, tenantA, "email", "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	checkIdentifier(t, found, email)
	later := verifiedAt.Add(time.Hour)
	if err = s.Identifiers().MarkVerified(ctx, tenantA, "email", "alice@example.com", later); err != nil {
		t.Fatal(err)
	}
	if found, err = s.Identifiers().Find(ctx, tenantA, "email", "alice@example.com"); err != nil || !sameTime(found.VerifiedAt, later) {
		t.Fatalf("a repeated MarkVerified must record the new time: %+v, %v", found, err)
	}

	if err = s.Identifiers().Remove(ctx, tenantA, "email", "alice@example.com"); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}
	if _, err = s.Identifiers().Find(ctx, tenantA, "email", "alice@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find after Remove = %v, want ErrNotFound", err)
	}
	mustAdd(t, s, email)
}

func testMarkVerifiedAtTheTimeItHas(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	mustAdd(t, s, newIdentifier(tenantA, "email", "a@example.com", id(1)))
	at := sessionBase
	sameInstant := []time.Time{
		at, at,
		at.In(time.FixedZone("UTC+3", 3*60*60)),
		at.Add(100 * time.Nanosecond),
	}
	for n, moment := range sameInstant {
		if err := s.Identifiers().MarkVerified(ctx, tenantA, "email", "a@example.com", moment); err != nil {
			t.Fatalf("MarkVerified %d at the time the identifier has = %v, want nil", n+1, err)
		}
		found, err := s.Identifiers().Find(ctx, tenantA, "email", "a@example.com")
		if err != nil || !sameTime(found.VerifiedAt, at) {
			t.Fatalf("after MarkVerified %d the identifier = %+v, %v; want it verified at %v", n+1, found, err, at)
		}
	}
	if err := s.Identifiers().MarkVerified(ctx, tenantA, "email", "missing@example.com", at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("MarkVerified of a missing identifier = %v, want ErrNotFound", err)
	}
}

func testIdentifierErrors(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	mustCreate(t, s, newUser(tenantA, id(2)))
	mustAdd(t, s, newIdentifier(tenantA, "email", "a@example.com", id(1)))

	if err := s.Identifiers().Add(ctx, newIdentifier(tenantA, "email", "a@example.com", id(1))); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Add of a taken value for the same user = %v, want ErrConflict", err)
	}
	if err := s.Identifiers().Add(ctx, newIdentifier(tenantA, "email", "a@example.com", id(2))); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Add of a taken value for another user = %v, want ErrConflict", err)
	}
	mustAdd(t, s, newIdentifier(tenantA, "phone", "a@example.com", id(2)))
	if err := s.Identifiers().Add(ctx, newIdentifier(tenantA, "email", "b@example.com", id(99))); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Add for an unknown user = %v, want ErrNotFound", err)
	}
	if _, err := s.Identifiers().Find(ctx, tenantA, "email", "missing@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find = %v, want ErrNotFound", err)
	}
	if _, err := s.Identifiers().Find(ctx, tenantA, "phone", "b@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find in another type = %v, want ErrNotFound", err)
	}
	if err := s.Identifiers().Remove(ctx, tenantA, "email", "missing@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Remove = %v, want ErrNotFound", err)
	}
	if err := s.Identifiers().MarkVerified(ctx, tenantA, "email", "missing@example.com", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("MarkVerified = %v, want ErrNotFound", err)
	}
	list, err := s.Identifiers().ListByUser(ctx, tenantA, id(99))
	if err != nil || len(list) != 0 {
		t.Fatalf("ListByUser of an unknown user = %v, %v; want an empty list", list, err)
	}
}

func testListByUserIsInByteOrder(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	mustCreate(t, s, newUser(tenantA, id(2)))
	given := []store.Identifier{
		newIdentifier(tenantA, "nick", "ab", id(1)),
		newIdentifier(tenantA, "nick", "\u044f", id(1)),
		newIdentifier(tenantA, "email", "z@example.com", id(1)),
		newIdentifier(tenantA, "nick", "Z", id(1)),
		newIdentifier(tenantA, "nick", "a-c", id(1)),
		newIdentifier(tenantA, "Phone", "+79261234567", id(1)),
		newIdentifier(tenantA, "nick", "\u00e9", id(1)),
		newIdentifier(tenantA, "nick", "a", id(1)),
		newIdentifier(tenantA, "email", "A@example.com", id(1)),
		newIdentifier(tenantA, "nick", "B", id(1)),
		newIdentifier(tenantA, "nick", "of-another-user", id(2)),
	}
	for _, i := range given {
		mustAdd(t, s, i)
	}
	want := [][2]string{
		{"Phone", "+79261234567"},
		{"email", "A@example.com"},
		{"email", "z@example.com"},
		{"nick", "B"},
		{"nick", "Z"},
		{"nick", "a"},
		{"nick", "a-c"},
		{"nick", "ab"},
		{"nick", "\u00e9"},
		{"nick", "\u044f"},
	}
	list, err := s.Identifiers().ListByUser(ctx, tenantA, id(1))
	if err != nil {
		t.Fatal(err)
	}
	got := make([][2]string, 0, len(list))
	for _, i := range list {
		got = append(got, [2]string{i.Type, i.Value})
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ListByUser must return the identifiers in byte order, whatever the collation of the database is:\n got %q\nwant %q", got, want)
	}
}

func testBytewiseValues(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	values := []string{
		"alice", "Alice", "ALICE", "alice ", " alice", "alice\u00a0", "alice\t",
		"café", "cafe\u0301", "straße", "strasse", "\u0430dmin", "admin",
		"ǅ", "ǆ", "a_b", "a%b", "axb", "a\\b", "100%", "x\u202e", strings.Repeat("y", store.MaxIdentifierValueLength),
	}
	for _, v := range values {
		mustAdd(t, s, newIdentifier(tenantA, "nick", v, id(1)))
	}
	for _, v := range values {
		found, err := s.Identifiers().Find(ctx, tenantA, "nick", v)
		if err != nil {
			t.Fatalf("Find(%q) failed: %v", v, err)
		}
		if found.Value != v || found.DisplayValue != v {
			t.Fatalf("Find(%q) returned %q: values must be stored and compared byte by byte", v, found.Value)
		}
	}
	list, err := s.Identifiers().ListByUser(ctx, tenantA, id(1))
	if err != nil || len(list) != len(values) {
		t.Fatalf("ListByUser returned %d identifiers, %v; want %d", len(list), err, len(values))
	}
	for _, v := range []string{"alicE", "alice  ", "CAFÉ", "STRASSE", "\u0410dmin"} {
		if _, err = s.Identifiers().Find(ctx, tenantA, "nick", v); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Find(%q) = %v, want ErrNotFound: only exact values match", v, err)
		}
	}
}

func testIdentifiersFollowTheUser(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	mustCreate(t, s, newUser(tenantA, id(2)))
	mustAdd(t, s, newIdentifier(tenantA, "email", "one@example.com", id(1)))
	mustAdd(t, s, newIdentifier(tenantA, "phone", "+79261234567", id(1)))
	mustAdd(t, s, newIdentifier(tenantA, "email", "two@example.com", id(2)))
	if err := s.Users().Delete(ctx, tenantA, id(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Identifiers().Find(ctx, tenantA, "email", "one@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an identifier must go with its user, Find = %v", err)
	}
	if list, err := s.Identifiers().ListByUser(ctx, tenantA, id(1)); err != nil || len(list) != 0 {
		t.Fatalf("ListByUser after Delete = %v, %v", list, err)
	}
	if _, err := s.Identifiers().Find(ctx, tenantA, "email", "two@example.com"); err != nil {
		t.Fatalf("identifiers of other users must stay: %v", err)
	}
	mustAdd(t, s, newIdentifier(tenantA, "email", "one@example.com", id(2)))
}

func testConcurrentAdd(t *testing.T, s store.Store) {
	ctx := t.Context()
	const racers = 8
	for n := range racers {
		mustCreate(t, s, newUser(tenantA, id(n+1)))
	}
	var wins, conflicts atomic.Int32
	parallel(racers, func(i int) {
		err := s.Identifiers().Add(ctx, newIdentifier(tenantA, "email", "race@example.com", id(i+1)))
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
		t.Fatalf("%d adds succeeded and %d conflicted; want exactly 1 and %d", wins.Load(), conflicts.Load(), racers-1)
	}
}

func testTenantIsolation(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	mustCreate(t, s, newUser(tenantB, id(1)))
	mustAdd(t, s, newIdentifier(tenantA, "email", "same@example.com", id(1)))
	mustAdd(t, s, newIdentifier(tenantB, "email", "same@example.com", id(1)))
	if err := s.Identifiers().Add(ctx, newIdentifier(tenantB, "email", "other@example.com", id(2))); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Add for a user of no tenant = %v, want ErrNotFound", err)
	}
	mustCreate(t, s, newUser(tenantA, id(2)))
	if err := s.Identifiers().Add(ctx, newIdentifier(tenantB, "email", "cross@example.com", id(2))); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Add must not attach an identifier to a user of another tenant, got %v", err)
	}

	blockedB := mustCreate(t, s, newUser("third", id(1)))
	blockedB.Status = store.StatusBlocked
	if _, err := s.Users().Update(ctx, blockedB); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Users().Get(ctx, tenantA, id(1)); err != nil || got.Status != store.StatusActive {
		t.Fatalf("an update in one tenant must not touch another: %+v, %v", got, err)
	}

	if err := s.Users().Delete(ctx, tenantA, id(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Users().Get(ctx, tenantB, id(1)); err != nil {
		t.Fatalf("Delete in one tenant removed a user of another: %v", err)
	}
	if _, err := s.Identifiers().Find(ctx, tenantB, "email", "same@example.com"); err != nil {
		t.Fatalf("Delete in one tenant removed an identifier of another: %v", err)
	}
	if _, err := s.Identifiers().Find(ctx, tenantA, "email", "same@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find = %v, want ErrNotFound", err)
	}
	if list, err := s.Identifiers().ListByUser(ctx, tenantA, id(1)); err != nil || len(list) != 0 {
		t.Fatalf("ListByUser = %v, %v; want an empty list", list, err)
	}
	if list, err := s.Identifiers().ListByUser(ctx, tenantB, id(1)); err != nil || len(list) != 1 {
		t.Fatalf("ListByUser = %v, %v; want the identifier of the other tenant", list, err)
	}
}

func testTxCommit(t *testing.T, s store.Store) {
	ctx := t.Context()
	err := s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if err := tx.Users().Create(ctx, newUser(tenantA, id(1))); err != nil {
			return err
		}
		if err := tx.Identifiers().Add(ctx, newIdentifier(tenantA, "email", "tx@example.com", id(1))); err != nil {
			return err
		}
		if _, err := tx.Users().Get(ctx, tenantA, id(1)); err != nil {
			return fmt.Errorf("the transaction must see its own writes: %w", err)
		}
		found, err := tx.Identifiers().Find(ctx, tenantA, "email", "tx@example.com")
		if err != nil || found.UserID != id(1) {
			return fmt.Errorf("the transaction must see its own identifier: %+v, %w", found, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("InTx failed: %v", err)
	}
	if _, err = s.Users().Get(ctx, tenantA, id(1)); err != nil {
		t.Fatalf("a committed user must be visible: %v", err)
	}
	if _, err = s.Identifiers().Find(ctx, tenantA, "email", "tx@example.com"); err != nil {
		t.Fatalf("a committed identifier must be visible: %v", err)
	}
}

var errRollback = errors.New("roll back")

func testTxRollbackOnError(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(9)))
	err := s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if err := tx.Users().Create(ctx, newUser(tenantA, id(1))); err != nil {
			return err
		}
		if err := tx.Identifiers().Add(ctx, newIdentifier(tenantA, "email", "tx@example.com", id(1))); err != nil {
			return err
		}
		if err := tx.Users().Delete(ctx, tenantA, id(9)); err != nil {
			return err
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatalf("InTx = %v, want the error of the function", err)
	}
	if _, err = s.Users().Get(ctx, tenantA, id(1)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a rolled back user must not exist, Get = %v", err)
	}
	if _, err = s.Identifiers().Find(ctx, tenantA, "email", "tx@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a rolled back identifier must not exist, Find = %v", err)
	}
	if _, err = s.Users().Get(ctx, tenantA, id(9)); err != nil {
		t.Fatalf("a rolled back delete must leave the user: %v", err)
	}
}

func testTxRollbackOnPanic(t *testing.T, s store.Store) {
	ctx := t.Context()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("InTx must let a panic of the function through")
			}
		}()
		_ = s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
			if err := tx.Users().Create(ctx, newUser(tenantA, id(1))); err != nil {
				return err
			}
			panic("boom")
		})
	}()
	if _, err := s.Users().Get(ctx, tenantA, id(1)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a user created before a panic must be rolled back, Get = %v", err)
	}
	mustCreate(t, s, newUser(tenantA, id(1)))
}

func testTxRollbackAfterConflict(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	mustAdd(t, s, newIdentifier(tenantA, "email", "taken@example.com", id(1)))
	err := s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if err := tx.Users().Create(ctx, newUser(tenantA, id(2))); err != nil {
			return err
		}
		return tx.Identifiers().Add(ctx, newIdentifier(tenantA, "email", "taken@example.com", id(2)))
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("InTx = %v, want ErrConflict from the function", err)
	}
	if _, err = s.Users().Get(ctx, tenantA, id(2)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the user of a failed registration must not exist, Get = %v", err)
	}
	if err = s.Users().Create(ctx, newUser(tenantA, id(2))); err != nil {
		t.Fatalf("the store must be usable after a failed transaction: %v", err)
	}
}

func testConcurrentTransactions(t *testing.T, s store.Store) {
	ctx := t.Context()
	const racers = 8
	var wins, conflicts atomic.Int32
	parallel(racers, func(i int) {
		err := s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
			if err := tx.Users().Create(ctx, newUser(tenantA, id(i+1))); err != nil {
				return err
			}
			time.Sleep(10 * time.Millisecond)
			return tx.Identifiers().Add(ctx, newIdentifier(tenantA, "email", "race@example.com", id(i+1)))
		})
		switch {
		case err == nil:
			wins.Add(1)
		case errors.Is(err, store.ErrConflict):
			conflicts.Add(1)
		default:
			t.Errorf("transaction %d: unexpected error %v", i, err)
		}
	})
	if wins.Load() != 1 || conflicts.Load() != racers-1 {
		t.Fatalf("%d transactions committed and %d conflicted; want exactly 1 and %d", wins.Load(), conflicts.Load(), racers-1)
	}
	found, err := s.Identifiers().Find(ctx, tenantA, "email", "race@example.com")
	if err != nil {
		t.Fatal(err)
	}
	survivors := 0
	for n := range racers {
		if _, err = s.Users().Get(ctx, tenantA, id(n+1)); err == nil {
			survivors++
			if id(n+1) != found.UserID {
				t.Fatalf("user %s survived but the identifier belongs to %s", id(n+1), found.UserID)
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
	}
	if survivors != 1 {
		t.Fatalf("%d users exist, want only the user of the winning transaction", survivors)
	}
}

func testCanceledContext(t *testing.T, s store.Store) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.Users().Get(ctx, tenantA, id(1)); !errors.Is(err, context.Canceled) {
		t.Errorf("Get = %v, want context.Canceled", err)
	}
	if err := s.Users().Create(ctx, newUser(tenantA, id(1))); !errors.Is(err, context.Canceled) {
		t.Errorf("Create = %v, want context.Canceled", err)
	}
	if _, err := s.Identifiers().Find(ctx, tenantA, "email", "a@example.com"); !errors.Is(err, context.Canceled) {
		t.Errorf("Find = %v, want context.Canceled", err)
	}
	if err := s.InTx(ctx, func(context.Context, store.Repositories) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Errorf("InTx = %v, want context.Canceled", err)
	}
	if _, err := s.Users().Get(t.Context(), tenantA, id(1)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a canceled Create must not store anything, Get = %v", err)
	}
}
