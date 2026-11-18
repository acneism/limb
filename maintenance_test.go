package limb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func userRecord(n int, edit func(*store.User)) store.User {
	u := store.User{
		TenantID: store.DefaultTenant, ID: fmt.Sprintf("00000000-0000-7000-8000-%012d", 7000+n), Status: store.StatusActive,
		PasswordHash: "x", CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	edit(&u)
	return u
}

func (f *sessionFixture) put(t *testing.T, u store.User, identifiers ...store.Identifier) {
	t.Helper()
	if err := f.a.store.Users().Create(t.Context(), u); err != nil {
		t.Fatal(err)
	}
	for _, i := range identifiers {
		i.TenantID, i.UserID = u.TenantID, u.ID
		if err := f.a.store.Identifiers().Add(t.Context(), i); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *sessionFixture) setUser(t *testing.T, id string, edit func(*store.User)) {
	t.Helper()
	u, err := f.a.store.Users().Get(t.Context(), f.a.tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	edit(&u)
	if _, err = f.a.store.Users().Update(t.Context(), u); err != nil {
		t.Fatal(err)
	}
}

func (f *sessionFixture) userExists(t *testing.T, id string) bool {
	t.Helper()
	_, err := f.a.store.Users().Get(t.Context(), f.a.tenant, id)
	switch {
	case err == nil:
		return true
	case errors.Is(err, store.ErrNotFound):
		return false
	}
	t.Fatal(err)
	return false
}

func TestCleanupRemovesTheSessionsOfAdministratorsThatEndedADayAgo(t *testing.T) {
	f := newSessionFixture(t)
	if _, err := f.a.Admin().CreateAdmin(t.Context(), "root", adminPassword); err != nil {
		t.Fatal(err)
	}
	root, err := f.a.store.Admins().FindByLogin(t.Context(), f.a.tenant, "root")
	if err != nil {
		t.Fatal(err)
	}
	now := f.clock.now().UTC().Truncate(time.Microsecond)
	session := func(n uint16, expires, seen time.Time) {
		s := store.AdminSession{
			TenantID: f.a.tenant, ID: fmt.Sprintf("00000000-0000-7000-8000-%012d", 8000+int(n)), AdminID: root.ID, Stage: store.AdminStageFull,
			SecretHash: hashFor(n), AdminVersion: root.Version, CreatedAt: now.Add(-72 * time.Hour), LastSeenAt: seen, ExpiresAt: expires,
		}
		if createErr := f.a.store.AdminSessions().Create(t.Context(), s); createErr != nil {
			t.Fatal(createErr)
		}
	}
	session(1, now.Add(-25*time.Hour), now.Add(-26*time.Hour))
	session(2, now.Add(-23*time.Hour), now.Add(-23*time.Hour))
	session(3, now.Add(6*time.Hour), now.Add(-25*time.Hour-adminSessionIdle))
	session(4, now.Add(6*time.Hour), now.Add(-time.Hour))
	if err = f.a.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	for n, want := range map[uint16]bool{1: false, 2: true, 3: false, 4: true} {
		_, resolveErr := f.a.store.AdminSessions().ResolveBySecret(t.Context(), f.a.tenant, hashFor(n))
		if got := resolveErr == nil; got != want {
			t.Errorf("the session %d is there = %v, want %v", n, got, want)
		}
	}
}

func auditRecordAt(n int, at time.Time) store.AuditRecord {
	return store.AuditRecord{
		TenantID: store.DefaultTenant, ID: fmt.Sprintf("00000000-0000-7000-8000-%012d", 9000+n), At: at,
		ActorKind: store.ActorSystem, ActorID: "test", Action: "test.action",
	}
}

func TestCleanupRemovesTheRecordsOfTheAuditLogThatAreOldEnough(t *testing.T) {
	logger, logs := capturingLogger()
	f := newSessionFixture(t, WithLogger(logger))
	now := f.clock.now().UTC().Truncate(time.Microsecond)
	cutoff := now.Add(-365 * 24 * time.Hour)
	const old = 1250
	for n := range old {
		if err := f.a.store.Audit().Add(t.Context(), auditRecordAt(n, cutoff.Add(-time.Duration(n+1)*time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
	kept := []store.AuditRecord{auditRecordAt(5000, cutoff), auditRecordAt(5001, cutoff.Add(time.Microsecond)), auditRecordAt(5002, now.Add(-time.Hour))}
	for _, r := range kept {
		if err := f.a.store.Audit().Add(t.Context(), r); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.a.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	remaining := recordsOf(t, f.a, "test.action")
	if len(remaining) != len(kept) {
		t.Fatalf("%d records are left, want the %d that are not old enough", len(remaining), len(kept))
	}
	for _, r := range remaining {
		if r.At.Before(cutoff) {
			t.Fatalf("a record from %v is left", r.At)
		}
	}
	if !strings.Contains(logs.String(), "audit_records=1250") {
		t.Fatalf("the removal was not logged with its count:\n%s", logs.String())
	}
}

func TestTheRetentionOfTheAuditLogCanBeSet(t *testing.T) {
	f := newSessionFixture(t, WithAuditRetention(48*time.Hour))
	now := f.clock.now().UTC().Truncate(time.Microsecond)
	for n, age := range []time.Duration{72 * time.Hour, 47 * time.Hour} {
		if err := f.a.store.Audit().Add(t.Context(), auditRecordAt(n, now.Add(-age))); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.a.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := recordsOf(t, f.a, "test.action"); len(got) != 1 {
		t.Fatalf("%d records are left, want the one that is not old enough", len(got))
	}
	for name, d := range map[string]time.Duration{"zero": 0, "negative": -time.Hour, "short": 23 * time.Hour, "long": 101 * 365 * 24 * time.Hour} {
		if err := newFixtureErr(t, WithAuditRetention(d)); err == nil {
			t.Errorf("%s: New accepted a retention of %v", name, d)
		}
	}
	for _, d := range []time.Duration{24 * time.Hour, 100 * 365 * 24 * time.Hour} {
		if err := newFixtureErr(t, WithAuditRetention(d)); err != nil {
			t.Errorf("New refused a retention of %v: %v", d, err)
		}
	}
}

func TestCleanupRemovesDeletedUsersWhoseRetentionHasEnded(t *testing.T) {
	f, log := newManageFixture(t)
	f.a.hooks.BeforeDelete = func(context.Context, User) error {
		t.Error("the hook before a deletion was called for the removal of a user whose retention ended")
		return errors.New("no")
	}
	now := f.clock.now().UTC().Truncate(time.Microsecond)
	deleted := func(n int, purge time.Time, ident ...store.Identifier) store.User {
		u := userRecord(n, func(u *store.User) {
			u.Status, u.DeletedAt, u.PurgeAfter = store.StatusDeleted, now.Add(-40*24*time.Hour), purge
		})
		f.put(t, u, ident...)
		return u
	}
	gone := deleted(1, now.Add(-time.Hour), store.Identifier{Type: "email", Value: "gone@example.com", DisplayValue: "Gone@Example.com"})
	exact := deleted(2, now)
	future := deleted(3, now.Add(time.Microsecond))
	active := userRecord(4, func(u *store.User) { u.PurgeAfter = now.Add(-time.Hour) })
	f.put(t, active)
	log.take()
	if err := f.a.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	for u, want := range map[string]bool{gone.ID: false, exact.ID: false, future.ID: true, active.ID: true, string(f.user.ID): true} {
		if got := f.userExists(t, u); got != want {
			t.Errorf("the user %s is there = %v, want %v", u, got, want)
		}
	}
	if _, err := f.a.store.Identifiers().Find(t.Context(), f.a.tenant, "email", "gone@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the address of a removed user is still taken: %v", err)
	}
	records := recordsOf(t, f.a, "user.purged")
	if len(records) != 2 {
		t.Fatalf("the audit log holds %d removals, want 2", len(records))
	}
	var first store.AuditRecord
	for _, r := range records {
		if r.TargetUserID == gone.ID {
			first = r
		}
	}
	details := detailsOf(t, first)
	values, _ := details["identifiers"].(map[string]any)
	if first.ActorKind != store.ActorSystem || first.ActorID != "maintenance" || details["reason"] != "retention" || values["email"] != "gone@example.com" {
		t.Fatalf("the removal is recorded as %+v %v", first, details)
	}
	events := log.take()
	if len(events) != 2 || events[0].Type != EventUserPurged || events[0].Details["reason"] != "retention" || events[1].Type != EventUserPurged {
		t.Fatalf("the events are %+v", events)
	}
	if err := f.a.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := len(recordsOf(t, f.a, "user.purged")); got != 2 {
		t.Fatalf("a second cleanup recorded more removals: %d", got)
	}
}

func TestCleanupRemovesManyDeletedUsersPageByPage(t *testing.T) {
	f := newSessionFixture(t)
	now := f.clock.now().UTC().Truncate(time.Microsecond)
	const count = 2*maintenancePage + 37
	for n := range count {
		f.put(t, userRecord(100+n, func(u *store.User) {
			u.Status, u.DeletedAt, u.PurgeAfter = store.StatusDeleted, now.Add(-time.Hour), now.Add(-time.Minute)
			u.CreatedAt = now.Add(-time.Duration(n) * time.Second)
		}))
	}
	if err := f.a.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := len(recordsOf(t, f.a, "user.purged")); got != count {
		t.Fatalf("%d users were removed, want %d", got, count)
	}
	page, err := f.a.Admin().ListUsers(t.Context(), UserFilter{Statuses: []Status{StatusDeleted}})
	if err != nil || len(page.Users) != 0 {
		t.Fatalf("deleted users are left: %d, %v", len(page.Users), err)
	}
}

type restoringUsers struct {
	store.Users
	once    sync.Once
	restore func()
}

func (r *restoringUsers) List(ctx context.Context, q store.UserQuery) ([]store.User, error) {
	users, err := r.Users.List(ctx, q)
	if len(users) > 0 {
		r.once.Do(r.restore)
	}
	return users, err
}

type restoringStore struct {
	store.Store
	users *restoringUsers
}

func (s restoringStore) Users() store.Users { return s.users }

func TestAUserWhoIsRestoredWhileTheMaintenanceRunsIsNotRemoved(t *testing.T) {
	f, _ := newManageFixture(t)
	now := f.clock.now().UTC().Truncate(time.Microsecond)
	doomed := userRecord(1, func(u *store.User) {
		u.Status, u.DeletedAt, u.PurgeAfter = store.StatusDeleted, now.Add(-time.Hour), now.Add(-time.Minute)
	})
	f.put(t, doomed)
	restore := func() {
		u, err := f.a.store.Users().Get(context.Background(), f.a.tenant, doomed.ID)
		if err != nil {
			t.Error(err)
			return
		}
		u.Status, u.DeletedAt, u.PurgeAfter = store.StatusActive, time.Time{}, time.Time{}
		if _, err = f.a.store.Users().Update(context.Background(), u); err != nil {
			t.Error(err)
		}
	}
	f.a.store = restoringStore{Store: f.a.store, users: &restoringUsers{Users: f.a.store.Users(), restore: restore}}
	if err := f.a.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	stored, err := f.a.store.Users().Get(t.Context(), f.a.tenant, doomed.ID)
	if err != nil || stored.Status != store.StatusActive {
		t.Fatalf("the user who was restored meanwhile is %+v, %v: they must stay", stored, err)
	}
	if got := len(recordsOf(t, f.a, "user.purged")); got != 0 {
		t.Fatalf("%d removals were recorded for a user who stayed", got)
	}
}

func TestInstancesRemoveAUserOnceAndRecordItOnce(t *testing.T) {
	f, _ := newManageFixture(t)
	other := f.a.sibling(t, f.clock)
	now := f.clock.now().UTC().Truncate(time.Microsecond)
	const count = 60
	for n := range count {
		f.put(t, userRecord(300+n, func(u *store.User) {
			u.Status, u.DeletedAt, u.PurgeAfter = store.StatusDeleted, now.Add(-time.Hour), now.Add(-time.Minute)
		}))
	}
	var wg sync.WaitGroup
	for _, a := range []*Auth{f.a, other} {
		wg.Go(func() {
			if err := a.Cleanup(context.Background()); err != nil {
				t.Errorf("Cleanup failed: %v", err)
			}
		})
	}
	wg.Wait()
	records := recordsOf(t, f.a, "user.purged")
	seen := map[string]int{}
	for _, r := range records {
		seen[r.TargetUserID]++
	}
	if len(records) != count || len(seen) != count {
		t.Fatalf("%d removals were recorded for %d users, want %d of each: one removal, one record", len(records), len(seen), count)
	}
}

func TestARemovalThatCannotBeRecordedDoesNotHappen(t *testing.T) {
	f, log := newManageFixture(t)
	now := f.clock.now().UTC().Truncate(time.Microsecond)
	doomed := userRecord(1, func(u *store.User) {
		u.Status, u.DeletedAt, u.PurgeAfter = store.StatusDeleted, now.Add(-time.Hour), now.Add(-time.Minute)
	})
	f.put(t, doomed, store.Identifier{Type: "email", Value: "doomed@example.com", DisplayValue: "doomed@example.com"})
	log.take()
	faults := newFaults()
	f.a.store = faultStore{Store: f.a.store, faults: faults}
	broken := errors.New("the audit log is gone")
	faults.set("audit.add", broken)
	err := f.a.Cleanup(t.Context())
	if !errors.Is(err, broken) || !strings.Contains(err.Error(), "deleted users") {
		t.Fatalf("Cleanup = %v, want the failure of the audit log", err)
	}
	faults.clear()
	if !f.userExists(t, doomed.ID) {
		t.Fatal("a user was removed although the removal could not be recorded")
	}
	if events := log.take(); len(events) != 0 {
		t.Fatalf("a removal that failed was reported: %+v", events)
	}
	if err = f.a.Cleanup(t.Context()); err != nil || f.userExists(t, doomed.ID) {
		t.Fatalf("Cleanup = %v, user still there: %v: the removal has to be done once the audit log works", err, f.userExists(t, doomed.ID))
	}
}

func newVisitorFixture(t *testing.T, opts ...Option) (*sessionFixture, *eventLog) {
	t.Helper()
	return newManageFixture(t, append([]Option{WithSignup(), WithoutVerificationRequired()}, opts...)...)
}

func (f *sessionFixture) visitor(t *testing.T, name string) string {
	t.Helper()
	err := f.a.Signup(t.Context(), SignupRequest{Registration: Registration{
		Identifiers: map[string]string{"email": name + "@example.com", "username": name + "_n"}, Password: goodPassword,
	}})
	if err != nil {
		t.Fatalf("Signup(%s) failed: %v", name, err)
	}
	found, err := f.a.store.Identifiers().Find(t.Context(), f.a.tenant, "email", name+"@example.com")
	if err != nil {
		t.Fatal(err)
	}
	return found.UserID
}

func TestCleanupRemovesTheAccountsOfVisitorsThatNobodyConfirmed(t *testing.T) {
	f, log := newVisitorFixture(t)
	stale := f.visitor(t, "stale")
	confirmed := f.visitor(t, "confirmed")
	signedIn := f.visitor(t, "signedin")
	blocked := f.visitor(t, "blocked")
	if err := f.a.store.Identifiers().MarkVerified(t.Context(), f.a.tenant, "email", "confirmed@example.com", f.clock.now()); err != nil {
		t.Fatal(err)
	}
	f.setUser(t, signedIn, func(u *store.User) { u.LastLoginAt = f.clock.now() })
	if err := f.a.Admin().BlockUser(t.Context(), UserID(blocked), "reason", time.Time{}); err != nil {
		t.Fatal(err)
	}
	byCode := mustRegister(t, f.a, map[string]string{"email": "bycode@example.com", "username": "bycode_c"}, goodPassword)
	byAdmin, err := f.a.Admin().CreateUser(t.Context(), NewUser{Identifiers: map[string]string{"email": "byadmin@example.com"}, Password: goodPassword})
	if err != nil {
		t.Fatal(err)
	}
	f.clock.advance(6 * 24 * time.Hour)
	young := f.visitor(t, "young")
	log.take()
	if err = f.a.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !f.userExists(t, stale) {
		t.Fatal("an account that is six days old was removed")
	}
	f.clock.advance(24 * time.Hour)
	if err = f.a.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		id   string
		want bool
	}{
		"stale": {stale, false}, "confirmed": {confirmed, true}, "signed in": {signedIn, true}, "blocked": {blocked, true}, "young": {young, true},
		"by the code": {string(byCode.ID), true}, "by an administrator": {string(byAdmin.ID), true}, "the user of the fixture": {string(f.user.ID), true},
	} {
		if got := f.userExists(t, c.id); got != c.want {
			t.Errorf("the account %q is there = %v, want %v", name, got, c.want)
		}
	}
	if _, findErr := f.a.store.Identifiers().Find(t.Context(), f.a.tenant, "email", "stale@example.com"); !errors.Is(findErr, store.ErrNotFound) {
		t.Fatalf("the address of the account that was removed is still taken: %v", findErr)
	}
	records := recordsOf(t, f.a, "user.purged")
	if len(records) != 1 || records[0].TargetUserID != stale || detailsOf(t, records[0])["reason"] != "unconfirmed" || records[0].ActorID != "maintenance" {
		t.Fatalf("the removal is recorded as %+v", records)
	}
	var purged []Event
	for _, e := range log.take() {
		if e.Type == EventUserPurged {
			purged = append(purged, e)
		}
	}
	if len(purged) != 1 || purged[0].UserID != stale || purged[0].Details["reason"] != "unconfirmed" {
		t.Fatalf("the events are %+v", purged)
	}
	if err = f.a.Signup(t.Context(), SignupRequest{Registration: Registration{
		Identifiers: map[string]string{"email": "stale@example.com", "username": "stale_n"}, Password: goodPassword,
	}}); err != nil {
		t.Fatalf("Signup with the address that was freed failed: %v", err)
	}
}

func TestTheRemovalOfUnconfirmedAccountsCanBeTunedOrTurnedOff(t *testing.T) {
	custom, _ := newVisitorFixture(t, WithUnconfirmedAccountLifetime(2*time.Hour))
	id := custom.visitor(t, "quick")
	custom.clock.advance(time.Hour)
	if err := custom.a.Cleanup(t.Context()); err != nil || !custom.userExists(t, id) {
		t.Fatalf("an account of an hour was removed: %v", err)
	}
	custom.clock.advance(time.Hour)
	if err := custom.a.Cleanup(t.Context()); err != nil || custom.userExists(t, id) {
		t.Fatalf("an account of two hours is still there: %v", err)
	}
	off, _ := newVisitorFixture(t, WithUnconfirmedAccountLifetime(0))
	kept := off.visitor(t, "kept")
	off.clock.advance(5 * 365 * 24 * time.Hour)
	if err := off.a.Cleanup(t.Context()); err != nil || !off.userExists(t, kept) {
		t.Fatalf("an account was removed although the removal is off: %v", err)
	}
	noSignup, _ := newManageFixture(t)
	noSignup.put(t, userRecord(1, func(u *store.User) { u.CreatedVia = store.CreatedViaSignup }))
	noSignup.clock.advance(30 * 24 * time.Hour)
	if err := noSignup.a.Cleanup(t.Context()); err != nil || !noSignup.userExists(t, userRecord(1, func(*store.User) {}).ID) {
		t.Fatalf("an account was removed by a service that has no Signup: %v", err)
	}
	for name, d := range map[string]time.Duration{"negative": -time.Hour, "short": 30 * time.Minute, "long": 400 * 24 * time.Hour} {
		if err := newFixtureErr(t, WithUnconfirmedAccountLifetime(d)); err == nil {
			t.Errorf("%s: New accepted a lifetime of %v", name, d)
		}
	}
	for _, d := range []time.Duration{0, time.Hour, 365 * 24 * time.Hour} {
		if err := newFixtureErr(t, WithUnconfirmedAccountLifetime(d)); err != nil {
			t.Errorf("New refused a lifetime of %v: %v", d, err)
		}
	}
}

func TestCleanupLiftsTheBlocksThatHaveRunOut(t *testing.T) {
	f, log := newManageFixture(t)
	until := f.clock.now().Add(time.Hour)
	limited := userRecord(1, func(u *store.User) { u.Status, u.BlockedReason, u.BlockedUntil = store.StatusBlocked, "limited", until })
	endless := userRecord(2, func(u *store.User) { u.Status, u.BlockedReason = store.StatusBlocked, "endless" })
	later := userRecord(3, func(u *store.User) {
		u.Status, u.BlockedReason, u.BlockedUntil = store.StatusBlocked, "later", until.Add(time.Hour)
	})
	for _, u := range []store.User{limited, endless, later} {
		f.put(t, u)
	}
	log.take()
	if err := f.a.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := len(recordsOf(t, f.a, "user.unblocked")); got != 0 {
		t.Fatalf("a block that holds was lifted: %d records", got)
	}
	f.clock.advance(time.Hour)
	if err := f.a.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	status := func(u store.User) store.User {
		got, err := f.a.store.Users().Get(t.Context(), f.a.tenant, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := status(limited); got.Status != store.StatusActive || got.BlockedReason != "" || !got.BlockedUntil.IsZero() {
		t.Fatalf("the user whose block ran out is %+v", got)
	}
	if status(endless).Status != store.StatusBlocked || status(later).Status != store.StatusBlocked {
		t.Fatal("a block that holds was lifted")
	}
	records := recordsOf(t, f.a, "user.unblocked")
	if len(records) != 1 || records[0].TargetUserID != limited.ID || records[0].ActorID != "maintenance" {
		t.Fatalf("the lifting is recorded as %+v", records)
	}
	details := detailsOf(t, records[0])
	if details["reason"] != "ended" || details["previous_reason"] != "limited" || details["previous_until"] != until.UTC().Format(time.RFC3339) {
		t.Fatalf("the details are %v", details)
	}
	events := log.take()
	if len(events) != 1 || events[0].Type != EventUserUnblocked || events[0].UserID != limited.ID || events[0].Details["reason"] != "ended" {
		t.Fatalf("the events are %+v", events)
	}
}

func TestTheMaintenanceRotatesTheKeyAheadOfTime(t *testing.T) {
	a, clock := newTokenAuth(t)
	if err := a.ring.maintain(t.Context()); err != nil || len(a.storedKeys(t)) != 0 {
		t.Fatalf("maintain made a key out of nothing: %v, %d keys", err, len(a.storedKeys(t)))
	}
	a.mustIssue(t, false)
	if len(a.storedKeys(t)) != 1 {
		t.Fatalf("there are %d keys, want 1", len(a.storedKeys(t)))
	}
	clock.advance(keyRotation / 2)
	if err := a.ring.maintain(t.Context()); err != nil || len(a.storedKeys(t)) != 1 {
		t.Fatalf("a key that is not due was rotated: %v, %d keys", err, len(a.storedKeys(t)))
	}
	clock.advance(keyRotation / 2)
	if err := a.ring.maintain(t.Context()); err != nil {
		t.Fatalf("maintain failed: %v", err)
	}
	if got := len(a.storedKeys(t)); got != 2 {
		t.Fatalf("there are %d keys after the rotation, want 2", got)
	}
	if err := a.ring.maintain(t.Context()); err != nil || len(a.storedKeys(t)) != 2 {
		t.Fatalf("a second call rotated again: %v, %d keys", err, len(a.storedKeys(t)))
	}
}

type countingAdminSessions struct {
	store.AdminSessions
	calls atomic.Int64
	panic bool
}

func (c *countingAdminSessions) DeleteStale(ctx context.Context, tenantID string, expiredBefore, idleBefore time.Time) (int, error) {
	c.calls.Add(1)
	if c.panic {
		panic("secret value " + goodPassword)
	}
	return c.AdminSessions.DeleteStale(ctx, tenantID, expiredBefore, idleBefore)
}

type countingStore struct {
	store.Store
	sessions *countingAdminSessions
}

func (s countingStore) AdminSessions() store.AdminSessions { return s.sessions }

func newCounting(t *testing.T) (*Auth, *countingAdminSessions, *logBuffer) {
	t.Helper()
	logger, logs := capturingLogger()
	f := newSessionFixture(t, WithLogger(logger))
	counting := &countingAdminSessions{AdminSessions: f.a.store.AdminSessions()}
	f.a.store = countingStore{Store: f.a.store, sessions: counting}
	return f.a, counting, logs
}

func TestTheMaintenanceRunsAtOnceAndThenEveryInterval(t *testing.T) {
	a, counting, _ := newCounting(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.RunMaintenance(ctx, 20*time.Millisecond) }()
	eventually(t, "the first run of the maintenance", func() bool { return counting.calls.Load() >= 1 })
	eventually(t, "the third run of the maintenance", func() bool { return counting.calls.Load() >= 3 })
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunMaintenance = %v, want nil when its context ends", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunMaintenance did not return when its context ended")
	}
	calls := counting.calls.Load()
	time.Sleep(80 * time.Millisecond)
	if counting.calls.Load() != calls {
		t.Fatal("the maintenance went on after its context ended")
	}
}

func TestOnlyOneMaintenanceRunsInAProcess(t *testing.T) {
	a, counting, _ := newCounting(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.RunMaintenance(ctx, time.Hour) }()
	eventually(t, "the first run of the maintenance", func() bool { return counting.calls.Load() >= 1 })
	if err := a.RunMaintenance(t.Context(), time.Hour); !errors.Is(err, ErrMaintenanceRunning) {
		t.Fatalf("a second RunMaintenance = %v, want ErrMaintenanceRunning", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	again, stop := context.WithCancel(t.Context())
	second := make(chan error, 1)
	go func() { second <- a.RunMaintenance(again, time.Hour) }()
	eventually(t, "the run of the maintenance that follows", func() bool { return counting.calls.Load() >= 2 })
	stop()
	if err := <-second; err != nil {
		t.Fatalf("RunMaintenance after the first one ended = %v, want it to run", err)
	}
}

func TestTheMaintenanceNeedsAPositiveIntervalAndALiveContext(t *testing.T) {
	a, counting, _ := newCounting(t)
	for _, d := range []time.Duration{0, -time.Second} {
		if err := a.RunMaintenance(t.Context(), d); err == nil || errors.Is(err, ErrMaintenanceRunning) {
			t.Errorf("RunMaintenance with an interval of %v = %v, want an error", d, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := a.RunMaintenance(ctx, time.Second); err != nil {
		t.Fatalf("RunMaintenance with a context that ended = %v, want nil", err)
	}
	if counting.calls.Load() != 0 {
		t.Fatal("the maintenance ran although its context had ended")
	}
	if err := a.RunMaintenance(t.Context(), 0); err == nil {
		t.Fatal("the failure to start left the maintenance marked as running")
	}
}

func TestAFailureOfTheMaintenanceIsLoggedAndTheLoopGoesOn(t *testing.T) {
	a, counting, logs := newCounting(t)
	faults := newFaults()
	a.store = faultStore{Store: a.store, faults: faults}
	faults.set("audit.delete", errors.New("the audit log is gone"))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.RunMaintenance(ctx, 10*time.Millisecond) }()
	eventually(t, "two runs that failed", func() bool {
		return strings.Count(logs.String(), "the cleanup did not finish") >= 2
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "the audit log is gone") || counting.calls.Load() < 2 {
		t.Fatalf("the failure was not logged or the loop stopped: %d calls\n%s", counting.calls.Load(), logs.String())
	}
}

func TestAStepThatPanicsIsContainedAndLogsOnlyTheTypeOfTheValue(t *testing.T) {
	a, counting, logs := newCounting(t)
	counting.panic = true
	err := a.Cleanup(t.Context())
	if err == nil || !strings.Contains(err.Error(), "panicked") || strings.Contains(err.Error(), goodPassword) {
		t.Fatalf("Cleanup = %v, want an error that says a step panicked", err)
	}
	if strings.Contains(logs.String(), goodPassword) || !strings.Contains(logs.String(), "panic_type=string") {
		t.Fatalf("the log says %s: only the type of the value of the panic is logged", logs.String())
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.RunMaintenance(ctx, 10*time.Millisecond) }()
	eventually(t, "runs of the maintenance that panicked", func() bool { return counting.calls.Load() >= 3 })
	cancel()
	if err = <-done; err != nil {
		t.Fatalf("RunMaintenance = %v: a panic of a step must not end it", err)
	}
}

func (a *Auth) storedKeysOrNil() []store.SigningKey {
	keys, _ := a.store.SigningKeys().List(context.Background())
	return keys
}

func TestTheIntervalOfTheMaintenanceHasASpreadOfTenPercent(t *testing.T) {
	const interval = time.Hour
	seen := map[time.Duration]bool{}
	for range 2000 {
		got := jittered(interval)
		if got < 54*time.Minute || got > 66*time.Minute {
			t.Fatalf("the interval is %v, want it within ten percent of %v", got, interval)
		}
		seen[got] = true
	}
	if len(seen) < 100 {
		t.Fatalf("the interval took %d different values in 2000 tries: it has no spread", len(seen))
	}
}

func TestTheMaintenanceRotatesTheKeyOfARunningService(t *testing.T) {
	a, clock := newTokenAuth(t)
	a.mustIssue(t, false)
	clock.advance(keyRotation)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.RunMaintenance(ctx, time.Hour) }()
	eventually(t, "the key to be rotated", func() bool { return len(a.storedKeysOrNil()) == 2 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func (f *sessionFixture) changeAfterTheList(t *testing.T, change func()) {
	t.Helper()
	eventually(t, "the audit records that wait to be written", func() bool { return f.a.auditing.pending.Load() == 0 })
	f.a.store = restoringStore{Store: f.a.store, users: &restoringUsers{Users: f.a.store.Users(), restore: change}}
}

func TestAUserWhoseRetentionIsExtendedWhileTheMaintenanceRunsIsNotRemoved(t *testing.T) {
	f, _ := newManageFixture(t)
	now := f.clock.now().UTC().Truncate(time.Microsecond)
	doomed := userRecord(1, func(u *store.User) {
		u.Status, u.DeletedAt, u.PurgeAfter = store.StatusDeleted, now.Add(-time.Hour), now.Add(-time.Minute)
	})
	f.put(t, doomed)
	f.changeAfterTheList(t, func() { f.setUser(t, doomed.ID, func(u *store.User) { u.PurgeAfter = now.Add(24 * time.Hour) }) })
	if err := f.a.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !f.userExists(t, doomed.ID) || len(recordsOf(t, f.a, "user.purged")) != 0 {
		t.Fatal("a user whose retention was extended meanwhile was removed")
	}
}

func TestAnAccountThatStopsBeingUnconfirmedWhileTheMaintenanceRunsIsNotRemoved(t *testing.T) {
	for name, change := range map[string]func(f *sessionFixture, id string){
		"the visitor signs in": func(f *sessionFixture, id string) {
			f.setUser(t, id, func(u *store.User) { u.LastLoginAt = f.clock.now() })
		},
		"the address is confirmed": func(f *sessionFixture, _ string) {
			if err := f.a.store.Identifiers().MarkVerified(t.Context(), f.a.tenant, "email", "olga@example.com", f.clock.now()); err != nil {
				t.Error(err)
			}
		},
	} {
		f, _ := newVisitorFixture(t)
		id := f.visitor(t, "olga")
		f.clock.advance(8 * 24 * time.Hour)
		f.changeAfterTheList(t, func() { change(f, id) })
		if err := f.a.Cleanup(t.Context()); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !f.userExists(t, id) || len(recordsOf(t, f.a, "user.purged")) != 0 {
			t.Errorf("%s: an account that was not unconfirmed any longer was removed", name)
		}
	}
}

func TestABlockThatIsChangedWhileTheMaintenanceRunsIsNotLifted(t *testing.T) {
	for name, change := range map[string]func(u *store.User, now time.Time){
		"it is made longer":  func(u *store.User, now time.Time) { u.BlockedUntil = now.Add(time.Hour) },
		"it is made endless": func(u *store.User, _ time.Time) { u.BlockedUntil = time.Time{} },
	} {
		f, _ := newManageFixture(t)
		now := f.clock.now().UTC().Truncate(time.Microsecond)
		blocked := userRecord(1, func(u *store.User) {
			u.Status, u.BlockedReason, u.BlockedUntil = store.StatusBlocked, "spam", now.Add(-time.Minute)
		})
		f.put(t, blocked)
		f.changeAfterTheList(t, func() { f.setUser(t, blocked.ID, func(u *store.User) { change(u, now) }) })
		if err := f.a.Cleanup(t.Context()); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := f.storedUser(t, UserID(blocked.ID)); got.Status != store.StatusBlocked || got.BlockedReason != "spam" {
			t.Errorf("%s: the block was lifted: %+v", name, got)
		}
		if got := len(recordsOf(t, f.a, "user.unblocked")); got != 0 {
			t.Errorf("%s: %d liftings were recorded", name, got)
		}
	}
}

func TestEveryUserThatCannotBeRemovedIsTriedOnceAndTheLaterPagesAreReached(t *testing.T) {
	f, _ := newManageFixture(t)
	now := f.clock.now().UTC().Truncate(time.Microsecond)
	const count = maintenancePage + 40
	for n := range count {
		f.put(t, userRecord(100+n, func(u *store.User) {
			u.Status, u.DeletedAt, u.PurgeAfter = store.StatusDeleted, now.Add(-time.Hour), now.Add(-time.Minute)
			u.CreatedAt = now.Add(-time.Duration(n) * time.Second)
		}))
	}
	faults := newFaults()
	f.a.store = faultStore{Store: f.a.store, faults: faults}
	broken := errors.New("the audit log is gone")
	faults.set("audit.add", broken)
	err := f.a.Cleanup(t.Context())
	if got := strings.Count(fmt.Sprint(err), "the audit log is gone"); got != count {
		t.Fatalf("%d removals failed, want %d: every user is tried once, and the second page is reached", got, count)
	}
}
