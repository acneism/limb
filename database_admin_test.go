package limb

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/internal/admin"
	"github.com/acneism/limb/internal/totp"
	"github.com/acneism/limb/store"
)

func TestAdministratorsAreSharedBetweenInstancesOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstances(t, d)
		ctx := t.Context()
		created, err := in.a.Admin().CreateAdmin(ctx, "Root", adminPassword)
		if err != nil {
			t.Fatalf("CreateAdmin failed: %v", err)
		}
		list, err := in.b.Admin().ListAdmins(ctx)
		if err != nil || len(list) != 1 || list[0].ID != created.ID || list[0].Login != "root" || !list[0].CreatedAt.Equal(created.CreatedAt.Truncate(time.Microsecond)) {
			t.Fatalf("the other instance lists %+v, %v; want the administrator that was made", list, err)
		}
		before, err := in.a.store.Admins().FindByLogin(ctx, in.a.tenant, "root")
		if err != nil {
			t.Fatal(err)
		}
		if err = in.b.Admin().ResetAdminPassword(ctx, "root", adminPassword+" again"); err != nil {
			t.Fatalf("ResetAdminPassword on the other instance failed: %v", err)
		}
		after, err := in.a.store.Admins().FindByLogin(ctx, in.a.tenant, "root")
		if err != nil || after.PasswordHash == before.PasswordHash || after.Version != before.Version+1 {
			t.Fatalf("the change of the other instance is not seen: %+v, %v", after, err)
		}
		if err = in.a.Admin().DisableAdmin(ctx, "root"); err != nil {
			t.Fatal(err)
		}
		if list, err = in.b.Admin().ListAdmins(ctx); err != nil || len(list) != 1 || !list[0].Disabled {
			t.Fatalf("the other instance lists %+v, %v; want a disabled administrator", list, err)
		}
		var actions []string
		for _, r := range auditRecords(t, in.b) {
			actions = append(actions, r.Action)
		}
		if strings.Join(actions, " ") != "admin.disabled admin.password_reset admin.created" {
			t.Fatalf("the audit log holds %v", actions)
		}
		if err = in.b.Admin().DeleteAdmin(ctx, "root"); err != nil {
			t.Fatal(err)
		}
		if _, err = in.a.Admin().CreateAdmin(ctx, "root", adminPassword); err != nil {
			t.Fatalf("the login of an administrator that was deleted can be used again: %v", err)
		}
	})
}

func TestTwoInstancesThatMakeTheSameAdministratorMakeOneOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstances(t, d)
		const racers = 8
		var made, taken atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range racers {
			api := in.a.Admin()
			if i%2 == 1 {
				api = in.b.Admin()
			}
			wg.Go(func() {
				<-start
				_, err := api.CreateAdmin(t.Context(), "race", adminPassword)
				switch {
				case err == nil:
					made.Add(1)
				case errors.Is(err, ErrAdminLoginTaken):
					taken.Add(1)
				default:
					t.Errorf("CreateAdmin: unexpected error %v", err)
				}
			})
		}
		close(start)
		wg.Wait()
		if made.Load() != 1 || taken.Load() != racers-1 {
			t.Fatalf("%d administrators were made and %d refused; want exactly 1 and %d", made.Load(), taken.Load(), racers-1)
		}
		if records := auditRecords(t, in.a); len(records) != 1 || records[0].Action != "admin.created" {
			t.Fatalf("the audit log holds %+v, want one record of the administrator that was made", records)
		}
	})
}

type auditFailingStore struct{ store.Store }

func (s auditFailingStore) InTx(ctx context.Context, fn func(ctx context.Context, tx store.Repositories) error) error {
	return s.Store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		return fn(ctx, auditFailingRepositories{tx})
	})
}

type auditFailingRepositories struct{ store.Repositories }

func (auditFailingRepositories) Audit() store.Audit { return missingAudit{} }

type missingAudit struct{}

var errMissingAudit = errors.New("the audit log is gone")

func (missingAudit) Add(context.Context, store.AuditRecord) error { return errMissingAudit }
func (missingAudit) List(context.Context, store.AuditQuery) ([]store.AuditRecord, error) {
	return nil, errMissingAudit
}
func (missingAudit) DeleteBefore(context.Context, string, time.Time, int) (int, error) {
	return 0, errMissingAudit
}

func TestAChangeOfAnAdministratorAndItsRecordStandOrFallTogetherOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstances(t, d)
		ctx := t.Context()
		if _, err := in.a.Admin().CreateAdmin(ctx, "root", adminPassword); err != nil {
			t.Fatal(err)
		}
		before, err := in.a.store.Admins().FindByLogin(ctx, in.a.tenant, "root")
		if err != nil {
			t.Fatal(err)
		}
		plain := in.a.store
		in.a.store = auditFailingStore{Store: plain}
		in.a.admins = in.a.newAdminService("")
		api := in.a.Admin()
		if _, err = api.CreateAdmin(ctx, "second", adminPassword); !errors.Is(err, errMissingAudit) {
			t.Fatalf("CreateAdmin = %v, want the failure of the audit log", err)
		}
		for name, call := range map[string]func() error{
			"ResetAdminPassword": func() error { return api.ResetAdminPassword(ctx, "root", adminPassword+" again") },
			"DisableAdmin":       func() error { return api.DisableAdmin(ctx, "root") },
			"ResetAdminTOTP":     func() error { return api.ResetAdminTOTP(ctx, "root") },
			"DeleteAdmin":        func() error { return api.DeleteAdmin(ctx, "root") },
		} {
			if err = call(); !errors.Is(err, errMissingAudit) {
				t.Errorf("%s = %v, want the failure of the audit log", name, err)
			}
		}
		in.a.store = plain
		after, err := in.a.store.Admins().FindByLogin(ctx, in.a.tenant, "root")
		if err != nil || after.Version != before.Version || after.PasswordHash != before.PasswordHash || after.Status != store.AdminActive {
			t.Fatalf("a change that could not be recorded was made: %+v, %v", after, err)
		}
		if _, err = in.a.store.Admins().FindByLogin(ctx, in.a.tenant, "second"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("an administrator whose creation could not be recorded exists: %v", err)
		}
		if records := auditRecords(t, in.a); len(records) != 1 {
			t.Fatalf("the audit log holds %d records, want only the one of the creation", len(records))
		}
	})
}

func TestTheSecondFactorOfAnAdministratorIsKeptByEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstances(t, d)
		ctx := t.Context()
		if _, err := in.a.Admin().CreateAdmin(ctx, "root", adminPassword); err != nil {
			t.Fatal(err)
		}
		root, err := in.a.store.Admins().FindByLogin(ctx, in.a.tenant, "root")
		if err != nil {
			t.Fatal(err)
		}
		enrollment, err := in.a.admins.NewEnrollment(root)
		if err != nil {
			t.Fatal(err)
		}
		root.TOTPSecret = enrollment.Sealed
		root.TOTPConfirmedAt = in.clock.now()
		if _, err = in.a.store.Admins().Update(ctx, root); err != nil {
			t.Fatalf("Update with a sealed seed failed: %v", err)
		}
		shown, hashes, err := in.a.admins.NewRecoveryCodes(root.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err = in.a.store.Admins().ReplaceRecoveryCodes(ctx, in.a.tenant, root.ID, hashes); err != nil {
			t.Fatal(err)
		}

		other, err := in.b.store.Admins().FindByLogin(ctx, in.b.tenant, "root")
		if err != nil || !bytes.Equal(other.TOTPSecret, enrollment.Sealed) || other.TOTPConfirmedAt.IsZero() {
			t.Fatalf("the other instance reads %+v, %v; want the sealed seed byte for byte", other, err)
		}
		now := in.clock.now()
		factor, err := in.b.admins.ReadFactor(other, totp.Code(enrollment.Seed, totp.Step(now)), now)
		if err != nil || factor.Kind != admin.FactorTOTP {
			t.Fatalf("the other instance cannot read a password of the authenticator: %+v, %v", factor, err)
		}
		if err = in.b.store.Admins().AcceptStep(ctx, in.b.tenant, other.ID, other.Version, factor.Step, now); err != nil {
			t.Fatalf("AcceptStep failed: %v", err)
		}
		if err = in.a.store.Admins().AcceptStep(ctx, in.a.tenant, other.ID, other.Version, factor.Step, now); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("a password that one instance accepted is accepted by the other = %v, want ErrConflict", err)
		}

		code, err := in.b.admins.ReadFactor(other, shown[4], now)
		if err != nil || code.Kind != admin.FactorRecovery {
			t.Fatalf("a recovery code cannot be read: %+v, %v", code, err)
		}
		if err = in.b.store.Admins().UseRecoveryCode(ctx, in.b.tenant, other.ID, code.Hash, now); err != nil {
			t.Fatalf("the recovery code does not work on the other instance: %v", err)
		}
		if err = in.a.store.Admins().UseRecoveryCode(ctx, in.a.tenant, other.ID, code.Hash, now); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a recovery code that was used works on the first instance = %v, want ErrNotFound", err)
		}
		if list, listErr := in.a.Admin().ListAdmins(ctx); listErr != nil || len(list) != 1 || !list[0].TOTPBound || list[0].RecoveryCodes != admin.RecoveryCodeCount-1 || list[0].LastLoginAt.IsZero() {
			t.Fatalf("ListAdmins = %+v, %v; want a bound authenticator, one recovery code less and a sign-in", list, listErr)
		}

		if err = in.b.Admin().ResetAdminTOTP(ctx, "root"); err != nil {
			t.Fatal(err)
		}
		reset, err := in.a.store.Admins().FindByLogin(ctx, in.a.tenant, "root")
		if err != nil || len(reset.TOTPSecret) != 0 || !reset.TOTPConfirmedAt.IsZero() {
			t.Fatalf("the authenticator was not removed: %+v, %v", reset, err)
		}
		if count, countErr := in.a.store.Admins().CountRecoveryCodes(ctx, in.a.tenant, root.ID); countErr != nil || count != 0 {
			t.Fatalf("the recovery codes were not removed: %d, %v", count, countErr)
		}
	})
}

func TestTheCommandLineWorksOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstances(t, d)
		run := func(stdin string, args ...string) (int, string, string) {
			t.Helper()
			return runCommand(t, in.a, stdin, args...)
		}
		if code, out, errs := run("", "migrate"); code != 0 || out != "the schema of the database is at version 4\n" {
			t.Fatalf("migrate: code %d, stdout %q, stderr %q", code, out, errs)
		}
		if code, out, errs := run(typedPassword+"\n", "admin", "create", "--login", "Root", "--password-stdin"); code != 0 || !strings.Contains(out, "the administrator root is created") {
			t.Fatalf("create: code %d, stdout %q, stderr %q", code, out, errs)
		}
		if code, _, errs := run(typedPassword+"\n", "admin", "create", "--login", "ROOT", "--password-stdin"); code != 1 || !strings.Contains(errs, "the login ROOT is taken") {
			t.Fatalf("create of a taken login: code %d, stderr %q", code, errs)
		}
		code, out, errs := run("", "admin", "list")
		if code != 0 || errs != "" || !strings.Contains(out, "root") || !strings.Contains(out, "not bound") {
			t.Fatalf("list: code %d, stdout %q, stderr %q", code, out, errs)
		}
		if code, _, errs = run("", "admin", "disable", "root"); code != 0 {
			t.Fatalf("disable: code %d, stderr %q", code, errs)
		}
		if code, out, _ = run("", "admin", "list"); code != 0 || !strings.Contains(out, "disabled") {
			t.Fatalf("list after disable: code %d, stdout %q", code, out)
		}
		if code, _, errs = run("", "admin", "reset-totp", "root"); code != 0 {
			t.Fatalf("reset-totp: code %d, stderr %q", code, errs)
		}
		if code, _, errs = run("another good password phrase\n", "admin", "reset-password", "root", "--password-stdin"); code != 0 {
			t.Fatalf("reset-password: code %d, stderr %q", code, errs)
		}
		if code, _, errs = run("", "cleanup"); code != 0 {
			t.Fatalf("cleanup: code %d, stderr %q", code, errs)
		}
		if code, _, errs = run("", "admin", "delete", "root"); code != 0 {
			t.Fatalf("delete: code %d, stderr %q", code, errs)
		}
		for _, r := range auditRecords(t, in.a) {
			if r.ActorID != "cli" || r.ActorKind != store.ActorSystem {
				t.Fatalf("the command line is the system actor cli: %+v", r)
			}
		}
		if records := auditRecords(t, in.a); len(records) != 5 {
			t.Fatalf("the audit log holds %d records, want 5: one for every change that was made", len(records))
		}
	})
}
