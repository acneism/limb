package sqlstore

import (
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

var errForeignKey = stubError{state: "23503"}

func anAdmin() store.Admin {
	return store.Admin{
		TenantID: store.DefaultTenant, ID: "a1", Login: "root", PasswordHash: "hash", Status: store.AdminActive,
		CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Version: 1,
	}
}

func marked(version, step int64) func(string, int) ([]string, [][]driver.Value) {
	return func(string, int) ([]string, [][]driver.Value) {
		return []string{"version", "step"}, [][]driver.Value{{version, step}}
	}
}

func TestCreateOfAnAdminTellsAConflictFromAFailure(t *testing.T) {
	probe, s := stubbedSettings(t, func(string, int) error { return errOther })
	if err := s.Admins().Create(t.Context(), anAdmin()); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Create = %v, want ErrConflict", err)
	}
	probe.script = func(string, int) error { return errors.New("the database is gone") }
	if err := s.Admins().Create(t.Context(), anAdmin()); err == nil || errors.Is(err, store.ErrConflict) {
		t.Fatalf("Create = %v, want the failure of the database", err)
	}
}

func TestAnAdminThatIsNotThereIsToldFromOneThatChanged(t *testing.T) {
	probe, s := stubbedSettings(t, nil)
	probe.affect = func(string, int) int64 { return 0 }
	probe.rows = func(string, int) ([]string, [][]driver.Value) { return nil, nil }
	ctx := t.Context()
	if _, err := s.Admins().Update(ctx, anAdmin()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Update of a missing administrator = %v, want ErrNotFound", err)
	}
	if err := s.Admins().AcceptStep(ctx, store.DefaultTenant, "a1", 1, 5, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("AcceptStep of a missing administrator = %v, want ErrNotFound", err)
	}
	if err := s.Admins().RecordLogin(ctx, store.DefaultTenant, "a1", 1, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("RecordLogin of a missing administrator = %v, want ErrNotFound", err)
	}

	probe.rows = marked(2, 9)
	if _, err := s.Admins().Update(ctx, anAdmin()); !errors.Is(err, store.ErrStale) {
		t.Errorf("Update with an old version = %v, want ErrStale", err)
	}
	if err := s.Admins().AcceptStep(ctx, store.DefaultTenant, "a1", 1, 5, time.Now()); !errors.Is(err, store.ErrStale) {
		t.Errorf("AcceptStep with an old version = %v, want ErrStale", err)
	}
	if err := s.Admins().RecordLogin(ctx, store.DefaultTenant, "a1", 1, time.Now()); !errors.Is(err, store.ErrStale) {
		t.Errorf("RecordLogin with an old version = %v, want ErrStale", err)
	}
	if err := s.Admins().AcceptStep(ctx, store.DefaultTenant, "a1", 2, 9, time.Now()); !errors.Is(err, store.ErrConflict) {
		t.Errorf("AcceptStep of the step that was accepted = %v, want ErrConflict", err)
	}
	if err := s.Admins().AcceptStep(ctx, store.DefaultTenant, "a1", 2, 8, time.Now()); !errors.Is(err, store.ErrConflict) {
		t.Errorf("AcceptStep of an earlier step = %v, want ErrConflict", err)
	}
	if err := s.Admins().AcceptStep(ctx, store.DefaultTenant, "a1", 2, 10, time.Now()); !errors.Is(err, store.ErrStale) {
		t.Errorf("AcceptStep that the database did not take although nothing stands in its way = %v, want ErrStale", err)
	}
	if _, err := s.Admins().Update(ctx, func() store.Admin { a := anAdmin(); a.Version = 2; return a }()); !errors.Is(err, store.ErrStale) {
		t.Errorf("Update that the database did not take although nothing stands in its way = %v, want ErrStale", err)
	}
	if err := s.Admins().RecordLogin(ctx, store.DefaultTenant, "a1", 2, time.Now()); err != nil {
		t.Errorf("RecordLogin that changed nothing because the time is the same = %v, want nil", err)
	}
}

func TestTheFailuresOfTheDatabaseReachTheCallerOfAnAdminOperation(t *testing.T) {
	broken := errors.New("the database is gone")
	_, s := stubbedSettings(t, func(string, int) error { return broken })
	ctx := t.Context()
	at := time.Now()
	checks := map[string]error{}
	_, checks["Get"] = s.Admins().Get(ctx, store.DefaultTenant, "a1")
	_, checks["FindByLogin"] = s.Admins().FindByLogin(ctx, store.DefaultTenant, "root")
	_, checks["List"] = s.Admins().List(ctx, store.DefaultTenant)
	_, checks["Update"] = s.Admins().Update(ctx, anAdmin())
	checks["Delete"] = s.Admins().Delete(ctx, store.DefaultTenant, "a1")
	checks["AcceptStep"] = s.Admins().AcceptStep(ctx, store.DefaultTenant, "a1", 1, 5, at)
	checks["RecordLogin"] = s.Admins().RecordLogin(ctx, store.DefaultTenant, "a1", 1, at)
	checks["ReplaceRecoveryCodes"] = s.Admins().ReplaceRecoveryCodes(ctx, store.DefaultTenant, "a1", nil)
	checks["UseRecoveryCode"] = s.Admins().UseRecoveryCode(ctx, store.DefaultTenant, "a1", make([]byte, store.SecretHashLength), at)
	_, checks["CountRecoveryCodes"] = s.Admins().CountRecoveryCodes(ctx, store.DefaultTenant, "a1")
	for name, err := range checks {
		if !errors.Is(err, broken) || errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s = %v, want the failure of the database", name, err)
		}
	}
}

func TestReplaceOfRecoveryCodesReportsWhatGoesWrongStatementByStatement(t *testing.T) {
	hashes := [][]byte{make([]byte, store.SecretHashLength)}
	exists := func(string, int) ([]string, [][]driver.Value) { return []string{"one"}, [][]driver.Value{{int64(1)}} }
	cases := map[string]struct {
		failing func(s *Store) string
		with    error
		want    func(error) bool
	}{
		"the deletion":                       {func(s *Store) string { return s.q.deleteRecoveryCodes }, errors.New("the database is gone"), func(err error) bool { return err != nil && !errors.Is(err, store.ErrNotFound) }},
		"an insert that clashes":             {func(s *Store) string { return s.q.insertRecoveryCode }, errOther, func(err error) bool { return errors.Is(err, store.ErrConflict) }},
		"an insert without an administrator": {func(s *Store) string { return s.q.insertRecoveryCode }, errForeignKey, func(err error) bool { return errors.Is(err, store.ErrNotFound) }},
		"an insert that fails": {func(s *Store) string { return s.q.insertRecoveryCode }, errors.New("the database is gone"), func(err error) bool {
			return err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrConflict)
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var target string
			probe, s := stubbedSettings(t, func(query string, _ int) error {
				if query == target {
					return c.with
				}
				return nil
			})
			probe.rows = exists
			target = c.failing(s)
			if err := s.Admins().ReplaceRecoveryCodes(t.Context(), store.DefaultTenant, "a1", hashes); !c.want(err) {
				t.Fatalf("ReplaceRecoveryCodes = %v", err)
			}
		})
	}
}

func TestAListOfAdminsThatCannotBeReadIsReported(t *testing.T) {
	probe, s := stubbedSettings(t, nil)
	probe.rows = func(string, int) ([]string, [][]driver.Value) {
		return []string{"tenant_id"}, [][]driver.Value{{"default"}}
	}
	if _, err := s.Admins().List(t.Context(), store.DefaultTenant); err == nil {
		t.Fatal("List must report a row that does not have the columns of an administrator")
	}
}
