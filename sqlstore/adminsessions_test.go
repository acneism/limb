package sqlstore

import (
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func anAdminSession() store.AdminSession {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return store.AdminSession{
		TenantID: store.DefaultTenant, ID: "s1", AdminID: "a1", Stage: store.AdminStageFull, SecretHash: make([]byte, store.SecretHashLength),
		AdminVersion: 1, CreatedAt: at, LastSeenAt: at, ExpiresAt: at.Add(time.Hour),
	}
}

func TestCreateOfAnAdminSessionTellsWhatWentWrong(t *testing.T) {
	cases := map[string]struct {
		with error
		want func(error) bool
	}{
		"a conflict":              {errOther, func(err error) bool { return errors.Is(err, store.ErrConflict) }},
		"a missing administrator": {errForeignKey, func(err error) bool { return errors.Is(err, store.ErrNotFound) }},
		"a failure": {errors.New("the database is gone"), func(err error) bool {
			return err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrConflict)
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, s := stubbedSettings(t, func(string, int) error { return c.with })
			if err := s.AdminSessions().Create(t.Context(), anAdminSession()); !c.want(err) {
				t.Fatalf("Create = %v", err)
			}
		})
	}
}

func TestTheFailuresOfTheDatabaseReachTheCallerOfAnAdminSessionOperation(t *testing.T) {
	broken := errors.New("the database is gone")
	_, s := stubbedSettings(t, func(string, int) error { return broken })
	ctx := t.Context()
	at := time.Now()
	hash := make([]byte, store.SecretHashLength)
	checks := map[string]error{}
	_, checks["ResolveBySecret"] = s.AdminSessions().ResolveBySecret(ctx, store.DefaultTenant, hash)
	checks["Touch"] = s.AdminSessions().Touch(ctx, store.DefaultTenant, "s1", at)
	_, checks["TryAttempt"] = s.AdminSessions().TryAttempt(ctx, store.DefaultTenant, "s1", 3)
	checks["Rebind"] = s.AdminSessions().Rebind(ctx, store.DefaultTenant, "a1", "s1", 2)
	checks["Delete"] = s.AdminSessions().Delete(ctx, store.DefaultTenant, "a1", "s1")
	_, checks["DeleteForAdmin"] = s.AdminSessions().DeleteForAdmin(ctx, store.DefaultTenant, "a1", "")
	_, checks["DeleteForAdmin except one"] = s.AdminSessions().DeleteForAdmin(ctx, store.DefaultTenant, "a1", "s1")
	_, checks["ListByAdmin"] = s.AdminSessions().ListByAdmin(ctx, store.DefaultTenant, "a1", at)
	_, checks["DeleteStale"] = s.AdminSessions().DeleteStale(ctx, store.DefaultTenant, at, at)
	for name, err := range checks {
		if !errors.Is(err, broken) || errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s = %v, want the failure of the database", name, err)
		}
	}
}

func TestAListOfAdminSessionsThatCannotBeReadIsReported(t *testing.T) {
	probe, s := stubbedSettings(t, nil)
	probe.rows = func(string, int) ([]string, [][]driver.Value) {
		return []string{"tenant_id"}, [][]driver.Value{{"default"}}
	}
	if _, err := s.AdminSessions().ListByAdmin(t.Context(), store.DefaultTenant, "a1", time.Now()); err == nil {
		t.Fatal("ListByAdmin must report a row that does not have the columns of a session")
	}
}
