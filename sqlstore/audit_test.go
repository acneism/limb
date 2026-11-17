package sqlstore

import (
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func anAuditRecord() store.AuditRecord {
	return store.AuditRecord{
		TenantID: store.DefaultTenant, ID: "a1", At: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		ActorKind: store.ActorSystem, Action: "maintenance.cleanup",
	}
}

func TestAddOfAnAuditRecordTellsAConflictFromAFailure(t *testing.T) {
	probe, s := stubbedSettings(t, nil)
	probe.script = func(string, int) error { return errOther }
	if err := s.Audit().Add(t.Context(), anAuditRecord()); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Add = %v, want ErrConflict for a taken ID", err)
	}
	probe.script = func(string, int) error { return errors.New("the database is gone") }
	if err := s.Audit().Add(t.Context(), anAuditRecord()); err == nil || errors.Is(err, store.ErrConflict) {
		t.Fatalf("Add = %v, want the failure of the database", err)
	}
}

func TestListOfAuditRecordsReportsFailures(t *testing.T) {
	broken := errors.New("the database is gone")
	probe, s := stubbedSettings(t, func(string, int) error { return broken })
	if _, err := s.Audit().List(t.Context(), store.AuditQuery{TenantID: store.DefaultTenant, Limit: 5}); !errors.Is(err, broken) {
		t.Fatalf("List = %v, want the failure of the database", err)
	}
	probe.script = nil
	probe.rows = func(string, int) ([]string, [][]driver.Value) {
		return []string{"tenant_id"}, [][]driver.Value{{"default"}}
	}
	if _, err := s.Audit().List(t.Context(), store.AuditQuery{TenantID: store.DefaultTenant, Limit: 5}); err == nil {
		t.Fatal("List must report a row that does not have the columns of a record")
	}
}

func TestListOfAuditRecordsNumbersItsParametersInTheOrderOfTheConditions(t *testing.T) {
	for _, d := range []struct {
		dialect Dialect
		marks   []string
	}{{Postgres, []string{"$1", "$2", "$3", "$4", "$5", "$6", "$7", "$8", "$9", "$10", "$11"}}, {Oracle, []string{":1", ":2", ":3", ":4", ":5", ":6", ":7", ":8", ":9", ":10", ":11"}}} {
		probe, db := newStub(t, nil)
		s, err := New(db, d.dialect)
		if err != nil {
			t.Fatal(err)
		}
		at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		_, err = s.Audit().List(t.Context(), store.AuditQuery{
			TenantID: "t", TargetUserID: "u", ActorKind: store.ActorAdmin, ActorID: "a", Actions: []string{"x", "y"},
			From: at, To: at.Add(time.Hour), After: &store.AuditRecord{ID: "i", At: at.Add(time.Minute)}, Limit: 51,
		})
		if err != nil {
			t.Fatal(err)
		}
		want := "SELECT " + auditColumns + " FROM limb_audit_log WHERE tenant_id = " + d.marks[0] + " AND target_user_id = " + d.marks[1] +
			" AND actor_kind = " + d.marks[2] + " AND actor_id = " + d.marks[3] + " AND action IN (" + d.marks[4] + ", " + d.marks[5] + ")" +
			" AND occurred_at >= " + d.marks[6] + " AND occurred_at < " + d.marks[7] +
			" AND (occurred_at < " + d.marks[8] + " OR (occurred_at = " + d.marks[9] + " AND id < " + d.marks[10] + "))" +
			" ORDER BY occurred_at DESC, id DESC" + d.dialect.Limit(51)
		if len(probe.queries) != 1 || probe.queries[0] != want {
			t.Fatalf("%s: the query is\n%v\nwant\n%s", d.dialect.Name(), probe.queries, want)
		}
	}
}

func TestDeleteOfAuditRecordsReportsFailures(t *testing.T) {
	broken := errors.New("the database is gone")
	cutoff := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for name, failing := range map[string]func(s *Store) string{
		"the selection": func(*Store) string {
			return "SELECT id FROM limb_audit_log WHERE tenant_id = $1 AND occurred_at < $2 ORDER BY occurred_at, id LIMIT 5"
		},
		"the deletion": func(*Store) string { return "DELETE FROM limb_audit_log WHERE tenant_id = $1 AND id IN ($2)" },
	} {
		t.Run(name, func(t *testing.T) {
			var target string
			probe, s := stubbedSettings(t, func(query string, _ int) error {
				if query == target {
					return broken
				}
				return nil
			})
			probe.rows = func(string, int) ([]string, [][]driver.Value) { return []string{"id"}, [][]driver.Value{{"a1"}} }
			target = failing(s)
			if _, err := s.Audit().DeleteBefore(t.Context(), store.DefaultTenant, cutoff, 5); !errors.Is(err, broken) {
				t.Fatalf("DeleteBefore = %v, want the failure of the database", err)
			}
		})
	}
	probe, s := stubbedSettings(t, nil)
	probe.rows = func(string, int) ([]string, [][]driver.Value) {
		return []string{"a", "b"}, [][]driver.Value{{"a1", "b"}}
	}
	if _, err := s.Audit().DeleteBefore(t.Context(), store.DefaultTenant, cutoff, 5); err == nil {
		t.Fatal("DeleteBefore must report an ID that cannot be read")
	}
}
