package sqlstore

import (
	"database/sql/driver"
	"errors"
	"slices"
	"strings"
	"testing"
)

func schemaAtVersion(version int64) func(string, int) ([]string, [][]driver.Value) {
	return func(string, int) ([]string, [][]driver.Value) {
		return []string{"version"}, [][]driver.Value{{version}}
	}
}

func statementsOf(s *Store) int {
	total := 0
	for _, m := range s.versions {
		total += len(m.statements)
	}
	return total
}

func TestAMigrationStatementThatFindsItsObjectIsSkipped(t *testing.T) {
	probe, s := newStubStore(t, func(query string, _ int) error {
		if strings.HasPrefix(query, "CREATE TABLE IF NOT EXISTS limb_users") || strings.HasPrefix(query, "CREATE INDEX IF NOT EXISTS limb_sessions_user_idx") {
			return stubError{state: "42P07"}
		}
		return nil
	})
	probe.rows = schemaAtVersion(0)
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate = %v, want the statements that find their objects to be skipped", err)
	}
	attempted := 0
	for _, m := range s.versions {
		for _, statement := range m.statements {
			if slices.Contains(probe.queries, statement) {
				attempted++
			}
		}
	}
	if attempted != statementsOf(s) {
		t.Fatalf("%d of %d statements were run, want all of them", attempted, statementsOf(s))
	}
	if got := probe.counts[s.q.setVersion]; got != len(s.versions) {
		t.Fatalf("the version was recorded %d times, want %d", got, len(s.versions))
	}
}

func TestAMigrationStatementThatFailsStopsTheMigration(t *testing.T) {
	probe, s := newStubStore(t, func(query string, _ int) error {
		if strings.HasPrefix(query, "CREATE TABLE IF NOT EXISTS limb_identifiers") {
			return errOther
		}
		return nil
	})
	probe.rows = schemaAtVersion(0)
	err := s.Migrate(t.Context())
	var got stubError
	if !errors.As(err, &got) || got != errOther || !strings.Contains(err.Error(), "0001_init.sql") {
		t.Fatalf("Migrate = %v, want the error of the statement that names the migration", err)
	}
	if probe.counts[s.q.setVersion] != 0 {
		t.Fatal("the version of a migration that failed was recorded")
	}
	if probe.counts[s.q.releaseLock] != 1 {
		t.Fatalf("the lock was released %d times, want once", probe.counts[s.q.releaseLock])
	}
}
