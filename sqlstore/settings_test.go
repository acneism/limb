package sqlstore

import (
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func stubbedSettings(t *testing.T, script func(query string, n int) error) (*stub, *Store) {
	t.Helper()
	probe, db := newStub(t, script)
	s, err := New(db, Postgres)
	if err != nil {
		t.Fatal(err)
	}
	return probe, s
}

func aSetting() store.Setting {
	return store.Setting{TenantID: store.DefaultTenant, Name: "name", Value: "value", UpdatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
}

func TestSetReportsTheFailureOfEveryStatement(t *testing.T) {
	failing := map[string]func(s *Store) string{
		"the update": func(s *Store) string { return s.q.updateSetting },
		"the insert": func(s *Store) string { return s.q.insertSetting },
		"the lookup": func(s *Store) string { return s.q.settingExists },
	}
	for name, which := range failing {
		t.Run(name, func(t *testing.T) {
			var target string
			probe, s := stubbedSettings(t, func(query string, _ int) error {
				if query == target {
					return errors.New("the database is gone")
				}
				return nil
			})
			probe.affect = func(string, int) int64 { return 0 }
			probe.rows = func(string, int) ([]string, [][]driver.Value) { return nil, nil }
			target = which(s)
			if err := s.Settings().Set(t.Context(), aSetting()); err == nil {
				t.Fatalf("Set must report that %s failed", name)
			}
		})
	}
}

func TestSetTakesTheUniqueViolationOfTheLoserForNoRow(t *testing.T) {
	probe, s := stubbedSettings(t, nil)
	probe.script = func(query string, _ int) error {
		if query == s.q.insertSetting {
			return errOther
		}
		return nil
	}
	probe.affect = func(string, int) int64 { return 0 }
	probe.rows = func(string, int) ([]string, [][]driver.Value) {
		return []string{"one"}, [][]driver.Value{{int64(1)}}
	}
	if err := s.Settings().Set(t.Context(), aSetting()); err != nil {
		t.Fatalf("Set = %v, want nil: the row that won the race is there", err)
	}
}

func TestSetGivesUpWhenTheRowKeepsDisappearing(t *testing.T) {
	probe, s := stubbedSettings(t, nil)
	probe.affect = func(string, int) int64 { return 0 }
	if err := s.Settings().Set(t.Context(), aSetting()); err == nil {
		t.Fatal("Set must give up when the row keeps changing under it")
	}
	if got := probe.counts[s.q.updateSetting]; got != setRetries {
		t.Fatalf("the update was tried %d times, want %d", got, setRetries)
	}
}

func TestSetInsertsWhenTheUpdateFoundNoRow(t *testing.T) {
	probe, s := stubbedSettings(t, nil)
	probe.affect = func(query string, _ int) int64 {
		if query == s.q.updateSetting {
			return 0
		}
		return 1
	}
	if err := s.Settings().Set(t.Context(), aSetting()); err != nil {
		t.Fatalf("Set = %v, want nil", err)
	}
	if probe.counts[s.q.insertSetting] != 1 {
		t.Fatalf("the row must be inserted once, the statements were %v", probe.queries)
	}
}

func TestSettingsReportTheFailuresOfTheDatabase(t *testing.T) {
	broken := errors.New("the database is gone")
	_, s := stubbedSettings(t, func(string, int) error { return broken })
	if _, err := s.Settings().Get(t.Context(), store.DefaultTenant, "name"); !errors.Is(err, broken) || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get = %v, want the failure of the database", err)
	}
	if _, err := s.Settings().List(t.Context(), store.DefaultTenant); !errors.Is(err, broken) {
		t.Fatalf("List = %v, want the failure of the database", err)
	}
	if err := s.Settings().Delete(t.Context(), store.DefaultTenant, "name"); !errors.Is(err, broken) || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete = %v, want the failure of the database", err)
	}
}

func TestListOfSettingsReportsARowThatCannotBeRead(t *testing.T) {
	probe, s := stubbedSettings(t, nil)
	probe.rows = func(string, int) ([]string, [][]driver.Value) {
		return []string{"tenant_id"}, [][]driver.Value{{"default"}}
	}
	if _, err := s.Settings().List(t.Context(), store.DefaultTenant); err == nil {
		t.Fatal("List must report a row that does not have the columns of a setting")
	}
}
