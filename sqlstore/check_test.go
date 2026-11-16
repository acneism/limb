package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
)

type checkedDialect struct {
	Dialect
	connection error
	count      error
	reported   []int64
}

func (d *checkedDialect) Check(context.Context, *sql.DB) error {
	return d.connection
}

func (d *checkedDialect) CheckUpdateCount(reported int64) error {
	d.reported = append(d.reported, reported)
	return d.count
}

func newCheckedStore(t *testing.T, d *checkedDialect) (*stub, *Store) {
	t.Helper()
	probe, db := newStub(t, nil)
	s, err := New(db, d)
	if err != nil {
		t.Fatal(err)
	}
	return probe, s
}

func TestCheckStopsAtTheConnection(t *testing.T) {
	broken := errors.New("the connection is set up wrongly")
	probe, s := newCheckedStore(t, &checkedDialect{Dialect: Postgres, connection: broken})
	if err := s.Check(t.Context()); !errors.Is(err, broken) {
		t.Fatalf("Check = %v, want the error of the dialect", err)
	}
	if len(probe.queries) != 0 {
		t.Fatalf("Check ran %q although the connection is wrong", probe.queries)
	}
}

func TestCheckLeavesTheCountAloneWithoutASchema(t *testing.T) {
	cases := map[string]func(s *Store, query string) error{
		"a missing table": func(s *Store, query string) error {
			if query == s.q.probeSchema {
				return stubError{state: "42P01"}
			}
			return nil
		},
		"a missing row": func(*Store, string) error { return nil },
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			d := &checkedDialect{Dialect: Postgres}
			probe, s := newCheckedStore(t, d)
			probe.script = func(query string, _ int) error { return script(s, query) }
			if err := s.Check(t.Context()); err != nil {
				t.Fatalf("Check = %v, want nil", err)
			}
			if len(d.reported) != 0 || probe.counts[s.q.touchSchema] != 0 {
				t.Fatalf("Check counted the rows of an UPDATE: %v, %d statements", d.reported, probe.counts[s.q.touchSchema])
			}
		})
	}
}

func withSchemaRow(probe *stub, s *Store, reported int64) {
	probe.rows = func(query string, _ int) ([]string, [][]driver.Value) {
		if query == s.q.probeSchema {
			return []string{"1"}, [][]driver.Value{{int64(1)}}
		}
		return nil, nil
	}
	probe.affect = func(string, int) int64 { return reported }
}

func TestCheckGivesTheReportedCountToTheDialect(t *testing.T) {
	d := &checkedDialect{Dialect: Postgres}
	probe, s := newCheckedStore(t, d)
	withSchemaRow(probe, s, 7)
	if err := s.Check(t.Context()); err != nil {
		t.Fatalf("Check = %v, want nil", err)
	}
	if len(d.reported) != 1 || d.reported[0] != 7 || probe.counts[s.q.touchSchema] != 1 {
		t.Fatalf("the dialect was given %v after %d UPDATE statements, want 7 after one", d.reported, probe.counts[s.q.touchSchema])
	}
	if !strings.HasPrefix(s.q.touchSchema, "UPDATE ") || !strings.Contains(s.q.touchSchema, "SET version = version") {
		t.Fatalf("the probing statement %q must set a column to the value it has", s.q.touchSchema)
	}
}

func TestCheckReturnsTheVerdictOnTheCount(t *testing.T) {
	wrong := errors.New("the rows are counted the wrong way")
	probe, s := newCheckedStore(t, &checkedDialect{Dialect: Postgres, count: wrong})
	withSchemaRow(probe, s, 1)
	if err := s.Check(t.Context()); !errors.Is(err, wrong) {
		t.Fatalf("Check = %v, want the verdict of the dialect", err)
	}
}

func TestCheckReportsAFailureToProbe(t *testing.T) {
	probe, s := newCheckedStore(t, &checkedDialect{Dialect: Postgres})
	probe.script = func(query string, _ int) error {
		if query == s.q.probeSchema {
			return errOther
		}
		return nil
	}
	err := s.Check(t.Context())
	var got stubError
	if !errors.As(err, &got) || got != errOther || !strings.Contains(err.Error(), "check the database") {
		t.Fatalf("Check = %v, want the error of the probe", err)
	}
	failing, s2 := newCheckedStore(t, &checkedDialect{Dialect: Postgres})
	withSchemaRow(failing, s2, 1)
	failing.script = func(query string, _ int) error {
		if query == s2.q.touchSchema {
			return errOther
		}
		return nil
	}
	if err = s2.Check(t.Context()); !errors.As(err, &got) || got != errOther {
		t.Fatalf("Check = %v, want the error of the UPDATE", err)
	}
}
