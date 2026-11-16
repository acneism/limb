package sqlstore

import (
	"context"
	"database/sql"
	"testing"

	"github.com/acneism/limb/store"
)

func newStubStore(t *testing.T, script func(query string, n int) error) (*stub, *Store) {
	t.Helper()
	probe, db := newStub(t, script)
	s, err := New(db, Postgres)
	if err != nil {
		t.Fatal(err)
	}
	return probe, s
}

func TestTransactionsRunAtTheIsolationOfTheDialect(t *testing.T) {
	probe, s := newStubStore(t, nil)
	if err := s.InTx(t.Context(), func(context.Context, store.Repositories) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(probe.options) != 1 || sql.IsolationLevel(probe.options[0].Isolation) != sql.LevelReadCommitted || probe.options[0].ReadOnly {
		t.Fatalf("the options of the transaction = %+v, want READ COMMITTED for writing", probe.options)
	}
}

type defaultIsolation struct{ Dialect }

func (defaultIsolation) TxOptions() *sql.TxOptions {
	return nil
}

func TestADialectCanLeaveTheIsolationToTheDriver(t *testing.T) {
	probe, db := newStub(t, nil)
	s, err := New(db, defaultIsolation{Postgres})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.InTx(t.Context(), func(context.Context, store.Repositories) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(probe.options) != 1 || sql.IsolationLevel(probe.options[0].Isolation) != sql.LevelDefault {
		t.Fatalf("the options of the transaction = %+v, want the default of the driver", probe.options)
	}
}
