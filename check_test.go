package limb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/acneism/limb/internal/memstore"
	"github.com/acneism/limb/sqlstore"
	"github.com/acneism/limb/store"
)

type watchedStore struct {
	store.Store
	calls *[]string
}

func (w watchedStore) SchemaVersion(ctx context.Context) (int, error) {
	*w.calls = append(*w.calls, "schema")
	return w.Store.SchemaVersion(ctx)
}

func TestTheConnectionIsCheckedBeforeAndAfterTheSchema(t *testing.T) {
	var calls []string
	check := func(context.Context) error {
		calls = append(calls, "check")
		return nil
	}
	_, err := create(watchedStore{Store: memstore.New(), calls: &calls}, []byte(testKey), newConfig([]Option{WithAutoMigrate()}), check)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"check", "schema", "schema", "check"}; !slices.Equal(calls, want) {
		t.Fatalf("the calls were %v, want %v", calls, want)
	}
}

func TestADatabaseThatFailsTheCheckIsNotTouched(t *testing.T) {
	var calls []string
	broken := errors.New("times are not in UTC")
	check := func(context.Context) error {
		calls = append(calls, "check")
		return broken
	}
	_, err := create(watchedStore{Store: memstore.New(), calls: &calls}, []byte(testKey), newConfig([]Option{WithAutoMigrate()}), check)
	if !errors.Is(err, broken) || !strings.Contains(err.Error(), "check the database connection") {
		t.Fatalf("create = %v, want the error of the check", err)
	}
	if want := []string{"check"}; !slices.Equal(calls, want) {
		t.Fatalf("the calls were %v, want the check alone", calls)
	}
}

func TestTheCheckAfterTheSchemaCanFail(t *testing.T) {
	broken := errors.New("rows are counted the wrong way")
	runs := 0
	check := func(context.Context) error {
		runs++
		if runs == 2 {
			return broken
		}
		return nil
	}
	if _, err := create(memstore.New(), []byte(testKey), newConfig([]Option{WithAutoMigrate()}), check); !errors.Is(err, broken) {
		t.Fatalf("create = %v, want the error of the second check", err)
	}
}

type checkingDialect struct {
	sqlstore.Dialect
	err error
}

func (d checkingDialect) Check(context.Context, *sql.DB) error {
	return d.err
}

type unreachable struct{}

func (unreachable) Connect(context.Context) (driver.Conn, error) {
	return nil, errors.New("the database must not be reached")
}

func (unreachable) Driver() driver.Driver {
	return nil
}

func TestNewChecksTheConnectionOfTheDialect(t *testing.T) {
	db := sql.OpenDB(unreachable{})
	t.Cleanup(func() { _ = db.Close() })
	broken := errors.New("the DSN lacks a parameter")
	_, err := New(db, Dialect{inner: checkingDialect{Dialect: sqlstore.Postgres, err: broken}}, []byte(testKey), WithAutoMigrate())
	if !errors.Is(err, broken) {
		t.Fatalf("New = %v, want the error of the dialect", err)
	}
}
