// Package dbtest runs the integration tests of limb on the databases that the
// environment provides. It is meant for tests and imports no database driver:
// the tests that use it import the drivers, which keeps them out of the
// library.
//
// A database takes part when the variable of its engine holds a DSN:
// LIMB_TEST_POSTGRES_DSN for PostgreSQL. Tests that use Each run once for
// every database that is configured, as a subtest named after the engine.
package dbtest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	connectTimeout = 20 * time.Second
	prefixBytes    = 4
)

type engine struct {
	name     string
	variable string
	driver   string
	reported int64
	list     func(ctx context.Context, db *sql.DB, prefix string) ([]string, error)
	drop     func(table string) string
}

var engines = []engine{
	{
		name:     "postgres",
		variable: "LIMB_TEST_POSTGRES_DSN",
		driver:   "pgx",
		reported: 1,
		list: func(ctx context.Context, db *sql.DB, prefix string) ([]string, error) {
			return listTables(ctx, db, "SELECT table_name FROM information_schema.tables "+
				"WHERE table_schema = current_schema() AND left(table_name, $2) = $1 ORDER BY table_name", prefix, len(prefix))
		},
		drop: func(table string) string { return "DROP TABLE " + table + " CASCADE" },
	},
}

// Live is a database that a test runs on.
type Live struct {
	// Name is the name of the engine: postgres.
	Name string

	// DB is the connection pool of the database.
	DB *sql.DB

	// Reported is the number of rows that the database reports for an UPDATE
	// that matches one row and leaves it as it was: 1 for the engines that
	// report the rows an UPDATE matched, 0 for those that report the rows it
	// changed.
	Reported int64

	engine engine
}

// Variables returns the names of the environment variables that configure the
// databases.
func Variables() []string {
	names := make([]string, len(engines))
	for i, e := range engines {
		names[i] = e.variable
	}
	return names
}

// Each runs the test on every database that is configured, as one subtest per
// engine. When names are given, only the engines with these names take part:
// the others have no subtest, so that a job that provides one database does not
// skip what only another one can run. When no database at all is configured the
// test is skipped.
func Each(t *testing.T, run func(t *testing.T, d *Live), only ...string) {
	t.Helper()
	var configured []engine
	for _, e := range engines {
		if os.Getenv(e.variable) != "" {
			configured = append(configured, e)
		}
	}
	if len(configured) == 0 {
		t.Skipf("no database is configured, set one of %s", strings.Join(Variables(), ", "))
	}
	for _, e := range configured {
		if len(only) > 0 && !slices.Contains(only, e.name) {
			continue
		}
		t.Run(e.name, func(t *testing.T) {
			run(t, open(t, e))
		})
	}
}

func open(t *testing.T, e engine) *Live {
	t.Helper()
	db, err := sql.Open(e.driver, os.Getenv(e.variable))
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), connectTimeout)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		t.Fatalf("the %s database is not reachable: %v", e.name, err)
	}
	return &Live{Name: e.name, DB: db, Reported: e.reported, engine: e}
}

// Prefix returns a table prefix that no other test uses and drops the tables
// that start with it when the test ends.
func (d *Live) Prefix(t *testing.T) string {
	t.Helper()
	raw := make([]byte, prefixBytes)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	prefix := "t" + hex.EncodeToString(raw) + "_"
	t.Cleanup(func() { d.dropTables(prefix) })
	return prefix
}

// Tables returns the names of the tables that start with the prefix, in
// lower case and in alphabetical order.
func (d *Live) Tables(t *testing.T, prefix string) []string {
	t.Helper()
	names, err := d.engine.list(t.Context(), d.DB, prefix)
	if err != nil {
		t.Fatalf("list the tables of %s: %v", prefix, err)
	}
	return names
}

func (d *Live) dropTables(prefix string) {
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	names, err := d.engine.list(ctx, d.DB, prefix)
	for round := 0; err == nil && len(names) > 0 && round <= len(names); round++ {
		var left []string
		for _, name := range names {
			if _, dropErr := d.DB.ExecContext(ctx, d.engine.drop(name)); dropErr != nil {
				left = append(left, name)
			}
		}
		names = left
	}
}

func listTables(ctx context.Context, db *sql.DB, query string, args ...any) ([]string, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan a table name: %w", err)
		}
		names = append(names, name)
	}
	return names, rows.Err()
}
