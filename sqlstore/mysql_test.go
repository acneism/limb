package sqlstore

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"
)

type MySQLError struct {
	Number  uint16
	Message string
}

func (e MySQLError) Error() string {
	return fmt.Sprintf("Error %d: %s", e.Number, e.Message)
}

type OtherError struct {
	Number uint16
}

func (e OtherError) Error() string {
	return "other"
}

func numberAsText() error {
	type MySQLError struct {
		error
		Number string
	}
	return MySQLError{error: errors.New("text"), Number: "1062"}
}

func TestMySQLDialectsRecognizeTheErrorsOfTheDriver(t *testing.T) {
	cases := []struct {
		name                                         string
		err                                          error
		unique, foreignKey, missing, exists, retrial bool
	}{
		{name: "a duplicate entry", err: &MySQLError{Number: 1062}, unique: true},
		{name: "a child without a parent", err: &MySQLError{Number: 1452}, foreignKey: true},
		{name: "a parent that is referenced", err: &MySQLError{Number: 1451}, foreignKey: true},
		{name: "a missing table", err: &MySQLError{Number: 1146}, missing: true},
		{name: "a table that exists", err: &MySQLError{Number: 1050}, exists: true},
		{name: "a key that exists", err: &MySQLError{Number: 1061}, exists: true},
		{name: "a constraint that exists", err: &MySQLError{Number: 1826}, exists: true},
		{name: "a deadlock", err: &MySQLError{Number: 1213}, retrial: true},
		{name: "a lock wait timeout", err: &MySQLError{Number: 1205}},
		{name: "a syntax error", err: &MySQLError{Number: 1064}},
		{name: "an error by value", err: MySQLError{Number: 1062}, unique: true},
		{name: "a wrapped error", err: fmt.Errorf("insert: %w", fmt.Errorf("driver: %w", &MySQLError{Number: 1213})), retrial: true},
		{name: "a joined error", err: errors.Join(errors.New("first"), fmt.Errorf("second: %w", &MySQLError{Number: 1146})), missing: true},
		{name: "a type of another name", err: OtherError{Number: 1062}},
		{name: "a field that is not a number", err: numberAsText()},
		{name: "a plain error", err: errors.New("Error 1062")},
		{name: "no error"},
	}
	for _, dialect := range []Dialect{MySQL, MariaDB} {
		for _, tc := range cases {
			t.Run(dialect.Name()+" "+tc.name, func(t *testing.T) {
				got := verdict{
					unique: dialect.IsUniqueViolation(tc.err), foreignKey: dialect.IsForeignKeyViolation(tc.err),
					missingTable: dialect.IsMissingTable(tc.err), exists: dialect.IsAlreadyExists(tc.err), retryable: dialect.IsRetryable(tc.err),
				}
				want := verdict{unique: tc.unique, foreignKey: tc.foreignKey, missingTable: tc.missing, exists: tc.exists, retryable: tc.retrial}
				if got != want {
					t.Fatalf("the dialect recognized %+v, want %+v", got, want)
				}
			})
		}
	}
}

func TestMySQLDialectsAreDescribed(t *testing.T) {
	for _, dialect := range []Dialect{MySQL, MariaDB} {
		if dialect.Placeholder(1) != "?" || dialect.Placeholder(7) != "?" {
			t.Errorf("%s: the placeholder is %q, want a question mark", dialect.Name(), dialect.Placeholder(7))
		}
		options := dialect.TxOptions()
		if options == nil || options.Isolation != sql.LevelReadCommitted || options.ReadOnly {
			t.Errorf("%s: the options of a transaction are %+v, want READ COMMITTED", dialect.Name(), options)
		}
		insert := dialect.InsertIgnoring("t", []string{"a", "b", "c"}, []string{"?", "?", "1"}, []string{"a", "b"})
		if want := "INSERT INTO t (a, b, c) VALUES (?, ?, 1) ON DUPLICATE KEY UPDATE a = a"; insert != want {
			t.Errorf("%s: InsertIgnoring = %q, want %q", dialect.Name(), insert, want)
		}
	}
	if MySQL.Name() != "mysql" || MariaDB.Name() != "mariadb" {
		t.Fatalf("the names are %q and %q", MySQL.Name(), MariaDB.Name())
	}
}

func TestEveryDialectHasTheSameMigrations(t *testing.T) {
	names := func(dialect Dialect) []string {
		entries, err := fs.ReadDir(dialect.Migrations(), ".")
		if err != nil {
			t.Fatal(err)
		}
		var list []string
		for _, entry := range entries {
			list = append(list, entry.Name())
		}
		return list
	}
	want := names(Postgres)
	if len(want) < 3 {
		t.Fatalf("the migrations of PostgreSQL are %v", want)
	}
	for _, dialect := range []Dialect{MySQL, MariaDB} {
		if got := names(dialect); !slices.Equal(got, want) {
			t.Errorf("%s has the migrations %v, PostgreSQL has %v: every dialect starts with the same versions", dialect.Name(), got, want)
		}
	}
}

func TestMySQLMigrationsSplitIntoTheSameStatementsAsPostgres(t *testing.T) {
	_, postgres, err := loadMigrations(Postgres.Migrations(), "p_")
	if err != nil {
		t.Fatal(err)
	}
	for _, dialect := range []Dialect{MySQL, MariaDB} {
		_, versions, err := loadMigrations(dialect.Migrations(), "p_")
		if err != nil {
			t.Fatalf("%s: %v", dialect.Name(), err)
		}
		for n := range versions {
			if len(versions[n].statements) != len(postgres[n].statements)-indexStatements(postgres[n]) {
				t.Errorf("%s: migration %s has %d statements, PostgreSQL has %d and %d of them create indexes",
					dialect.Name(), versions[n].name, len(versions[n].statements), len(postgres[n].statements), indexStatements(postgres[n]))
			}
			for _, statement := range versions[n].statements {
				if !strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS ") {
					t.Errorf("%s: %q is not a CREATE TABLE IF NOT EXISTS statement: indexes belong inside it", dialect.Name(), statement)
				}
			}
		}
	}
}

func indexStatements(m migration) int {
	n := 0
	for _, statement := range m.statements {
		if strings.HasPrefix(statement, "CREATE INDEX") {
			n++
		}
	}
	return n
}

type probeRow struct {
	received string
	read     any
	counted  int64
}

func checkWithProbe(t *testing.T, dialect Dialect, row probeRow, queryErr error) error {
	t.Helper()
	probe, db := newStub(t, func(string, int) error { return queryErr })
	probe.rows = func(string, int) ([]string, [][]driver.Value) {
		return []string{"received", "read", "counted"}, [][]driver.Value{{row.received, row.read, row.counted}}
	}
	return dialect.Check(t.Context(), db)
}

func TestMySQLCheckReadsTheProbe(t *testing.T) {
	moment := time.Date(2001, 2, 3, 4, 5, 6, 789000000, time.UTC)
	good := probeRow{received: "2001-02-03 04:05:06.789000", read: moment, counted: 3}
	cases := []struct {
		name string
		row  probeRow
		want string
	}{
		{"a connection that is set up well", good, ""},
		{"a server that cuts the zeros", probeRow{received: "2001-02-03 04:05:06.789", read: moment, counted: 3}, ""},
		{"times that are read as text", probeRow{received: good.received, read: []byte("2001-02-03 04:05:06.789000"), counted: 3}, "parseTime=true"},
		{"a time zone of the driver", probeRow{received: "2001-02-03 13:05:06.789000", read: moment, counted: 3}, "loc=UTC"},
		{"a time that is not a time", probeRow{received: "soon", read: moment, counted: 3}, "loc=UTC"},
		{"a time that is read back wrongly", probeRow{received: good.received, read: moment.Add(time.Hour), counted: 3}, "parseTime=true and loc=UTC"},
		{"a character set of three bytes", probeRow{received: good.received, read: moment, counted: 6}, "utf8mb4"},
	}
	for _, dialect := range []Dialect{MySQL, MariaDB} {
		for _, tc := range cases {
			t.Run(dialect.Name()+" "+tc.name, func(t *testing.T) {
				err := checkWithProbe(t, dialect, tc.row, nil)
				switch {
				case tc.want == "" && err != nil:
					t.Fatalf("Check = %v, want nil", err)
				case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
					t.Fatalf("Check = %v, want an error that mentions %q", err, tc.want)
				}
			})
		}
	}
}

func TestMySQLCheckReportsAFailureOfTheProbe(t *testing.T) {
	broken := errors.New("the server is gone")
	err := checkWithProbe(t, MySQL, probeRow{}, broken)
	if !errors.Is(err, broken) || !strings.Contains(err.Error(), "check the mysql connection") {
		t.Fatalf("Check = %v, want the error of the probe", err)
	}
}

func TestMySQLCheckUpdateCount(t *testing.T) {
	for _, dialect := range []Dialect{MySQL, MariaDB} {
		if err := dialect.CheckUpdateCount(0); err != nil {
			t.Errorf("%s: a count of 0 = %v, want nil: the rows that changed are counted", dialect.Name(), err)
		}
		if err := dialect.CheckUpdateCount(1); err == nil || !strings.Contains(err.Error(), "clientFoundRows=true") {
			t.Errorf("%s: a count of 1 = %v, want an error about clientFoundRows=true", dialect.Name(), err)
		}
	}
}
