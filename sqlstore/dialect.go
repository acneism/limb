package sqlstore

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"io/fs"
	"strconv"
	"strings"
)

// Dialect describes how a database differs from the others: how parameters are
// written, how its errors are recognized and which migrations create its
// schema. It does not import any driver.
type Dialect interface {
	// Name identifies the dialect.
	Name() string

	// Placeholder returns the marker of the n-th query parameter, counting from 1.
	Placeholder(n int) string

	// IsUniqueViolation reports whether err means that a unique constraint was
	// violated.
	IsUniqueViolation(err error) bool

	// IsForeignKeyViolation reports whether err means that a foreign key
	// constraint was violated.
	IsForeignKeyViolation(err error) bool

	// IsMissingTable reports whether err means that a table does not exist.
	IsMissingTable(err error) bool

	// IsRetryable reports whether err means that the database gave up a
	// statement or a transaction because of a conflict with another one, a
	// deadlock or a failure to serialize, and that running it again may well
	// succeed.
	IsRetryable(err error) bool

	// TxOptions returns the options of the transactions of the store, or nil for
	// the default of the driver. They have to give READ COMMITTED: a statement
	// must see what was committed before it began, whatever the transaction has
	// read before.
	TxOptions() *sql.TxOptions

	// IsAlreadyExists reports whether err means that what a statement creates, a
	// table, an index or a constraint, exists already.
	IsAlreadyExists(err error) bool

	// InsertIgnoring returns an INSERT statement for the table that stores one
	// row and, when a row with the same values of the key columns exists, stores
	// nothing and raises no error. The statement reports one row when it stored
	// the row and none when it did not, so the caller learns which of several
	// concurrent inserts won without a failed statement. The values are SQL
	// expressions, one for every column, in which each parameter is written as a
	// question mark, and the statement takes the parameters in their order.
	InsertIgnoring(table string, columns, values, key []string) string

	// Check verifies that the connections of db are set up as the dialect needs,
	// for example that times are read and written in UTC, and returns an error
	// that says what to change in the way the database is opened. It reads no
	// table and writes nothing, so it can run before the schema exists.
	Check(ctx context.Context, db *sql.DB) error

	// CheckUpdateCount is given the number of rows that the database reported
	// for an UPDATE that matched one row and left it as it was. Some databases
	// report the rows that an UPDATE matched, others the rows that it changed,
	// and the store relies on the way of its dialect. An error says what to
	// change in the way the database is opened.
	CheckUpdateCount(reported int64) error

	// Migrations returns the files of the schema: bootstrap.sql, which creates
	// the table that records the schema version and the migration lock, and the
	// numbered migrations such as 0001_init.sql. They are made of statements
	// separated by semicolons, and every occurrence of {prefix} is replaced by
	// the table prefix.
	Migrations() fs.FS
}

//go:embed migrations
var migrationFiles embed.FS

var (
	postgresMigrations = mustSub(migrationFiles, "migrations/postgres")
	mysqlMigrations    = mustSub(migrationFiles, "migrations/mysql")
	mariadbMigrations  = mustSub(migrationFiles, "migrations/mariadb")
)

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("sqlstore: embedded migrations are missing: " + err.Error())
	}
	return sub
}

// Postgres is the dialect of PostgreSQL 15 and newer.
var Postgres Dialect = postgres{}

type postgres struct{}

func (postgres) Name() string {
	return "postgres"
}

func (postgres) Placeholder(n int) string {
	return "$" + strconv.Itoa(n)
}

func (postgres) IsUniqueViolation(err error) bool {
	return sqlState(err) == "23505"
}

func (postgres) IsForeignKeyViolation(err error) bool {
	return sqlState(err) == "23503"
}

func (postgres) IsMissingTable(err error) bool {
	return sqlState(err) == "42P01"
}

func (postgres) IsRetryable(err error) bool {
	switch sqlState(err) {
	case "40P01", "40001":
		return true
	}
	return false
}

func (postgres) TxOptions() *sql.TxOptions {
	return &sql.TxOptions{Isolation: sql.LevelReadCommitted}
}

func (postgres) IsAlreadyExists(err error) bool {
	switch sqlState(err) {
	case "42P07", "42710", "42701":
		return true
	}
	return false
}

func (postgres) InsertIgnoring(table string, columns, values, key []string) string {
	return "INSERT INTO " + table + " (" + strings.Join(columns, ", ") + ") VALUES (" + strings.Join(values, ", ") +
		") ON CONFLICT (" + strings.Join(key, ", ") + ") DO NOTHING"
}

func (postgres) Check(context.Context, *sql.DB) error {
	return nil
}

func (postgres) CheckUpdateCount(int64) error {
	return nil
}

func (postgres) Migrations() fs.FS {
	return postgresMigrations
}

func sqlState(err error) string {
	var coded interface{ SQLState() string }
	if errors.As(err, &coded) {
		return coded.SQLState()
	}
	return ""
}
