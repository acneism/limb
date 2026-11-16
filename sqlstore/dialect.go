package sqlstore

import (
	"database/sql"
	"embed"
	"errors"
	"io/fs"
	"strconv"
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

	// TxOptions returns the options of the transactions of the store, or nil for
	// the default of the driver. They have to give READ COMMITTED: a statement
	// must see what was committed before it began, whatever the transaction has
	// read before.
	TxOptions() *sql.TxOptions

	// IgnoreConflict turns an INSERT statement into one that inserts nothing and
	// raises no error when the row conflicts with an existing one. Its result is
	// the number of rows inserted, so the caller learns which of several
	// concurrent inserts won without a failed statement.
	IgnoreConflict(insert string) string

	// Migrations returns the files of the schema: bootstrap.sql, which creates
	// the table that records the schema version and the migration lock, and the
	// numbered migrations such as 0001_init.sql. They are made of statements
	// separated by semicolons, and every occurrence of {prefix} is replaced by
	// the table prefix.
	Migrations() fs.FS
}

//go:embed migrations/postgres/*.sql
var postgresFiles embed.FS

var postgresMigrations = mustSub(postgresFiles, "migrations/postgres")

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

func (postgres) TxOptions() *sql.TxOptions {
	return &sql.TxOptions{Isolation: sql.LevelReadCommitted}
}

func (postgres) IgnoreConflict(insert string) string {
	return insert + " ON CONFLICT DO NOTHING"
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
