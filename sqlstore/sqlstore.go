// Package sqlstore implements store.Store on top of database/sql. It does not
// import any database driver: the application opens the *sql.DB with the
// driver it prefers and tells the store which Dialect the database speaks.
//
// The tables are created by the migrations embedded in the package, in tables
// whose names start with a configurable prefix, limb_ by default. All times
// are written in UTC with microsecond precision and the database never decides
// a time or an identifier on its own.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/acneism/limb/store"
)

const (
	defaultPrefix = "limb_"
	prefixPattern = `^[a-z][a-z0-9_]{0,15}$`
)

var prefixRegexp = regexp.MustCompile(prefixPattern)

type config struct {
	prefix string
	err    error
}

// Option customizes a Store.
type Option func(*config)

// WithTablePrefix sets the prefix of the table names. It starts with a lower
// case letter, continues with lower case letters, digits and underscores, and
// is at most 16 characters long. The default is limb_. An invalid prefix makes
// New return an error.
func WithTablePrefix(prefix string) Option {
	return func(c *config) {
		if c.err != nil {
			return
		}
		if !prefixRegexp.MatchString(prefix) {
			c.err = fmt.Errorf("sqlstore: invalid table prefix %q: it must match %s", prefix, prefixPattern)
			return
		}
		c.prefix = prefix
	}
}

type executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Store is a store.Store that keeps its records in a SQL database.
type Store struct {
	db        *sql.DB
	auto      executor
	dialect   Dialect
	prefix    string
	q         queries
	bootstrap []string
	versions  []migration
	latest    int
	lockTTL   time.Duration
	now       func() time.Time
}

var _ store.Store = (*Store)(nil)

// New creates a store that works on db and speaks the given dialect. It reads
// the embedded migrations of the dialect but does not touch the database:
// call Migrate to create or update the schema.
func New(db *sql.DB, dialect Dialect, opts ...Option) (*Store, error) {
	if db == nil {
		return nil, errors.New("sqlstore: the database is nil")
	}
	if dialect == nil {
		return nil, errors.New("sqlstore: the dialect is nil")
	}
	cfg := config{prefix: defaultPrefix}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.err != nil {
		return nil, cfg.err
	}
	bootstrap, versions, err := loadMigrations(dialect.Migrations(), cfg.prefix)
	if err != nil {
		return nil, err
	}
	s := &Store{
		db:        db,
		dialect:   dialect,
		prefix:    cfg.prefix,
		bootstrap: bootstrap,
		versions:  versions,
		latest:    versions[len(versions)-1].version,
		lockTTL:   defaultLockTTL,
		now:       time.Now,
	}
	s.auto = retryingDB{db: db, s: s}
	s.q = newQueries(s.prefix, dialect)
	return s, nil
}

// Users returns the repository of user accounts.
func (s *Store) Users() store.Users {
	return users{s: s, x: s.auto}
}

// Identifiers returns the repository of login identifiers.
func (s *Store) Identifiers() store.Identifiers {
	return identifiers{s: s, x: s.auto}
}

// Sessions returns the repository of sessions.
func (s *Store) Sessions() store.Sessions {
	return sessions{s: s, x: s.auto}
}

// RefreshTokens returns the repository of refresh tokens.
func (s *Store) RefreshTokens() store.RefreshTokens {
	return refreshTokens{s: s, x: s.auto}
}

// Secrets returns the repository of the secrets of links and codes.
func (s *Store) Secrets() store.Secrets {
	return secrets{s: s, x: s.auto}
}

// Attempts returns the repository of counters of failed attempts.
func (s *Store) Attempts() store.Attempts {
	return attempts{s: s, x: s.auto}
}

// SigningKeys returns the repository of the keys that sign access tokens.
func (s *Store) SigningKeys() store.SigningKeys {
	return signingKeys{s: s, x: s.auto}
}

// Settings returns the repository of the settings that administrators change at
// run time.
func (s *Store) Settings() store.Settings {
	return settings{s: s, x: s.auto}
}

type repositories struct {
	s *Store
	x executor
}

func (r repositories) Users() store.Users {
	return users(r)
}

func (r repositories) Identifiers() store.Identifiers {
	return identifiers(r)
}

func (r repositories) Sessions() store.Sessions {
	return sessions(r)
}

func (r repositories) RefreshTokens() store.RefreshTokens {
	return refreshTokens(r)
}

func (r repositories) Secrets() store.Secrets {
	return secrets(r)
}

func (r repositories) Attempts() store.Attempts {
	return attempts(r)
}

func (r repositories) SigningKeys() store.SigningKeys {
	return signingKeys(r)
}

func (r repositories) Settings() store.Settings {
	return settings(r)
}

// InTx runs fn in a database transaction at the isolation level that the dialect
// asks for, READ COMMITTED. The transaction is committed if fn returns nil and
// rolled back if fn returns an error or panics. When the database aborts the
// transaction because of a deadlock or a failure to serialize, the whole
// transaction is run again, at most three times in all.
func (s *Store) InTx(ctx context.Context, fn func(ctx context.Context, tx store.Repositories) error) error {
	return s.retrying(ctx, func() error { return s.runTx(ctx, fn) })
}

func (s *Store) runTx(ctx context.Context, fn func(ctx context.Context, tx store.Repositories) error) error {
	tx, err := s.db.BeginTx(ctx, s.dialect.TxOptions())
	if err != nil {
		return fmt.Errorf("sqlstore: begin transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err = fn(ctx, repositories{s: s, x: tx}); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("sqlstore: commit transaction: %w", err)
	}
	committed = true
	return nil
}

// Check verifies that the connections of the database are set up as the dialect
// needs and returns an error that says what to change when they are not. It
// can be called before the schema exists, then it checks what needs no table,
// and again when the schema is there, then it also checks how the connections
// count the rows of an UPDATE, which writes to the table of the schema without
// changing anything.
func (s *Store) Check(ctx context.Context) error {
	if err := s.dialect.Check(ctx, s.db); err != nil {
		return fmt.Errorf("sqlstore: %w", err)
	}
	var one int
	switch err := s.db.QueryRowContext(ctx, s.q.probeSchema).Scan(&one); {
	case errors.Is(err, sql.ErrNoRows), err != nil && s.dialect.IsMissingTable(err):
		return nil
	case err != nil:
		return fmt.Errorf("sqlstore: check the database: %w", err)
	}
	result, err := s.db.ExecContext(ctx, s.q.touchSchema)
	if err != nil {
		return fmt.Errorf("sqlstore: check the database: %w", err)
	}
	reported, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlstore: check the database: %w", err)
	}
	if err = s.dialect.CheckUpdateCount(reported); err != nil {
		return fmt.Errorf("sqlstore: %w", err)
	}
	return nil
}

// SchemaVersion returns the version recorded in the database, 0 if the schema
// does not exist, together with an error that wraps store.ErrSchemaOutdated if
// it is older than the latest embedded migration.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var version int
	err := s.db.QueryRowContext(ctx, s.q.schemaVersion).Scan(&version)
	switch {
	case err == nil:
	case errors.Is(err, sql.ErrNoRows), s.dialect.IsMissingTable(err):
		version = 0
	default:
		return 0, fmt.Errorf("sqlstore: read schema version: %w", err)
	}
	if version < s.latest {
		return version, fmt.Errorf("%w: the database has version %d, version %d is needed", store.ErrSchemaOutdated, version, s.latest)
	}
	return version, nil
}
