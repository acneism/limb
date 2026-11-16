// Package store defines the storage interface that limb works with. The core
// of the library never talks to a database directly, it only uses a Store, so
// it can be tested without a database and run on top of any implementation:
// the SQL one in package sqlstore, or one written by the application. Package
// storetest checks that an implementation behaves as the core expects.
//
// Every value is stored exactly as given: keys are compared byte by byte, so
// "a" and "A", or a composed and a decomposed character, are different keys.
// Times are stored in UTC with microsecond precision, and an unset time is the
// zero time.Time. Strings are never stored empty: an empty optional string
// means that there is no value.
package store

import (
	"context"
	"errors"
)

// DefaultTenant is the tenant that limb uses until tenants are supported. It
// is not empty because some databases cannot tell an empty string from NULL.
const DefaultTenant = "default"

var (
	// ErrNotFound is returned when the requested record does not exist.
	ErrNotFound = errors.New("store: not found")

	// ErrConflict is returned when a record would violate a uniqueness
	// constraint, for example when a user or an identifier already exists.
	ErrConflict = errors.New("store: conflict")

	// ErrStale is returned by Users.Update when the record was changed since it
	// was read: the version in the update does not match the stored one.
	ErrStale = errors.New("store: stale version")

	// ErrSchemaOutdated is returned by Store.SchemaVersion when the schema in
	// the database is older than the one the store needs. Migrate brings it up
	// to date.
	ErrSchemaOutdated = errors.New("store: schema is outdated")
)

// Repositories gives access to the records. The value passed to the function of
// Store.InTx works inside the transaction; the one embedded in a Store works on
// its own, one operation at a time.
type Repositories interface {
	// Users returns the repository of user accounts.
	Users() Users
	// Identifiers returns the repository of login identifiers.
	Identifiers() Identifiers
	// Sessions returns the repository of sessions.
	Sessions() Sessions
	// RefreshTokens returns the repository of refresh tokens.
	RefreshTokens() RefreshTokens
}

// Store is the storage that limb runs on. Implementations are safe for
// concurrent use. The set of repositories grows with the stages of the library
// until version 1.0.
type Store interface {
	Repositories

	// InTx runs fn in a transaction. The transaction is committed if fn returns
	// nil and rolled back if fn returns an error or panics; the error of fn is
	// returned as is. Inside fn only the Repositories argument may be used.
	InTx(ctx context.Context, fn func(ctx context.Context, tx Repositories) error) error

	// SchemaVersion returns the schema version recorded in the database, or 0
	// if the schema has not been created yet. When the version is lower than
	// the one the store needs it is returned together with an error that wraps
	// ErrSchemaOutdated.
	SchemaVersion(ctx context.Context) (int, error)

	// Migrate creates the schema or brings it up to date. It is safe to call
	// from several processes at once and when the schema is already current.
	Migrate(ctx context.Context) error
}
