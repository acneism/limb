package limb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/acneism/limb/sqlstore"
)

func migrateDatabase(ctx context.Context, db *sql.DB, dialect Dialect, opts []Option) (int, error) {
	if db == nil {
		return 0, errors.New("limb: the database is nil")
	}
	if dialect.inner == nil {
		return 0, errors.New("limb: the dialect is not set")
	}
	cfg := newConfig(opts)
	var storeOpts []sqlstore.Option
	if cfg.prefixSet {
		storeOpts = append(storeOpts, sqlstore.WithTablePrefix(cfg.tablePrefix))
	}
	s, err := sqlstore.New(db, dialect.inner, storeOpts...)
	if err != nil {
		return 0, fmt.Errorf("limb: %w", err)
	}
	if err = checkConnection(ctx, s.Check); err != nil {
		return 0, err
	}
	if err = s.Migrate(ctx); err != nil {
		return 0, fmt.Errorf("limb: migrate the database schema: %w", err)
	}
	version, err := s.SchemaVersion(ctx)
	if err != nil {
		return 0, fmt.Errorf("limb: check the database schema: %w", err)
	}
	return version, nil
}

// Migrate creates the database schema or brings it up to date, without a
// service: New refuses a database whose schema is missing or outdated unless
// WithAutoMigrate is given, so a service that migrates by itself has no way to
// call the method Auth.Migrate before the schema is there. It is safe to call
// when the schema is current and from several processes at once, for example
// from the step of a deployment that runs before the new version starts.
//
// opts are the options that the service is made with, so that the same slice can
// be passed to New and here. Of them only WithTablePrefix is used, and the others
// are not looked at. The command line does the same with the command migrate, see
// RunCommand.
func Migrate(ctx context.Context, db *sql.DB, dialect Dialect, opts ...Option) error {
	_, err := migrateDatabase(ctx, db, dialect, opts)
	return err
}
