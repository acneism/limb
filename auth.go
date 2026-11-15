package limb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/internal/password"
	"github.com/acneism/limb/sqlstore"
	"github.com/acneism/limb/store"
)

const (
	minMasterKeyLength = 32
	startupTimeout     = 3 * time.Minute
)

type passwordHasher interface {
	Hash(ctx context.Context, password string) (string, error)
	Verify(ctx context.Context, password, encoded string) (ok, needsRehash bool, err error)
	DummyVerify(ctx context.Context, password string) error
}

// Auth is the authentication service of an application. It is safe for
// concurrent use and is meant to be created once.
type Auth struct {
	store     store.Store
	types     []identifier.Type
	known     map[string]identifier.Type
	hasher    passwordHasher
	policy    password.Policy
	logger    *slog.Logger
	masterKey []byte
	tenant    string
	now       func() time.Time
	newID     func() (string, error)
}

// New creates the service on top of the database db, which the application
// opened with the driver it prefers. dialect tells which database engine it
// is. masterKey is at least 32 random bytes that protect the secrets limb
// stores; keep it out of the database and the source code.
//
// New checks the configuration and the schema of the database. It returns an
// error for a configuration that cannot work and for a database whose schema
// is missing or outdated, unless WithAutoMigrate is given.
func New(db *sql.DB, dialect Dialect, masterKey []byte, opts ...Option) (*Auth, error) {
	if db == nil {
		return nil, errors.New("limb: the database is nil")
	}
	if dialect.inner == nil {
		return nil, errors.New("limb: the dialect is not set")
	}
	cfg := newConfig(opts)
	var storeOpts []sqlstore.Option
	if cfg.prefixSet {
		storeOpts = append(storeOpts, sqlstore.WithTablePrefix(cfg.tablePrefix))
	}
	s, err := sqlstore.New(db, dialect.inner, storeOpts...)
	if err != nil {
		return nil, fmt.Errorf("limb: %w", err)
	}
	return create(s, masterKey, cfg)
}

// NewWithStore creates the service on top of a store that the application
// provides, for example one for a database that limb has no dialect for. The
// store should pass the tests of package storetest. WithTablePrefix is not
// accepted, because the tables belong to the store.
func NewWithStore(s store.Store, masterKey []byte, opts ...Option) (*Auth, error) {
	if s == nil {
		return nil, errors.New("limb: the store is nil")
	}
	cfg := newConfig(opts)
	if cfg.prefixSet {
		return nil, errors.New("limb: WithTablePrefix applies only to New, a custom store has its own tables")
	}
	return create(s, masterKey, cfg)
}

func newConfig(opts []Option) config {
	var cfg config
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

func create(s store.Store, masterKey []byte, cfg config) (*Auth, error) {
	if len(masterKey) < minMasterKeyLength {
		return nil, fmt.Errorf("limb: the master key must be at least %d bytes long, got %d", minMasterKeyLength, len(masterKey))
	}
	types, known, err := checkIdentifiers(cfg.identifiers)
	if err != nil {
		return nil, err
	}
	policy := cfg.policy.internal()
	if err = policy.Validate(); err != nil {
		return nil, fmt.Errorf("limb: %w", err)
	}
	hasher, err := password.NewHasher()
	if err != nil {
		return nil, fmt.Errorf("limb: %w", err)
	}
	logger := cfg.logger
	if logger == nil {
		logger = slog.Default()
	}
	a := &Auth{
		store:     s,
		types:     types,
		known:     known,
		hasher:    hasher,
		policy:    policy,
		logger:    logger,
		masterKey: bytes.Clone(masterKey),
		tenant:    store.DefaultTenant,
		now:       time.Now,
		newID:     newUserID,
	}
	if err = a.ensureSchema(cfg.autoMigrate); err != nil {
		return nil, err
	}
	return a, nil
}

func checkIdentifiers(declared []identifier.Type) ([]identifier.Type, map[string]identifier.Type, error) {
	types := declared
	if len(types) == 0 {
		types = []identifier.Type{identifier.Email(identifier.Required())}
	}
	known := make(map[string]identifier.Type, len(types))
	canSignIn := false
	for _, t := range types {
		if err := t.Err(); err != nil {
			return nil, nil, fmt.Errorf("limb: identifier %q: %w", t.Name(), err)
		}
		if _, twice := known[t.Name()]; twice {
			return nil, nil, fmt.Errorf("limb: identifier %q is declared twice", t.Name())
		}
		known[t.Name()] = t
		canSignIn = canSignIn || t.IsLogin()
	}
	if !canSignIn {
		return nil, nil, errors.New("limb: at least one identifier type must allow signing in")
	}
	return types, known, nil
}

func (a *Auth) ensureSchema(autoMigrate bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()
	_, err := a.store.SchemaVersion(ctx)
	switch {
	case err == nil:
		return nil
	case !errors.Is(err, store.ErrSchemaOutdated):
		return fmt.Errorf("limb: check the database schema: %w", err)
	case !autoMigrate:
		return fmt.Errorf("limb: the database schema is missing or outdated, call Migrate or use WithAutoMigrate: %w", err)
	}
	if err = a.store.Migrate(ctx); err != nil {
		return fmt.Errorf("limb: migrate the database schema: %w", err)
	}
	if _, err = a.store.SchemaVersion(ctx); err != nil {
		return fmt.Errorf("limb: check the database schema: %w", err)
	}
	return nil
}

// Migrate creates the database schema or brings it up to date. It is safe to
// call when the schema is current and from several processes at once.
func (a *Auth) Migrate(ctx context.Context) error {
	return a.store.Migrate(ctx)
}

func newUserID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("limb: generate a user ID: %w", err)
	}
	return id.String(), nil
}
