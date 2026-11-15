package limb

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/internal/memstore"
	"github.com/acneism/limb/internal/password"
	"github.com/acneism/limb/store"
)

const (
	testKey      = "0123456789abcdef0123456789abcdef"
	goodPassword = "correct horse battery staple"
	otherTenant  = "other"
)

var (
	weakParams   = password.Params{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	strongParams = password.Params{Memory: 128, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}
)

func newHasher(t testing.TB, params password.Params) *password.Hasher {
	t.Helper()
	h, err := password.NewHasher(password.WithParams(params), password.WithConcurrency(4))
	if err != nil {
		t.Fatalf("NewHasher failed: %v", err)
	}
	return h
}

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func capturingLogger() (*slog.Logger, *logBuffer) {
	b := &logBuffer{}
	return slog.New(slog.NewTextHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})), b
}

func discardingLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestAuth(t *testing.T, opts ...Option) *Auth {
	t.Helper()
	all := append([]Option{WithAutoMigrate(), WithLogger(discardingLogger())}, opts...)
	a, err := NewWithStore(memstore.New(), []byte(testKey), all...)
	if err != nil {
		t.Fatalf("NewWithStore failed: %v", err)
	}
	a.hasher = newHasher(t, weakParams)
	return a
}

func emailAndUsername() Option {
	return WithIdentifiers(identifier.Email(identifier.Required()), identifier.Username())
}

func mustRegister(t *testing.T, a *Auth, fields map[string]string, pw string) User {
	t.Helper()
	user, err := a.Register(t.Context(), Registration{Identifiers: fields, Password: pw})
	if err != nil {
		t.Fatalf("Register(%v) failed: %v", fields, err)
	}
	return user
}

type countingHasher struct {
	passwordHasher
	hashes, verifies, dummies atomic.Int32
	hashErr                   error
	verifyErr                 error
	dummyErr                  error
}

func (c *countingHasher) Hash(ctx context.Context, pw string) (string, error) {
	c.hashes.Add(1)
	if c.hashErr != nil {
		return "", c.hashErr
	}
	return c.passwordHasher.Hash(ctx, pw)
}

func (c *countingHasher) Verify(ctx context.Context, pw, encoded string) (bool, bool, error) {
	c.verifies.Add(1)
	if c.verifyErr != nil {
		return false, false, c.verifyErr
	}
	return c.passwordHasher.Verify(ctx, pw, encoded)
}

func (c *countingHasher) DummyVerify(ctx context.Context, pw string) error {
	c.dummies.Add(1)
	if c.dummyErr != nil {
		return c.dummyErr
	}
	return c.passwordHasher.DummyVerify(ctx, pw)
}

type faultyStore struct {
	store.Store
	schemaErr  error
	migrateErr error
	txErr      error
	findErr    error
	getErr     error
	updateErr  error
	beforeSave func(ctx context.Context, tx store.Users, u store.User)
}

func (f *faultyStore) SchemaVersion(ctx context.Context) (int, error) {
	if f.schemaErr != nil {
		return 0, f.schemaErr
	}
	return f.Store.SchemaVersion(ctx)
}

func (f *faultyStore) Migrate(ctx context.Context) error {
	if f.migrateErr != nil {
		return f.migrateErr
	}
	return f.Store.Migrate(ctx)
}

func (f *faultyStore) InTx(ctx context.Context, fn func(ctx context.Context, tx store.Repositories) error) error {
	if f.txErr != nil {
		return f.txErr
	}
	return f.Store.InTx(ctx, fn)
}

func (f *faultyStore) Users() store.Users {
	return faultyUsers{Users: f.Store.Users(), f: f}
}

func (f *faultyStore) Identifiers() store.Identifiers {
	return faultyIdentifiers{Identifiers: f.Store.Identifiers(), f: f}
}

type faultyUsers struct {
	store.Users
	f *faultyStore
}

func (u faultyUsers) Get(ctx context.Context, tenantID, id string) (store.User, error) {
	if u.f.getErr != nil {
		return store.User{}, u.f.getErr
	}
	return u.Users.Get(ctx, tenantID, id)
}

func (u faultyUsers) Update(ctx context.Context, user store.User) (store.User, error) {
	if u.f.beforeSave != nil {
		u.f.beforeSave(ctx, u.Users, user)
	}
	if u.f.updateErr != nil {
		return store.User{}, u.f.updateErr
	}
	return u.Users.Update(ctx, user)
}

type faultyIdentifiers struct {
	store.Identifiers
	f *faultyStore
}

func (i faultyIdentifiers) Find(ctx context.Context, tenantID, typ, value string) (store.Identifier, error) {
	if i.f.findErr != nil {
		return store.Identifier{}, i.f.findErr
	}
	return i.Identifiers.Find(ctx, tenantID, typ, value)
}

func TestMasterKeyLength(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31} {
		_, err := NewWithStore(memstore.New(), bytes.Repeat([]byte{'k'}, n), WithAutoMigrate())
		if err == nil || !strings.Contains(err.Error(), "master key") {
			t.Errorf("a key of %d bytes: got %v, want a master key error", n, err)
		}
	}
	for _, n := range []int{32, 33, 64} {
		if _, err := NewWithStore(memstore.New(), bytes.Repeat([]byte{'k'}, n), WithAutoMigrate()); err != nil {
			t.Errorf("a key of %d bytes: %v", n, err)
		}
	}
	key := []byte(testKey)
	a, err := NewWithStore(memstore.New(), key, WithAutoMigrate())
	if err != nil {
		t.Fatal(err)
	}
	key[0] = 'X'
	if a.masterKey[0] != '0' {
		t.Fatal("the master key must be copied: changing the caller's slice changed the service")
	}
}

func TestNewRejectsMissingArguments(t *testing.T) {
	if _, err := NewWithStore(nil, []byte(testKey)); err == nil {
		t.Error("a nil store must be rejected")
	}
	if _, err := New(nil, Postgres, []byte(testKey)); err == nil {
		t.Error("a nil database must be rejected")
	}
	if _, err := New(newClosedDB(t), Dialect{}, []byte(testKey)); err == nil {
		t.Error("a dialect that is not set must be rejected")
	}
	if _, err := New(newClosedDB(t), Postgres, []byte(testKey), WithTablePrefix("Bad!")); err == nil || !strings.Contains(err.Error(), "prefix") {
		t.Errorf("an invalid table prefix must be rejected, got %v", err)
	}
	if _, err := NewWithStore(memstore.New(), []byte(testKey), WithTablePrefix("x_")); err == nil || !strings.Contains(err.Error(), "WithTablePrefix") {
		t.Errorf("WithTablePrefix must be refused for a custom store, got %v", err)
	}
	if _, err := NewWithStore(memstore.New(), []byte(testKey), nil, WithAutoMigrate(), nil); err != nil {
		t.Errorf("a nil option must be skipped: %v", err)
	}
}

func TestNewChecksTheIdentifiers(t *testing.T) {
	cases := []struct {
		name  string
		types []identifier.Type
		want  string
	}{
		{"misconfigured type", []identifier.Type{identifier.Email(), identifier.Custom("badge", identifier.Pattern("["))}, `identifier "badge"`},
		{"zero type", []identifier.Type{{}}, "identifier"},
		{"declared twice", []identifier.Type{identifier.Email(), identifier.Email()}, `"email" is declared twice`},
		{"nobody can sign in", []identifier.Type{identifier.Custom("badge")}, "allow signing in"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewWithStore(memstore.New(), []byte(testKey), WithAutoMigrate(), WithIdentifiers(tc.types...))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestDefaultIdentifierIsARequiredEmail(t *testing.T) {
	a := newTestAuth(t)
	if len(a.types) != 1 || a.types[0].Name() != "email" || !a.types[0].IsRequired() || !a.types[0].IsLogin() {
		t.Fatalf("unexpected defaults: %+v", a.types)
	}
	_, err := a.Register(t.Context(), Registration{Password: goodPassword})
	var invalid *ValidationError
	if !errors.As(err, &invalid) || invalid.Field != "email" || invalid.Reason != "required" {
		t.Fatalf("Register without an e-mail address = %v", err)
	}
}

func TestNewChecksThePolicy(t *testing.T) {
	cases := map[string]PasswordPolicy{
		"minimum below the floor": {MinLength: 7},
		"maximum below minimum":   {MinLength: 20, MaxLength: 19},
		"maximum above ceiling":   {MaxLength: 2000},
		"nil check":               {Checks: []func(context.Context, string) error{nil}},
	}
	for name, policy := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewWithStore(memstore.New(), []byte(testKey), WithAutoMigrate(), WithPasswordPolicy(policy)); err == nil {
				t.Fatal("an invalid policy must be rejected")
			}
		})
	}
	valid := PasswordPolicy{MinLength: 8, MaxLength: 64, AllowCommon: true, AllowLoginIdentifier: true}
	a, err := NewWithStore(memstore.New(), []byte(testKey), WithAutoMigrate(), WithPasswordPolicy(valid))
	if err != nil {
		t.Fatal(err)
	}
	if a.policy.MinLength != 8 || a.policy.MaxLength != 64 || !a.policy.AllowCommon || !a.policy.AllowLogin {
		t.Fatalf("the policy was not applied: %+v", a.policy)
	}
	zero, err := NewWithStore(memstore.New(), []byte(testKey), WithAutoMigrate(), WithPasswordPolicy(PasswordPolicy{}))
	if err != nil || zero.policy.MinLength != 12 || zero.policy.MaxLength != 128 {
		t.Fatalf("the zero policy must be the default one: %+v, %v", zero.policy, err)
	}
}

func TestSchemaIsCheckedAtStart(t *testing.T) {
	boom := errors.New("database is down")
	t.Run("outdated without auto migration", func(t *testing.T) {
		_, err := NewWithStore(memstore.New(), []byte(testKey))
		if !errors.Is(err, store.ErrSchemaOutdated) || !strings.Contains(err.Error(), "WithAutoMigrate") {
			t.Fatalf("got %v, want ErrSchemaOutdated with a hint", err)
		}
	})
	t.Run("outdated with auto migration", func(t *testing.T) {
		s := memstore.New()
		if _, err := NewWithStore(s, []byte(testKey), WithAutoMigrate()); err != nil {
			t.Fatal(err)
		}
		if version, err := s.SchemaVersion(t.Context()); err != nil || version < 1 {
			t.Fatalf("the schema must be migrated: %d, %v", version, err)
		}
	})
	t.Run("current without auto migration", func(t *testing.T) {
		s := memstore.New()
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := NewWithStore(s, []byte(testKey)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("the check fails", func(t *testing.T) {
		_, err := NewWithStore(&faultyStore{Store: memstore.New(), schemaErr: boom}, []byte(testKey), WithAutoMigrate())
		if !errors.Is(err, boom) || !strings.Contains(err.Error(), "check the database schema") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("the migration fails", func(t *testing.T) {
		_, err := NewWithStore(&faultyStore{Store: memstore.New(), migrateErr: boom}, []byte(testKey), WithAutoMigrate())
		if !errors.Is(err, boom) || !strings.Contains(err.Error(), "migrate") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("the schema is still outdated after migrating", func(t *testing.T) {
		stuck := &stuckStore{Store: memstore.New()}
		_, err := NewWithStore(stuck, []byte(testKey), WithAutoMigrate())
		if !errors.Is(err, store.ErrSchemaOutdated) {
			t.Fatalf("got %v", err)
		}
	})
}

type stuckStore struct{ store.Store }

func (s *stuckStore) SchemaVersion(context.Context) (int, error) {
	return 0, store.ErrSchemaOutdated
}

func TestMigrate(t *testing.T) {
	a := newTestAuth(t)
	if err := a.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate on a current schema failed: %v", err)
	}
	boom := errors.New("cannot migrate")
	a.store = &faultyStore{Store: a.store, migrateErr: boom}
	if err := a.Migrate(t.Context()); !errors.Is(err, boom) {
		t.Fatalf("Migrate = %v, want %v", err, boom)
	}
}

func TestLoggerDefaultsAndIsUsed(t *testing.T) {
	a, err := NewWithStore(memstore.New(), []byte(testKey), WithAutoMigrate(), WithLogger(nil))
	if err != nil || a.logger == nil {
		t.Fatalf("a nil logger must fall back to the default: %v, %v", a.logger, err)
	}
	logger, _ := capturingLogger()
	custom, err := NewWithStore(memstore.New(), []byte(testKey), WithAutoMigrate(), WithLogger(logger))
	if err != nil || custom.logger != logger {
		t.Fatalf("the logger was not used: %v", err)
	}
}

func TestClockAndIDsAreInjectedInTests(t *testing.T) {
	a := newTestAuth(t)
	before := time.Now()
	if got := a.now(); got.Before(before) {
		t.Fatalf("the default clock is the system clock, got %v", got)
	}
	first, err := a.newID()
	second, err2 := a.newID()
	if err != nil || err2 != nil || first == second || len(first) != 36 {
		t.Fatalf("IDs must be unique 36 character UUIDs: %q %q %v %v", first, second, err, err2)
	}
}
