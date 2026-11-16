package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/acneism/limb/store"
	"github.com/acneism/limb/store/storetest"
)

const dsnVariable = "LIMB_TEST_POSTGRES_DSN"

func openPostgres(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv(dsnVariable)
	if dsn == "" {
		t.Skipf("%s is not set", dsnVariable)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		t.Fatalf("PostgreSQL is not reachable: %v", err)
	}
	return db
}

func uniquePrefix(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 4)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return "t" + hex.EncodeToString(raw) + "_"
}

func tablesOf(prefix string) []string {
	var names []string
	for _, table := range []string{"identifiers", "users", "schema", "probe", "sessions", "refresh_tokens", "attempts", "signing_keys"} {
		names = append(names, prefix+table)
	}
	return names
}

func dropTables(db *sql.DB, prefix string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, _ = db.ExecContext(ctx, "DROP TABLE IF EXISTS "+strings.Join(tablesOf(prefix), ", ")+" CASCADE")
}

func newPostgresStore(t *testing.T, db *sql.DB) *Store {
	t.Helper()
	prefix := uniquePrefix(t)
	t.Cleanup(func() { dropTables(db, prefix) })
	s, err := New(db, Postgres, WithTablePrefix(prefix))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	return s
}

func TestPostgresCompatibility(t *testing.T) {
	db := openPostgres(t)
	storetest.Run(t, func(t *testing.T) store.Store {
		return newPostgresStore(t, db)
	})
}

func tableNames(t *testing.T, db *sql.DB, prefix string) []string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(),
		"SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND left(table_name, $2) = $1 ORDER BY table_name",
		prefix, len(prefix))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return names
}

func TestTablesUseThePrefix(t *testing.T) {
	db := openPostgres(t)
	s := newPostgresStore(t, db)
	if names := tableNames(t, db, s.prefix); len(names) != 0 {
		t.Fatalf("New must not touch the database, found %v", names)
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		s.prefix + "attempts", s.prefix + "identifiers", s.prefix + "refresh_tokens", s.prefix + "schema",
		s.prefix + "sessions", s.prefix + "signing_keys", s.prefix + "users",
	}
	if got := tableNames(t, db, s.prefix); !slices.Equal(got, want) {
		t.Fatalf("tables = %v, want %v", got, want)
	}
}

func TestStoresWithDifferentPrefixesAreIndependent(t *testing.T) {
	db := openPostgres(t)
	first, second := newPostgresStore(t, db), newPostgresStore(t, db)
	ctx := t.Context()
	for _, s := range []*Store{first, second} {
		if err := s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	u := store.User{TenantID: store.DefaultTenant, ID: "00000000-0000-7000-8000-000000000001", Status: store.StatusActive, CreatedAt: time.Now()}
	if err := first.Users().Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Users().Get(ctx, u.TenantID, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a user of one prefix must not be visible under another, Get = %v", err)
	}
	if err := second.Users().Create(ctx, u); err != nil {
		t.Fatalf("the same user must be creatable under another prefix: %v", err)
	}
}

func TestSchemaVersionLifecycle(t *testing.T) {
	db := openPostgres(t)
	s := newPostgresStore(t, db)
	ctx := t.Context()
	if version, err := s.SchemaVersion(ctx); version != 0 || !errors.Is(err, store.ErrSchemaOutdated) {
		t.Fatalf("SchemaVersion before Migrate = %d, %v; want 0 and ErrSchemaOutdated", version, err)
	}
	if err := s.createSchemaTable(ctx); err != nil {
		t.Fatal(err)
	}
	if version, err := s.SchemaVersion(ctx); version != 0 || !errors.Is(err, store.ErrSchemaOutdated) {
		t.Fatalf("SchemaVersion with an empty schema table = %d, %v; want 0 and ErrSchemaOutdated", version, err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if version, err := s.SchemaVersion(ctx); version != s.latest || err != nil {
		t.Fatalf("SchemaVersion after Migrate = %d, %v; want %d", version, err, s.latest)
	}
	if _, err := db.ExecContext(ctx, "UPDATE "+s.prefix+"schema SET version = 99 WHERE id = 1"); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if version, err := s.SchemaVersion(ctx); version != 99 || err != nil {
		t.Fatalf("a schema newer than the code must be accepted, got %d, %v", version, err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if version, _ := s.SchemaVersion(ctx); version != 99 {
		t.Fatalf("Migrate must never lower the version, got %d", version)
	}
}

func lockHolder(t *testing.T, db *sql.DB, prefix string) sql.NullString {
	t.Helper()
	var holder sql.NullString
	if err := db.QueryRowContext(t.Context(), "SELECT lock_holder FROM "+prefix+"schema WHERE id = 1").Scan(&holder); err != nil {
		t.Fatal(err)
	}
	return holder
}

func TestMigrateTakesOverAnExpiredLease(t *testing.T) {
	db := openPostgres(t)
	s := newPostgresStore(t, db)
	ctx := t.Context()
	if err := s.createSchemaTable(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE "+s.prefix+"schema SET lock_holder = 'crashed', lock_expires_at = $1 WHERE id = 1", time.Now().Add(-time.Minute)); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate must take over a lease that expired: %v", err)
	}
	if holder := lockHolder(t, db, s.prefix); holder.Valid {
		t.Fatalf("the lease must be released after Migrate, held by %q", holder.String)
	}
	if version, err := s.SchemaVersion(ctx); err != nil || version != s.latest {
		t.Fatalf("SchemaVersion = %d, %v", version, err)
	}
}

func TestMigrateWaitsForALiveLease(t *testing.T) {
	db := openPostgres(t)
	s := newPostgresStore(t, db)
	if err := s.createSchemaTable(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), "UPDATE "+s.prefix+"schema SET lock_holder = 'busy', lock_expires_at = $1 WHERE id = 1", time.Now().Add(time.Hour)); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	err := s.Migrate(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Migrate = %v, want it to give up when the context ends", err)
	}
	if holder := lockHolder(t, db, s.prefix); holder.String != "busy" {
		t.Fatalf("a lease of another process must stay untouched, holder is %q", holder.String)
	}
	if names := tableNames(t, db, s.prefix+"users"); len(names) != 0 {
		t.Fatalf("nothing must be applied without the lease, found %v", names)
	}
}

func TestMigrateDetectsALostLease(t *testing.T) {
	db := openPostgres(t)
	s := newPostgresStore(t, db)
	if err := s.createSchemaTable(t.Context()); err != nil {
		t.Fatal(err)
	}
	err := s.apply(t.Context(), "stranger", s.versions[0])
	if err == nil || !strings.Contains(err.Error(), "lost") {
		t.Fatalf("apply without holding the lease = %v, want a lost lease error", err)
	}
}

func TestMigrationsCanBeAppliedTwice(t *testing.T) {
	db := openPostgres(t)
	s := newPostgresStore(t, db)
	ctx := t.Context()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, m := range s.versions {
		for _, statement := range m.statements {
			if _, err := db.ExecContext(ctx, statement); err != nil {
				t.Fatalf("migration %s is not safe to repeat: %v\n%s", m.name, err, statement)
			}
		}
	}
}

func TestStatusIsCheckedByTheDatabase(t *testing.T) {
	db := openPostgres(t)
	s := newPostgresStore(t, db)
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, err := db.ExecContext(t.Context(), "INSERT INTO "+s.prefix+"users (id, status, created_at) VALUES ('x', 'frozen', $1)", time.Now()) //nolint:gosec
	if err == nil || sqlState(err) != "23514" {
		t.Fatalf("a status outside the list must violate a check constraint, got %v", err)
	}
	if _, err = db.ExecContext(t.Context(), "INSERT INTO "+s.prefix+"users (id, status, created_at) VALUES ('x', 'active', $1)", time.Now()); err != nil { //nolint:gosec
		t.Fatalf("the tenant must default to %q: %v", store.DefaultTenant, err)
	}
	got, err := s.Users().Get(t.Context(), store.DefaultTenant, "x")
	if err != nil || got.Version != 1 || got.MustChangePassword {
		t.Fatalf("column defaults are wrong: %+v, %v", got, err)
	}
}

type customMigrations struct {
	Dialect
	files fs.FS
}

func (c customMigrations) Migrations() fs.FS {
	return c.files
}

func slowStore(t *testing.T, db *sql.DB, prefix, seconds string) *Store {
	t.Helper()
	bootstrap, err := fs.ReadFile(Postgres.Migrations(), bootstrapFile)
	if err != nil {
		t.Fatal(err)
	}
	slow := "CREATE TABLE IF NOT EXISTS {prefix}probe (n integer);\nINSERT INTO {prefix}probe (n) VALUES (1);\nSELECT pg_sleep(" + seconds + ")"
	files := fstest.MapFS{bootstrapFile: {Data: bootstrap}, "0001_slow.sql": {Data: []byte(slow)}}
	s, err := New(db, customMigrations{Dialect: Postgres, files: files}, WithTablePrefix(prefix))
	if err != nil {
		t.Fatal(err)
	}
	s.lockTTL = time.Second
	return s
}

func waitForLease(t *testing.T, db *sql.DB, prefix string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var holder sql.NullString
		err := db.QueryRowContext(t.Context(), "SELECT lock_holder FROM "+prefix+"schema WHERE id = 1").Scan(&holder)
		if err == nil && holder.Valid {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the migration never took the lease")
}

func waitForSlowStatement(t *testing.T, db *sql.DB, prefix string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var rows int
		if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+prefix+"probe").Scan(&rows); err == nil && rows > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the migration never reached its slow statement")
}

func leaseExpiry(t *testing.T, db *sql.DB, prefix string) time.Time {
	t.Helper()
	var expiry sql.NullTime
	if err := db.QueryRowContext(t.Context(), "SELECT lock_expires_at FROM "+prefix+"schema WHERE id = 1").Scan(&expiry); err != nil {
		t.Fatal(err)
	}
	return expiry.Time
}

func countProbes(t *testing.T, db *sql.DB, prefix string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+prefix+"probe").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func recordedVersion(t *testing.T, db *sql.DB, prefix string) int {
	t.Helper()
	var version int
	if err := db.QueryRowContext(t.Context(), "SELECT version FROM "+prefix+"schema WHERE id = 1").Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func TestMigrateKeepsTheLeaseWhileMigrationsRun(t *testing.T) {
	db := openPostgres(t)
	prefix := uniquePrefix(t)
	t.Cleanup(func() { dropTables(db, prefix) })
	first, rival := slowStore(t, db, prefix, "3.5"), slowStore(t, db, prefix, "3.5")

	finished := make(chan error, 1)
	go func() { finished <- first.Migrate(t.Context()) }()
	waitForLease(t, db, prefix)
	early := leaseExpiry(t, db, prefix)
	time.Sleep(1500 * time.Millisecond)
	if late := leaseExpiry(t, db, prefix); late.Sub(early) < 500*time.Millisecond {
		t.Fatalf("the lease must be pushed forward while a migration runs: it expired at %v and later at %v", early, late)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 1200*time.Millisecond)
	defer cancel()
	if err := rival.Migrate(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a second process must wait for the lease of a slow migration, got %v", err)
	}
	if err := <-finished; err != nil {
		t.Fatalf("the slow migration failed: %v", err)
	}
	if n := countProbes(t, db, prefix); n != 1 {
		t.Fatalf("the migration ran %d times, want once: another process took the lease while it was still held", n)
	}
	if version := recordedVersion(t, db, prefix); version != 1 {
		t.Fatalf("version = %d, want 1", version)
	}
	if holder := lockHolder(t, db, prefix); holder.Valid {
		t.Fatalf("the lease must be released, held by %q", holder.String)
	}
}

func TestMigrateIsAbandonedWhenTheLeaseIsTaken(t *testing.T) {
	db := openPostgres(t)
	prefix := uniquePrefix(t)
	t.Cleanup(func() { dropTables(db, prefix) })
	s := slowStore(t, db, prefix, "30")

	started := time.Now()
	finished := make(chan error, 1)
	go func() { finished <- s.Migrate(t.Context()) }()
	waitForLease(t, db, prefix)
	if _, err := db.ExecContext(t.Context(), "UPDATE "+prefix+"schema SET lock_holder = 'thief', lock_expires_at = $1 WHERE id = 1", time.Now().Add(time.Hour)); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	var err error
	select {
	case err = <-finished:
	case <-time.After(15 * time.Second):
		t.Fatal("the migration kept running after another process took its lease")
	}
	if !errors.Is(err, errLeaseLost) {
		t.Fatalf("Migrate = %v, want an error about the lost lease", err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("the running statement must be canceled, Migrate took %v", elapsed)
	}
	if holder := lockHolder(t, db, prefix); holder.String != "thief" {
		t.Fatalf("a lease of another process must stay untouched, holder is %q", holder.String)
	}
	if version := recordedVersion(t, db, prefix); version != 0 {
		t.Fatalf("an abandoned migration must not record its version, got %d", version)
	}
}

func TestMigrateIsAbandonedWhenTheLeaseCannotBeRenewed(t *testing.T) {
	db := openPostgres(t)
	prefix := uniquePrefix(t)
	t.Cleanup(func() { dropTables(db, prefix) })
	s := slowStore(t, db, prefix, "30")

	finished := make(chan error, 1)
	go func() { finished <- s.Migrate(t.Context()) }()
	waitForLease(t, db, prefix)
	waitForSlowStatement(t, db, prefix)
	if _, err := db.ExecContext(t.Context(), "DROP TABLE "+prefix+"schema"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if !errors.Is(err, errLeaseLost) {
			t.Fatalf("Migrate = %v, want an error about the lost lease", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the migration kept running although its lease could not be renewed")
	}
}
