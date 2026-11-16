package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/sijms/go-ora/v2"

	"github.com/acneism/limb/internal/dbtest"
	"github.com/acneism/limb/store"
	"github.com/acneism/limb/store/storetest"
)

type database struct {
	*dbtest.Live
	dialect Dialect
}

var dialects = map[string]Dialect{
	"postgres": Postgres,
	"mysql":    MySQL,
	"mariadb":  MariaDB,
	"oracle":   Oracle,
}

func eachDatabase(t *testing.T, run func(t *testing.T, d *database), only ...string) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, live *dbtest.Live) {
		t.Helper()
		dialect, ok := dialects[live.Name]
		if !ok {
			t.Fatalf("the database %q has no dialect", live.Name)
		}
		run(t, &database{Live: live, dialect: dialect})
	}, only...)
}

func (d *database) newStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(d.DB, d.dialect, WithTablePrefix(d.Prefix(t)))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	return s
}

func (d *database) p(n int) string {
	return d.dialect.Placeholder(n)
}

func (d *database) exec(t *testing.T, statements ...string) {
	t.Helper()
	for _, statement := range statements {
		if _, err := d.DB.ExecContext(t.Context(), statement); err != nil {
			t.Fatalf("%v\n%s", err, statement)
		}
	}
}

func TestCompatibility(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		storetest.Run(t, func(t *testing.T) store.Store {
			return d.newStore(t)
		})
	})
}

func TestTablesUseThePrefix(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		s := d.newStore(t)
		if names := d.Tables(t, s.prefix); len(names) != 0 {
			t.Fatalf("New must not touch the database, found %v", names)
		}
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
		want := []string{
			s.prefix + "attempts", s.prefix + "identifiers", s.prefix + "refresh_tokens", s.prefix + "schema",
			s.prefix + "sessions", s.prefix + "signing_keys", s.prefix + "users",
		}
		if got := d.Tables(t, s.prefix); !slices.Equal(got, want) {
			t.Fatalf("tables = %v, want %v", got, want)
		}
	})
}

func TestCheck(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		s := d.newStore(t)
		if err := s.Check(t.Context()); err != nil {
			t.Fatalf("Check before the schema exists = %v, want nil", err)
		}
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := s.Check(t.Context()); err != nil {
			t.Fatalf("Check after the schema exists = %v, want nil", err)
		}
		result, err := d.DB.ExecContext(t.Context(), s.q.touchSchema)
		if err != nil {
			t.Fatal(err)
		}
		if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != d.Reported {
			t.Fatalf("the probing UPDATE reported %d rows, %v; the database is expected to report %d", rows, rowsErr, d.Reported)
		}
	})
}

func TestStoresWithDifferentPrefixesAreIndependent(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		first, second := d.newStore(t), d.newStore(t)
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
	})
}

func TestSchemaVersionLifecycle(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		s := d.newStore(t)
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
		d.exec(t, "UPDATE "+s.prefix+"schema SET version = 99 WHERE id = 1")
		if version, err := s.SchemaVersion(ctx); version != 99 || err != nil {
			t.Fatalf("a schema newer than the code must be accepted, got %d, %v", version, err)
		}
		if err := s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		if version, _ := s.SchemaVersion(ctx); version != 99 {
			t.Fatalf("Migrate must never lower the version, got %d", version)
		}
	})
}

func (d *database) lockHolder(t *testing.T, prefix string) sql.NullString {
	t.Helper()
	var holder sql.NullString
	if err := d.DB.QueryRowContext(t.Context(), "SELECT lock_holder FROM "+prefix+"schema WHERE id = 1").Scan(&holder); err != nil {
		t.Fatal(err)
	}
	return holder
}

func (d *database) setLease(t *testing.T, prefix, holder string, expires time.Time) {
	t.Helper()
	statement := "UPDATE " + prefix + "schema SET lock_holder = " + d.p(1) + ", lock_expires_at = " + d.p(2) + " WHERE id = 1" //nolint:gosec
	if _, err := d.DB.ExecContext(t.Context(), statement, holder, storedTime(expires)); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateTakesOverAnExpiredLease(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		s := d.newStore(t)
		ctx := t.Context()
		if err := s.createSchemaTable(ctx); err != nil {
			t.Fatal(err)
		}
		d.setLease(t, s.prefix, "crashed", time.Now().Add(-time.Minute))
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("Migrate must take over a lease that expired: %v", err)
		}
		if holder := d.lockHolder(t, s.prefix); holder.Valid {
			t.Fatalf("the lease must be released after Migrate, held by %q", holder.String)
		}
		if version, err := s.SchemaVersion(ctx); err != nil || version != s.latest {
			t.Fatalf("SchemaVersion = %d, %v", version, err)
		}
	})
}

func TestMigrateWaitsForALiveLease(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		s := d.newStore(t)
		if err := s.createSchemaTable(t.Context()); err != nil {
			t.Fatal(err)
		}
		d.setLease(t, s.prefix, "busy", time.Now().Add(time.Hour))
		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		defer cancel()
		err := s.Migrate(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Migrate = %v, want it to give up when the context ends", err)
		}
		if holder := d.lockHolder(t, s.prefix); holder.String != "busy" {
			t.Fatalf("a lease of another process must stay untouched, holder is %q", holder.String)
		}
		if names := d.Tables(t, s.prefix+"users"); len(names) != 0 {
			t.Fatalf("nothing must be applied without the lease, found %v", names)
		}
	})
}

func TestMigrateDetectsALostLease(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		s := d.newStore(t)
		if err := s.createSchemaTable(t.Context()); err != nil {
			t.Fatal(err)
		}
		err := s.apply(t.Context(), "stranger", s.versions[0])
		if err == nil || !strings.Contains(err.Error(), "lost") {
			t.Fatalf("apply without holding the lease = %v, want a lost lease error", err)
		}
	})
}

func TestRenewingTheLeaseAtTheSameTime(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		s := d.newStore(t)
		ctx := t.Context()
		if err := s.createSchemaTable(ctx); err != nil {
			t.Fatal(err)
		}
		moment := time.Now()
		s.now = func() time.Time { return moment }
		if err := s.acquire(ctx, "frozen"); err != nil {
			t.Fatal(err)
		}
		for n := range 3 {
			if err := s.extendLease(ctx, "frozen"); err != nil {
				t.Fatalf("renewal %d at the very time of the last one = %v, want nil", n+1, err)
			}
		}
		if err := s.extendLease(ctx, "stranger"); err == nil {
			t.Fatal("a process that does not hold the lease renewed it")
		}
		if holder := d.lockHolder(t, s.prefix); holder.String != "frozen" {
			t.Fatalf("the holder of the lease is %q, want it untouched", holder.String)
		}
	})
}

func TestMigrationsCanBeAppliedTwice(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		s := d.newStore(t)
		ctx := t.Context()
		if err := s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		for _, m := range s.versions {
			for _, statement := range m.statements {
				if _, err := d.DB.ExecContext(ctx, statement); err != nil && !d.dialect.IsAlreadyExists(err) {
					t.Fatalf("migration %s is not safe to repeat: %v\n%s", m.name, err, statement)
				}
			}
		}
	})
}

func TestStatusIsCheckedByTheDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		s := d.newStore(t)
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
		insert := func(status string) error {
			_, err := d.DB.ExecContext(t.Context(),
				"INSERT INTO "+s.prefix+"users (id, status, created_at) VALUES ('x', '"+status+"', "+d.p(1)+")", storedTime(time.Now())) //nolint:gosec
			return err
		}
		err := insert("frozen")
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), s.prefix+"users_status_check") {
			t.Fatalf("a status outside the list must violate the check constraint, got %v", err)
		}
		if err = insert("active"); err != nil {
			t.Fatalf("the tenant must default to %q: %v", store.DefaultTenant, err)
		}
		got, err := s.Users().Get(t.Context(), store.DefaultTenant, "x")
		if err != nil || got.Version != 1 || got.MustChangePassword {
			t.Fatalf("column defaults are wrong: %+v, %v", got, err)
		}
	})
}

type verdict struct {
	unique, foreignKey, missingTable, exists, retryable bool
}

func TestTheDialectRecognizesTheErrorsOfTheDriver(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		prefix := d.Prefix(t)
		parent, child := prefix+"parent", prefix+"child"
		d.exec(t,
			"CREATE TABLE "+parent+" (id INTEGER NOT NULL PRIMARY KEY)",
			"CREATE TABLE "+child+" (id INTEGER NOT NULL PRIMARY KEY, parent_id INTEGER NOT NULL, CONSTRAINT "+prefix+
				"child_fk FOREIGN KEY (parent_id) REFERENCES "+parent+" (id))",
			"CREATE INDEX "+prefix+"child_idx ON "+child+" (parent_id)",
			"INSERT INTO "+parent+" (id) VALUES (1)",
		)
		probes := []struct {
			name, statement string
			want            verdict
		}{
			{"a duplicate key", "INSERT INTO " + parent + " (id) VALUES (1)", verdict{unique: true}},
			{"a missing parent", "INSERT INTO " + child + " (id, parent_id) VALUES (1, 2)", verdict{foreignKey: true}},
			{"a missing table", "SELECT 1 FROM " + prefix + "missing", verdict{missingTable: true}},
			{"an existing table", "CREATE TABLE " + parent + " (id INTEGER NOT NULL PRIMARY KEY)", verdict{exists: true}},
			{"an existing index", "CREATE INDEX " + prefix + "child_idx ON " + child + " (parent_id)", verdict{exists: true}},
			{"a syntax error", "SELEKT 1", verdict{}},
		}
		for _, probe := range probes {
			var err error
			if strings.HasPrefix(probe.statement, "SELECT") {
				var one int
				err = d.DB.QueryRowContext(t.Context(), probe.statement).Scan(&one)
			} else {
				_, err = d.DB.ExecContext(t.Context(), probe.statement)
			}
			if err == nil {
				t.Fatalf("%s: the statement succeeded\n%s", probe.name, probe.statement)
			}
			got := verdict{
				unique: d.dialect.IsUniqueViolation(err), foreignKey: d.dialect.IsForeignKeyViolation(err),
				missingTable: d.dialect.IsMissingTable(err), exists: d.dialect.IsAlreadyExists(err), retryable: d.dialect.IsRetryable(err),
			}
			if got != probe.want {
				t.Errorf("%s: the dialect recognized %+v, want %+v, for the error %v", probe.name, got, probe.want, err)
			}
		}
	})
}

func TestTheDialectRecognizesADeadlock(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		prefix := d.Prefix(t)
		tables := [2]string{prefix + "first", prefix + "second"}
		var txs [2]*sql.Tx
		for i, table := range tables {
			d.exec(t, "CREATE TABLE "+table+" (n INTEGER NOT NULL)", "INSERT INTO "+table+" (n) VALUES (0)")
			tx, err := d.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = tx.Rollback() })
			if _, err = tx.ExecContext(ctx, "UPDATE "+table+" SET n = n + 1"); err != nil { //nolint:gosec
				t.Fatal(err)
			}
			txs[i] = tx
		}
		outcomes := make(chan error, len(txs))
		for i := range txs {
			go func() {
				_, err := txs[i].ExecContext(ctx, "UPDATE "+tables[1-i]+" SET n = n + 1")
				if err != nil {
					_ = txs[i].Rollback()
				}
				outcomes <- err
			}()
		}
		victims := 0
		for range txs {
			select {
			case err := <-outcomes:
				if err == nil {
					continue
				}
				victims++
				if !d.dialect.IsRetryable(err) {
					t.Errorf("the dialect does not take the error of a deadlock for one that can be repeated: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("the database detected no deadlock")
			}
		}
		if victims != 1 {
			t.Fatalf("%d transactions were chosen as the victim of the deadlock, want one", victims)
		}
	})
}

func TestInsertIgnoringStoresTheRowOnce(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		s := d.newStore(t)
		ctx := t.Context()
		if err := s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		at := storedTime(time.Now())
		insert := func(key string) (int64, error) {
			result, err := d.DB.ExecContext(ctx, s.q.insertAttempt, key, at)
			if err != nil {
				return 0, err
			}
			return result.RowsAffected()
		}
		if rows, err := insert("one"); err != nil || rows != 1 {
			t.Fatalf("the first insert reported %d rows, %v; want one", rows, err)
		}
		if rows, err := insert("one"); err != nil || rows != 0 {
			t.Fatalf("an insert of a key that exists reported %d rows, %v; want none and no error", rows, err)
		}
		const racers = 8
		var stored atomic.Int64
		var wg sync.WaitGroup
		for range racers {
			wg.Go(func() {
				rows, err := insert("raced")
				if err != nil && !d.dialect.IsUniqueViolation(err) {
					t.Errorf("an insert of a key that is being inserted failed: %v", err)
				}
				stored.Add(rows)
			})
		}
		wg.Wait()
		if stored.Load() != 1 {
			t.Fatalf("%d of %d concurrent inserts of one key stored a row, want exactly one", stored.Load(), racers)
		}
	})
}

type customMigrations struct {
	Dialect
	files fs.FS
}

func (c customMigrations) Migrations() fs.FS {
	return c.files
}

type gate struct {
	tx *sql.Tx
}

func (g *gate) open() {
	_ = g.tx.Rollback()
}

func (d *database) closedGate(t *testing.T, prefix string) *gate {
	t.Helper()
	d.exec(t, "CREATE TABLE "+prefix+"gate (n INTEGER NOT NULL)", "INSERT INTO "+prefix+"gate (n) VALUES (1)")
	tx, err := d.DB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	g := &gate{tx: tx}
	t.Cleanup(g.open)
	if _, err = tx.ExecContext(t.Context(), "UPDATE "+prefix+"gate SET n = n"); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	return g
}

func (d *database) slowStore(t *testing.T, prefix string) *Store {
	t.Helper()
	bootstrap, err := fs.ReadFile(d.dialect.Migrations(), bootstrapFile)
	if err != nil {
		t.Fatal(err)
	}
	slow := "CREATE TABLE {prefix}probe (n INTEGER NOT NULL);\nINSERT INTO {prefix}probe (n) VALUES (1);\nUPDATE {prefix}gate SET n = n"
	files := fstest.MapFS{bootstrapFile: {Data: bootstrap}, "0001_slow.sql": {Data: []byte(slow)}}
	s, err := New(d.DB, customMigrations{Dialect: d.dialect, files: files}, WithTablePrefix(prefix))
	if err != nil {
		t.Fatal(err)
	}
	s.lockTTL = time.Second
	return s
}

func (d *database) waitForLease(t *testing.T, prefix string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var holder sql.NullString
		err := d.DB.QueryRowContext(t.Context(), "SELECT lock_holder FROM "+prefix+"schema WHERE id = 1").Scan(&holder)
		if err == nil && holder.Valid {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the migration never took the lease")
}

func (d *database) waitForSlowStatement(t *testing.T, prefix string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var rows int
		if err := d.DB.QueryRowContext(t.Context(), "SELECT count(*) FROM "+prefix+"probe").Scan(&rows); err == nil && rows > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the migration never reached its slow statement")
}

func (d *database) leaseExpiry(t *testing.T, prefix string) time.Time {
	t.Helper()
	var expiry sql.NullTime
	if err := d.DB.QueryRowContext(t.Context(), "SELECT lock_expires_at FROM "+prefix+"schema WHERE id = 1").Scan(&expiry); err != nil {
		t.Fatal(err)
	}
	return expiry.Time
}

func (d *database) countProbes(t *testing.T, prefix string) int {
	t.Helper()
	var n int
	if err := d.DB.QueryRowContext(t.Context(), "SELECT count(*) FROM "+prefix+"probe").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (d *database) recordedVersion(t *testing.T, prefix string) int {
	t.Helper()
	var version int
	if err := d.DB.QueryRowContext(t.Context(), "SELECT version FROM "+prefix+"schema WHERE id = 1").Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func TestMigrateKeepsTheLeaseWhileMigrationsRun(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		prefix := d.Prefix(t)
		slow := d.closedGate(t, prefix)
		first, rival := d.slowStore(t, prefix), d.slowStore(t, prefix)

		finished := make(chan error, 1)
		go func() { finished <- first.Migrate(t.Context()) }()
		d.waitForLease(t, prefix)
		d.waitForSlowStatement(t, prefix)
		early := d.leaseExpiry(t, prefix)
		time.Sleep(1500 * time.Millisecond)
		if late := d.leaseExpiry(t, prefix); late.Sub(early) < 500*time.Millisecond {
			t.Fatalf("the lease must be pushed forward while a migration runs: it expired at %v and later at %v", early, late)
		}

		ctx, cancel := context.WithTimeout(t.Context(), 1200*time.Millisecond)
		defer cancel()
		if err := rival.Migrate(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("a second process must wait for the lease of a slow migration, got %v", err)
		}
		slow.open()
		select {
		case err := <-finished:
			if err != nil {
				t.Fatalf("the slow migration failed: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("the slow migration did not finish after its statement was released")
		}
		if n := d.countProbes(t, prefix); n != 1 {
			t.Fatalf("the migration ran %d times, want once: another process took the lease while it was still held", n)
		}
		if version := d.recordedVersion(t, prefix); version != 1 {
			t.Fatalf("version = %d, want 1", version)
		}
		if holder := d.lockHolder(t, prefix); holder.Valid {
			t.Fatalf("the lease must be released, held by %q", holder.String)
		}
	})
}

func TestMigrateIsAbandonedWhenTheLeaseIsTaken(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		prefix := d.Prefix(t)
		slow := d.closedGate(t, prefix)
		s := d.slowStore(t, prefix)

		started := time.Now()
		finished := make(chan error, 1)
		go func() { finished <- s.Migrate(t.Context()) }()
		d.waitForLease(t, prefix)
		d.waitForSlowStatement(t, prefix)
		d.setLease(t, prefix, "thief", time.Now().Add(time.Hour))
		if !d.Cancels {
			slow.open()
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
		if holder := d.lockHolder(t, prefix); holder.String != "thief" {
			t.Fatalf("a lease of another process must stay untouched, holder is %q", holder.String)
		}
		if version := d.recordedVersion(t, prefix); version != 0 {
			t.Fatalf("an abandoned migration must not record its version, got %d", version)
		}
	})
}

func TestMigrateIsAbandonedWhenTheLeaseCannotBeRenewed(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		prefix := d.Prefix(t)
		slow := d.closedGate(t, prefix)
		s := d.slowStore(t, prefix)

		finished := make(chan error, 1)
		go func() { finished <- s.Migrate(t.Context()) }()
		d.waitForLease(t, prefix)
		d.waitForSlowStatement(t, prefix)
		d.exec(t, "DROP TABLE "+prefix+"schema")
		if !d.Cancels {
			time.Sleep(3 * s.lockTTL / 2)
			slow.open()
		}
		select {
		case err := <-finished:
			if !errors.Is(err, errLeaseLost) {
				t.Fatalf("Migrate = %v, want an error about the lost lease", err)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("the migration kept running although its lease could not be renewed")
		}
	})
}

func TestTheTimeZoneOfTheProcessDoesNotMatter(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		ctx := t.Context()
		first := d.newStore(t)
		if err := first.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		instant := time.Date(2026, 6, 7, 8, 9, 10, 123456000, time.UTC)
		for n, offset := range []int{9 * 60 * 60, -5 * 60 * 60} {
			func() {
				previous := time.Local
				time.Local = time.FixedZone("elsewhere", offset)
				defer func() { time.Local = previous }()
				db, err := sql.Open(d.Driver, d.DSN)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = db.Close() }()
				s, err := New(db, d.dialect, WithTablePrefix(first.prefix))
				if err != nil {
					t.Fatal(err)
				}
				userID := fmt.Sprintf("00000000-0000-7000-8000-%012d", n+1)
				if err = s.Users().Create(ctx, store.User{TenantID: store.DefaultTenant, ID: userID, Status: store.StatusActive, CreatedAt: instant}); err != nil {
					t.Fatalf("offset %d: %v", offset, err)
				}
				sess := store.Session{
					TenantID: store.DefaultTenant, ID: userID, Kind: store.SessionToken, UserID: userID,
					CreatedAt: instant, LastSeenAt: instant, ExpiresAt: instant.Add(time.Hour),
				}
				if err = s.Sessions().Create(ctx, sess); err != nil {
					t.Fatalf("offset %d: %v", offset, err)
				}
				for moment, want := range map[time.Time]int{instant.Add(time.Hour - time.Second): 1, instant.Add(time.Hour + time.Second): 0} {
					if list, listErr := s.Sessions().ListByUser(ctx, store.DefaultTenant, userID, moment); listErr != nil || len(list) != want {
						t.Fatalf("offset %d: ListByUser at %v = %d sessions, %v; want %d", offset, moment, len(list), listErr, want)
					}
				}
				key := fmt.Sprintf("zone-%d", n)
				for step, hit := range []struct {
					at   time.Time
					want int
				}{
					{instant, 1},
					{instant.Add(time.Minute - time.Microsecond), 2},
					{instant.Add(time.Minute), 1},
				} {
					counter, hitErr := s.Attempts().Hit(ctx, key, hit.at, time.Minute)
					if hitErr != nil || counter.Count != hit.want {
						t.Fatalf("offset %d: hit %d = %+v, %v; want a count of %d", offset, step+1, counter, hitErr, hit.want)
					}
				}
			}()
		}
	})
}
