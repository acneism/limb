package limb

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/sijms/go-ora/v2"

	"github.com/acneism/limb/internal/dbtest"
	"github.com/acneism/limb/store"
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

func newClosedDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestEndToEnd(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		db := d.DB
		prefix := d.Prefix(t)
		ctx := t.Context()

		if _, err := New(db, d.dialect, []byte(testKey), WithTablePrefix(prefix), WithLogger(discardingLogger())); !errors.Is(err, store.ErrSchemaOutdated) {
			t.Fatalf("New on an empty database without WithAutoMigrate = %v, want ErrSchemaOutdated", err)
		}
		logger, logs := capturingLogger()
		a, err := New(db, d.dialect, []byte(testKey), WithTablePrefix(prefix), WithAutoMigrate(), WithLogger(logger), emailAndUsername())
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		if _, err = New(db, d.dialect, []byte(testKey), WithTablePrefix(prefix), WithLogger(logger)); err != nil {
			t.Fatalf("New on a migrated database must work without WithAutoMigrate: %v", err)
		}
		a.hasher = newHasher(t, weakParams)

		first := mustRegister(t, a, map[string]string{"email": "Olga@Example.com", "username": "olga_o"}, goodPassword)
		if _, err = a.Register(ctx, Registration{Identifiers: map[string]string{"email": "olga@example.com"}, Password: goodPassword}); !errors.Is(err, ErrIdentifierTaken) {
			t.Fatalf("a second registration with the same e-mail address = %v, want ErrIdentifierTaken", err)
		}
		if _, err = a.Register(ctx, Registration{Identifiers: map[string]string{"email": "other@example.com", "username": "OLGA_O"}, Password: goodPassword}); !errors.Is(err, ErrIdentifierTaken) {
			t.Fatalf("a second registration with the same nickname = %v, want ErrIdentifierTaken", err)
		}
		if _, err = a.store.Identifiers().Find(ctx, store.DefaultTenant, "email", "other@example.com"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the failed registration must be rolled back, Find = %v", err)
		}

		user, _, err := a.checkPassword(ctx, "OLGA_O", goodPassword)
		if err != nil || user.ID != string(first.ID) {
			t.Fatalf("checkPassword = %+v, %v", user, err)
		}
		if _, _, err = a.checkPassword(ctx, "olga@example.com", "wrong password!!"); err != ErrInvalidCredentials { //nolint:errorlint
			t.Fatalf("err = %v, want ErrInvalidCredentials", err)
		}
		if strings.Contains(logs.String(), goodPassword) {
			t.Fatalf("logs must not contain passwords:\n%s", logs.String())
		}
	})
}

func TestRegistersConcurrently(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		db := d.DB
		a, err := New(db, d.dialect, []byte(testKey), WithTablePrefix(d.Prefix(t)), WithAutoMigrate(), WithLogger(discardingLogger()), emailAndUsername())
		if err != nil {
			t.Fatal(err)
		}
		a.hasher = newHasher(t, weakParams)
		const racers = 8
		var wins, taken atomic.Int32
		var wg sync.WaitGroup
		for n := range racers {
			wg.Go(func() {
				_, regErr := a.Register(t.Context(), Registration{
					Identifiers: map[string]string{"email": "race@example.com", "username": fmt.Sprintf("racer_%d", n)},
					Password:    goodPassword,
				})
				switch {
				case regErr == nil:
					wins.Add(1)
				case errors.Is(regErr, ErrIdentifierTaken):
					taken.Add(1)
				default:
					t.Errorf("racer %d: %v", n, regErr)
				}
			})
		}
		wg.Wait()
		if wins.Load() != 1 || taken.Load() != racers-1 {
			t.Fatalf("%d registrations succeeded and %d were refused; want exactly 1 and %d", wins.Load(), taken.Load(), racers-1)
		}
		left := 0
		for n := range racers {
			if _, findErr := a.store.Identifiers().Find(t.Context(), store.DefaultTenant, "username", fmt.Sprintf("racer_%d", n)); findErr == nil {
				left++
			}
		}
		if left != 1 {
			t.Fatalf("%d nicknames were stored, want only the one of the winner", left)
		}
	})
}

func TestUpgradesAHashOnlyOnce(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		db := d.DB
		a, err := New(db, d.dialect, []byte(testKey), WithTablePrefix(d.Prefix(t)), WithAutoMigrate(), WithLogger(discardingLogger()), emailAndUsername())
		if err != nil {
			t.Fatal(err)
		}
		a.hasher = newHasher(t, weakParams)
		user := mustRegister(t, a, map[string]string{"email": "pavel@example.com"}, goodPassword)
		counting := &countingHasher{passwordHasher: newHasher(t, strongParams)}
		a.hasher = counting

		const signIns = 8
		var wg sync.WaitGroup
		for range signIns {
			wg.Go(func() {
				if _, _, signErr := a.checkPassword(t.Context(), "pavel@example.com", goodPassword); signErr != nil {
					t.Errorf("checkPassword failed: %v", signErr)
				}
			})
		}
		wg.Wait()
		stored, err := a.store.Users().Get(t.Context(), store.DefaultTenant, string(user.ID))
		if err != nil {
			t.Fatal(err)
		}
		if stored.Version != 2 || !strings.Contains(stored.PasswordHash, "m=128,t=2,p=1") {
			t.Fatalf("exactly one of the concurrent upgrades must win: version %d, hash %s", stored.Version, stored.PasswordHash)
		}
		if ok, _, verifyErr := counting.Verify(t.Context(), goodPassword, stored.PasswordHash); verifyErr != nil || !ok {
			t.Fatalf("the upgraded hash must match the password: %v %v", ok, verifyErr)
		}
	})
}

func TestNewRejectsAConnectionOfMySQLThatIsSetUpWrongly(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		cfg, err := mysql.ParseDSN(d.DSN)
		if err != nil {
			t.Fatal(err)
		}
		cfg.ParseTime = false
		connector, err := mysql.NewConnector(cfg)
		if err != nil {
			t.Fatal(err)
		}
		db := sql.OpenDB(connector)
		t.Cleanup(func() { _ = db.Close() })
		prefix := d.Prefix(t)
		_, err = New(db, d.dialect, []byte(testKey), WithTablePrefix(prefix), WithAutoMigrate(), WithLogger(discardingLogger()))
		if err == nil || !strings.Contains(err.Error(), "parseTime=true") || !strings.Contains(err.Error(), "check the database connection") {
			t.Fatalf("New = %v, want an error that tells to add parseTime=true to the DSN", err)
		}
		if tables := d.Tables(t, prefix); len(tables) != 0 {
			t.Fatalf("New wrote %v to a database whose connection is wrong", tables)
		}
	}, "mysql", "mariadb")
}
