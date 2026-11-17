package limb

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/acneism/limb/store"
)

func TestMigrateNeedsADatabaseAndADialect(t *testing.T) {
	if err := Migrate(t.Context(), nil, Postgres); err == nil || !strings.Contains(err.Error(), "database is nil") {
		t.Fatalf("Migrate without a database = %v", err)
	}
	if err := Migrate(t.Context(), newClosedDB(t), Dialect{}); err == nil || !strings.Contains(err.Error(), "dialect is not set") {
		t.Fatalf("Migrate without a dialect = %v", err)
	}
	if err := Migrate(t.Context(), newClosedDB(t), Postgres, WithTablePrefix("Not Valid")); err == nil || !strings.Contains(err.Error(), "prefix") {
		t.Fatalf("Migrate with a prefix that is not valid = %v", err)
	}
	if err := Migrate(t.Context(), newClosedDB(t), Postgres); err == nil || errors.Is(err, store.ErrSchemaOutdated) {
		t.Fatalf("Migrate with a database that cannot be reached = %v, want the failure to reach it", err)
	}
}

func TestTheCommandLineNeedsNoServiceToHelpOrToRefuse(t *testing.T) {
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := runStandalone(t.Context(), strings.NewReader(""), nil, Dialect{}, nil, args, &stdout, &stderr, nil)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("help"); code != 0 || !strings.Contains(stdout, "migrate") || stderr != "" {
		t.Fatalf("help: code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if code, _, stderr := run("bogus"); code != 2 || !strings.Contains(stderr, "commands:") {
		t.Fatalf("a command that is not understood: code %d, stderr %q", code, stderr)
	}
	for _, args := range [][]string{{"admin", "list"}, {"cleanup"}, {"admin", "delete", "root"}, {"migrate"}} {
		code, stdout, stderr := run(args...)
		if code != 1 || stdout != "" || !strings.HasPrefix(stderr, "limb: the ") || strings.Contains(stderr, "limb: limb:") {
			t.Errorf("%v with no database: code %d, stdout %q, stderr %q, want a failure that says what is missing", args, code, stdout, stderr)
		}
	}
}

func TestTheSchemaIsCreatedWithoutAServiceOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		ctx := t.Context()
		prefix := d.Prefix(t)
		opts := []Option{WithTablePrefix(prefix), WithLogger(discardingLogger())}
		if _, err := New(d.DB, d.dialect, []byte(testKey), opts...); !errors.Is(err, store.ErrSchemaOutdated) || !strings.Contains(err.Error(), "function Migrate") {
			t.Fatalf("New on an empty database = %v, want a refusal that names the function Migrate", err)
		}
		if err := Migrate(ctx, d.DB, d.dialect, append([]Option{WithAuditRetention(1)}, opts...)...); err != nil {
			t.Fatalf("Migrate failed: %v: only the prefix of the options counts, the others are not looked at", err)
		}
		a, err := New(d.DB, d.dialect, []byte(testKey), opts...)
		if err != nil {
			t.Fatalf("New after Migrate failed: %v", err)
		}
		if err = Migrate(ctx, d.DB, d.dialect, opts...); err != nil {
			t.Fatalf("a second Migrate failed: %v", err)
		}
		if err = a.Migrate(ctx); err != nil {
			t.Fatalf("the method Migrate failed: %v", err)
		}
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(func() {
				if migrateErr := Migrate(context.Background(), d.DB, d.dialect, opts...); migrateErr != nil {
					t.Errorf("Migrate at the same time as others failed: %v", migrateErr)
				}
			})
		}
		wg.Wait()
	})
}

func TestTheCommandLineMigratesAnEmptyDatabaseAndThenWorksWithoutAutoMigrateOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		ctx := t.Context()
		opts := []Option{WithTablePrefix(d.Prefix(t)), WithLogger(discardingLogger())}
		run := func(stdin string, args ...string) (int, string, string) {
			var stdout, stderr bytes.Buffer
			code := runStandalone(ctx, strings.NewReader(stdin), d.DB, d.dialect, []byte(testKey), args, &stdout, &stderr, opts)
			return code, stdout.String(), stderr.String()
		}
		code, stdout, stderr := run("", "admin", "list")
		if code != 1 || stdout != "" || !strings.Contains(stderr, "command migrate") {
			t.Fatalf("admin list on an empty database: code %d, stdout %q, stderr %q, want a refusal that names the command migrate", code, stdout, stderr)
		}
		if code, stdout, stderr = run("", "migrate"); code != 0 || !strings.Contains(stdout, "the schema of the database is at version 4") || stderr != "" {
			t.Fatalf("migrate: code %d, stdout %q, stderr %q", code, stdout, stderr)
		}
		if code, stdout, stderr = run(adminPassword+"\n", "admin", "create", "root", "--password-stdin"); code != 0 || !strings.Contains(stdout, "the administrator root is created") || stderr != "" {
			t.Fatalf("admin create: code %d, stdout %q, stderr %q", code, stdout, stderr)
		}
		if code, stdout, stderr = run("", "admin", "list"); code != 0 || !strings.Contains(stdout, "root") || stderr != "" {
			t.Fatalf("admin list: code %d, stdout %q, stderr %q", code, stdout, stderr)
		}
		if code, stdout, _ = run("", "cleanup"); code != 0 || !strings.Contains(stdout, "old data is removed") {
			t.Fatalf("cleanup: code %d, stdout %q", code, stdout)
		}
		if code, _, stderr = run("", "migrate"); code != 0 {
			t.Fatalf("a second migrate: code %d, stderr %q", code, stderr)
		}
		if _, err := New(d.DB, d.dialect, []byte(testKey), opts...); err != nil {
			t.Fatalf("New after the command failed: %v", err)
		}
	})
}
