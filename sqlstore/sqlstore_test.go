package sqlstore

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

type stateError struct{ state string }

func (e stateError) Error() string    { return "state " + e.state }
func (e stateError) SQLState() string { return e.state }

type questionMarkDialect struct{ Dialect }

func (questionMarkDialect) Placeholder(n int) string { return fmt.Sprintf(":p%d", n) }

func TestNewValidatesItsArguments(t *testing.T) {
	if _, err := New(nil, Postgres); err == nil {
		t.Fatal("a nil database must be rejected")
	}
	if _, err := New(new(sql.DB), nil); err == nil {
		t.Fatal("a nil dialect must be rejected")
	}
	s, err := New(new(sql.DB), Postgres, nil)
	if err != nil {
		t.Fatalf("a nil option must be skipped: %v", err)
	}
	if s.prefix != "limb_" || s.latest != 4 || len(s.bootstrap) == 0 || s.lockTTL != 2*time.Minute {
		t.Fatalf("unexpected defaults: prefix=%q latest=%d bootstrap=%d lease=%v", s.prefix, s.latest, len(s.bootstrap), s.lockTTL)
	}
}

func TestWithTablePrefix(t *testing.T) {
	for _, prefix := range []string{"limb_", "a", "app_", "x1_y2", "abcdefghijklmnop", "tenant"} {
		s, err := New(new(sql.DB), Postgres, WithTablePrefix(prefix))
		if err != nil || s.prefix != prefix {
			t.Errorf("prefix %q: got %v, %v", prefix, s, err)
		}
	}
	for _, prefix := range []string{"", "Limb_", "1abc", "has space", "dash-", "abcdefghijklmnopq", "limb_;drop table x", "ünï", "_x", "a.b", "a\"b"} {
		_, err := New(new(sql.DB), Postgres, WithTablePrefix(prefix))
		if err == nil || !strings.Contains(err.Error(), "invalid table prefix") {
			t.Errorf("prefix %q: got %v, want an invalid prefix error", prefix, err)
		}
	}
	_, err := New(new(sql.DB), Postgres, WithTablePrefix("Bad"), WithTablePrefix("good_"))
	if err == nil || !strings.Contains(err.Error(), `"Bad"`) {
		t.Fatalf("the first error must be kept, got %v", err)
	}
}

func TestPostgresMigrationsAreWellFormed(t *testing.T) {
	bootstrap, versions, err := loadMigrations(Postgres.Migrations(), "zz_")
	if err != nil {
		t.Fatal(err)
	}
	if len(bootstrap) != 1 || !strings.Contains(bootstrap[0], "zz_schema") {
		t.Fatalf("unexpected bootstrap: %q", bootstrap)
	}
	if len(versions) != 4 || versions[0].name != "0001_init.sql" || versions[1].version != 2 || versions[1].name != "0002_sessions_and_tokens.sql" ||
		versions[2].version != 3 || versions[2].name != "0003_secrets.sql" || versions[3].version != 4 || versions[3].name != "0004_admin.sql" {
		t.Fatalf("unexpected migrations: %+v", versions)
	}
	all := slices.Clone(bootstrap)
	for _, m := range versions {
		all = append(all, m.statements...)
	}
	joined := strings.Join(all, "\n")
	for _, token := range []string{"{prefix}", "?"} {
		if strings.Contains(joined, token) {
			t.Fatalf("migrations must not contain %q after preparation", token)
		}
	}
	tables := []string{
		"zz_schema", "zz_users", "zz_identifiers", "zz_sessions", "zz_refresh_tokens", "zz_attempts", "zz_signing_keys", "zz_secrets",
		"zz_admins", "zz_admin_sessions", "zz_admin_recovery_codes", "zz_audit_log", "zz_settings",
	}
	for _, table := range tables {
		if !strings.Contains(joined, "TABLE IF NOT EXISTS "+table+" ") {
			t.Fatalf("table %s must be created idempotently", table)
		}
	}
	for _, statement := range strings.Split(joined, "\n") {
		if strings.HasPrefix(strings.TrimSpace(statement), "CREATE") && !strings.Contains(statement, "IF NOT EXISTS") {
			t.Fatalf("every statement must be safe to repeat: %s", statement)
		}
	}
}

func TestLoadMigrationsRejectsBrokenSets(t *testing.T) {
	file := func(text string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(text)} }
	cases := map[string]fstest.MapFS{
		"no bootstrap":      {"0001_init.sql": file("CREATE TABLE a (x int)")},
		"empty bootstrap":   {"bootstrap.sql": file(" ;; "), "0001_init.sql": file("CREATE TABLE a (x int)")},
		"no migrations":     {"bootstrap.sql": file("CREATE TABLE s (x int)")},
		"a gap":             {"bootstrap.sql": file("CREATE TABLE s (x int)"), "0001_a.sql": file("SELECT 1"), "0003_c.sql": file("SELECT 1")},
		"starts at two":     {"bootstrap.sql": file("CREATE TABLE s (x int)"), "0002_b.sql": file("SELECT 1")},
		"empty migration":   {"bootstrap.sql": file("CREATE TABLE s (x int)"), "0001_a.sql": file("  \n ")},
		"unexpected file":   {"bootstrap.sql": file("CREATE TABLE s (x int)"), "0001_a.sql": file("SELECT 1"), "readme.txt": file("x")},
		"upper case name":   {"bootstrap.sql": file("CREATE TABLE s (x int)"), "0001_Init.sql": file("SELECT 1")},
		"short number":      {"bootstrap.sql": file("CREATE TABLE s (x int)"), "001_a.sql": file("SELECT 1")},
		"duplicate numbers": {"bootstrap.sql": file("CREATE TABLE s (x int)"), "0001_a.sql": file("SELECT 1"), "0001_b.sql": file("SELECT 1")},
	}
	for name, fsys := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := loadMigrations(fsys, "p_"); err == nil {
				t.Fatal("a broken set of migrations must be rejected")
			}
		})
	}
	good := fstest.MapFS{
		"bootstrap.sql": file("CREATE TABLE {prefix}s (x int)"),
		"0001_a.sql":    file("CREATE TABLE {prefix}a (x int); CREATE INDEX {prefix}ai ON {prefix}a (x);"),
		"0002_b.sql":    file("ALTER TABLE {prefix}a ADD y int"),
		"notes":         &fstest.MapFile{Mode: fs.ModeDir},
	}
	bootstrap, versions, err := loadMigrations(good, "p_")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(bootstrap, []string{"CREATE TABLE p_s (x int)"}) || len(versions) != 2 ||
		!slices.Equal(versions[0].statements, []string{"CREATE TABLE p_a (x int)", "CREATE INDEX p_ai ON p_a (x)"}) ||
		versions[1].version != 2 {
		t.Fatalf("unexpected result: %q %+v", bootstrap, versions)
	}
}

func TestSplitStatements(t *testing.T) {
	cases := map[string][]string{
		"":                       nil,
		" ; \n ;":                nil,
		"SELECT 1":               {"SELECT 1"},
		"SELECT 1;":              {"SELECT 1"},
		"A;\n\nB ;\n C":          {"A", "B", "C"},
		"CREATE TABLE t (\n x);": {"CREATE TABLE t (\n x)"},
	}
	for in, want := range cases {
		if got := splitStatements(in); !slices.Equal(got, want) {
			t.Errorf("splitStatements(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPostgresDialect(t *testing.T) {
	if Postgres.Name() != "postgres" || Postgres.Placeholder(1) != "$1" || Postgres.Placeholder(12) != "$12" {
		t.Fatalf("unexpected dialect basics: %q %q %q", Postgres.Name(), Postgres.Placeholder(1), Postgres.Placeholder(12))
	}
	cases := []struct {
		name   string
		err    error
		unique bool
		fk     bool
		table  bool
		exists bool
	}{
		{"unique violation", stateError{"23505"}, true, false, false, false},
		{"wrapped unique violation", fmt.Errorf("insert: %w", stateError{"23505"}), true, false, false, false},
		{"foreign key violation", stateError{"23503"}, false, true, false, false},
		{"missing table", fmt.Errorf("a: %w", fmt.Errorf("b: %w", stateError{"42P01"})), false, false, true, false},
		{"duplicate table", stateError{"42P07"}, false, false, false, true},
		{"duplicate object", fmt.Errorf("create: %w", stateError{"42710"}), false, false, false, true},
		{"duplicate column", stateError{"42701"}, false, false, false, true},
		{"other state", stateError{"23514"}, false, false, false, false},
		{"plain error", errors.New("boom"), false, false, false, false},
		{"nil", nil, false, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Postgres.IsUniqueViolation(tc.err); got != tc.unique {
				t.Errorf("IsUniqueViolation = %v", got)
			}
			if got := Postgres.IsForeignKeyViolation(tc.err); got != tc.fk {
				t.Errorf("IsForeignKeyViolation = %v", got)
			}
			if got := Postgres.IsMissingTable(tc.err); got != tc.table {
				t.Errorf("IsMissingTable = %v", got)
			}
			if got := Postgres.IsAlreadyExists(tc.err); got != tc.exists {
				t.Errorf("IsAlreadyExists = %v", got)
			}
		})
	}
	insert := Postgres.InsertIgnoring("t", []string{"a", "b", "c"}, []string{"?", "?", "1"}, []string{"a", "b"})
	if want := "INSERT INTO t (a, b, c) VALUES (?, ?, 1) ON CONFLICT (a, b) DO NOTHING"; insert != want {
		t.Fatalf("InsertIgnoring = %q, want %q", insert, want)
	}
	entries, err := fs.ReadDir(Postgres.Migrations(), ".")
	if err != nil || len(entries) < 2 {
		t.Fatalf("the embedded migrations are missing: %v, %v", entries, err)
	}
}

func TestQueriesUseThePrefixAndTheDialectPlaceholders(t *testing.T) {
	q := newQueries("zz_", Postgres)
	want := map[string]struct {
		text   string
		params int
	}{
		"insertUser": {q.insertUser, 11}, "selectUser": {q.selectUser, 2}, "updateUser": {q.updateUser, 11},
		"userExists": {q.userExists, 2}, "deleteUser": {q.deleteUser, 2}, "insertIdentifier": {q.insertIdentifier, 6},
		"selectIdentifier": {q.selectIdentifier, 3}, "listIdentifiers": {q.listIdentifiers, 2},
		"deleteIdentifier": {q.deleteIdentifier, 3}, "markVerified": {q.markVerified, 4}, "schemaVersion": {q.schemaVersion, 0},
		"probeSchema": {q.probeSchema, 0}, "insertSchemaRow": {q.insertSchemaRow, 1}, "acquireLock": {q.acquireLock, 3},
		"setVersion": {q.setVersion, 4}, "releaseLock": {q.releaseLock, 1},
		"insertSession": {q.insertSession, 10}, "resolveByID": {q.resolveByID, 2}, "resolveBySecret": {q.resolveBySecret, 2},
		"touchSession": {q.touchSession, 4}, "revokeSession": {q.revokeSession, 4}, "revokeAll": {q.revokeAll, 3},
		"revokeAllExcept": {q.revokeAllExcept, 4}, "listSessions": {q.listSessions, 3}, "deleteSessions": {q.deleteSessions, 4},
		"insertToken": {q.insertToken, 4}, "useToken": {q.useToken, 3}, "selectToken": {q.selectToken, 2},
		"deleteTokens": {q.deleteTokens, 2}, "insertAttempt": {q.insertAttempt, 2}, "bumpAttempt": {q.bumpAttempt, 2},
		"restartAttempt": {q.restartAttempt, 3}, "selectAttempt": {q.selectAttempt, 1}, "holdBlock": {q.holdBlock, 3},
		"holdDelay": {q.holdDelay, 3}, "resetAttempt": {q.resetAttempt, 1}, "deleteAttempts": {q.deleteAttempts, 3},
		"insertKey": {q.insertKey, 6}, "listKeys": {q.listKeys, 0}, "retireKey": {q.retireKey, 2}, "keyExists": {q.keyExists, 1},
		"deleteKeys": {q.deleteKeys, 1},
	}
	marker := regexp.MustCompile(`\$\d+`)
	for name, tc := range want {
		found := marker.FindAllString(tc.text, -1)
		if len(found) != tc.params {
			t.Errorf("%s has %d parameters, want %d: %s", name, len(found), tc.params, tc.text)
		}
		for n, m := range found {
			if m != fmt.Sprintf("$%d", n+1) {
				t.Errorf("%s: parameter %d is written %s: %s", name, n+1, m, tc.text)
			}
		}
		if strings.ContainsAny(tc.text, "?{}") || !strings.Contains(tc.text, "zz_") {
			t.Errorf("%s was not prepared: %s", name, tc.text)
		}
	}
	other := newQueries("p_", questionMarkDialect{Postgres})
	if !strings.Contains(other.selectUser, "tenant_id = :p1 AND id = :p2") || strings.Contains(other.selectUser, "$") {
		t.Fatalf("the placeholders must come from the dialect: %s", other.selectUser)
	}
}

func TestValueHelpers(t *testing.T) {
	west := time.FixedZone("UTC-7", -7*60*60)
	got := storedTime(time.Date(2026, 1, 2, 3, 4, 5, 123456789, west))
	if !got.Equal(time.Date(2026, 1, 2, 10, 4, 5, 123456000, time.UTC)) || got.Location() != time.UTC {
		t.Fatalf("storedTime = %v", got)
	}
	if optionalTime(time.Time{}) != nil || optionalText("") != nil {
		t.Fatal("unset values must be written as NULL")
	}
	if optionalText("x") != "x" {
		t.Fatal("a set text must be written as is")
	}
	if v, ok := optionalTime(time.Date(2026, 1, 2, 3, 4, 5, 999, time.UTC)).(time.Time); !ok || v.Nanosecond() != 0 {
		t.Fatalf("optionalTime must cut to microseconds, got %v", v)
	}
	if !storedOptional(time.Time{}).IsZero() {
		t.Fatal("the zero time must stay zero")
	}
}

func TestEveryDialectWritesItsClauseThatLimitsTheRows(t *testing.T) {
	want := map[string]string{
		"postgres": " LIMIT 51",
		"mysql":    " LIMIT 51",
		"mariadb":  " LIMIT 51",
		"oracle":   " FETCH FIRST 51 ROWS ONLY",
	}
	for _, dialect := range []Dialect{Postgres, MySQL, MariaDB, Oracle} {
		if got := dialect.Limit(51); got != want[dialect.Name()] {
			t.Errorf("%s limits the rows with %q, want %q", dialect.Name(), got, want[dialect.Name()])
		}
	}
}
