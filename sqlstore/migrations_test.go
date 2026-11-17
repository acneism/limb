package sqlstore

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

var (
	createTable   = regexp.MustCompile(`(?is)^CREATE TABLE (?:IF NOT EXISTS )?(\S+)\s*\((.*)\)[^)]*$`)
	keyedColumns  = regexp.MustCompile(`(?i)(?:PRIMARY KEY|UNIQUE)\s*\(([^)]*)\)`)
	timestampType = regexp.MustCompile(`(?i)^\S+\s+TIMESTAMP`)
	nonColumn     = map[string]bool{"CONSTRAINT": true, "PRIMARY": true, "UNIQUE": true, "INDEX": true, "FOREIGN": true, "CHECK": true, "KEY": true}
)

func topLevelParts(body string) []string {
	var parts []string
	depth, start := 0, 0
	for i, r := range body {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(body[start:i]))
				start = i + 1
			}
		}
	}
	return append(parts, strings.TrimSpace(body[start:]))
}

type table struct {
	columns []string
	types   map[string]string
	keys    [][]string
}

func tablesOf(t *testing.T, dialect Dialect) map[string]table {
	t.Helper()
	bootstrap, versions, err := loadMigrations(dialect.Migrations(), "p_")
	if err != nil {
		t.Fatalf("%s: %v", dialect.Name(), err)
	}
	statements := slices.Clone(bootstrap)
	for _, m := range versions {
		statements = append(statements, m.statements...)
	}
	tables := map[string]table{}
	for _, statement := range statements {
		match := createTable.FindStringSubmatch(statement)
		if match == nil {
			continue
		}
		found := table{types: map[string]string{}}
		for _, part := range topLevelParts(match[2]) {
			first, _, _ := strings.Cut(part, " ")
			if nonColumn[strings.ToUpper(first)] {
				for _, keyed := range keyedColumns.FindAllStringSubmatch(part, -1) {
					var names []string
					for _, name := range strings.Split(keyed[1], ",") {
						names = append(names, strings.TrimSpace(name))
					}
					found.keys = append(found.keys, names)
				}
				continue
			}
			found.columns = append(found.columns, first)
			found.types[first] = part
			if strings.Contains(strings.ToUpper(part), "PRIMARY KEY") || strings.Contains(strings.ToUpper(part), " UNIQUE") {
				found.keys = append(found.keys, []string{first})
			}
		}
		tables[match[1]] = found
	}
	return tables
}

func TestEveryDialectHasTheSameTablesAndColumns(t *testing.T) {
	want := tablesOf(t, Postgres)
	if len(want) != 8 {
		t.Fatalf("PostgreSQL has %d tables, want 8", len(want))
	}
	for _, dialect := range []Dialect{MySQL, MariaDB, Oracle} {
		got := tablesOf(t, dialect)
		for name, expected := range want {
			actual, ok := got[name]
			if !ok {
				t.Errorf("%s has no table %s", dialect.Name(), name)
				continue
			}
			if !slices.Equal(actual.columns, expected.columns) {
				t.Errorf("%s: the columns of %s are %v, PostgreSQL has %v", dialect.Name(), name, actual.columns, expected.columns)
			}
		}
		if len(got) != len(want) {
			t.Errorf("%s has %d tables, PostgreSQL has %d", dialect.Name(), len(got), len(want))
		}
	}
}

func TestOracleDoesNotKeyATableOnATime(t *testing.T) {
	for name, found := range tablesOf(t, Oracle) {
		for _, key := range found.keys {
			for _, column := range key {
				if timestampType.MatchString(found.types[column]) {
					t.Errorf("%s is keyed on the time %s: Oracle refuses a primary or unique key on TIMESTAMP WITH TIME ZONE", name, column)
				}
			}
		}
	}
	if keys := tablesOf(t, Oracle)["p_schema"].keys; len(keys) == 0 {
		t.Fatal("the test found no keys, so it checks nothing")
	}
}
