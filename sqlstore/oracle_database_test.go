package sqlstore

import (
	"database/sql"
	"strings"
	"testing"
)

func TestCheckRejectsASessionOfOracleThatIgnoresCase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		db, err := sql.Open(d.Driver, d.DSN)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		db.SetMaxOpenConns(1)
		if err = Oracle.Check(t.Context(), db); err != nil {
			t.Fatalf("Check of a session that compares bytes = %v, want nil", err)
		}
		if _, err = db.ExecContext(t.Context(), "ALTER SESSION SET NLS_COMP = LINGUISTIC"); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(t.Context(), "ALTER SESSION SET NLS_SORT = BINARY_CI"); err != nil {
			t.Fatal(err)
		}
		if err = Oracle.Check(t.Context(), db); err == nil || !strings.Contains(err.Error(), "NLS_COMP") {
			t.Fatalf("Check of a session that ignores case = %v, want an error about NLS_COMP", err)
		}
	}, "oracle")
}
