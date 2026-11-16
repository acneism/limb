package sqlstore

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func TestCheckRejectsAConnectionOfMySQLThatIsSetUpWrongly(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		good := d.newStore(t)
		if err := good.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
		base, err := mysql.ParseDSN(d.DSN)
		if err != nil {
			t.Fatal(err)
		}
		cases := []struct {
			name        string
			edit        func(*mysql.Config)
			want        string
			afterSchema bool
		}{
			{"times that are read as text", func(c *mysql.Config) { c.ParseTime = false }, "parseTime=true", false},
			{"another time zone", func(c *mysql.Config) { c.Loc = time.FixedZone("UTC+9", 9*60*60) }, "loc=UTC", false},
			{"a character set of three bytes", func(c *mysql.Config) { c.Collation = "utf8_general_ci" }, "four byte characters", false},
			{"rows that were found", func(c *mysql.Config) { c.ClientFoundRows = true }, "clientFoundRows=true", true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				cfg := base.Clone()
				tc.edit(cfg)
				connector, connErr := mysql.NewConnector(cfg)
				if connErr != nil {
					t.Fatal(connErr)
				}
				db := sql.OpenDB(connector)
				t.Cleanup(func() { _ = db.Close() })
				bad, newErr := New(db, d.dialect, WithTablePrefix(good.prefix))
				if newErr != nil {
					t.Fatal(newErr)
				}
				err := bad.Check(t.Context())
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("Check = %v, want an error that mentions %q", err, tc.want)
				}
				if tc.afterSchema {
					fresh, freshErr := New(db, d.dialect, WithTablePrefix(d.Prefix(t)))
					if freshErr != nil {
						t.Fatal(freshErr)
					}
					if err = fresh.Check(t.Context()); err != nil {
						t.Fatalf("Check before the schema exists = %v, want nil: the rows can be counted only when there is a table", err)
					}
				}
			})
		}
	}, "mysql", "mariadb")
}
