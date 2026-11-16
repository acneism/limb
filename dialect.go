package limb

import "github.com/acneism/limb/sqlstore"

// Dialect tells limb which database engine it stores its data in.
type Dialect struct {
	inner sqlstore.Dialect
}

// Postgres is the dialect of PostgreSQL 15 and newer.
var Postgres = Dialect{inner: sqlstore.Postgres}

// MySQL is the dialect of MySQL 8.4 and newer, for the driver
// github.com/go-sql-driver/mysql. The DSN of the driver has to contain
// parseTime=true and loc=UTC and must not contain clientFoundRows=true; New
// checks it and reports what to change.
var MySQL = Dialect{inner: sqlstore.MySQL}

// MariaDB is the dialect of MariaDB 10.11 and newer, for the driver
// github.com/go-sql-driver/mysql. The DSN of the driver has to contain
// parseTime=true and loc=UTC and must not contain clientFoundRows=true; New
// checks it and reports what to change.
var MariaDB = Dialect{inner: sqlstore.MariaDB}

// Oracle is the dialect of Oracle Database 19c and newer, for the driver
// github.com/sijms/go-ora/v2.
var Oracle = Dialect{inner: sqlstore.Oracle}
