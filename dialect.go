package limb

import "github.com/acneism/limb/sqlstore"

// Dialect tells limb which database engine it stores its data in.
type Dialect struct {
	inner sqlstore.Dialect
}

// Postgres is the dialect of PostgreSQL 15 and newer.
var Postgres = Dialect{inner: sqlstore.Postgres}
