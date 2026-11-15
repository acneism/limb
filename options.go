package limb

import (
	"log/slog"

	"github.com/acneism/limb/identifier"
)

type config struct {
	identifiers []identifier.Type
	policy      PasswordPolicy
	logger      *slog.Logger
	tablePrefix string
	prefixSet   bool
	autoMigrate bool
}

// Option customizes the Auth that New and NewWithStore create. Every option
// has a safe default.
type Option func(*config)

// WithIdentifiers declares the kinds of values users sign in with and are
// reached at. The order matters: when a user signs in, the login is tried as
// each type that allows signing in, in this order, and the first type that
// accepts it wins. Without this option users have a required e-mail address.
// New fails if a type is misconfigured, if two types have the same name or if
// none of them allows signing in.
func WithIdentifiers(types ...identifier.Type) Option {
	return func(c *config) {
		c.identifiers = append([]identifier.Type(nil), types...)
	}
}

// WithPasswordPolicy replaces the default password policy. New fails if the
// policy is not valid. The texts of the errors that its checks return end up
// in PolicyError.Rules and may be shown to users, so they should be short
// codes, see PasswordPolicy.Checks.
func WithPasswordPolicy(p PasswordPolicy) Option {
	return func(c *config) {
		c.policy = p
	}
}

// WithTablePrefix sets the prefix of the table names, limb_ by default. It
// starts with a lower case letter, continues with lower case letters, digits
// and underscores and is at most 16 characters long. It only applies to New:
// NewWithStore fails if it is given.
func WithTablePrefix(prefix string) Option {
	return func(c *config) {
		c.tablePrefix = prefix
		c.prefixSet = true
	}
}

// WithAutoMigrate makes New create the database schema or bring it up to date
// when it is missing or outdated. Without it New fails on such a database and
// the schema has to be created by calling Migrate.
func WithAutoMigrate() Option {
	return func(c *config) {
		c.autoMigrate = true
	}
}

// WithLogger sets the logger. Messages never contain passwords, hashes or
// tokens. The default is slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(c *config) {
		c.logger = l
	}
}
