package limb

import (
	"errors"
	"log/slog"
	"net/netip"

	"github.com/acneism/limb/identifier"
)

type config struct {
	identifiers []identifier.Type
	policy      PasswordPolicy
	logger      *slog.Logger
	tablePrefix string
	prefixSet   bool
	autoMigrate bool
	proxies     []netip.Prefix
	limits      LoginLimits
	err         error
}

func (c *config) fail(err error) {
	if c.err == nil {
		c.err = err
	}
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

// WithTrustedProxies lists the networks of the reverse proxies that stand in
// front of the application. Only a request that comes from one of them may say
// in X-Forwarded-For who the client is and in X-Forwarded-Proto which scheme it
// used; the headers of any other request are ignored, because anyone can send
// them. The client is the first address of X-Forwarded-For, read from the right,
// that does not belong to a trusted proxy. Without this option the address of
// the connection is the address of the client. New fails for an invalid prefix
// and for one that covers every address.
func WithTrustedProxies(prefixes ...netip.Prefix) Option {
	return func(c *config) {
		for _, p := range prefixes {
			switch {
			case !p.IsValid():
				c.fail(errors.New("limb: a trusted proxy prefix is not valid"))
			case p.Bits() == 0:
				c.fail(errors.New("limb: a trusted proxy prefix must not cover every address, list the networks of the proxies"))
			default:
				c.proxies = append(c.proxies, p.Masked())
			}
		}
	}
}

// WithLoginLimits sets the limits on failed sign-in attempts. A field that is
// zero keeps its default, see LoginLimits. New fails for a negative value.
func WithLoginLimits(l LoginLimits) Option {
	return func(c *config) {
		c.limits = l
	}
}

// WithLogger sets the logger. Messages never contain passwords, hashes or
// tokens. The default is slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(c *config) {
		c.logger = l
	}
}
