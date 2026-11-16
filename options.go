package limb

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

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
	absolute    time.Duration
	idle        time.Duration
	origins     []string
	development bool
	algorithm   SigningAlgorithm
	accessTTL   time.Duration
	revocation  RevocationMode
	issuer      string
	audience    string
	endSessions bool
	services    []serviceKey
	err         error
}

type serviceKey struct {
	name string
	hash [sha256.Size]byte
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

// WithSessionTTL sets how long a session lasts. A session ends absolute after
// the user signed in whatever they do, and idle after the last time it was used
// if that is earlier. The defaults are 30 days and 7 days. Both must be at least
// a minute and idle must not exceed absolute, or New fails.
func WithSessionTTL(absolute, idle time.Duration) Option {
	return func(c *config) {
		switch {
		case absolute < time.Minute || idle < time.Minute:
			c.fail(errors.New("limb: the session lifetimes must be at least a minute"))
		case idle > absolute:
			c.fail(errors.New("limb: the idle lifetime of a session must not exceed its absolute lifetime"))
		default:
			c.absolute, c.idle = absolute, idle
		}
	}
}

// WithTrustedOrigins lists the origins other than the application's own whose
// pages may send requests that change data with the cookie of a session, for
// example a single-page application served from another host. An origin is
// written as scheme://host or scheme://host:port with no path, and New fails
// for anything else. The origin of the application itself is always allowed.
// limb does not send any CORS headers: the application has to allow these
// origins itself.
func WithTrustedOrigins(origins ...string) Option {
	return func(c *config) {
		for _, origin := range origins {
			normalized, ok := parseOrigin(origin)
			if !ok {
				c.fail(fmt.Errorf("limb: %q is not an origin: write scheme://host or scheme://host:port without a path", origin))
				continue
			}
			c.origins = append(c.origins, normalized)
		}
	}
}

// WithDevelopmentMode relaxes what only works on a development machine: the
// cookies are not marked Secure and lose their __Host- and __Secure- prefixes,
// so that they work over plain http. It must never be used in production, and
// limb logs a warning when it starts in this mode.
func WithDevelopmentMode() Option {
	return func(c *config) {
		c.development = true
	}
}

func parseOrigin(origin string) (string, bool) {
	if origin != strings.TrimSpace(origin) || origin == "" {
		return "", false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" ||
		u.ForceQuery || strings.HasSuffix(origin, "/") {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if port != "" {
		if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 || port != strconv.Itoa(number) {
			return "", false
		}
	}
	if port == "" || (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return scheme + "://" + host, true
	}
	return scheme + "://" + host + ":" + port, true
}

// WithSigningAlgorithm sets the algorithm that signs access tokens: SigningEdDSA,
// the default, SigningES256 or SigningRS256, which is there for services that
// cannot verify the others. limb makes the keys itself. Changing the algorithm
// of a running application gives it a new key at once, and the tokens signed
// with the old algorithm stop working.
func WithSigningAlgorithm(algorithm SigningAlgorithm) Option {
	return func(c *config) {
		switch algorithm {
		case SigningEdDSA, SigningES256, SigningRS256:
			c.algorithm = algorithm
		default:
			c.fail(fmt.Errorf("limb: unknown signing algorithm %q", algorithm))
		}
	}
}

// WithAccessTokenTTL sets how long an access token is valid, 10 minutes by
// default. It must be between a minute and a day. The shorter it is, the sooner
// a token stops working after the session ends when WithRevocation is
// RevocationAfterTTL.
func WithAccessTokenTTL(d time.Duration) Option {
	return func(c *config) {
		if d < time.Minute || d > 24*time.Hour {
			c.fail(errors.New("limb: the lifetime of an access token must be between a minute and a day"))
			return
		}
		c.accessTTL = d
	}
}

// RevocationMode tells how soon ending a session or blocking a user stops its
// access tokens from working.
type RevocationMode int

// The modes of revocation.
const (
	// RevocationInstant checks every access token against the database: the
	// session must be in use and the user must not be blocked or deleted. It is
	// the default and costs one query by index per request.
	RevocationInstant RevocationMode = iota
	// RevocationAfterTTL checks an access token by its signature only, without
	// the database, so it works until it expires. Sessions that live in a cookie
	// are always checked against the database.
	RevocationAfterTTL
)

// WithRevocation sets the revocation mode, RevocationInstant by default.
func WithRevocation(mode RevocationMode) Option {
	return func(c *config) {
		switch mode {
		case RevocationInstant, RevocationAfterTTL:
			c.revocation = mode
		default:
			c.fail(fmt.Errorf("limb: unknown revocation mode %d", mode))
		}
	}
}

// WithTokenIssuer sets the iss claim of access tokens and the value that is
// required in it, "limb" by default. Services that verify the tokens expect it.
func WithTokenIssuer(issuer string) Option {
	return func(c *config) {
		if err := checkClaim("issuer", issuer); err != nil {
			c.fail(err)
			return
		}
		c.issuer = issuer
	}
}

// WithTokenAudience sets the aud claim of access tokens and the value that is
// required in it, the issuer by default. A token that does not name the
// audience is refused, so a token made for another service is not accepted.
func WithTokenAudience(audience string) Option {
	return func(c *config) {
		if err := checkClaim("audience", audience); err != nil {
			c.fail(err)
			return
		}
		c.audience = audience
	}
}

func checkClaim(name, value string) error {
	if value == "" || len(value) > 256 || strings.ContainsFunc(value, func(r rune) bool { return r < ' ' || r == 0x7f }) {
		return fmt.Errorf("limb: the token %s must be 1 to 256 characters without control characters", name)
	}
	return nil
}

// WithPasswordToEndSessions makes ending sessions other than the current one,
// and ending all of them, ask for the current password again. It applies to
// TerminateSession for a session other than that of the principal and to
// LogoutAll. The password is checked under the same limits on failed attempts as
// that of ChangePassword. Without the option the password is not needed and a
// password that is given is ignored. Ending the current session never needs it.
//
// The option meets the requirement of OWASP ASVS 5.0, V7.5.2, that a user has to
// authenticate again to end their sessions. It is recommended wherever the theft
// of a session is a real risk, because a thief cannot then end the sessions of
// the owner, who would otherwise lose track of the devices they are signed in on.
func WithPasswordToEndSessions() Option {
	return func(c *config) {
		c.endSessions = true
	}
}

// WithServiceKey lets a service that checks access tokens outside the
// application ask limb whether a token is still good, which gives it the instant
// revocation that a signature alone cannot. The service sends the key as the
// Bearer token of its request. The name only says in the log which service asked.
// The key is made of printable ASCII characters without spaces and is at least 32
// bytes long, for example the output of "openssl rand -base64 48"; limb keeps only
// its hash. The option can be given for every service, each with its own key. New
// fails for a name or a key that is invalid or used twice.
func WithServiceKey(name, key string) Option {
	return func(c *config) {
		switch {
		case name == "" || len(name) > 64 || strings.ContainsFunc(name, func(r rune) bool { return r < ' ' || r == 0x7f }):
			c.fail(errors.New("limb: the name of a service must be 1 to 64 characters without control characters"))
		case len(key) < minServiceKeyLength:
			c.fail(fmt.Errorf("limb: the key of the service %q must be at least %d bytes long, got %d", name, minServiceKeyLength, len(key)))
		case strings.ContainsFunc(key, func(r rune) bool { return r <= ' ' || r > '~' }):
			c.fail(fmt.Errorf("limb: the key of the service %q must be printable ASCII without spaces", name))
		default:
			c.services = append(c.services, serviceKey{name: name, hash: sha256.Sum256([]byte(key))})
		}
	}
}

// WithLogger sets the logger. Messages never contain passwords, hashes or
// tokens. The default is slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(c *config) {
		c.logger = l
	}
}
