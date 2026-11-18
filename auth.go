package limb

import (
	"cmp"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"runtime"
	"slices"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/internal/admin"
	"github.com/acneism/limb/internal/adminui"
	"github.com/acneism/limb/internal/password"
	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/sqlstore"
	"github.com/acneism/limb/store"
)

const (
	minMasterKeyLength = 32
	startupTimeout     = 3 * time.Minute

	defaultSessionAbsolute = 30 * 24 * time.Hour
	defaultSessionIdle     = 7 * 24 * time.Hour
	defaultAccessTTL       = 10 * time.Minute
	minServiceKeyLength    = 32
	defaultIssuer          = "limb"
	touchInterval          = time.Minute
)

type passwordHasher interface {
	Hash(ctx context.Context, password string) (string, error)
	Verify(ctx context.Context, password, encoded string) (ok, needsRehash bool, err error)
	DummyVerify(ctx context.Context, password string) error
}

// Auth is the authentication service of an application. It is safe for
// concurrent use and is meant to be created once.
type Auth struct {
	store   store.Store
	types   []identifier.Type
	known   map[string]identifier.Type
	hasher  passwordHasher
	policy  password.Policy
	logger  *slog.Logger
	keys    *secret.Keys
	tenant  string
	proxies []netip.Prefix
	limits  loginLimits
	slots   chan struct{}

	absolute   time.Duration
	idle       time.Duration
	recovery   recoveryLimits
	origins    map[string]struct{}
	cookie     string
	algorithm  SigningAlgorithm
	accessTTL  time.Duration
	revocation RevocationMode
	issuer     string
	audience   string
	endNeeds   bool
	services   []serviceKey
	secure     bool
	sameSite   http.SameSite
	refreshJar bool
	disabled   map[Endpoint]bool
	ring       *keyring
	now        func() time.Time
	newID      func() (string, error)

	refreshCookie string
	refreshPath   string

	sender     Sender
	renderer   *renderer
	dispatcher *dispatcher
	hooks      Hooks
	delivers   bool
	resetURL   string
	verifyURL  string

	immediate    bool
	retention    time.Duration
	auditKept    time.Duration
	unconfirmed  time.Duration
	maintaining  atomic.Bool
	keepSessions bool
	signup       bool
	needVerified bool
	events       *eventQueue
	auditing     *eventQueue
	admins       *admin.Service
	settings     settingsCache

	adminMount    string
	adminIPs      []netip.Prefix
	adminLimits   loginLimits
	adminAbsolute time.Duration
	adminIdle     time.Duration
	adminNoTOTP   bool
	adminCatalog  *adminui.Catalog
	brand         string
}

// New creates the service on top of the database db, which the application
// opened with the driver it prefers. dialect tells which database engine it
// is.
//
// masterKey is at least 32 random bytes that protect the secrets limb stores.
// It is a key, not a passphrase: generate it once, for example with
// "openssl rand -base64 32", keep the text in the secret storage of the
// application, never in the database or the source code, and pass the decoded
// bytes, for example the result of base64.StdEncoding.DecodeString.
//
// New checks the configuration and the schema of the database. It returns an
// error for a configuration that cannot work and for a database whose schema
// is missing or outdated, unless WithAutoMigrate is given. It also checks how
// the connections of the database are set up, before it writes anything: the
// error of a connection that the dialect cannot work with says what to change
// in the way the database is opened, for example parseTime=true in the DSN of
// MySQL.
func New(db *sql.DB, dialect Dialect, masterKey []byte, opts ...Option) (*Auth, error) {
	if db == nil {
		return nil, errors.New("limb: the database is nil")
	}
	if dialect.inner == nil {
		return nil, errors.New("limb: the dialect is not set")
	}
	cfg := newConfig(opts)
	var storeOpts []sqlstore.Option
	if cfg.prefixSet {
		storeOpts = append(storeOpts, sqlstore.WithTablePrefix(cfg.tablePrefix))
	}
	s, err := sqlstore.New(db, dialect.inner, storeOpts...)
	if err != nil {
		return nil, fmt.Errorf("limb: %w", err)
	}
	return create(s, masterKey, cfg, s.Check)
}

// NewWithStore creates the service on top of a store that the application
// provides, for example one for a database that limb has no dialect for. The
// store should pass the tests of package storetest. masterKey is the same as
// in New. WithTablePrefix is not accepted, because the tables belong to the
// store.
func NewWithStore(s store.Store, masterKey []byte, opts ...Option) (*Auth, error) {
	if s == nil {
		return nil, errors.New("limb: the store is nil")
	}
	cfg := newConfig(opts)
	if cfg.prefixSet {
		return nil, errors.New("limb: WithTablePrefix applies only to New, a custom store has its own tables")
	}
	return create(s, masterKey, cfg, nil)
}

func newConfig(opts []Option) config {
	var cfg config
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

func create(s store.Store, masterKey []byte, cfg config, check func(context.Context) error) (*Auth, error) {
	if cfg.err != nil {
		return nil, cfg.err
	}
	if len(masterKey) < minMasterKeyLength {
		return nil, fmt.Errorf("limb: the master key must be at least %d bytes long, got %d", minMasterKeyLength, len(masterKey))
	}
	types, known, err := checkIdentifiers(cfg.identifiers)
	if err != nil {
		return nil, err
	}
	policy := cfg.policy.internal()
	if err = policy.Validate(); err != nil {
		return nil, fmt.Errorf("limb: %w", err)
	}
	absolute, idle := cfg.absolute, cfg.idle
	if absolute == 0 {
		absolute, idle = defaultSessionAbsolute, defaultSessionIdle
	}
	if err = checkServiceKeys(cfg.services); err != nil {
		return nil, err
	}
	if cfg.refreshJar && cfg.mountPath == "" {
		return nil, errors.New("limb: WithRefreshCookie needs WithMountPath, because the cookie is scoped to the path of the refresh route")
	}
	if cfg.sameSite == http.SameSiteNoneMode && cfg.development {
		return nil, errors.New("limb: SameSite=None needs a Secure cookie, and the development mode turns Secure off")
	}
	limits, err := cfg.limits.resolve()
	if err != nil {
		return nil, err
	}
	adminLimits, err := cfg.admin.limits.resolveOver(adminLimitDefaults)
	if err != nil {
		return nil, err
	}
	adminCatalog, err := adminui.NewCatalog(cfg.admin.texts)
	if err != nil {
		return nil, fmt.Errorf("limb: WithAdminTexts: %w", err)
	}
	if cfg.admin.noTOTP && !cfg.development {
		return nil, errors.New("limb: WithoutAdminTOTP needs WithDevelopmentMode: an administration that is open to a password alone is not for production")
	}
	recovery, err := cfg.recovery.resolve()
	if err != nil {
		return nil, err
	}
	if err = checkBaseURL("WithResetURL", cfg.resetURL, cfg.development); err != nil {
		return nil, err
	}
	if err = checkBaseURL("WithVerifyURL", cfg.verifyURL, cfg.development); err != nil {
		return nil, err
	}
	sending, err := cfg.sending.resolve()
	if err != nil {
		return nil, err
	}
	needVerified := cfg.signup && !cfg.unverified && slices.ContainsFunc(types, identifier.Type.IsDelivery)
	if needVerified && cfg.sender == nil {
		return nil, errors.New("limb: WithSignup with an identifier type that is a delivery channel needs WithSender to confirm the addresses, or WithoutVerificationRequired")
	}
	messages, err := newRenderer(cfg.templates, cfg.serviceName, cfg.development)
	if err != nil {
		return nil, err
	}
	keys, err := secret.NewKeys(masterKey)
	if err != nil {
		return nil, fmt.Errorf("limb: %w", err)
	}
	hasher, err := password.NewHasher()
	if err != nil {
		return nil, fmt.Errorf("limb: %w", err)
	}
	logger := cfg.logger
	if logger == nil {
		logger = slog.Default()
	}
	a := &Auth{
		store:   s,
		types:   types,
		known:   known,
		hasher:  hasher,
		policy:  policy,
		logger:  logger,
		keys:    keys,
		tenant:  store.DefaultTenant,
		proxies: cfg.proxies,
		limits:  limits,
		slots:   make(chan struct{}, runtime.GOMAXPROCS(0)),
		now:     time.Now,
		newID:   newUserID,

		absolute:   absolute,
		idle:       idle,
		recovery:   recovery,
		origins:    make(map[string]struct{}, len(cfg.origins)),
		cookie:     sessionCookieName(cfg.development),
		algorithm:  cmp.Or(cfg.algorithm, SigningEdDSA),
		accessTTL:  cmp.Or(cfg.accessTTL, defaultAccessTTL),
		revocation: cfg.revocation,
		issuer:     cmp.Or(cfg.issuer, defaultIssuer),
		endNeeds:   cfg.endSessions,
		services:   cfg.services,
		secure:     !cfg.development,
		sameSite:   cmp.Or(cfg.sameSite, http.SameSiteLaxMode),
		refreshJar: cfg.refreshJar,
		disabled:   make(map[Endpoint]bool, len(cfg.disabled)),

		refreshCookie: refreshCookieName(cfg.development),
		refreshPath:   refreshCookiePath(cfg.mountPath),

		sender:    cfg.sender,
		renderer:  messages,
		hooks:     cfg.hooks,
		delivers:  slices.ContainsFunc(types, identifier.Type.IsDelivery),
		resetURL:  cfg.resetURL,
		verifyURL: cfg.verifyURL,

		immediate:    cfg.immediate,
		retention:    cmp.Or(cfg.retention, defaultDeletedRetention),
		auditKept:    cmp.Or(cfg.auditKept, defaultAuditRetention),
		unconfirmed:  unconfirmedLifetime(cfg),
		keepSessions: cfg.keepOpen,
		signup:       cfg.signup,
		needVerified: needVerified,
	}
	a.adminMount, a.adminIPs, a.adminLimits = cfg.admin.mountPath, cfg.admin.ips, adminLimits
	a.adminAbsolute = cmp.Or(cfg.admin.absolute, defaultAdminSessionAbsolute)
	a.adminIdle = cmp.Or(cfg.admin.idle, defaultAdminSessionIdle)
	a.adminNoTOTP, a.adminCatalog, a.brand = cfg.admin.noTOTP, adminCatalog, cmp.Or(cfg.serviceName, defaultIssuer)
	a.admins = a.newAdminService(cfg.serviceName, cfg.admin)
	if cfg.sender != nil {
		a.dispatcher = newDispatcher(sending, logger, a.reportMessageFailure)
	}
	if cfg.hooks.OnEvent != nil {
		a.events = newEventQueue(eventQueueSize, a.callHook, logger)
	}
	a.auditing = newRecordQueue(eventQueueSize, a.recordEvent, logger)
	for _, endpoint := range cfg.disabled {
		a.disabled[endpoint] = true
	}
	a.audience = cmp.Or(cfg.audience, a.issuer)
	a.ring = newKeyring(a)
	for _, origin := range cfg.origins {
		a.origins[origin] = struct{}{}
	}
	if cfg.development {
		logger.Warn("limb: development mode is on, cookies are not Secure: never use it in production")
	}
	if err = a.ensureSchema(cfg.autoMigrate, check); err != nil {
		return nil, err
	}
	return a, nil
}

func checkServiceKeys(services []serviceKey) error {
	names := make(map[string]bool, len(services))
	hashes := make(map[[sha256.Size]byte]bool, len(services))
	for _, s := range services {
		if names[s.name] {
			return fmt.Errorf("limb: the service %q is given twice", s.name)
		}
		if hashes[s.hash] {
			return fmt.Errorf("limb: the service %q has the key of another service", s.name)
		}
		names[s.name], hashes[s.hash] = true, true
	}
	return nil
}

func checkIdentifiers(declared []identifier.Type) ([]identifier.Type, map[string]identifier.Type, error) {
	types := declared
	if len(types) == 0 {
		types = []identifier.Type{identifier.Email(identifier.Required())}
	}
	known := make(map[string]identifier.Type, len(types))
	canSignIn := false
	for _, t := range types {
		if err := t.Err(); err != nil {
			return nil, nil, fmt.Errorf("limb: identifier %q: %w", t.Name(), err)
		}
		if _, twice := known[t.Name()]; twice {
			return nil, nil, fmt.Errorf("limb: identifier %q is declared twice", t.Name())
		}
		known[t.Name()] = t
		canSignIn = canSignIn || t.IsLogin()
	}
	if !canSignIn {
		return nil, nil, errors.New("limb: at least one identifier type must allow signing in")
	}
	return types, known, nil
}

func (a *Auth) ensureSchema(autoMigrate bool, check func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()
	if err := checkConnection(ctx, check); err != nil {
		return err
	}
	if err := a.updateSchema(ctx, autoMigrate); err != nil {
		return err
	}
	return checkConnection(ctx, check)
}

func checkConnection(ctx context.Context, check func(context.Context) error) error {
	if check == nil {
		return nil
	}
	if err := check(ctx); err != nil {
		return fmt.Errorf("limb: check the database connection: %w", err)
	}
	return nil
}

func (a *Auth) updateSchema(ctx context.Context, autoMigrate bool) error {
	_, err := a.store.SchemaVersion(ctx)
	switch {
	case err == nil:
		return nil
	case !errors.Is(err, store.ErrSchemaOutdated):
		return fmt.Errorf("limb: check the database schema: %w", err)
	case !autoMigrate:
		return fmt.Errorf("limb: the database schema is missing or outdated, run the function Migrate or the command migrate, or use WithAutoMigrate: %w", err)
	}
	if err = a.store.Migrate(ctx); err != nil {
		return fmt.Errorf("limb: migrate the database schema: %w", err)
	}
	if _, err = a.store.SchemaVersion(ctx); err != nil {
		return fmt.Errorf("limb: check the database schema: %w", err)
	}
	return nil
}

// Migrate creates the database schema or brings it up to date. It is safe to
// call when the schema is current and from several processes at once. It needs
// the service, which New makes only for a database whose schema is current or
// with WithAutoMigrate: to create the schema before the service exists, call the
// function Migrate.
func (a *Auth) Migrate(ctx context.Context) error {
	return a.store.Migrate(ctx)
}

func newUserID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("limb: generate a user ID: %w", err)
	}
	return id.String(), nil
}
