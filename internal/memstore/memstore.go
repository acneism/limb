package memstore

import (
	"context"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/acneism/limb/internal/storecheck"
	"github.com/acneism/limb/store"
)

const latestVersion = 4

type userKey struct{ tenant, id string }

type identKey struct{ tenant, typ, value string }

type data struct {
	users    map[userKey]store.User
	idents   map[identKey]store.Identifier
	sessions map[sessionKey]store.Session
	tokens   map[string]store.RefreshToken
	secrets  map[secretKey]store.Secret
	attempts map[string]store.Attempt
	keys     map[string]store.SigningKey
	settings map[settingKey]store.Setting
	audit    map[auditKey]store.AuditRecord

	admins        map[adminKey]store.Admin
	recoveryCodes map[recoveryKey]time.Time
}

func newData() *data {
	return &data{
		users:    map[userKey]store.User{},
		idents:   map[identKey]store.Identifier{},
		sessions: map[sessionKey]store.Session{},
		tokens:   map[string]store.RefreshToken{},
		secrets:  map[secretKey]store.Secret{},
		attempts: map[string]store.Attempt{},
		keys:     map[string]store.SigningKey{},
		settings: map[settingKey]store.Setting{},
		audit:    map[auditKey]store.AuditRecord{},

		admins:        map[adminKey]store.Admin{},
		recoveryCodes: map[recoveryKey]time.Time{},
	}
}

func (d *data) clone() *data {
	return &data{
		users:    maps.Clone(d.users),
		idents:   maps.Clone(d.idents),
		sessions: maps.Clone(d.sessions),
		tokens:   maps.Clone(d.tokens),
		secrets:  maps.Clone(d.secrets),
		attempts: maps.Clone(d.attempts),
		keys:     maps.Clone(d.keys),
		settings: maps.Clone(d.settings),
		audit:    maps.Clone(d.audit),

		admins:        maps.Clone(d.admins),
		recoveryCodes: maps.Clone(d.recoveryCodes),
	}
}

type Store struct {
	mu      sync.Mutex
	data    *data
	version int
}

func New() *Store {
	return &Store{data: newData()}
}

var _ store.Store = (*Store)(nil)

func (s *Store) Users() store.Users {
	return users{d: func() *data { return s.data }, mu: &s.mu}
}

func (s *Store) Identifiers() store.Identifiers {
	return identifiers{d: func() *data { return s.data }, mu: &s.mu}
}

func (s *Store) Sessions() store.Sessions {
	return sessions{d: func() *data { return s.data }, mu: &s.mu}
}

func (s *Store) RefreshTokens() store.RefreshTokens {
	return refreshTokens{d: func() *data { return s.data }, mu: &s.mu}
}

func (s *Store) Secrets() store.Secrets {
	return secrets{d: func() *data { return s.data }, mu: &s.mu}
}

func (s *Store) Attempts() store.Attempts {
	return attempts{d: func() *data { return s.data }, mu: &s.mu}
}

func (s *Store) SigningKeys() store.SigningKeys {
	return signingKeys{d: func() *data { return s.data }, mu: &s.mu}
}

func (s *Store) Settings() store.Settings {
	return settings{d: func() *data { return s.data }, mu: &s.mu}
}

func (s *Store) Audit() store.Audit {
	return audit{d: func() *data { return s.data }, mu: &s.mu}
}

func (s *Store) Admins() store.Admins {
	return admins{d: func() *data { return s.data }, mu: &s.mu}
}

func (s *Store) InTx(ctx context.Context, fn func(ctx context.Context, tx store.Repositories) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	work := s.data.clone()
	if err := fn(ctx, txRepositories{d: work}); err != nil {
		return err
	}
	s.data = work
	return nil
}

func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.version < latestVersion {
		return s.version, store.ErrSchemaOutdated
	}
	return s.version, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.version = latestVersion
	return nil
}

type txRepositories struct{ d *data }

func (r txRepositories) Users() store.Users {
	return users{d: func() *data { return r.d }}
}

func (r txRepositories) Identifiers() store.Identifiers {
	return identifiers{d: func() *data { return r.d }}
}

func (r txRepositories) Sessions() store.Sessions {
	return sessions{d: func() *data { return r.d }}
}

func (r txRepositories) RefreshTokens() store.RefreshTokens {
	return refreshTokens{d: func() *data { return r.d }}
}

func (r txRepositories) Secrets() store.Secrets {
	return secrets{d: func() *data { return r.d }}
}

func (r txRepositories) Attempts() store.Attempts {
	return attempts{d: func() *data { return r.d }}
}

func (r txRepositories) SigningKeys() store.SigningKeys {
	return signingKeys{d: func() *data { return r.d }}
}

func (r txRepositories) Settings() store.Settings {
	return settings{d: func() *data { return r.d }}
}

func (r txRepositories) Audit() store.Audit {
	return audit{d: func() *data { return r.d }}
}

func (r txRepositories) Admins() store.Admins {
	return admins{d: func() *data { return r.d }}
}

type users struct {
	d  func() *data
	mu *sync.Mutex
}

func (r users) enter(ctx context.Context) (*data, func(), error) {
	return enter(ctx, r.d, r.mu)
}

func enter(ctx context.Context, d func() *data, mu *sync.Mutex) (*data, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if mu == nil {
		return d(), func() {}, nil
	}
	mu.Lock()
	return d(), mu.Unlock, nil
}

func normalizeTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return t.UTC().Truncate(time.Microsecond)
}

func normalizeUser(u store.User) store.User {
	u.BlockedUntil = normalizeTime(u.BlockedUntil)
	u.DeletedAt = normalizeTime(u.DeletedAt)
	u.PurgeAfter = normalizeTime(u.PurgeAfter)
	u.CreatedAt = normalizeTime(u.CreatedAt)
	u.LastLoginAt = normalizeTime(u.LastLoginAt)
	return u
}

func (r users) Create(ctx context.Context, u store.User) error {
	if err := storecheck.NewUser(u); err != nil {
		return err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	key := userKey{u.TenantID, u.ID}
	if _, taken := d.users[key]; taken {
		return store.ErrConflict
	}
	u = normalizeUser(u)
	u.Version = 1
	d.users[key] = u
	return nil
}

func (r users) Get(ctx context.Context, tenantID, id string) (store.User, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return store.User{}, err
	}
	defer leave()
	u, found := d.users[userKey{tenantID, id}]
	if !found {
		return store.User{}, store.ErrNotFound
	}
	return u, nil
}

func (r users) Update(ctx context.Context, u store.User) (store.User, error) {
	if err := storecheck.User(u); err != nil {
		return store.User{}, err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return store.User{}, err
	}
	defer leave()
	key := userKey{u.TenantID, u.ID}
	stored, found := d.users[key]
	if !found {
		return store.User{}, store.ErrNotFound
	}
	if stored.Version != u.Version {
		return store.User{}, store.ErrStale
	}
	u = normalizeUser(u)
	u.CreatedAt = stored.CreatedAt
	u.Version = stored.Version + 1
	d.users[key] = u
	return u, nil
}

func (r users) Delete(ctx context.Context, tenantID, id string) error {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	key := userKey{tenantID, id}
	if _, found := d.users[key]; !found {
		return store.ErrNotFound
	}
	delete(d.users, key)
	for k, i := range d.idents {
		if i.TenantID == tenantID && i.UserID == id {
			delete(d.idents, k)
		}
	}
	for k, s := range d.sessions {
		if s.TenantID == tenantID && s.UserID == id {
			d.removeSession(k)
		}
	}
	for k, s := range d.secrets {
		if s.TenantID == tenantID && s.UserID == id {
			delete(d.secrets, k)
		}
	}
	return nil
}

type identifiers struct {
	d  func() *data
	mu *sync.Mutex
}

func (r identifiers) enter(ctx context.Context) (*data, func(), error) {
	return enter(ctx, r.d, r.mu)
}

func (r identifiers) Add(ctx context.Context, i store.Identifier) error {
	if err := storecheck.Identifier(i); err != nil {
		return err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	key := identKey{i.TenantID, i.Type, i.Value}
	if _, taken := d.idents[key]; taken {
		return store.ErrConflict
	}
	if _, found := d.users[userKey{i.TenantID, i.UserID}]; !found {
		return store.ErrNotFound
	}
	i.VerifiedAt = normalizeTime(i.VerifiedAt)
	d.idents[key] = i
	return nil
}

func (r identifiers) Find(ctx context.Context, tenantID, typ, value string) (store.Identifier, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return store.Identifier{}, err
	}
	defer leave()
	i, found := d.idents[identKey{tenantID, typ, value}]
	if !found {
		return store.Identifier{}, store.ErrNotFound
	}
	return i, nil
}

func (r identifiers) ListByUser(ctx context.Context, tenantID, userID string) ([]store.Identifier, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer leave()
	var list []store.Identifier
	for _, i := range d.idents {
		if i.TenantID == tenantID && i.UserID == userID {
			list = append(list, i)
		}
	}
	slices.SortFunc(list, storecheck.CompareIdentifiers)
	return list, nil
}

func (r identifiers) Remove(ctx context.Context, tenantID, typ, value string) error {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	key := identKey{tenantID, typ, value}
	if _, found := d.idents[key]; !found {
		return store.ErrNotFound
	}
	delete(d.idents, key)
	for k, s := range d.secrets {
		if s.TenantID == tenantID && s.ChannelType == typ && s.ChannelValue == value {
			delete(d.secrets, k)
		}
	}
	return nil
}

func (r identifiers) MarkVerified(ctx context.Context, tenantID, typ, value string, at time.Time) error {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	key := identKey{tenantID, typ, value}
	i, found := d.idents[key]
	if !found {
		return store.ErrNotFound
	}
	i.VerifiedAt = normalizeTime(at)
	d.idents[key] = i
	return nil
}
