package limb

import (
	"context"
	"sync"
	"time"

	"github.com/acneism/limb/store"
)

type faultSet struct {
	mu     sync.Mutex
	failed map[string]error
}

func newFaults() *faultSet {
	return &faultSet{failed: map[string]error{}}
}

func (f *faultSet) set(name string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed[name] = err
}

func (f *faultSet) clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	clear(f.failed)
}

func (f *faultSet) check(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.failed[name]
}

type faultStore struct {
	store.Store
	faults *faultSet
}

func (s faultStore) Users() store.Users {
	return faultUsers{Users: s.Store.Users(), faults: s.faults}
}

func (s faultStore) Identifiers() store.Identifiers {
	return faultIdentifiers{Identifiers: s.Store.Identifiers(), faults: s.faults}
}

func (s faultStore) Secrets() store.Secrets {
	return faultSecrets{Secrets: s.Store.Secrets(), faults: s.faults}
}

func (s faultStore) Sessions() store.Sessions {
	return faultSessions{Sessions: s.Store.Sessions(), faults: s.faults}
}

func (s faultStore) InTx(ctx context.Context, fn func(ctx context.Context, tx store.Repositories) error) error {
	return s.Store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		return fn(ctx, faultRepositories{Repositories: tx, faults: s.faults})
	})
}

type faultRepositories struct {
	store.Repositories
	faults *faultSet
}

func (r faultRepositories) Users() store.Users {
	return faultUsers{Users: r.Repositories.Users(), faults: r.faults}
}

func (r faultRepositories) Identifiers() store.Identifiers {
	return faultIdentifiers{Identifiers: r.Repositories.Identifiers(), faults: r.faults}
}

func (r faultRepositories) Secrets() store.Secrets {
	return faultSecrets{Secrets: r.Repositories.Secrets(), faults: r.faults}
}

func (r faultRepositories) Sessions() store.Sessions {
	return faultSessions{Sessions: r.Repositories.Sessions(), faults: r.faults}
}

type faultUsers struct {
	store.Users
	faults *faultSet
}

func (u faultUsers) Get(ctx context.Context, tenantID, id string) (store.User, error) {
	if err := u.faults.check("users.get"); err != nil {
		return store.User{}, err
	}
	return u.Users.Get(ctx, tenantID, id)
}

func (u faultUsers) Create(ctx context.Context, user store.User) error {
	if err := u.faults.check("users.create"); err != nil {
		return err
	}
	return u.Users.Create(ctx, user)
}

func (u faultUsers) Update(ctx context.Context, user store.User) (store.User, error) {
	if err := u.faults.check("users.update"); err != nil {
		return store.User{}, err
	}
	return u.Users.Update(ctx, user)
}

type faultIdentifiers struct {
	store.Identifiers
	faults *faultSet
}

func (i faultIdentifiers) Add(ctx context.Context, identifier store.Identifier) error {
	if err := i.faults.check("identifiers.add"); err != nil {
		return err
	}
	return i.Identifiers.Add(ctx, identifier)
}

func (i faultIdentifiers) Find(ctx context.Context, tenantID, typ, value string) (store.Identifier, error) {
	if err := i.faults.check("identifiers.find"); err != nil {
		return store.Identifier{}, err
	}
	return i.Identifiers.Find(ctx, tenantID, typ, value)
}

func (i faultIdentifiers) ListByUser(ctx context.Context, tenantID, userID string) ([]store.Identifier, error) {
	if err := i.faults.check("identifiers.list"); err != nil {
		return nil, err
	}
	return i.Identifiers.ListByUser(ctx, tenantID, userID)
}

type faultSecrets struct {
	store.Secrets
	faults *faultSet
}

func (s faultSecrets) End(ctx context.Context, scope store.SecretScope, at time.Time) (int, error) {
	if err := s.faults.check("secrets.end"); err != nil {
		return 0, err
	}
	return s.Secrets.End(ctx, scope, at)
}

type faultSessions struct {
	store.Sessions
	faults *faultSet
}

func (s faultSessions) RevokeAllForUser(ctx context.Context, tenantID, userID, exceptID string, at time.Time) (int, error) {
	if err := s.faults.check("sessions.revoke"); err != nil {
		return 0, err
	}
	return s.Sessions.RevokeAllForUser(ctx, tenantID, userID, exceptID, at)
}

type failingHasher struct {
	passwordHasher
	err error
}

func (h failingHasher) Hash(context.Context, string) (string, error) {
	return "", h.err
}
