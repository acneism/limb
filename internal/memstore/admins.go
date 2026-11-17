package memstore

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"time"

	"github.com/acneism/limb/internal/storecheck"
	"github.com/acneism/limb/store"
)

type adminKey struct{ tenant, id string }

type recoveryKey struct{ tenant, admin, hash string }

type admins struct {
	d  func() *data
	mu *sync.Mutex
}

func (r admins) enter(ctx context.Context) (*data, func(), error) {
	return enter(ctx, r.d, r.mu)
}

func normalizeAdmin(a store.Admin) store.Admin {
	a.TOTPSecret = bytes.Clone(a.TOTPSecret)
	a.TOTPConfirmedAt = normalizeTime(a.TOTPConfirmedAt)
	a.CreatedAt = normalizeTime(a.CreatedAt)
	a.LastLoginAt = normalizeTime(a.LastLoginAt)
	return a
}

func (r admins) Create(ctx context.Context, a store.Admin) error {
	if err := storecheck.NewAdmin(a); err != nil {
		return err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	if _, taken := d.admins[adminKey{a.TenantID, a.ID}]; taken {
		return store.ErrConflict
	}
	for _, stored := range d.admins {
		if stored.TenantID == a.TenantID && stored.Login == a.Login {
			return store.ErrConflict
		}
	}
	a = normalizeAdmin(a)
	a.Version = 1
	d.admins[adminKey{a.TenantID, a.ID}] = a
	return nil
}

func (r admins) Get(ctx context.Context, tenantID, id string) (store.Admin, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return store.Admin{}, err
	}
	defer leave()
	a, found := d.admins[adminKey{tenantID, id}]
	if !found {
		return store.Admin{}, store.ErrNotFound
	}
	return normalizeAdmin(a), nil
}

func (r admins) FindByLogin(ctx context.Context, tenantID, login string) (store.Admin, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return store.Admin{}, err
	}
	defer leave()
	for _, a := range d.admins {
		if a.TenantID == tenantID && a.Login == login {
			return normalizeAdmin(a), nil
		}
	}
	return store.Admin{}, store.ErrNotFound
}

func (r admins) List(ctx context.Context, tenantID string) ([]store.Admin, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer leave()
	var list []store.Admin
	for _, a := range d.admins {
		if a.TenantID == tenantID {
			list = append(list, normalizeAdmin(a))
		}
	}
	slices.SortFunc(list, storecheck.CompareAdmins)
	return list, nil
}

func (r admins) Update(ctx context.Context, a store.Admin) (store.Admin, error) {
	if err := storecheck.Admin(a); err != nil {
		return store.Admin{}, err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return store.Admin{}, err
	}
	defer leave()
	key := adminKey{a.TenantID, a.ID}
	stored, found := d.admins[key]
	if !found {
		return store.Admin{}, store.ErrNotFound
	}
	if stored.Version != a.Version {
		return store.Admin{}, store.ErrStale
	}
	stored.PasswordHash = a.PasswordHash
	stored.TOTPSecret = bytes.Clone(a.TOTPSecret)
	stored.TOTPConfirmedAt = normalizeTime(a.TOTPConfirmedAt)
	stored.Status = a.Status
	stored.Version++
	d.admins[key] = stored
	a = normalizeAdmin(a)
	a.Version = stored.Version
	return a, nil
}

func (r admins) Delete(ctx context.Context, tenantID, id string) error {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	key := adminKey{tenantID, id}
	if _, found := d.admins[key]; !found {
		return store.ErrNotFound
	}
	delete(d.admins, key)
	for k := range d.recoveryCodes {
		if k.tenant == tenantID && k.admin == id {
			delete(d.recoveryCodes, k)
		}
	}
	for k, s := range d.adminSessions {
		if s.TenantID == tenantID && s.AdminID == id {
			delete(d.adminSessions, k)
		}
	}
	return nil
}

func (r admins) AcceptStep(ctx context.Context, tenantID, id string, version, step int64, at time.Time) error {
	if err := storecheck.Time("sign-in time", at); err != nil {
		return err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	key := adminKey{tenantID, id}
	stored, found := d.admins[key]
	switch {
	case !found:
		return store.ErrNotFound
	case stored.Version != version:
		return store.ErrStale
	case step <= stored.TOTPLastStep:
		return store.ErrConflict
	}
	stored.TOTPLastStep = step
	stored.LastLoginAt = normalizeTime(at)
	d.admins[key] = stored
	return nil
}

func (r admins) RecordLogin(ctx context.Context, tenantID, id string, version int64, at time.Time) error {
	if err := storecheck.Time("sign-in time", at); err != nil {
		return err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	key := adminKey{tenantID, id}
	stored, found := d.admins[key]
	switch {
	case !found:
		return store.ErrNotFound
	case stored.Version != version:
		return store.ErrStale
	}
	stored.LastLoginAt = normalizeTime(at)
	d.admins[key] = stored
	return nil
}

func (r admins) ReplaceRecoveryCodes(ctx context.Context, tenantID, id string, hashes [][]byte) error {
	if err := storecheck.RecoveryHashes(hashes); err != nil {
		return err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	if _, found := d.admins[adminKey{tenantID, id}]; !found {
		return store.ErrNotFound
	}
	for k := range d.recoveryCodes {
		if k.tenant == tenantID && k.admin == id {
			delete(d.recoveryCodes, k)
		}
	}
	for _, hash := range hashes {
		d.recoveryCodes[recoveryKey{tenantID, id, string(hash)}] = time.Time{}
	}
	return nil
}

func (r admins) UseRecoveryCode(ctx context.Context, tenantID, id string, hash []byte, at time.Time) error {
	if err := storecheck.Time("use time", at); err != nil {
		return err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	key := recoveryKey{tenantID, id, string(hash)}
	used, found := d.recoveryCodes[key]
	if !found || !used.IsZero() {
		return store.ErrNotFound
	}
	d.recoveryCodes[key] = normalizeTime(at)
	return nil
}

func (r admins) CountRecoveryCodes(ctx context.Context, tenantID, id string) (int, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return 0, err
	}
	defer leave()
	count := 0
	for k, used := range d.recoveryCodes {
		if k.tenant == tenantID && k.admin == id && used.IsZero() {
			count++
		}
	}
	return count, nil
}
