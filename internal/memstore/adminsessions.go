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

type adminSessionKey struct{ tenant, id string }

type adminSessions struct {
	d  func() *data
	mu *sync.Mutex
}

func (r adminSessions) enter(ctx context.Context) (*data, func(), error) {
	return enter(ctx, r.d, r.mu)
}

func normalizeAdminSession(s store.AdminSession) store.AdminSession {
	s.SecretHash = bytes.Clone(s.SecretHash)
	s.CreatedAt = normalizeTime(s.CreatedAt)
	s.LastSeenAt = normalizeTime(s.LastSeenAt)
	s.ExpiresAt = normalizeTime(s.ExpiresAt)
	return s
}

func (r adminSessions) Create(ctx context.Context, s store.AdminSession) error {
	if err := storecheck.NewAdminSession(s); err != nil {
		return err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	if _, taken := d.adminSessions[adminSessionKey{s.TenantID, s.ID}]; taken {
		return store.ErrConflict
	}
	for _, stored := range d.adminSessions {
		if bytes.Equal(stored.SecretHash, s.SecretHash) {
			return store.ErrConflict
		}
	}
	if _, found := d.admins[adminKey{s.TenantID, s.AdminID}]; !found {
		return store.ErrNotFound
	}
	d.adminSessions[adminSessionKey{s.TenantID, s.ID}] = normalizeAdminSession(s)
	return nil
}

func (r adminSessions) ResolveBySecret(ctx context.Context, tenantID string, secretHash []byte) (store.ResolvedAdminSession, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return store.ResolvedAdminSession{}, err
	}
	defer leave()
	for _, s := range d.adminSessions {
		if s.TenantID != tenantID || !bytes.Equal(s.SecretHash, secretHash) {
			continue
		}
		a, found := d.admins[adminKey{s.TenantID, s.AdminID}]
		if !found {
			return store.ResolvedAdminSession{}, store.ErrNotFound
		}
		state := store.AdminState{Login: a.Login, Status: a.Status, Version: a.Version, TOTPConfirmed: !a.TOTPConfirmedAt.IsZero()}
		return store.ResolvedAdminSession{Session: normalizeAdminSession(s), Admin: state}, nil
	}
	return store.ResolvedAdminSession{}, store.ErrNotFound
}

func (r adminSessions) Touch(ctx context.Context, tenantID, id string, at time.Time) error {
	if err := storecheck.Time("touch time", at); err != nil {
		return err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	key := adminSessionKey{tenantID, id}
	s, found := d.adminSessions[key]
	if found && normalizeTime(at).After(s.LastSeenAt) {
		s.LastSeenAt = normalizeTime(at)
		d.adminSessions[key] = s
	}
	return nil
}

func (r adminSessions) TryAttempt(ctx context.Context, tenantID, id string, limit int) (bool, error) {
	if err := storecheck.Attempts(limit); err != nil {
		return false, err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return false, err
	}
	defer leave()
	key := adminSessionKey{tenantID, id}
	s, found := d.adminSessions[key]
	if !found || s.Stage != store.AdminStagePassword || s.Attempts >= limit {
		return false, nil
	}
	s.Attempts++
	d.adminSessions[key] = s
	return true, nil
}

func (r adminSessions) Rebind(ctx context.Context, tenantID, adminID, id string, version int64) error {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	key := adminSessionKey{tenantID, id}
	s, found := d.adminSessions[key]
	if !found || s.AdminID != adminID {
		return store.ErrNotFound
	}
	s.AdminVersion = version
	d.adminSessions[key] = s
	return nil
}

func (r adminSessions) Delete(ctx context.Context, tenantID, adminID, id string) error {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	key := adminSessionKey{tenantID, id}
	if s, found := d.adminSessions[key]; !found || s.AdminID != adminID {
		return store.ErrNotFound
	}
	delete(d.adminSessions, key)
	return nil
}

func (r adminSessions) DeleteForAdmin(ctx context.Context, tenantID, adminID, exceptID string) (int, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return 0, err
	}
	defer leave()
	removed := 0
	for key, s := range d.adminSessions {
		if s.TenantID == tenantID && s.AdminID == adminID && (exceptID == "" || s.ID != exceptID) {
			delete(d.adminSessions, key)
			removed++
		}
	}
	return removed, nil
}

func (r adminSessions) ListByAdmin(ctx context.Context, tenantID, adminID string, now time.Time) ([]store.AdminSession, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer leave()
	var list []store.AdminSession
	for _, s := range d.adminSessions {
		if s.TenantID == tenantID && s.AdminID == adminID && s.Stage == store.AdminStageFull && s.ExpiresAt.After(normalizeTime(now)) {
			list = append(list, normalizeAdminSession(s))
		}
	}
	slices.SortFunc(list, storecheck.CompareAdminSessions)
	return list, nil
}

func (r adminSessions) DeleteStale(ctx context.Context, tenantID string, expiredBefore, idleBefore time.Time) (int, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return 0, err
	}
	defer leave()
	expired, idle := normalizeTime(expiredBefore), normalizeTime(idleBefore)
	removed := 0
	for key, s := range d.adminSessions {
		if s.TenantID == tenantID && (s.ExpiresAt.Before(expired) || s.LastSeenAt.Before(idle)) {
			delete(d.adminSessions, key)
			removed++
		}
	}
	return removed, nil
}
