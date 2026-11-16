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

type sessionKey struct{ tenant, id string }

func (d *data) removeSession(key sessionKey) {
	delete(d.sessions, key)
	for hash, t := range d.tokens {
		if t.TenantID == key.tenant && t.SessionID == key.id {
			delete(d.tokens, hash)
		}
	}
}

func (d *data) secretTaken(hash []byte) bool {
	if len(hash) == 0 {
		return false
	}
	for _, s := range d.sessions {
		if bytes.Equal(s.SecretHash, hash) {
			return true
		}
	}
	return false
}

func (d *data) resolve(s store.Session) store.ResolvedSession {
	u := d.users[userKey{s.TenantID, s.UserID}]
	return store.ResolvedSession{
		Session: cloneSession(s),
		User:    store.UserState{Status: u.Status, BlockedUntil: u.BlockedUntil, MustChangePassword: u.MustChangePassword},
	}
}

func normalizeSession(s store.Session) store.Session {
	s.CreatedAt = normalizeTime(s.CreatedAt)
	s.LastSeenAt = normalizeTime(s.LastSeenAt)
	s.ExpiresAt = normalizeTime(s.ExpiresAt)
	s.RevokedAt = normalizeTime(s.RevokedAt)
	return cloneSession(s)
}

func cloneSession(s store.Session) store.Session {
	if len(s.SecretHash) == 0 {
		s.SecretHash = nil
	} else {
		s.SecretHash = bytes.Clone(s.SecretHash)
	}
	return s
}

type sessions struct {
	d  func() *data
	mu *sync.Mutex
}

func (r sessions) enter(ctx context.Context) (*data, func(), error) {
	return enter(ctx, r.d, r.mu)
}

func (r sessions) Create(ctx context.Context, s store.Session) error {
	if err := storecheck.NewSession(s); err != nil {
		return err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	key := sessionKey{s.TenantID, s.ID}
	if _, taken := d.sessions[key]; taken || d.secretTaken(s.SecretHash) {
		return store.ErrConflict
	}
	if _, found := d.users[userKey{s.TenantID, s.UserID}]; !found {
		return store.ErrNotFound
	}
	d.sessions[key] = normalizeSession(s)
	return nil
}

func (r sessions) ResolveByID(ctx context.Context, tenantID, id string) (store.ResolvedSession, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return store.ResolvedSession{}, err
	}
	defer leave()
	s, found := d.sessions[sessionKey{tenantID, id}]
	if !found {
		return store.ResolvedSession{}, store.ErrNotFound
	}
	return d.resolve(s), nil
}

func (r sessions) ResolveBySecret(ctx context.Context, tenantID string, secretHash []byte) (store.ResolvedSession, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return store.ResolvedSession{}, err
	}
	defer leave()
	if !storecheck.ValidHash(secretHash) {
		return store.ResolvedSession{}, store.ErrNotFound
	}
	for _, s := range d.sessions {
		if s.TenantID == tenantID && bytes.Equal(s.SecretHash, secretHash) {
			return d.resolve(s), nil
		}
	}
	return store.ResolvedSession{}, store.ErrNotFound
}

func (r sessions) Touch(ctx context.Context, tenantID, id string, at time.Time) error {
	if err := storecheck.Time("touch time", at); err != nil {
		return err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	key := sessionKey{tenantID, id}
	s, found := d.sessions[key]
	if found && normalizeTime(at).After(s.LastSeenAt) {
		s.LastSeenAt = normalizeTime(at)
		d.sessions[key] = s
	}
	return nil
}

func (r sessions) Revoke(ctx context.Context, tenantID, userID, id string, at time.Time) error {
	if err := storecheck.Time("revocation time", at); err != nil {
		return err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	key := sessionKey{tenantID, id}
	s, found := d.sessions[key]
	if !found || s.UserID != userID || !s.RevokedAt.IsZero() {
		return store.ErrNotFound
	}
	s.RevokedAt = normalizeTime(at)
	d.sessions[key] = s
	return nil
}

func (r sessions) RevokeAllForUser(ctx context.Context, tenantID, userID, exceptID string, at time.Time) (int, error) {
	if err := storecheck.Time("revocation time", at); err != nil {
		return 0, err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return 0, err
	}
	defer leave()
	revoked := 0
	for key, s := range d.sessions {
		if s.TenantID != tenantID || s.UserID != userID || !s.RevokedAt.IsZero() || (exceptID != "" && s.ID == exceptID) {
			continue
		}
		s.RevokedAt = normalizeTime(at)
		d.sessions[key] = s
		revoked++
	}
	return revoked, nil
}

func (r sessions) ListByUser(ctx context.Context, tenantID, userID string, now time.Time) ([]store.Session, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer leave()
	var list []store.Session
	for _, s := range d.sessions {
		if s.TenantID == tenantID && s.UserID == userID && s.RevokedAt.IsZero() && s.ExpiresAt.After(normalizeTime(now)) {
			list = append(list, cloneSession(s))
		}
	}
	slices.SortFunc(list, storecheck.CompareSessions)
	return list, nil
}

func (r sessions) DeleteInactive(ctx context.Context, tenantID string, expiredBefore, idleBefore, revokedBefore time.Time) (int, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return 0, err
	}
	defer leave()
	removed := 0
	for key, s := range d.sessions {
		if s.TenantID != tenantID {
			continue
		}
		revokedLongAgo := !s.RevokedAt.IsZero() && s.RevokedAt.Before(normalizeTime(revokedBefore))
		if s.ExpiresAt.Before(normalizeTime(expiredBefore)) || s.LastSeenAt.Before(normalizeTime(idleBefore)) || revokedLongAgo {
			d.removeSession(key)
			removed++
		}
	}
	return removed, nil
}

type refreshTokens struct {
	d  func() *data
	mu *sync.Mutex
}

func (r refreshTokens) enter(ctx context.Context) (*data, func(), error) {
	return enter(ctx, r.d, r.mu)
}

func (r refreshTokens) Add(ctx context.Context, t store.RefreshToken) error {
	if err := storecheck.NewRefreshToken(t); err != nil {
		return err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	if _, taken := d.tokens[string(t.Hash)]; taken {
		return store.ErrConflict
	}
	if _, found := d.sessions[sessionKey{t.TenantID, t.SessionID}]; !found {
		return store.ErrNotFound
	}
	d.tokens[string(t.Hash)] = cloneToken(t)
	return nil
}

func (r refreshTokens) Use(ctx context.Context, tenantID string, hash []byte, at time.Time) (store.RefreshUse, error) {
	if err := storecheck.Time("use time", at); err != nil {
		return store.RefreshUse{}, err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return store.RefreshUse{}, err
	}
	defer leave()
	stored, found := d.tokens[string(hash)]
	if !found || stored.TenantID != tenantID {
		return store.RefreshUse{}, store.ErrNotFound
	}
	reused := !stored.UsedAt.IsZero()
	if !reused {
		stored.UsedAt = normalizeTime(at)
		d.tokens[string(hash)] = stored
	}
	return store.RefreshUse{Token: cloneToken(stored), Reused: reused}, nil
}

func (r refreshTokens) DeleteExpired(ctx context.Context, tenantID string, before time.Time) (int, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return 0, err
	}
	defer leave()
	removed := 0
	for hash, t := range d.tokens {
		if t.TenantID == tenantID && t.ExpiresAt.Before(normalizeTime(before)) {
			delete(d.tokens, hash)
			removed++
		}
	}
	return removed, nil
}

func cloneToken(t store.RefreshToken) store.RefreshToken {
	t.Hash = bytes.Clone(t.Hash)
	t.ExpiresAt = normalizeTime(t.ExpiresAt)
	t.UsedAt = normalizeTime(t.UsedAt)
	return t
}
