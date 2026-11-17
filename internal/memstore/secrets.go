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

type secretKey struct{ tenant, id string }

type secrets struct {
	d  func() *data
	mu *sync.Mutex
}

func (r secrets) enter(ctx context.Context) (*data, func(), error) {
	return enter(ctx, r.d, r.mu)
}

func (r secrets) Add(ctx context.Context, s store.Secret) error {
	if err := storecheck.NewSecret(s); err != nil {
		return err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	if _, taken := d.secrets[secretKey{s.TenantID, s.ID}]; taken {
		return store.ErrConflict
	}
	for _, other := range d.secrets {
		if bytes.Equal(other.Hash, s.Hash) {
			return store.ErrConflict
		}
	}
	if _, found := d.users[userKey{s.TenantID, s.UserID}]; !found {
		return store.ErrNotFound
	}
	if _, found := d.idents[identKey{s.TenantID, s.ChannelType, s.ChannelValue}]; !found {
		return store.ErrNotFound
	}
	d.secrets[secretKey{s.TenantID, s.ID}] = cloneSecret(s)
	return nil
}

func (r secrets) End(ctx context.Context, scope store.SecretScope, at time.Time) (int, error) {
	if err := storecheck.SecretScope(scope); err != nil {
		return 0, err
	}
	if err := storecheck.Time("end time", at); err != nil {
		return 0, err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return 0, err
	}
	defer leave()
	ended := 0
	for key, s := range d.secrets {
		if inScope(s, scope) && s.UsedAt.IsZero() {
			s.UsedAt = normalizeTime(at)
			d.secrets[key] = s
			ended++
		}
	}
	return ended, nil
}

func (r secrets) UseLink(ctx context.Context, tenantID string, purpose store.SecretPurpose, hash []byte, at time.Time) (store.Secret, error) {
	if err := storecheck.Purpose(purpose); err != nil {
		return store.Secret{}, err
	}
	if err := storecheck.Time("use time", at); err != nil {
		return store.Secret{}, err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return store.Secret{}, err
	}
	defer leave()
	for key, s := range d.secrets {
		if s.TenantID != tenantID || s.Kind != store.SecretLink || s.Purpose != purpose || !bytes.Equal(s.Hash, hash) {
			continue
		}
		if !s.UsedAt.IsZero() || !s.ExpiresAt.After(normalizeTime(at)) {
			return store.Secret{}, store.ErrNotFound
		}
		s.UsedAt = normalizeTime(at)
		d.secrets[key] = s
		return cloneSecret(s), nil
	}
	return store.Secret{}, store.ErrNotFound
}

func (r secrets) TryCodes(ctx context.Context, scope store.SecretScope, at time.Time, limit int) ([]store.Secret, error) {
	if err := storecheck.SecretScope(scope); err != nil {
		return nil, err
	}
	if err := storecheck.Time("attempt time", at); err != nil {
		return nil, err
	}
	if err := storecheck.Attempts(limit); err != nil {
		return nil, err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer leave()
	var tried []store.Secret
	for key, s := range d.secrets {
		if !inScope(s, scope) || s.Kind != store.SecretCode || !s.UsedAt.IsZero() ||
			!s.ExpiresAt.After(normalizeTime(at)) || s.Attempts >= limit {
			continue
		}
		tried = append(tried, cloneSecret(s))
		s.Attempts++
		d.secrets[key] = s
	}
	slices.SortFunc(tried, storecheck.CompareSecrets)
	return tried, nil
}

func (r secrets) UseCode(ctx context.Context, tenantID, id string, at time.Time) error {
	if err := storecheck.Time("use time", at); err != nil {
		return err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	key := secretKey{tenantID, id}
	s, found := d.secrets[key]
	if !found || s.Kind != store.SecretCode || !s.UsedAt.IsZero() || !s.ExpiresAt.After(normalizeTime(at)) {
		return store.ErrNotFound
	}
	s.UsedAt = normalizeTime(at)
	d.secrets[key] = s
	return nil
}

func (r secrets) DeleteStale(ctx context.Context, tenantID string, before time.Time) (int, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return 0, err
	}
	defer leave()
	cutoff := normalizeTime(before)
	removed := 0
	for key, s := range d.secrets {
		if s.TenantID == tenantID && (s.ExpiresAt.Before(cutoff) || (!s.UsedAt.IsZero() && s.UsedAt.Before(cutoff))) {
			delete(d.secrets, key)
			removed++
		}
	}
	return removed, nil
}

func inScope(s store.Secret, scope store.SecretScope) bool {
	return s.TenantID == scope.TenantID && s.UserID == scope.UserID && s.Purpose == scope.Purpose &&
		(scope.ChannelType == "" || (s.ChannelType == scope.ChannelType && s.ChannelValue == scope.ChannelValue))
}

func cloneSecret(s store.Secret) store.Secret {
	s.Hash = bytes.Clone(s.Hash)
	s.CreatedAt = normalizeTime(s.CreatedAt)
	s.ExpiresAt = normalizeTime(s.ExpiresAt)
	s.UsedAt = normalizeTime(s.UsedAt)
	return s
}
