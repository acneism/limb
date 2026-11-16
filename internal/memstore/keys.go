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

type signingKeys struct {
	d  func() *data
	mu *sync.Mutex
}

func (r signingKeys) enter(ctx context.Context) (*data, func(), error) {
	return enter(ctx, r.d, r.mu)
}

func cloneKey(k store.SigningKey) store.SigningKey {
	k.PrivateKey = bytes.Clone(k.PrivateKey)
	k.PublicKey = bytes.Clone(k.PublicKey)
	k.CreatedAt = normalizeTime(k.CreatedAt)
	k.RetireAfter = normalizeTime(k.RetireAfter)
	return k
}

func (r signingKeys) Add(ctx context.Context, k store.SigningKey) error {
	if err := storecheck.NewSigningKey(k); err != nil {
		return err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	if _, taken := d.keys[k.KID]; taken {
		return store.ErrConflict
	}
	for _, stored := range d.keys {
		if stored.Generation == k.Generation {
			return store.ErrConflict
		}
	}
	d.keys[k.KID] = cloneKey(k)
	return nil
}

func (r signingKeys) List(ctx context.Context) ([]store.SigningKey, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer leave()
	var list []store.SigningKey
	for _, k := range d.keys {
		list = append(list, cloneKey(k))
	}
	slices.SortFunc(list, func(a, b store.SigningKey) int {
		switch {
		case a.Generation < b.Generation:
			return -1
		case a.Generation > b.Generation:
			return 1
		}
		return 0
	})
	return list, nil
}

func (r signingKeys) Retire(ctx context.Context, kid string, retireAfter time.Time) error {
	if err := storecheck.Time("retirement time", retireAfter); err != nil {
		return err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	k, found := d.keys[kid]
	if !found {
		return store.ErrNotFound
	}
	if k.RetireAfter.IsZero() {
		k.RetireAfter = normalizeTime(retireAfter)
		d.keys[kid] = k
	}
	return nil
}

func (r signingKeys) DeleteRetired(ctx context.Context, before time.Time) (int, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return 0, err
	}
	defer leave()
	removed := 0
	for kid, k := range d.keys {
		if !k.RetireAfter.IsZero() && k.RetireAfter.Before(normalizeTime(before)) {
			delete(d.keys, kid)
			removed++
		}
	}
	return removed, nil
}
