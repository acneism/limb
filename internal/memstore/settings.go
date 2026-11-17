package memstore

import (
	"context"
	"slices"
	"sync"

	"github.com/acneism/limb/internal/storecheck"
	"github.com/acneism/limb/store"
)

type settingKey struct{ tenant, name string }

type settings struct {
	d  func() *data
	mu *sync.Mutex
}

func (r settings) enter(ctx context.Context) (*data, func(), error) {
	return enter(ctx, r.d, r.mu)
}

func (r settings) Get(ctx context.Context, tenantID, name string) (store.Setting, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return store.Setting{}, err
	}
	defer leave()
	s, found := d.settings[settingKey{tenantID, name}]
	if !found {
		return store.Setting{}, store.ErrNotFound
	}
	return s, nil
}

func (r settings) List(ctx context.Context, tenantID string) ([]store.Setting, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer leave()
	var list []store.Setting
	for key, s := range d.settings {
		if key.tenant == tenantID {
			list = append(list, s)
		}
	}
	slices.SortFunc(list, storecheck.CompareSettings)
	return list, nil
}

func (r settings) Set(ctx context.Context, s store.Setting) error {
	if err := storecheck.Setting(s); err != nil {
		return err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	s.UpdatedAt = normalizeTime(s.UpdatedAt)
	d.settings[settingKey{s.TenantID, s.Name}] = s
	return nil
}

func (r settings) Delete(ctx context.Context, tenantID, name string) error {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	key := settingKey{tenantID, name}
	if _, found := d.settings[key]; !found {
		return store.ErrNotFound
	}
	delete(d.settings, key)
	return nil
}
