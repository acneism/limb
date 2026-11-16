package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/acneism/limb/internal/storecheck"
	"github.com/acneism/limb/store"
)

type attempts struct {
	d  func() *data
	mu *sync.Mutex
}

func (r attempts) enter(ctx context.Context) (*data, func(), error) {
	return enter(ctx, r.d, r.mu)
}

func (r attempts) Hit(ctx context.Context, key string, at time.Time, window time.Duration) (store.Attempt, error) {
	if err := storecheck.AttemptKey(key); err != nil {
		return store.Attempt{}, err
	}
	if err := storecheck.Time("attempt time", at); err != nil {
		return store.Attempt{}, err
	}
	if err := storecheck.Window(window); err != nil {
		return store.Attempt{}, err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return store.Attempt{}, err
	}
	defer leave()
	moment, cutoff := normalizeTime(at), normalizeTime(at.Add(-window))
	counter, found := d.attempts[key]
	switch {
	case found && counter.WindowStart.After(cutoff):
		counter.Count++
	case found:
		counter.Count, counter.WindowStart = 1, moment
	default:
		counter = store.Attempt{Key: key, WindowStart: moment, Count: 1}
	}
	d.attempts[key] = counter
	return counter, nil
}

func (r attempts) Get(ctx context.Context, keys ...string) ([]store.Attempt, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer leave()
	var list []store.Attempt
	seen := make(map[string]bool, len(keys))
	for _, key := range keys {
		if counter, found := d.attempts[key]; found && !seen[key] {
			seen[key] = true
			list = append(list, counter)
		}
	}
	return list, nil
}

func (r attempts) Hold(ctx context.Context, key string, h store.Hold) error {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	counter, found := d.attempts[key]
	if !found {
		return store.ErrNotFound
	}
	if until := normalizeTime(h.BlockedUntil); until.After(counter.BlockedUntil) {
		counter.BlockedUntil = until
	}
	if next := normalizeTime(h.NextAllowedAt); next.After(counter.NextAllowedAt) {
		counter.NextAllowedAt = next
	}
	d.attempts[key] = counter
	return nil
}

func (r attempts) Reset(ctx context.Context, key string) error {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	delete(d.attempts, key)
	return nil
}

func (r attempts) DeleteStale(ctx context.Context, before time.Time) (int, error) {
	d, leave, err := r.enter(ctx)
	if err != nil {
		return 0, err
	}
	defer leave()
	limit := normalizeTime(before)
	removed := 0
	for key, counter := range d.attempts {
		stale := counter.WindowStart.Before(limit) &&
			(counter.BlockedUntil.IsZero() || counter.BlockedUntil.Before(limit)) &&
			(counter.NextAllowedAt.IsZero() || counter.NextAllowedAt.Before(limit))
		if stale {
			delete(d.attempts, key)
			removed++
		}
	}
	return removed, nil
}
