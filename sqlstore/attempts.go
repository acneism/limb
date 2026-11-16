package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/acneism/limb/internal/storecheck"
	"github.com/acneism/limb/store"
)

const hitRetries = 20

type attempts struct {
	s *Store
	x executor
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
	moment, cutoff := storedTime(at), storedTime(at.Add(-window))
	for range hitRetries {
		counted, err := r.count(ctx, key, moment, cutoff)
		if err != nil {
			return store.Attempt{}, err
		}
		if counted {
			counter, readErr := r.read(ctx, key)
			if errors.Is(readErr, store.ErrNotFound) {
				continue
			}
			return counter, readErr
		}
		inserted, err := r.exec(ctx, r.s.q.insertAttempt, key, moment)
		if err != nil && !r.s.dialect.IsUniqueViolation(err) {
			return store.Attempt{}, err
		}
		if err == nil && inserted > 0 {
			return store.Attempt{Key: key, WindowStart: moment, Count: 1}, nil
		}
	}
	return store.Attempt{}, errors.New("sqlstore: count attempt: the counter kept changing under the call")
}

func (r attempts) count(ctx context.Context, key string, moment, cutoff time.Time) (bool, error) {
	changed, err := r.exec(ctx, r.s.q.bumpAttempt, key, cutoff)
	if err != nil || changed > 0 {
		return changed > 0, err
	}
	changed, err = r.exec(ctx, r.s.q.restartAttempt, moment, key, cutoff)
	return changed > 0, err
}

func (r attempts) exec(ctx context.Context, query string, args ...any) (int, error) {
	result, err := r.x.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("sqlstore: count attempt: %w", err)
	}
	return affected(result, "count attempt")
}

func (r attempts) read(ctx context.Context, key string) (store.Attempt, error) {
	counter, err := scanAttempt(r.x.QueryRowContext(ctx, r.s.q.selectAttempt, key))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return store.Attempt{}, store.ErrNotFound
	case err != nil:
		return store.Attempt{}, fmt.Errorf("sqlstore: read attempts: %w", err)
	}
	return counter, nil
}

func (r attempts) Get(ctx context.Context, keys ...string) ([]store.Attempt, error) {
	var valid []any
	for _, key := range keys {
		if storecheck.ValidAttemptKey(key) {
			valid = append(valid, key)
		}
	}
	if len(valid) == 0 {
		return nil, nil
	}
	marks := make([]string, len(valid))
	for i := range marks {
		marks[i] = r.s.dialect.Placeholder(i + 1)
	}
	query := "SELECT " + attemptColumns + " FROM " + r.s.prefix + "attempts WHERE attempt_key IN (" + strings.Join(marks, ", ") + ")"
	rows, err := r.x.QueryContext(ctx, query, valid...)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: read attempts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var list []store.Attempt
	for rows.Next() {
		counter, scanErr := scanAttempt(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("sqlstore: read attempts: %w", scanErr)
		}
		list = append(list, counter)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore: read attempts: %w", err)
	}
	return list, nil
}

func (r attempts) Hold(ctx context.Context, key string, h store.Hold) error {
	if !storecheck.ValidAttemptKey(key) {
		return store.ErrNotFound
	}
	changed := 0
	if !h.BlockedUntil.IsZero() {
		n, err := r.hold(ctx, r.s.q.holdBlock, key, h.BlockedUntil)
		if err != nil {
			return err
		}
		changed += n
	}
	if !h.NextAllowedAt.IsZero() {
		n, err := r.hold(ctx, r.s.q.holdDelay, key, h.NextAllowedAt)
		if err != nil {
			return err
		}
		changed += n
	}
	if changed > 0 {
		return nil
	}
	if _, err := r.read(ctx, key); err != nil {
		return err
	}
	return nil
}

func (r attempts) hold(ctx context.Context, query, key string, until time.Time) (int, error) {
	moment := storedTime(until)
	result, err := r.x.ExecContext(ctx, query, moment, key, moment)
	if err != nil {
		return 0, fmt.Errorf("sqlstore: hold attempts: %w", err)
	}
	return affected(result, "hold attempts")
}

func (r attempts) Reset(ctx context.Context, key string) error {
	if !storecheck.ValidAttemptKey(key) {
		return nil
	}
	if _, err := r.x.ExecContext(ctx, r.s.q.resetAttempt, key); err != nil {
		return fmt.Errorf("sqlstore: reset attempts: %w", err)
	}
	return nil
}

func (r attempts) DeleteStale(ctx context.Context, before time.Time) (int, error) {
	moment := storedTime(before)
	result, err := r.x.ExecContext(ctx, r.s.q.deleteAttempts, moment, moment, moment)
	if err != nil {
		return 0, fmt.Errorf("sqlstore: delete attempts: %w", err)
	}
	return affected(result, "delete attempts")
}

func scanAttempt(row scanner) (store.Attempt, error) {
	var (
		a            store.Attempt
		start        time.Time
		blocked, nxt sql.NullTime
	)
	if err := row.Scan(&a.Key, &start, &a.Count, &blocked, &nxt); err != nil {
		return store.Attempt{}, err
	}
	a.WindowStart = start.UTC()
	a.BlockedUntil = utcOrZero(blocked)
	a.NextAllowedAt = utcOrZero(nxt)
	return a, nil
}
