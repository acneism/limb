package sqlstore

import (
	"context"
	"database/sql"
	"math/rand/v2"
	"time"
)

const (
	maxAttempts  = 3
	minRetryWait = 5 * time.Millisecond
	retryJitter  = 20 * time.Millisecond
)

func (s *Store) retrying(ctx context.Context, run func() error) error {
	for attempt := 1; ; attempt++ {
		err := run()
		if err == nil || attempt == maxAttempts || !s.dialect.IsRetryable(err) {
			return err
		}
		timer := time.NewTimer(minRetryWait + rand.N(retryJitter)) //nolint:gosec
		select {
		case <-ctx.Done():
			timer.Stop()
			return err
		case <-timer.C:
		}
	}
}

type retryingDB struct {
	db *sql.DB
	s  *Store
}

func (r retryingDB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	var result sql.Result
	err := r.s.retrying(ctx, func() (execErr error) {
		result, execErr = r.db.ExecContext(ctx, query, args...)
		return execErr
	})
	return result, err
}

func (r retryingDB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return r.db.QueryContext(ctx, query, args...)
}

func (r retryingDB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return r.db.QueryRowContext(ctx, query, args...)
}
