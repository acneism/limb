package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/acneism/limb/internal/storecheck"
	"github.com/acneism/limb/store"
)

type refreshTokens struct {
	s *Store
	x executor
}

func (r refreshTokens) Add(ctx context.Context, t store.RefreshToken) error {
	if err := storecheck.NewRefreshToken(t); err != nil {
		return err
	}
	_, err := r.x.ExecContext(ctx, r.s.q.insertToken, t.Hash, t.TenantID, t.SessionID, storedTime(t.ExpiresAt))
	switch {
	case err == nil:
		return nil
	case r.s.dialect.IsUniqueViolation(err):
		return store.ErrConflict
	case r.s.dialect.IsForeignKeyViolation(err):
		return store.ErrNotFound
	}
	return fmt.Errorf("sqlstore: add refresh token: %w", err)
}

func (r refreshTokens) Use(ctx context.Context, tenantID string, hash []byte, at time.Time) (store.RefreshUse, error) {
	if err := storecheck.Time("use time", at); err != nil {
		return store.RefreshUse{}, err
	}
	if !storecheck.ValidText(tenantID) || !storecheck.ValidHash(hash) {
		return store.RefreshUse{}, store.ErrNotFound
	}
	result, err := r.x.ExecContext(ctx, r.s.q.useToken, storedTime(at), tenantID, hash)
	if err != nil {
		return store.RefreshUse{}, fmt.Errorf("sqlstore: use refresh token: %w", err)
	}
	changed, err := affected(result, "use refresh token")
	if err != nil {
		return store.RefreshUse{}, err
	}
	token, err := scanToken(r.x.QueryRowContext(ctx, r.s.q.selectToken, tenantID, hash))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return store.RefreshUse{}, store.ErrNotFound
	case err != nil:
		return store.RefreshUse{}, fmt.Errorf("sqlstore: use refresh token: %w", err)
	}
	return store.RefreshUse{Token: token, Reused: changed == 0}, nil
}

func (r refreshTokens) DeleteExpired(ctx context.Context, tenantID string, before time.Time) (int, error) {
	if !storecheck.ValidText(tenantID) {
		return 0, nil
	}
	result, err := r.x.ExecContext(ctx, r.s.q.deleteTokens, tenantID, storedTime(before))
	if err != nil {
		return 0, fmt.Errorf("sqlstore: delete refresh tokens: %w", err)
	}
	return affected(result, "delete refresh tokens")
}

func scanToken(row scanner) (store.RefreshToken, error) {
	var (
		t       store.RefreshToken
		expires time.Time
		used    sql.NullTime
	)
	if err := row.Scan(&t.TenantID, &t.Hash, &t.SessionID, &expires, &used); err != nil {
		return store.RefreshToken{}, err
	}
	t.ExpiresAt = expires.UTC()
	t.UsedAt = utcOrZero(used)
	return t, nil
}
