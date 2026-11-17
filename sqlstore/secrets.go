package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"time"

	"github.com/acneism/limb/internal/storecheck"
	"github.com/acneism/limb/store"
)

type secrets struct {
	s *Store
	x executor
}

func (r secrets) Add(ctx context.Context, s store.Secret) error {
	if err := storecheck.NewSecret(s); err != nil {
		return err
	}
	_, err := r.x.ExecContext(ctx, r.s.q.insertSecret,
		s.TenantID, s.ID, string(s.Kind), s.Hash, s.UserID, string(s.Purpose), s.ChannelType, s.ChannelValue,
		storedTime(s.CreatedAt), storedTime(s.ExpiresAt))
	switch {
	case err == nil:
		return nil
	case r.s.dialect.IsUniqueViolation(err):
		return store.ErrConflict
	case r.s.dialect.IsForeignKeyViolation(err):
		return store.ErrNotFound
	}
	return fmt.Errorf("sqlstore: add secret: %w", err)
}

func (r secrets) End(ctx context.Context, scope store.SecretScope, at time.Time) (int, error) {
	if err := storecheck.SecretScope(scope); err != nil {
		return 0, err
	}
	if err := storecheck.Time("end time", at); err != nil {
		return 0, err
	}
	if !storecheck.ValidScope(scope) {
		return 0, nil
	}
	query, args := r.s.q.endSecrets, []any{storedTime(at), scope.TenantID, scope.UserID, string(scope.Purpose)}
	if scope.ChannelType != "" {
		query, args = r.s.q.endChannel, append(args, scope.ChannelType, scope.ChannelValue)
	}
	result, err := r.x.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("sqlstore: end secrets: %w", err)
	}
	return affected(result, "end secrets")
}

func (r secrets) UseLink(ctx context.Context, tenantID string, purpose store.SecretPurpose, hash []byte, at time.Time) (store.Secret, error) {
	if err := storecheck.Purpose(purpose); err != nil {
		return store.Secret{}, err
	}
	if err := storecheck.Time("use time", at); err != nil {
		return store.Secret{}, err
	}
	if !storecheck.ValidText(tenantID) || !storecheck.ValidHash(hash) {
		return store.Secret{}, store.ErrNotFound
	}
	result, err := r.x.ExecContext(ctx, r.s.q.useLink, storedTime(at), tenantID, string(purpose), hash, storedTime(at))
	if err != nil {
		return store.Secret{}, fmt.Errorf("sqlstore: use link: %w", err)
	}
	if err = requireRow(result, "use link"); err != nil {
		return store.Secret{}, err
	}
	found, err := scanSecret(r.x.QueryRowContext(ctx, r.s.q.selectLink, tenantID, hash))
	if err != nil {
		return store.Secret{}, fmt.Errorf("sqlstore: use link: %w", err)
	}
	return found, nil
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
	if !storecheck.ValidScope(scope) {
		return nil, nil
	}
	moment := storedTime(at)
	query, args := r.s.q.selectCodes, []any{scope.TenantID, scope.UserID, string(scope.Purpose), moment, limit}
	if scope.ChannelType != "" {
		query, args = r.s.q.selectChannel, append(args, scope.ChannelType, scope.ChannelValue)
	}
	candidates, err := r.list(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	var tried []store.Secret
	for _, candidate := range candidates {
		result, execErr := r.x.ExecContext(ctx, r.s.q.countAttempt, scope.TenantID, candidate.ID, limit)
		if execErr != nil {
			return nil, fmt.Errorf("sqlstore: count an attempt: %w", execErr)
		}
		counted, affectedErr := affected(result, "count an attempt")
		if affectedErr != nil {
			return nil, affectedErr
		}
		if counted == 1 {
			tried = append(tried, candidate)
		}
	}
	return tried, nil
}

func (r secrets) list(ctx context.Context, query string, args ...any) ([]store.Secret, error) {
	rows, err := r.x.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: list secrets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var list []store.Secret
	for rows.Next() {
		found, scanErr := scanSecret(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("sqlstore: list secrets: %w", scanErr)
		}
		list = append(list, found)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore: list secrets: %w", err)
	}
	slices.SortFunc(list, storecheck.CompareSecrets)
	return list, nil
}

func (r secrets) UseCode(ctx context.Context, tenantID, id string, at time.Time) error {
	if err := storecheck.Time("use time", at); err != nil {
		return err
	}
	if !storecheck.ValidText(tenantID, id) {
		return store.ErrNotFound
	}
	result, err := r.x.ExecContext(ctx, r.s.q.useCode, storedTime(at), tenantID, id, storedTime(at))
	if err != nil {
		return fmt.Errorf("sqlstore: use code: %w", err)
	}
	return requireRow(result, "use code")
}

func (r secrets) DeleteStale(ctx context.Context, tenantID string, before time.Time) (int, error) {
	if !storecheck.ValidText(tenantID) {
		return 0, nil
	}
	cutoff := storedTime(before)
	result, err := r.x.ExecContext(ctx, r.s.q.deleteSecrets, tenantID, cutoff, cutoff)
	if err != nil {
		return 0, fmt.Errorf("sqlstore: delete secrets: %w", err)
	}
	return affected(result, "delete secrets")
}

func scanSecret(row scanner) (store.Secret, error) {
	var (
		s                store.Secret
		kind, purpose    string
		created, expires time.Time
		used             sql.NullTime
	)
	if err := row.Scan(&s.TenantID, &s.ID, &kind, &s.Hash, &s.UserID, &purpose, &s.ChannelType, &s.ChannelValue,
		&s.Attempts, &created, &expires, &used); err != nil {
		return store.Secret{}, err
	}
	s.Kind = store.SecretKind(kind)
	s.Purpose = store.SecretPurpose(purpose)
	s.CreatedAt = created.UTC()
	s.ExpiresAt = expires.UTC()
	s.UsedAt = utcOrZero(used)
	return s, nil
}
