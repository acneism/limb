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

type scanner interface {
	Scan(dest ...any) error
}

type users struct {
	s *Store
	x executor
}

func (r users) Create(ctx context.Context, u store.User) error {
	if err := storecheck.NewUser(u); err != nil {
		return err
	}
	_, err := r.x.ExecContext(ctx, r.s.q.insertUser,
		u.TenantID, u.ID, string(u.Status), optionalText(u.PasswordHash), u.MustChangePassword,
		optionalText(u.BlockedReason), optionalTime(u.BlockedUntil), optionalTime(u.DeletedAt),
		optionalTime(u.PurgeAfter), storedTime(u.CreatedAt), optionalTime(u.LastLoginAt), string(createdVia(u)))
	if err != nil {
		if r.s.dialect.IsUniqueViolation(err) {
			return store.ErrConflict
		}
		return fmt.Errorf("sqlstore: create user: %w", err)
	}
	return nil
}

func createdVia(u store.User) store.CreatedVia {
	if u.CreatedVia == "" {
		return store.CreatedViaAPI
	}
	return u.CreatedVia
}

func (r users) Get(ctx context.Context, tenantID, id string) (store.User, error) {
	if !storecheck.ValidText(tenantID, id) {
		return store.User{}, store.ErrNotFound
	}
	u, err := scanUser(r.x.QueryRowContext(ctx, r.s.q.selectUser, tenantID, id))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return store.User{}, store.ErrNotFound
	case err != nil:
		return store.User{}, fmt.Errorf("sqlstore: get user: %w", err)
	}
	return u, nil
}

func (r users) Update(ctx context.Context, u store.User) (store.User, error) {
	if err := storecheck.User(u); err != nil {
		return store.User{}, err
	}
	result, err := r.x.ExecContext(ctx, r.s.q.updateUser,
		string(u.Status), optionalText(u.PasswordHash), u.MustChangePassword, optionalText(u.BlockedReason),
		optionalTime(u.BlockedUntil), optionalTime(u.DeletedAt), optionalTime(u.PurgeAfter),
		optionalTime(u.LastLoginAt), u.TenantID, u.ID, u.Version)
	if err != nil {
		return store.User{}, fmt.Errorf("sqlstore: update user: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return store.User{}, fmt.Errorf("sqlstore: update user: %w", err)
	}
	if changed == 0 {
		return store.User{}, r.explainMiss(ctx, u.TenantID, u.ID)
	}
	u.BlockedUntil = storedOptional(u.BlockedUntil)
	u.DeletedAt = storedOptional(u.DeletedAt)
	u.PurgeAfter = storedOptional(u.PurgeAfter)
	u.LastLoginAt = storedOptional(u.LastLoginAt)
	u.CreatedAt = storedOptional(u.CreatedAt)
	u.Version++
	return u, nil
}

func (r users) explainMiss(ctx context.Context, tenantID, id string) error {
	var one int
	err := r.x.QueryRowContext(ctx, r.s.q.userExists, tenantID, id).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return store.ErrNotFound
	case err != nil:
		return fmt.Errorf("sqlstore: update user: %w", err)
	}
	return store.ErrStale
}

func (r users) Delete(ctx context.Context, tenantID, id string) error {
	if !storecheck.ValidText(tenantID, id) {
		return store.ErrNotFound
	}
	result, err := r.x.ExecContext(ctx, r.s.q.deleteUser, tenantID, id)
	if err != nil {
		return fmt.Errorf("sqlstore: delete user: %w", err)
	}
	return requireRow(result, "delete user")
}

func requireRow(result sql.Result, action string) error {
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlstore: %s: %w", action, err)
	}
	if changed == 0 {
		return store.ErrNotFound
	}
	return nil
}

func storedOptional(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return storedTime(t)
}

func scanUser(row scanner) (store.User, error) {
	var (
		u            store.User
		status       string
		hash, reason sql.NullString
		blockedUntil sql.NullTime
		deletedAt    sql.NullTime
		purgeAfter   sql.NullTime
		lastLogin    sql.NullTime
		createdAt    time.Time
		via          string
	)
	err := row.Scan(&u.TenantID, &u.ID, &status, &hash, &u.MustChangePassword, &reason,
		&blockedUntil, &deletedAt, &purgeAfter, &createdAt, &lastLogin, &u.Version, &via)
	if err != nil {
		return store.User{}, err
	}
	u.Status = store.Status(status)
	u.PasswordHash = hash.String
	u.BlockedReason = reason.String
	u.BlockedUntil = utcOrZero(blockedUntil)
	u.DeletedAt = utcOrZero(deletedAt)
	u.PurgeAfter = utcOrZero(purgeAfter)
	u.LastLoginAt = utcOrZero(lastLogin)
	u.CreatedAt = createdAt.UTC()
	u.CreatedVia = store.CreatedVia(via)
	return u, nil
}

func utcOrZero(t sql.NullTime) time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return t.Time.UTC()
}
