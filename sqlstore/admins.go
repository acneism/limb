package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/acneism/limb/internal/storecheck"
	"github.com/acneism/limb/store"
)

type admins struct {
	s *Store
	x executor
}

func (r admins) Create(ctx context.Context, a store.Admin) error {
	if err := storecheck.NewAdmin(a); err != nil {
		return err
	}
	_, err := r.x.ExecContext(ctx, r.s.q.insertAdmin,
		a.TenantID, a.ID, a.Login, a.PasswordHash, optionalBytes(a.TOTPSecret), optionalTime(a.TOTPConfirmedAt),
		a.TOTPLastStep, string(a.Status), storedTime(a.CreatedAt), optionalTime(a.LastLoginAt))
	if err != nil {
		if r.s.dialect.IsUniqueViolation(err) {
			return store.ErrConflict
		}
		return fmt.Errorf("sqlstore: create admin: %w", err)
	}
	return nil
}

func (r admins) Get(ctx context.Context, tenantID, id string) (store.Admin, error) {
	if !storecheck.ValidText(tenantID, id) {
		return store.Admin{}, store.ErrNotFound
	}
	return r.find(ctx, r.s.q.selectAdmin, tenantID, id)
}

func (r admins) FindByLogin(ctx context.Context, tenantID, login string) (store.Admin, error) {
	if !storecheck.ValidText(tenantID, login) {
		return store.Admin{}, store.ErrNotFound
	}
	return r.find(ctx, r.s.q.selectAdminByLogin, tenantID, login)
}

func (r admins) find(ctx context.Context, query string, args ...any) (store.Admin, error) {
	a, err := scanAdmin(r.x.QueryRowContext(ctx, query, args...))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return store.Admin{}, store.ErrNotFound
	case err != nil:
		return store.Admin{}, fmt.Errorf("sqlstore: get admin: %w", err)
	}
	return a, nil
}

func (r admins) List(ctx context.Context, tenantID string) ([]store.Admin, error) {
	if !storecheck.ValidText(tenantID) {
		return nil, nil
	}
	rows, err := r.x.QueryContext(ctx, r.s.q.listAdmins, tenantID)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: list admins: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var list []store.Admin
	for rows.Next() {
		a, scanErr := scanAdmin(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("sqlstore: list admins: %w", scanErr)
		}
		list = append(list, a)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore: list admins: %w", err)
	}
	slices.SortFunc(list, storecheck.CompareAdmins)
	return list, nil
}

func (r admins) Update(ctx context.Context, a store.Admin) (store.Admin, error) {
	if err := storecheck.Admin(a); err != nil {
		return store.Admin{}, err
	}
	result, err := r.x.ExecContext(ctx, r.s.q.updateAdmin,
		a.PasswordHash, optionalBytes(a.TOTPSecret), optionalTime(a.TOTPConfirmedAt), string(a.Status), a.TenantID, a.ID, a.Version)
	if err != nil {
		return store.Admin{}, fmt.Errorf("sqlstore: update admin: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return store.Admin{}, fmt.Errorf("sqlstore: update admin: %w", err)
	}
	if changed == 0 {
		return store.Admin{}, r.explainMiss(ctx, a.TenantID, a.ID, "update admin")
	}
	a.TOTPSecret = bytes.Clone(a.TOTPSecret)
	a.TOTPConfirmedAt = storedOptional(a.TOTPConfirmedAt)
	a.CreatedAt = storedOptional(a.CreatedAt)
	a.LastLoginAt = storedOptional(a.LastLoginAt)
	a.Version++
	return a, nil
}

type adminMark struct {
	version  int64
	lastStep int64
}

func (r admins) mark(ctx context.Context, tenantID, id, action string) (adminMark, error) {
	var m adminMark
	err := r.x.QueryRowContext(ctx, r.s.q.adminMark, tenantID, id).Scan(&m.version, &m.lastStep)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return adminMark{}, store.ErrNotFound
	case err != nil:
		return adminMark{}, fmt.Errorf("sqlstore: %s: %w", action, err)
	}
	return m, nil
}

func (r admins) explainMiss(ctx context.Context, tenantID, id, action string) error {
	if _, err := r.mark(ctx, tenantID, id, action); err != nil {
		return err
	}
	return store.ErrStale
}

func (r admins) Delete(ctx context.Context, tenantID, id string) error {
	if !storecheck.ValidText(tenantID, id) {
		return store.ErrNotFound
	}
	result, err := r.x.ExecContext(ctx, r.s.q.deleteAdmin, tenantID, id)
	if err != nil {
		return fmt.Errorf("sqlstore: delete admin: %w", err)
	}
	return requireRow(result, "delete admin")
}

func (r admins) AcceptStep(ctx context.Context, tenantID, id string, version, step int64, at time.Time) error {
	if err := storecheck.Time("sign-in time", at); err != nil {
		return err
	}
	if !storecheck.ValidText(tenantID, id) {
		return store.ErrNotFound
	}
	result, err := r.x.ExecContext(ctx, r.s.q.acceptStep, step, storedTime(at), tenantID, id, version, step)
	if err != nil {
		return fmt.Errorf("sqlstore: accept a time step: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlstore: accept a time step: %w", err)
	}
	if changed > 0 {
		return nil
	}
	m, err := r.mark(ctx, tenantID, id, "accept a time step")
	switch {
	case err != nil:
		return err
	case m.version != version:
		return store.ErrStale
	case m.lastStep >= step:
		return store.ErrConflict
	}
	return store.ErrStale
}

func (r admins) RecordLogin(ctx context.Context, tenantID, id string, version int64, at time.Time) error {
	if err := storecheck.Time("sign-in time", at); err != nil {
		return err
	}
	if !storecheck.ValidText(tenantID, id) {
		return store.ErrNotFound
	}
	result, err := r.x.ExecContext(ctx, r.s.q.recordLogin, storedTime(at), tenantID, id, version)
	if err != nil {
		return fmt.Errorf("sqlstore: record a sign-in: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlstore: record a sign-in: %w", err)
	}
	if changed > 0 {
		return nil
	}
	m, err := r.mark(ctx, tenantID, id, "record a sign-in")
	switch {
	case err != nil:
		return err
	case m.version != version:
		return store.ErrStale
	}
	return nil
}

func (r admins) ReplaceRecoveryCodes(ctx context.Context, tenantID, id string, hashes [][]byte) error {
	if err := storecheck.RecoveryHashes(hashes); err != nil {
		return err
	}
	if !storecheck.ValidText(tenantID, id) {
		return store.ErrNotFound
	}
	var one int
	switch err := r.x.QueryRowContext(ctx, r.s.q.adminExists, tenantID, id).Scan(&one); {
	case errors.Is(err, sql.ErrNoRows):
		return store.ErrNotFound
	case err != nil:
		return fmt.Errorf("sqlstore: replace recovery codes: %w", err)
	}
	if _, err := r.x.ExecContext(ctx, r.s.q.deleteRecoveryCodes, tenantID, id); err != nil {
		return fmt.Errorf("sqlstore: replace recovery codes: %w", err)
	}
	for _, hash := range hashes {
		_, err := r.x.ExecContext(ctx, r.s.q.insertRecoveryCode, tenantID, id, hash)
		switch {
		case err == nil:
		case r.s.dialect.IsUniqueViolation(err):
			return store.ErrConflict
		case r.s.dialect.IsForeignKeyViolation(err):
			return store.ErrNotFound
		default:
			return fmt.Errorf("sqlstore: replace recovery codes: %w", err)
		}
	}
	return nil
}

func (r admins) UseRecoveryCode(ctx context.Context, tenantID, id string, hash []byte, at time.Time) error {
	if err := storecheck.Time("use time", at); err != nil {
		return err
	}
	if !storecheck.ValidText(tenantID, id) || !storecheck.ValidHash(hash) {
		return store.ErrNotFound
	}
	result, err := r.x.ExecContext(ctx, r.s.q.useRecoveryCode, storedTime(at), tenantID, id, hash)
	if err != nil {
		return fmt.Errorf("sqlstore: use a recovery code: %w", err)
	}
	return requireRow(result, "use a recovery code")
}

func (r admins) CountRecoveryCodes(ctx context.Context, tenantID, id string) (int, error) {
	if !storecheck.ValidText(tenantID, id) {
		return 0, nil
	}
	var count int
	if err := r.x.QueryRowContext(ctx, r.s.q.countRecoveryCodes, tenantID, id).Scan(&count); err != nil {
		return 0, fmt.Errorf("sqlstore: count recovery codes: %w", err)
	}
	return count, nil
}

func scanAdmin(row scanner) (store.Admin, error) {
	var (
		a                    store.Admin
		status               string
		secret               []byte
		confirmed, lastLogin sql.NullTime
		created              time.Time
	)
	err := row.Scan(&a.TenantID, &a.ID, &a.Login, &a.PasswordHash, &secret, &confirmed, &a.TOTPLastStep, &status, &created, &lastLogin, &a.Version)
	if err != nil {
		return store.Admin{}, err
	}
	if len(secret) > 0 {
		a.TOTPSecret = secret
	}
	a.TOTPConfirmedAt = utcOrZero(confirmed)
	a.Status = store.AdminStatus(status)
	a.CreatedAt = created.UTC()
	a.LastLoginAt = utcOrZero(lastLogin)
	return a, nil
}
