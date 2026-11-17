package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/acneism/limb/internal/storecheck"
	"github.com/acneism/limb/store"
)

const setRetries = 5

type settings struct {
	s *Store
	x executor
}

func (r settings) Get(ctx context.Context, tenantID, name string) (store.Setting, error) {
	if !storecheck.ValidText(tenantID, name) {
		return store.Setting{}, store.ErrNotFound
	}
	setting, err := scanSetting(r.x.QueryRowContext(ctx, r.s.q.selectSetting, tenantID, name))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return store.Setting{}, store.ErrNotFound
	case err != nil:
		return store.Setting{}, fmt.Errorf("sqlstore: get setting: %w", err)
	}
	return setting, nil
}

func (r settings) List(ctx context.Context, tenantID string) ([]store.Setting, error) {
	if !storecheck.ValidText(tenantID) {
		return nil, nil
	}
	rows, err := r.x.QueryContext(ctx, r.s.q.listSettings, tenantID)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: list settings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var list []store.Setting
	for rows.Next() {
		setting, scanErr := scanSetting(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("sqlstore: list settings: %w", scanErr)
		}
		list = append(list, setting)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore: list settings: %w", err)
	}
	slices.SortFunc(list, storecheck.CompareSettings)
	return list, nil
}

func (r settings) Set(ctx context.Context, s store.Setting) error {
	if err := storecheck.Setting(s); err != nil {
		return err
	}
	at := storedTime(s.UpdatedAt)
	for range setRetries {
		updated, err := r.exec(ctx, r.s.q.updateSetting, s.Value, at, optionalText(s.UpdatedBy), s.TenantID, s.Name)
		if err != nil || updated > 0 {
			return err
		}
		inserted, err := r.exec(ctx, r.s.q.insertSetting, s.TenantID, s.Name, s.Value, at, optionalText(s.UpdatedBy))
		if err != nil && !r.s.dialect.IsUniqueViolation(err) {
			return err
		}
		if err == nil && inserted > 0 {
			return nil
		}
		exists, err := r.exists(ctx, s.TenantID, s.Name)
		if err != nil || exists {
			return err
		}
	}
	return errors.New("sqlstore: set setting: the row kept changing under the call")
}

func (r settings) exec(ctx context.Context, query string, args ...any) (int, error) {
	result, err := r.x.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("sqlstore: set setting: %w", err)
	}
	return affected(result, "set setting")
}

func (r settings) exists(ctx context.Context, tenantID, name string) (bool, error) {
	var one int
	err := r.x.QueryRowContext(ctx, r.s.q.settingExists, tenantID, name).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("sqlstore: set setting: %w", err)
	}
	return true, nil
}

func (r settings) Delete(ctx context.Context, tenantID, name string) error {
	if !storecheck.ValidText(tenantID, name) {
		return store.ErrNotFound
	}
	result, err := r.x.ExecContext(ctx, r.s.q.deleteSetting, tenantID, name)
	if err != nil {
		return fmt.Errorf("sqlstore: delete setting: %w", err)
	}
	return requireRow(result, "delete setting")
}

func scanSetting(row scanner) (store.Setting, error) {
	var (
		s         store.Setting
		updatedAt time.Time
		updatedBy sql.NullString
	)
	if err := row.Scan(&s.TenantID, &s.Name, &s.Value, &updatedAt, &updatedBy); err != nil {
		return store.Setting{}, err
	}
	s.UpdatedAt = updatedAt.UTC()
	s.UpdatedBy = updatedBy.String
	return s, nil
}
