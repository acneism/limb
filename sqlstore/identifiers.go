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

type identifiers struct {
	s *Store
	x executor
}

func (r identifiers) Add(ctx context.Context, i store.Identifier) error {
	if err := storecheck.Identifier(i); err != nil {
		return err
	}
	_, err := r.x.ExecContext(ctx, r.s.q.insertIdentifier,
		i.TenantID, i.Type, i.Value, i.DisplayValue, i.UserID, optionalTime(i.VerifiedAt))
	switch {
	case err == nil:
		return nil
	case r.s.dialect.IsUniqueViolation(err):
		return store.ErrConflict
	case r.s.dialect.IsForeignKeyViolation(err):
		return store.ErrNotFound
	}
	return fmt.Errorf("sqlstore: add identifier: %w", err)
}

func (r identifiers) Find(ctx context.Context, tenantID, typ, value string) (store.Identifier, error) {
	if !storecheck.ValidText(tenantID, typ, value) {
		return store.Identifier{}, store.ErrNotFound
	}
	i, err := scanIdentifier(r.x.QueryRowContext(ctx, r.s.q.selectIdentifier, tenantID, typ, value))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return store.Identifier{}, store.ErrNotFound
	case err != nil:
		return store.Identifier{}, fmt.Errorf("sqlstore: find identifier: %w", err)
	}
	return i, nil
}

func (r identifiers) ListByUser(ctx context.Context, tenantID, userID string) ([]store.Identifier, error) {
	if !storecheck.ValidText(tenantID, userID) {
		return nil, nil
	}
	rows, err := r.x.QueryContext(ctx, r.s.q.listIdentifiers, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: list identifiers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var list []store.Identifier
	for rows.Next() {
		i, scanErr := scanIdentifier(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("sqlstore: list identifiers: %w", scanErr)
		}
		list = append(list, i)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore: list identifiers: %w", err)
	}
	slices.SortFunc(list, storecheck.CompareIdentifiers)
	return list, nil
}

func (r identifiers) Remove(ctx context.Context, tenantID, typ, value string) error {
	if !storecheck.ValidText(tenantID, typ, value) {
		return store.ErrNotFound
	}
	result, err := r.x.ExecContext(ctx, r.s.q.deleteIdentifier, tenantID, typ, value)
	if err != nil {
		return fmt.Errorf("sqlstore: remove identifier: %w", err)
	}
	return requireRow(result, "remove identifier")
}

func (r identifiers) MarkVerified(ctx context.Context, tenantID, typ, value string, at time.Time) error {
	if !storecheck.ValidText(tenantID, typ, value) {
		return store.ErrNotFound
	}
	result, err := r.x.ExecContext(ctx, r.s.q.markVerified, optionalTime(at), tenantID, typ, value)
	if err != nil {
		return fmt.Errorf("sqlstore: mark identifier verified: %w", err)
	}
	return requireRow(result, "mark identifier verified")
}

func scanIdentifier(row scanner) (store.Identifier, error) {
	var (
		i          store.Identifier
		verifiedAt sql.NullTime
	)
	if err := row.Scan(&i.TenantID, &i.Type, &i.Value, &i.DisplayValue, &i.UserID, &verifiedAt); err != nil {
		return store.Identifier{}, err
	}
	i.VerifiedAt = utcOrZero(verifiedAt)
	return i, nil
}
