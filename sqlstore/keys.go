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

type signingKeys struct {
	s *Store
	x executor
}

func (r signingKeys) Add(ctx context.Context, k store.SigningKey) error {
	if err := storecheck.NewSigningKey(k); err != nil {
		return err
	}
	_, err := r.x.ExecContext(ctx, r.s.q.insertKey,
		k.KID, k.Algorithm, k.Generation, k.PrivateKey, k.PublicKey, storedTime(k.CreatedAt))
	switch {
	case err == nil:
		return nil
	case r.s.dialect.IsUniqueViolation(err):
		return store.ErrConflict
	}
	return fmt.Errorf("sqlstore: add signing key: %w", err)
}

func (r signingKeys) List(ctx context.Context) ([]store.SigningKey, error) {
	rows, err := r.x.QueryContext(ctx, r.s.q.listKeys)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: list signing keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var list []store.SigningKey
	for rows.Next() {
		var (
			k       store.SigningKey
			created time.Time
			retire  sql.NullTime
		)
		if err = rows.Scan(&k.KID, &k.Algorithm, &k.Generation, &k.PrivateKey, &k.PublicKey, &created, &retire); err != nil {
			return nil, fmt.Errorf("sqlstore: list signing keys: %w", err)
		}
		k.CreatedAt = created.UTC()
		k.RetireAfter = utcOrZero(retire)
		list = append(list, k)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore: list signing keys: %w", err)
	}
	return list, nil
}

func (r signingKeys) Retire(ctx context.Context, kid string, retireAfter time.Time) error {
	if err := storecheck.Time("retirement time", retireAfter); err != nil {
		return err
	}
	if !storecheck.ValidText(kid) {
		return store.ErrNotFound
	}
	result, err := r.x.ExecContext(ctx, r.s.q.retireKey, storedTime(retireAfter), kid)
	if err != nil {
		return fmt.Errorf("sqlstore: retire signing key: %w", err)
	}
	changed, err := affected(result, "retire signing key")
	if err != nil || changed > 0 {
		return err
	}
	var one int
	switch err = r.x.QueryRowContext(ctx, r.s.q.keyExists, kid).Scan(&one); {
	case errors.Is(err, sql.ErrNoRows):
		return store.ErrNotFound
	case err != nil:
		return fmt.Errorf("sqlstore: retire signing key: %w", err)
	}
	return nil
}

func (r signingKeys) DeleteRetired(ctx context.Context, before time.Time) (int, error) {
	result, err := r.x.ExecContext(ctx, r.s.q.deleteKeys, storedTime(before))
	if err != nil {
		return 0, fmt.Errorf("sqlstore: delete signing keys: %w", err)
	}
	return affected(result, "delete signing keys")
}
