package limb

import (
	"context"
	"errors"
	"fmt"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/store"
)

func (a *Auth) checkPassword(ctx context.Context, login, password string) (store.User, store.Identifier, error) {
	kind, value, err := identifier.Resolve(a.types, login)
	if err != nil {
		return a.reject(ctx, password)
	}
	found, err := a.store.Identifiers().Find(ctx, a.tenant, kind.Name(), value)
	if errors.Is(err, store.ErrNotFound) {
		return a.reject(ctx, password)
	}
	if err != nil {
		return store.User{}, store.Identifier{}, fmt.Errorf("limb: find the identifier: %w", err)
	}
	user, err := a.store.Users().Get(ctx, a.tenant, found.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return a.reject(ctx, password)
	}
	if err != nil {
		return store.User{}, store.Identifier{}, fmt.Errorf("limb: get the user: %w", err)
	}
	if user.PasswordHash == "" {
		return a.reject(ctx, password)
	}
	matched, needsRehash, err := a.hasher.Verify(ctx, password, user.PasswordHash)
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return store.User{}, store.Identifier{}, fmt.Errorf("limb: verify the password: %w", err)
	case err != nil:
		a.logger.ErrorContext(ctx, "limb: the stored password hash cannot be used", "user_id", user.ID, "error", err)
		return a.reject(ctx, password)
	case !matched:
		return store.User{}, store.Identifier{}, ErrInvalidCredentials
	}
	if err = a.usable(user); err != nil {
		return store.User{}, store.Identifier{}, err
	}
	if needsRehash {
		user = a.rehash(ctx, user, password)
	}
	return user, found, nil
}

func (a *Auth) reject(ctx context.Context, password string) (store.User, store.Identifier, error) {
	if err := a.hasher.DummyVerify(ctx, password); err != nil {
		return store.User{}, store.Identifier{}, fmt.Errorf("limb: verify the password: %w", err)
	}
	return store.User{}, store.Identifier{}, ErrInvalidCredentials
}

func (a *Auth) usable(user store.User) error {
	switch user.Status {
	case store.StatusActive:
		return nil
	case store.StatusBlocked:
		if user.BlockedUntil.IsZero() || a.now().Before(user.BlockedUntil) {
			return ErrUserBlocked
		}
		return nil
	case store.StatusDeleted:
		return ErrInvalidCredentials
	}
	return ErrInvalidCredentials
}

func (a *Auth) rehash(ctx context.Context, user store.User, password string) store.User {
	hash, err := a.hasher.Hash(ctx, password)
	if err != nil {
		a.logger.WarnContext(ctx, "limb: the password hash cannot be upgraded", "user_id", user.ID, "error", err)
		return user
	}
	upgraded := user
	upgraded.PasswordHash = hash
	saved, err := a.store.Users().Update(ctx, upgraded)
	switch {
	case err == nil:
		return saved
	case errors.Is(err, store.ErrStale), errors.Is(err, store.ErrNotFound):
		a.logger.DebugContext(ctx, "limb: the password hash was not upgraded because the user changed meanwhile", "user_id", user.ID)
	default:
		a.logger.WarnContext(ctx, "limb: the password hash cannot be upgraded", "user_id", user.ID, "error", err)
	}
	return user
}
