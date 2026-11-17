package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

// Create makes an administrator with the login and the password. The account
// has no authenticator: the administrator binds one at the first sign-in. It
// returns a *LoginError for a login that breaks the rules, a *PolicyError for a
// password that breaks the policy and ErrLoginTaken if the login is taken.
func (s *Service) Create(ctx context.Context, actor audit.Actor, login, password string) (Account, error) {
	normalized, err := NormalizeLogin(login)
	if err != nil {
		return Account{}, err
	}
	if err = s.checkPassword(ctx, password, normalized); err != nil {
		return Account{}, err
	}
	hash, err := s.hasher.Hash(ctx, password)
	if err != nil {
		return Account{}, fmt.Errorf("admin: hash the password: %w", err)
	}
	id, err := s.newID()
	if err != nil {
		return Account{}, fmt.Errorf("admin: make the ID of an administrator: %w", err)
	}
	a := store.Admin{TenantID: s.tenant, ID: id, Login: normalized, PasswordHash: hash, Status: store.AdminActive, CreatedAt: s.now()}
	err = s.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if createErr := tx.Admins().Create(ctx, a); createErr != nil {
			if errors.Is(createErr, store.ErrConflict) {
				return ErrLoginTaken
			}
			return fmt.Errorf("admin: create the administrator: %w", createErr)
		}
		return s.audit.Add(ctx, tx.Audit(), audit.Entry{
			Actor: actor, Action: audit.AdminCreated, Details: map[string]any{"admin_id": id, "login": normalized},
		})
	})
	if err != nil {
		return Account{}, err
	}
	return accountOf(a, 0), nil
}

func (s *Service) checkPassword(ctx context.Context, password, login string) error {
	if rules := s.policy(ctx, password, []string{login}); len(rules) > 0 {
		return &PolicyError{Rules: rules}
	}
	return nil
}

// Delete removes the administrator with the sessions and the recovery codes. It
// returns ErrNotFound if there is no such administrator.
func (s *Service) Delete(ctx context.Context, actor audit.Actor, login string) error {
	normalized, err := NormalizeLogin(login)
	if err != nil {
		return ErrNotFound
	}
	return s.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		a, findErr := tx.Admins().FindByLogin(ctx, s.tenant, normalized)
		switch {
		case errors.Is(findErr, store.ErrNotFound):
			return ErrNotFound
		case findErr != nil:
			return fmt.Errorf("admin: find the administrator: %w", findErr)
		}
		if deleteErr := tx.Admins().Delete(ctx, s.tenant, a.ID); deleteErr != nil {
			if errors.Is(deleteErr, store.ErrNotFound) {
				return ErrNotFound
			}
			return fmt.Errorf("admin: delete the administrator: %w", deleteErr)
		}
		return s.audit.Add(ctx, tx.Audit(), audit.Entry{
			Actor: actor, Action: audit.AdminDeleted, Details: map[string]any{"admin_id": a.ID, "login": a.Login},
		})
	})
}

// List returns the administrators ordered by login.
func (s *Service) List(ctx context.Context) ([]Account, error) {
	admins, err := s.store.Admins().List(ctx, s.tenant)
	if err != nil {
		return nil, fmt.Errorf("admin: list the administrators: %w", err)
	}
	accounts := make([]Account, 0, len(admins))
	for _, a := range admins {
		left, countErr := s.store.Admins().CountRecoveryCodes(ctx, s.tenant, a.ID)
		if countErr != nil {
			return nil, fmt.Errorf("admin: count the recovery codes: %w", countErr)
		}
		accounts = append(accounts, accountOf(a, left))
	}
	return accounts, nil
}

// Disable stops the administrator from signing in and ends their sessions. It
// does nothing if the account is disabled already.
func (s *Service) Disable(ctx context.Context, actor audit.Actor, login string) error {
	return s.mutate(ctx, login, func(_ context.Context, _ store.Repositories, a store.Admin) (store.Admin, *audit.Entry, error) {
		if a.Status == store.AdminDisabled {
			return a, nil, nil
		}
		a.Status = store.AdminDisabled
		return a, &audit.Entry{Actor: actor, Action: audit.AdminDisabled, Details: details(a)}, nil
	})
}

// Enable lets the administrator sign in again. It does nothing if the account is
// enabled already.
func (s *Service) Enable(ctx context.Context, actor audit.Actor, login string) error {
	return s.mutate(ctx, login, func(_ context.Context, _ store.Repositories, a store.Admin) (store.Admin, *audit.Entry, error) {
		if a.Status == store.AdminActive {
			return a, nil, nil
		}
		a.Status = store.AdminActive
		return a, &audit.Entry{Actor: actor, Action: audit.AdminEnabled, Details: details(a)}, nil
	})
}

// ResetPassword gives the administrator a new password and ends their sessions,
// the one of the current sign-in included. It returns a *PolicyError for a
// password that breaks the policy and ErrNotFound if there is no such
// administrator.
func (s *Service) ResetPassword(ctx context.Context, actor audit.Actor, login, password string) error {
	normalized, err := NormalizeLogin(login)
	if err != nil {
		return ErrNotFound
	}
	if err = s.checkPassword(ctx, password, normalized); err != nil {
		return err
	}
	hash, err := s.hasher.Hash(ctx, password)
	if err != nil {
		return fmt.Errorf("admin: hash the password: %w", err)
	}
	return s.mutate(ctx, login, func(_ context.Context, _ store.Repositories, a store.Admin) (store.Admin, *audit.Entry, error) {
		a.PasswordHash = hash
		return a, &audit.Entry{Actor: actor, Action: audit.AdminPasswordReset, Details: details(a)}, nil
	})
}

// ResetTOTP removes the authenticator of the administrator and their recovery
// codes and ends their sessions, so that they bind a new authenticator at the
// next sign-in. It returns ErrNotFound if there is no such administrator.
func (s *Service) ResetTOTP(ctx context.Context, actor audit.Actor, login string) error {
	return s.mutate(ctx, login, func(ctx context.Context, tx store.Repositories, a store.Admin) (store.Admin, *audit.Entry, error) {
		if err := tx.Admins().ReplaceRecoveryCodes(ctx, s.tenant, a.ID, nil); err != nil {
			return a, nil, fmt.Errorf("admin: remove the recovery codes: %w", err)
		}
		a.TOTPSecret = nil
		a.TOTPConfirmedAt = time.Time{}
		return a, &audit.Entry{Actor: actor, Action: audit.AdminTOTPReset, Details: details(a)}, nil
	})
}

func details(a store.Admin) map[string]any {
	return map[string]any{"admin_id": a.ID, "login": a.Login}
}

func (s *Service) mutate(
	ctx context.Context, login string,
	change func(ctx context.Context, tx store.Repositories, a store.Admin) (store.Admin, *audit.Entry, error),
) error {
	normalized, err := NormalizeLogin(login)
	if err != nil {
		return ErrNotFound
	}
	for range maxChangeAttempts {
		err = s.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
			a, findErr := tx.Admins().FindByLogin(ctx, s.tenant, normalized)
			switch {
			case errors.Is(findErr, store.ErrNotFound):
				return ErrNotFound
			case findErr != nil:
				return fmt.Errorf("admin: find the administrator: %w", findErr)
			}
			next, entry, changeErr := change(ctx, tx, a)
			if changeErr != nil || entry == nil {
				return changeErr
			}
			if _, updateErr := tx.Admins().Update(ctx, next); updateErr != nil {
				if errors.Is(updateErr, store.ErrStale) {
					return updateErr
				}
				return fmt.Errorf("admin: update the administrator: %w", updateErr)
			}
			if _, endErr := tx.AdminSessions().DeleteForAdmin(ctx, s.tenant, a.ID, ""); endErr != nil {
				return fmt.Errorf("admin: end the sessions of the administrator: %w", endErr)
			}
			return s.audit.Add(ctx, tx.Audit(), *entry)
		})
		if !errors.Is(err, store.ErrStale) {
			return err
		}
	}
	return ErrConcurrent
}
