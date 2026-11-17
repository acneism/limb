package limb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

const (
	defaultDeletedRetention = 30 * 24 * time.Hour
	shortestRetention       = time.Hour
	longestRetention        = 10 * 365 * 24 * time.Hour
)

var secretPurposes = []store.SecretPurpose{store.PurposeVerify, store.PurposeReset, store.PurposeInvite}

// WithImmediateDeletion makes AdminAPI.DeleteUser erase the user at once, with
// their values, sessions, tokens and secrets, instead of keeping the account
// until its retention ends so that it can be restored. What the audit log says
// about the user stays, because a record of it holds no table of its own to be
// removed from.
func WithImmediateDeletion() Option {
	return func(c *config) {
		c.immediate = true
	}
}

// WithDeletedUserRetention sets how long a deleted user is kept before the
// record is removed for good, 30 days by default. Until then the user cannot sign
// in, their values stay taken, and an administrator can restore them. It must be
// between an hour and ten years. It has no effect with WithImmediateDeletion.
func WithDeletedUserRetention(d time.Duration) Option {
	return func(c *config) {
		if d < shortestRetention || d > longestRetention {
			c.fail(errors.New("limb: the retention of deleted users must be between an hour and ten years"))
			return
		}
		c.retention = d
	}
}

func (a *Auth) beforeDelete(ctx context.Context, user User) (err error) {
	if a.hooks.BeforeDelete == nil {
		return nil
	}
	defer func() {
		if p := recover(); p != nil {
			a.logger.ErrorContext(ctx, "limb: the hook before a deletion panicked", "panic_type", fmt.Sprintf("%T", p))
			err = ErrDeletionRefused
		}
	}()
	if refusal := a.hooks.BeforeDelete(ctx, user); refusal != nil {
		a.logger.WarnContext(ctx, "limb: the hook before a deletion refused it", "user_id", user.ID, "error", refusal)
		return fmt.Errorf("%w: %w", ErrDeletionRefused, refusal)
	}
	return nil
}

func (a *Auth) deleteUser(ctx context.Context, by actorRef, id UserID) error {
	card, err := a.managedUserByID(ctx, id)
	if err != nil {
		return err
	}
	if card.Status == store.StatusDeleted && !a.immediate {
		return ErrUserDeleted
	}
	if err = a.beforeDelete(ctx, card.User); err != nil {
		return err
	}
	if a.immediate {
		return a.eraseUser(ctx, by, id)
	}
	return a.softDelete(ctx, by, id)
}

func (a *Auth) softDelete(ctx context.Context, by actorRef, id UserID) error {
	return a.editUser(ctx, by, id, func(ctx context.Context, tx store.Repositories, u store.User, now time.Time) (userEdit, error) {
		identifiers, err := tx.Identifiers().ListByUser(ctx, a.tenant, u.ID)
		if err != nil {
			return userEdit{}, fmt.Errorf("limb: list the identifiers: %w", err)
		}
		for _, purpose := range secretPurposes {
			if _, err = tx.Secrets().End(ctx, store.SecretScope{TenantID: a.tenant, UserID: u.ID, Purpose: purpose}, now); err != nil {
				return userEdit{}, fmt.Errorf("limb: end the secrets: %w", err)
			}
		}
		next := u
		next.Status, next.DeletedAt, next.PurgeAfter = store.StatusDeleted, now, now.Add(a.retention)
		purgeAfter := next.PurgeAfter.UTC().Format(time.RFC3339)
		return userEdit{
			next: next, update: true, revoke: true,
			entry: &audit.Entry{Action: audit.UserDeleted, Details: map[string]any{
				"mode": "soft", "purge_after": purgeAfter, "identifiers": identifierValues(identifiers),
			}},
			events: []Event{{Type: EventUserDeleted, Details: map[string]string{"mode": "soft", "purge_after": purgeAfter}}},
		}, nil
	})
}

func (a *Auth) eraseUser(ctx context.Context, by actorRef, id UserID) error {
	err := a.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if _, getErr := tx.Users().Get(ctx, a.tenant, string(id)); getErr != nil {
			if errors.Is(getErr, store.ErrNotFound) {
				return ErrUserNotFound
			}
			return fmt.Errorf("limb: get the user: %w", getErr)
		}
		identifiers, listErr := tx.Identifiers().ListByUser(ctx, a.tenant, string(id))
		if listErr != nil {
			return fmt.Errorf("limb: list the identifiers: %w", listErr)
		}
		err := a.auditWriter().Add(ctx, tx.Audit(), audit.Entry{
			Actor: by.actor, Action: audit.UserDeleted, TargetUserID: string(id), IP: by.ip,
			Details: map[string]any{"mode": "immediate", "identifiers": identifierValues(identifiers)},
		})
		if err != nil {
			return err
		}
		if deleteErr := tx.Users().Delete(ctx, a.tenant, string(id)); deleteErr != nil {
			if errors.Is(deleteErr, store.ErrNotFound) {
				return ErrUserNotFound
			}
			return fmt.Errorf("limb: delete the user: %w", deleteErr)
		}
		return nil
	})
	if err == nil {
		a.emitHook(ctx, Event{Type: EventUserDeleted, UserID: string(id), IP: by.ip, Details: map[string]string{"mode": "immediate"}})
	}
	return err
}

func (a *Auth) restoreUser(ctx context.Context, by actorRef, id UserID) error {
	return a.editDeletedUser(ctx, by, id, func(_ context.Context, _ store.Repositories, u store.User, now time.Time) (userEdit, error) {
		switch {
		case u.Status != store.StatusDeleted:
			return userEdit{}, &ValidationError{Field: "user", Reason: "is not deleted"}
		case !u.PurgeAfter.After(now):
			return userEdit{}, ErrRetentionOver
		}
		next := u
		next.Status, next.DeletedAt, next.PurgeAfter = store.StatusActive, time.Time{}, time.Time{}
		if u.BlockedReason != "" && (u.BlockedUntil.IsZero() || u.BlockedUntil.After(now)) {
			next.Status = store.StatusBlocked
		}
		return userEdit{
			next: next, update: true,
			entry:  &audit.Entry{Action: audit.UserRestored, Details: map[string]any{"status": string(next.Status)}},
			events: []Event{{Type: EventUserRestored}},
		}, nil
	})
}

// DeleteUser deletes the user. With WithImmediateDeletion the user is erased at
// once with what belongs to them. Without it, which is the default, the account
// stays until its retention ends, see WithDeletedUserRetention: the user cannot
// sign in, their sessions and secrets are ended, their values stay taken and an
// administrator can restore them with RestoreUser. The hook BeforeDelete is
// called first and can refuse. The ID of the user and what the audit log holds of
// them stay.
//
// It returns ErrUserNotFound, ErrUserDeleted for a user who is deleted already,
// unless the deletion is immediate, and ErrDeletionRefused.
func (x *AdminAPI) DeleteUser(ctx context.Context, id UserID) error {
	return x.a.deleteUser(ctx, apiActor, id)
}

// RestoreUser makes a deleted user an active one again, or a blocked one when
// they were blocked at the deletion and the block still holds. The sessions that
// ended are not restored. It returns ErrUserNotFound, a *ValidationError for a
// user who is not deleted and ErrRetentionOver when the time of retention has
// passed.
func (x *AdminAPI) RestoreUser(ctx context.Context, id UserID) error {
	return x.a.restoreUser(ctx, apiActor, id)
}
