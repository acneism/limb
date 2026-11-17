package limb

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

const (
	adminSessionIdle      = 30 * time.Minute
	adminSessionRetention = 24 * time.Hour

	defaultAuditRetention  = 365 * 24 * time.Hour
	shortestAuditRetention = 24 * time.Hour
	longestAuditRetention  = 100 * 365 * 24 * time.Hour

	defaultUnconfirmedLifetime = 7 * 24 * time.Hour
	shortestUnconfirmed        = time.Hour
	longestUnconfirmed         = 365 * 24 * time.Hour

	maintenancePage    = 100
	maintenancePages   = 20
	auditBatchesPerRun = 100
	stepTimeout        = 5 * time.Minute
	maintenanceJitter  = 0.1
)

// ErrMaintenanceRunning is returned by RunMaintenance when it runs in this process
// already.
var ErrMaintenanceRunning = errors.New("limb: the maintenance runs in this process already")

var errSkipped = errors.New("limb: skipped")

// WithAuditRetention sets how long the records of the audit log are kept, a year
// by default. It must be between a day and a hundred years. Cleanup removes the
// older ones, oldest first.
func WithAuditRetention(d time.Duration) Option {
	return func(c *config) {
		if d < shortestAuditRetention || d > longestAuditRetention {
			c.fail(errors.New("limb: the retention of the audit log must be between a day and a hundred years"))
			return
		}
		c.auditKept = d
	}
}

// WithUnconfirmedAccountLifetime sets how long an account that a visitor made
// with Signup is kept when nobody confirms an address or a phone number of it and
// nobody signs in to it, seven days by default, so that a visitor cannot hold an
// address that is not theirs for good. Cleanup removes the account then, and the
// address is free again. Zero turns the removal off, and otherwise the time must
// be between an hour and a year. It applies only with WithSignup, and only to the
// accounts that Signup made: an account that an administrator made is never
// removed this way.
func WithUnconfirmedAccountLifetime(d time.Duration) Option {
	return func(c *config) {
		if d != 0 && (d < shortestUnconfirmed || d > longestUnconfirmed) {
			c.fail(errors.New("limb: the lifetime of an unconfirmed account must be zero, to keep it, or between an hour and a year"))
			return
		}
		c.unconfirmed, c.hasUnconf = d, true
	}
}

func unconfirmedLifetime(cfg config) time.Duration {
	if cfg.hasUnconf {
		return cfg.unconfirmed
	}
	return defaultUnconfirmedLifetime
}

func (a *Auth) step(ctx context.Context, name string, run func(ctx context.Context) (int, error)) (n int, err error) {
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	defer func() {
		if p := recover(); p != nil {
			a.logger.ErrorContext(ctx, "limb: a step of the maintenance panicked", "step", name, "panic_type", fmt.Sprintf("%T", p))
			n, err = 0, fmt.Errorf("limb: %s panicked", name)
		}
	}()
	return run(ctx)
}

func (a *Auth) deleteOldAudit(ctx context.Context, now time.Time) (int, error) {
	before := now.Add(-a.auditKept)
	total := 0
	for range auditBatchesPerRun {
		n, err := a.store.Audit().DeleteBefore(ctx, a.tenant, before, store.MaxAuditPage)
		total += n
		if err != nil || n < store.MaxAuditPage {
			return total, err
		}
	}
	return total, nil
}

func (a *Auth) forEachUser(ctx context.Context, q store.UserQuery, visit func(u store.User) (bool, error)) (int, error) {
	q.TenantID, q.Order, q.Limit = a.tenant, store.OrderUsersByCreation, maintenancePage
	visited := 0
	var failures []error
	for range maintenancePages {
		users, err := a.store.Users().List(ctx, q)
		if err != nil {
			return visited, errors.Join(append(failures, fmt.Errorf("limb: list the users: %w", err))...)
		}
		for _, u := range users {
			done, visitErr := visit(u)
			if visitErr != nil {
				failures = append(failures, visitErr)
				continue
			}
			if done {
				visited++
			}
		}
		if len(users) < maintenancePage {
			break
		}
		last := users[len(users)-1]
		q.After = &last
	}
	return visited, errors.Join(failures...)
}

func (a *Auth) purgeDeletedUsers(ctx context.Context, now time.Time) (int, error) {
	q := store.UserQuery{Statuses: []store.Status{store.StatusDeleted}, PurgeBefore: now.Add(time.Microsecond)}
	return a.forEachUser(ctx, q, func(u store.User) (bool, error) {
		return a.removeUser(ctx, u.ID, "retention", func(current store.User, _ []store.Identifier) bool {
			return current.Status == store.StatusDeleted && !current.PurgeAfter.After(now)
		})
	})
}

func (a *Auth) removeUnconfirmed(ctx context.Context, now time.Time) (int, error) {
	if !a.signup || a.unconfirmed <= 0 {
		return 0, nil
	}
	cutoff := now.Add(-a.unconfirmed)
	unconfirmed := false
	q := store.UserQuery{
		Statuses: []store.Status{store.StatusActive}, CreatedVia: store.CreatedViaSignup, Confirmed: &unconfirmed,
		NeverLoggedIn: true, CreatedBefore: cutoff.Add(time.Microsecond),
	}
	return a.forEachUser(ctx, q, func(u store.User) (bool, error) {
		return a.removeUser(ctx, u.ID, "unconfirmed", func(current store.User, identifiers []store.Identifier) bool {
			confirmed := false
			for _, i := range identifiers {
				confirmed = confirmed || !i.VerifiedAt.IsZero()
			}
			return current.Status == store.StatusActive && current.CreatedVia == store.CreatedViaSignup && current.LastLoginAt.IsZero() &&
				!current.CreatedAt.After(cutoff) && !confirmed
		})
	})
}

func (a *Auth) removeUser(ctx context.Context, id, reason string, due func(u store.User, identifiers []store.Identifier) bool) (bool, error) {
	err := a.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		u, err := tx.Users().Get(ctx, a.tenant, id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return errSkipped
		case err != nil:
			return fmt.Errorf("limb: get the user: %w", err)
		}
		identifiers, err := tx.Identifiers().ListByUser(ctx, a.tenant, id)
		if err != nil {
			return fmt.Errorf("limb: list the identifiers: %w", err)
		}
		if !due(u, identifiers) {
			return errSkipped
		}
		if _, err = tx.Users().Update(ctx, u); err != nil {
			if errors.Is(err, store.ErrStale) || errors.Is(err, store.ErrNotFound) {
				return errSkipped
			}
			return fmt.Errorf("limb: update the user: %w", err)
		}
		err = a.auditWriter().Add(ctx, tx.Audit(), audit.Entry{
			Actor: audit.Maintenance, Action: audit.UserPurged, TargetUserID: id,
			Details: map[string]any{"reason": reason, "identifiers": identifierValues(identifiers)},
		})
		if err != nil {
			return err
		}
		if err = tx.Users().Delete(ctx, a.tenant, id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return errSkipped
			}
			return fmt.Errorf("limb: delete the user: %w", err)
		}
		return nil
	})
	switch {
	case errors.Is(err, errSkipped):
		return false, nil
	case err != nil:
		return false, err
	}
	a.emitHook(ctx, Event{Type: EventUserPurged, UserID: id, Details: map[string]string{"reason": reason}})
	return true, nil
}

func (a *Auth) liftEndedBlocks(ctx context.Context, now time.Time) (int, error) {
	q := store.UserQuery{Statuses: []store.Status{store.StatusBlocked}, BlockedBefore: now.Add(time.Microsecond)}
	maintenance := actorRef{actor: audit.Maintenance}
	return a.forEachUser(ctx, q, func(u store.User) (bool, error) {
		lifted := false
		err := a.editUser(ctx, maintenance, UserID(u.ID), func(_ context.Context, _ store.Repositories, current store.User, _ time.Time) (userEdit, error) {
			lifted = false
			if current.Status != store.StatusBlocked || current.BlockedUntil.IsZero() || current.BlockedUntil.After(now) {
				return userEdit{}, nil
			}
			lifted = true
			next := current
			next.Status, next.BlockedReason, next.BlockedUntil = store.StatusActive, "", time.Time{}
			details := map[string]any{
				"reason": "ended", "previous_reason": current.BlockedReason, "previous_until": current.BlockedUntil.UTC().Format(time.RFC3339),
			}
			return userEdit{
				next: next, update: true, entry: &audit.Entry{Action: audit.UserUnblocked, Details: details},
				events: []Event{{Type: EventUserUnblocked, Details: map[string]string{"reason": "ended"}}},
			}, nil
		})
		if errors.Is(err, ErrUserNotFound) || errors.Is(err, ErrUserDeleted) {
			return false, nil
		}
		return lifted, err
	})
}

func jittered(d time.Duration) time.Duration {
	spread := (rand.Float64()*2 - 1) * maintenanceJitter //nolint:gosec
	return d + time.Duration(spread*float64(d))
}

func (a *Auth) maintain(ctx context.Context) {
	if err := a.Cleanup(ctx); err != nil {
		a.logger.ErrorContext(ctx, "limb: the cleanup did not finish", "error", err)
	}
	if _, err := a.step(ctx, "the rotation of the signing keys", func(ctx context.Context) (int, error) {
		return 0, a.ring.maintain(ctx)
	}); err != nil {
		a.logger.ErrorContext(ctx, "limb: the signing keys cannot be rotated", "error", err)
	}
}

// RunMaintenance does what a service needs done from time to time: it calls
// Cleanup and changes the signing key when it is due, at once and then every
// interval, with a spread of ten percent so that the instances of a service do
// not all go to the database in the same second. It blocks until ctx ends and
// returns nil then, so run it in a goroutine of its own and cancel its context
// when the service stops.
//
// Every step has a limit of time, and an error or a panic of a step is logged and
// does not stop the loop. The steps are safe to run in several instances at once,
// see Cleanup, so no instance is made the one that does the work. One loop runs
// in a process: a second call returns ErrMaintenanceRunning. The interval has to
// be positive, and from a minute to an hour is a good one.
//
// A service that calls Cleanup from a scheduler of its own does not need it, but
// then nobody changes the signing key unless access tokens are issued.
func (a *Auth) RunMaintenance(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return errors.New("limb: the interval of the maintenance must be positive")
	}
	if !a.maintaining.CompareAndSwap(false, true) {
		return ErrMaintenanceRunning
	}
	defer a.maintaining.Store(false)
	for ctx.Err() == nil {
		a.maintain(ctx)
		timer := time.NewTimer(jittered(interval))
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return nil
}
