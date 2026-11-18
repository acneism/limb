package limb

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	sessionRetention = 7 * 24 * time.Hour
	tokenRetention   = 24 * time.Hour
	attemptRetention = time.Hour
	secretRetention  = 24 * time.Hour
)

// Cleanup removes what is no longer of any use: sessions that expired, went idle
// or were ended more than a week ago, refresh tokens that expired more than a day
// ago together with those of the removed sessions, counters of failed attempts
// whose window and pauses are over, links and codes that expired or were used
// more than a day ago, signing keys that are retired and the sessions of
// administrators that ended more than a day ago. Recent sessions are kept for a
// while so that a refresh token that is replayed after its session ended can still
// be recognized.
//
// It also removes the records of the audit log that are older than their
// retention, see WithAuditRetention, up to 50 000 at a time, oldest first; the
// deleted users whose retention has ended, see WithDeletedUserRetention, and the
// accounts of Signup that nobody confirmed, see WithUnconfirmedAccountLifetime,
// each with everything that belongs to it, which is written to the audit log and
// reported as EventUserPurged, up to 2 000 of each at a time; and it lifts the
// blocks that ran out. Whatever is left is taken at the next call.
//
// It is safe to call from several instances at once and as often as wanted, for
// example from a timer once an hour, or let RunMaintenance do it. A failure of one
// kind of data does not stop the others; the errors are returned together.
func (a *Auth) Cleanup(ctx context.Context) error {
	now := a.now().UTC().Truncate(time.Microsecond)
	sessions, sessionsErr := a.store.Sessions().DeleteInactive(ctx, a.tenant,
		now.Add(-sessionRetention), now.Add(-a.idle-sessionRetention), now.Add(-sessionRetention))
	tokens, tokensErr := a.store.RefreshTokens().DeleteExpired(ctx, a.tenant, now.Add(-tokenRetention))
	attempts, attemptsErr := a.store.Attempts().DeleteStale(ctx, now.Add(-a.longestWindow()-attemptRetention))
	secrets, secretsErr := a.store.Secrets().DeleteStale(ctx, a.tenant, now.Add(-secretRetention))
	keys, keysErr := a.store.SigningKeys().DeleteRetired(ctx, now)
	adminSessions, adminErr := a.step(ctx, "the removal of the sessions of administrators", func(ctx context.Context) (int, error) {
		return a.store.AdminSessions().DeleteStale(ctx, a.tenant, now.Add(-adminSessionRetention), now.Add(-a.adminIdle-adminSessionRetention))
	})
	records, recordsErr := a.step(ctx, "the removal of the audit log", func(ctx context.Context) (int, error) { return a.deleteOldAudit(ctx, now) })
	lifted, liftedErr := a.step(ctx, "the lifting of the blocks", func(ctx context.Context) (int, error) { return a.liftEndedBlocks(ctx, now) })
	purged, purgedErr := a.step(ctx, "the removal of the deleted users", func(ctx context.Context) (int, error) { return a.purgeDeletedUsers(ctx, now) })
	unconfirmed, unconfirmedErr := a.step(ctx, "the removal of the unconfirmed accounts", func(ctx context.Context) (int, error) {
		return a.removeUnconfirmed(ctx, now)
	})
	if sessions+tokens+attempts+secrets+keys+adminSessions+records+lifted+purged+unconfirmed > 0 {
		a.logger.InfoContext(ctx, "limb: old data was removed",
			"sessions", sessions, "refresh_tokens", tokens, "attempt_counters", attempts, "secrets", secrets, "signing_keys", keys,
			"admin_sessions", adminSessions, "audit_records", records, "lifted_blocks", lifted, "deleted_users", purged, "unconfirmed_users", unconfirmed)
	}
	return errors.Join(
		removalFailure("sessions", sessionsErr),
		removalFailure("refresh tokens", tokensErr),
		removalFailure("counters of failed attempts", attemptsErr),
		removalFailure("secrets", secretsErr),
		removalFailure("signing keys", keysErr),
		removalFailure("sessions of administrators", adminErr),
		removalFailure("records of the audit log", recordsErr),
		removalFailure("blocks that ended", liftedErr),
		removalFailure("deleted users", purgedErr),
		removalFailure("unconfirmed accounts", unconfirmedErr),
	)
}

func removalFailure(what string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("limb: remove old %s: %w", what, err)
}

func (a *Auth) longestWindow() time.Duration {
	return max(a.limits.accountIP.Window, a.limits.ip.Window, a.limits.account.Window)
}
