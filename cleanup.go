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
// more than a day ago and signing keys that are retired. Recent sessions are
// kept for a while so that a refresh token that is replayed after its session
// ended can still be recognized. It is safe to call from several
// instances at once and as often as wanted, for example from a timer once an
// hour. A failure of one kind of data does not stop the others; the errors are
// returned together.
func (a *Auth) Cleanup(ctx context.Context) error {
	now := a.now().UTC().Truncate(time.Microsecond)
	sessions, sessionsErr := a.store.Sessions().DeleteInactive(ctx, a.tenant,
		now.Add(-sessionRetention), now.Add(-a.idle-sessionRetention), now.Add(-sessionRetention))
	tokens, tokensErr := a.store.RefreshTokens().DeleteExpired(ctx, a.tenant, now.Add(-tokenRetention))
	attempts, attemptsErr := a.store.Attempts().DeleteStale(ctx, now.Add(-a.longestWindow()-attemptRetention))
	secrets, secretsErr := a.store.Secrets().DeleteStale(ctx, a.tenant, now.Add(-secretRetention))
	keys, keysErr := a.store.SigningKeys().DeleteRetired(ctx, now)
	if sessions+tokens+attempts+secrets+keys > 0 {
		a.logger.InfoContext(ctx, "limb: old data was removed",
			"sessions", sessions, "refresh_tokens", tokens, "attempt_counters", attempts, "secrets", secrets, "signing_keys", keys)
	}
	return errors.Join(
		removalFailure("sessions", sessionsErr),
		removalFailure("refresh tokens", tokensErr),
		removalFailure("counters of failed attempts", attemptsErr),
		removalFailure("secrets", secretsErr),
		removalFailure("signing keys", keysErr),
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
