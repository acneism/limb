package limb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/store"
)

const reuseWindow = 10 * time.Second

var errRefreshRejected = errors.New("limb: the refresh token is not accepted")

type refreshOutcome int

const (
	refreshRefused refreshOutcome = iota
	refreshDone
	refreshRaced
	refreshReplayed
	refreshReused
)

// Refresh exchanges a refresh token for a new pair of tokens of the same
// session. A refresh token works once: the exchange marks it as used and makes
// a new one, which expires after the idle lifetime or when the session ends,
// whichever comes first, and the use, the new token and the mark that the
// session was used are one transaction, so a failure leaves the old token
// usable.
//
// A token that was used already is refused. If it was used less than ten
// seconds before, the two requests are taken for a race of the same client and
// nothing else happens. If it was used longer ago, someone is replaying a stolen
// token, and the whole session is ended and a warning with the user and the
// session, but no secrets, goes to the log.
//
// Every failure, an unknown or malformed token, an expired one, a session that
// ended or went idle, a user who is blocked or deleted and a token that was
// used already, gives the same ErrUnauthenticated. Other errors are failures of
// the application.
func (a *Auth) Refresh(ctx context.Context, refreshToken string) (Tokens, error) {
	tokens, _, err := a.refresh(ctx, refreshToken)
	return tokens, err
}

func (a *Auth) refresh(ctx context.Context, refreshToken string) (Tokens, refreshOutcome, error) {
	hash, err := secret.Hash(refreshToken)
	if err != nil {
		return Tokens{}, refreshRefused, ErrUnauthenticated
	}
	if _, err = a.ring.signer(ctx); err != nil {
		return Tokens{}, refreshRefused, err
	}
	now := a.now().UTC().Truncate(time.Microsecond)
	var (
		outcome refreshOutcome
		fresh   newRefresh
		current store.ResolvedSession
	)
	err = a.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		outcome, fresh, current = refreshRefused, newRefresh{}, store.ResolvedSession{}
		use, useErr := tx.RefreshTokens().Use(ctx, a.tenant, hash, now)
		if errors.Is(useErr, store.ErrNotFound) {
			return nil
		}
		if useErr != nil {
			return useErr
		}
		resolved, resolveErr := tx.Sessions().ResolveByID(ctx, a.tenant, use.Token.SessionID)
		if resolveErr != nil {
			return resolveErr
		}
		current = resolved
		if use.Reused {
			if now.Sub(use.Token.UsedAt) <= reuseWindow {
				outcome = refreshRaced
				return nil
			}
			outcome = refreshReplayed
			return a.endReusedSession(ctx, tx, resolved.Session, now, &outcome)
		}
		if !a.mayRefresh(use.Token, resolved, now) {
			return errRefreshRejected
		}
		var newErr error
		fresh, newErr = a.newRefreshToken(resolved.Session, now)
		if newErr != nil {
			return newErr
		}
		if addErr := tx.RefreshTokens().Add(ctx, fresh.record); addErr != nil {
			return addErr
		}
		if touchErr := tx.Sessions().Touch(ctx, a.tenant, resolved.Session.ID, now); touchErr != nil {
			return touchErr
		}
		outcome = refreshDone
		return nil
	})
	switch {
	case errors.Is(err, errRefreshRejected):
		return Tokens{}, refreshRefused, ErrUnauthenticated
	case err != nil:
		return Tokens{}, refreshRefused, fmt.Errorf("limb: refresh the tokens: %w", err)
	}
	if outcome == refreshReused {
		a.logger.WarnContext(ctx, "limb: a refresh token was used again, the session was ended",
			"user_id", current.Session.UserID, "session_id", current.Session.ID)
	}
	if outcome != refreshDone {
		return Tokens{}, outcome, ErrUnauthenticated
	}
	access, accessExpires, err := a.issueAccessToken(ctx, current.Session.UserID, current.Session.ID, current.User.MustChangePassword, now)
	if err != nil {
		return Tokens{}, refreshRefused, err
	}
	return Tokens{
		AccessToken:      access,
		AccessExpiresAt:  accessExpires,
		RefreshToken:     fresh.text,
		RefreshExpiresAt: fresh.record.ExpiresAt,
	}, refreshDone, nil
}

func (a *Auth) mayRefresh(token store.RefreshToken, resolved store.ResolvedSession, now time.Time) bool {
	return token.ExpiresAt.After(now) && resolved.Session.Kind == store.SessionToken &&
		a.sessionActive(resolved.Session, now) && userActive(resolved.User, now)
}

func (a *Auth) endReusedSession(ctx context.Context, tx store.Repositories, session store.Session, now time.Time, outcome *refreshOutcome) error {
	err := tx.Sessions().Revoke(ctx, a.tenant, session.UserID, session.ID, now)
	switch {
	case err == nil:
		*outcome = refreshReused
		return nil
	case errors.Is(err, store.ErrNotFound):
		return nil
	}
	return err
}
