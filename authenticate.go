package limb

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/store"
)

const sessionCookieBase = "limb_session"

func sessionCookieName(development bool) string {
	if development {
		return sessionCookieBase
	}
	return "__Host-" + sessionCookieBase
}

// Authenticate finds out who makes the request. A request that carries an
// Authorization header with the Bearer scheme is a token request and is checked
// only as such; an empty or wrong token is not looked for in the cookie. Any
// other request is a cookie request: the session cookie is looked up and, for a
// method that changes data, the request must also pass the cross-site check, see
// ErrCSRF.
//
// It returns ErrUnauthenticated, the same for every reason, when there is no
// valid session: no cookie, a damaged or unknown secret, a session that was
// ended, expired or has been idle for too long, a user who is blocked or
// deleted. Other errors are failures of the application and not of the client.
//
// When the user has to choose a new password the Principal is returned
// together with ErrPasswordChangeRequired. The Principal is valid then, so a
// handler that lets the user change the password can carry on with it, but
// code that only looks at the error stays closed.
func (a *Auth) Authenticate(r *http.Request) (Principal, error) {
	ctx := r.Context()
	if token, bearer := bearerToken(r); bearer {
		return a.authenticateToken(ctx, token)
	}
	cookie, err := r.Cookie(a.cookie)
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	hash, err := secret.Hash(cookie.Value)
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	resolved, err := a.store.Sessions().ResolveBySecret(ctx, a.tenant, hash)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Principal{}, ErrUnauthenticated
	case err != nil:
		return Principal{}, fmt.Errorf("limb: read the session: %w", err)
	}
	principal, err := a.activePrincipal(resolved)
	if err != nil {
		return Principal{}, err
	}
	if changesData(r.Method) {
		if err = a.checkCSRF(r, principal); err != nil {
			return Principal{}, err
		}
	}
	a.touch(ctx, resolved.Session)
	if principal.MustChangePassword {
		return principal, ErrPasswordChangeRequired
	}
	return principal, nil
}

func (a *Auth) authenticateToken(ctx context.Context, token string) (Principal, error) {
	claims, err := a.verifyAccessToken(ctx, token)
	if err != nil {
		return Principal{}, err
	}
	principal := Principal{
		UserID:             UserID(claims.Subject),
		SessionID:          claims.SessionID,
		SessionKind:        store.SessionToken,
		MustChangePassword: claims.ChangePassword,
	}
	if a.revocation == RevocationInstant {
		principal, err = a.checkTokenSession(ctx, claims)
		if err != nil {
			return Principal{}, err
		}
	}
	if principal.MustChangePassword {
		return principal, ErrPasswordChangeRequired
	}
	return principal, nil
}

func (a *Auth) checkTokenSession(ctx context.Context, claims accessClaims) (Principal, error) {
	resolved, err := a.store.Sessions().ResolveByID(ctx, a.tenant, claims.SessionID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Principal{}, ErrUnauthenticated
	case err != nil:
		return Principal{}, fmt.Errorf("limb: read the session: %w", err)
	}
	if resolved.Session.UserID != claims.Subject || resolved.Session.Kind != store.SessionToken {
		return Principal{}, ErrUnauthenticated
	}
	principal, err := a.activePrincipal(resolved)
	if err != nil {
		return Principal{}, err
	}
	a.touch(ctx, resolved.Session)
	return principal, nil
}

func bearerToken(r *http.Request) (string, bool) {
	for _, line := range r.Header.Values("Authorization") {
		scheme, token, _ := strings.Cut(strings.TrimSpace(line), " ")
		if strings.EqualFold(scheme, "Bearer") {
			return strings.TrimSpace(token), true
		}
	}
	return "", false
}

func (a *Auth) activePrincipal(resolved store.ResolvedSession) (Principal, error) {
	now := a.now()
	if !a.sessionActive(resolved.Session, now) || !userActive(resolved.User, now) {
		return Principal{}, ErrUnauthenticated
	}
	return Principal{
		UserID:             UserID(resolved.Session.UserID),
		SessionID:          resolved.Session.ID,
		SessionKind:        resolved.Session.Kind,
		MustChangePassword: resolved.User.MustChangePassword,
	}, nil
}

func (a *Auth) sessionActive(s store.Session, now time.Time) bool {
	return s.RevokedAt.IsZero() && s.ExpiresAt.After(now) && s.LastSeenAt.Add(a.idle).After(now)
}

func userActive(u store.UserState, now time.Time) bool {
	switch u.Status {
	case store.StatusActive:
		return true
	case store.StatusBlocked:
		return !u.BlockedUntil.IsZero() && !u.BlockedUntil.After(now)
	case store.StatusDeleted:
		return false
	}
	return false
}

func (a *Auth) touch(ctx context.Context, s store.Session) {
	now := a.now()
	if now.Sub(s.LastSeenAt) < touchInterval {
		return
	}
	if err := a.store.Sessions().Touch(ctx, a.tenant, s.ID, now); err != nil {
		a.logger.DebugContext(ctx, "limb: the time of the last use of the session cannot be saved", "session_id", s.ID, "error", err)
	}
}
