package limb

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/store"
)

// Login signs a user in with a login and a password and opens a session of the
// kind Credentials.Kind asks for.
//
// It returns ErrInvalidCredentials when the login or the password is wrong,
// the same error and after the same work whether the account exists or not, and
// ErrUserBlocked when the password is right but the account is blocked. Too
// many failed attempts turn the next ones down with a *RateLimitError before the
// password is looked at; the limits come from WithLoginLimits and the counters
// live in the database, so every instance of the application counts. When the
// user has to choose a new password the sign-in succeeds, Principal.MustChangePassword
// is set and the session can only be used to change it.
//
// The attempts that run at the same time are limited to the number of CPU
// cores of the instance, and the limits are checked inside that limit, so a burst
// of parallel requests cannot get past a limit before the first failure is
// counted: at most as many attempts as there are slots can slip through per
// instance.
func (a *Auth) Login(ctx context.Context, c Credentials) (Login, error) {
	switch c.Kind {
	case SessionCookie:
	case SessionToken:
		return Login{}, &ValidationError{Field: "kind", Reason: "token sessions are not supported yet"}
	default:
		return Login{}, &ValidationError{Field: "kind", Reason: "must be cookie or token"}
	}
	keys := a.loginAttemptKeys(c.Login, c.IP)
	var user store.User
	err := a.limited(ctx, keys, func() error {
		var checkErr error
		user, _, checkErr = a.checkPassword(ctx, c.Login, c.Password)
		return checkErr
	})
	if err != nil {
		return Login{}, err
	}
	now := a.now().UTC().Truncate(time.Microsecond)
	login, err := a.openCookieSession(ctx, user, c, now)
	if err != nil {
		return Login{}, err
	}
	a.recordLogin(ctx, user, now)
	a.clearFailures(ctx, keys.accountIP)
	return login, nil
}

func (a *Auth) openCookieSession(ctx context.Context, user store.User, c Credentials, now time.Time) (Login, error) {
	id, err := a.newID()
	if err != nil {
		return Login{}, err
	}
	text, err := secret.New()
	if err != nil {
		return Login{}, fmt.Errorf("limb: %w", err)
	}
	hash, err := secret.Hash(text)
	if err != nil {
		return Login{}, fmt.Errorf("limb: %w", err)
	}
	session := store.Session{
		TenantID:   a.tenant,
		ID:         id,
		Kind:       store.SessionCookie,
		SecretHash: hash,
		UserID:     user.ID,
		IP:         addressText(c.IP),
		UserAgent:  cleanUserAgent(c.UserAgent),
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(a.absolute),
	}
	if err = a.store.Sessions().Create(ctx, session); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Login{}, ErrInvalidCredentials
		}
		return Login{}, fmt.Errorf("limb: create the session: %w", err)
	}
	return Login{
		Principal: Principal{
			UserID:             UserID(user.ID),
			SessionID:          id,
			SessionKind:        store.SessionCookie,
			MustChangePassword: user.MustChangePassword,
		},
		Secret:    text,
		CSRFToken: a.keys.CSRFToken(id),
		ExpiresAt: session.ExpiresAt,
	}, nil
}

func (a *Auth) recordLogin(ctx context.Context, user store.User, at time.Time) {
	user.LastLoginAt = at
	_, err := a.store.Users().Update(ctx, user)
	if err != nil && !errors.Is(err, store.ErrStale) && !errors.Is(err, store.ErrNotFound) {
		a.logger.WarnContext(ctx, "limb: the time of the sign-in cannot be saved", "user_id", user.ID, "error", err)
	}
}

func addressText(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	return cleanAddr(ip).String()
}

func cleanUserAgent(agent string) string {
	var out strings.Builder
	for _, r := range agent {
		if r == utf8.RuneError || unicode.IsControl(r) {
			continue
		}
		if out.Len()+utf8.RuneLen(r) > store.MaxUserAgentLength {
			break
		}
		out.WriteRune(r)
	}
	return out.String()
}
