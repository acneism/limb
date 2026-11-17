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
// the same error and after the same work whether the account exists or not,
// ErrUserBlocked when the password is right but the account is blocked and
// ErrVerificationRequired when the password is right but the service asks for a
// confirmed address or phone number, see WithSignup, and the user has none. Too
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
	case SessionCookie, SessionToken:
	default:
		return Login{}, &ValidationError{Field: "kind", Reason: "must be cookie or token"}
	}
	keys := a.loginAttemptKeys(c.Login, c.IP)
	var user store.User
	var known string
	err := a.limited(ctx, keys, func() error {
		var checkErr error
		user, _, checkErr = a.lookupAndVerify(ctx, c.Login, c.Password, &known)
		return checkErr
	})
	if err == nil {
		err = a.requireVerified(ctx, user)
	}
	if err != nil {
		a.reportFailedLogin(ctx, c, known, err)
		return Login{}, err
	}
	now := a.now().UTC().Truncate(time.Microsecond)
	var login Login
	if c.Kind == SessionToken {
		login, err = a.openTokenSession(ctx, user, c, now)
	} else {
		login, err = a.openCookieSession(ctx, user, c, now)
	}
	if err != nil {
		return Login{}, err
	}
	a.recordLogin(ctx, user, now)
	a.clearFailures(ctx, keys.accountIP)
	a.emit(ctx, Event{
		Type: EventLogin, UserID: user.ID, SessionID: login.Principal.SessionID, IP: eventAddress(c.IP),
		Details: map[string]string{"kind": string(c.Kind)},
	})
	return login, nil
}

func (a *Auth) requireVerified(ctx context.Context, user store.User) error {
	if !a.needVerified {
		return nil
	}
	identifiers, err := a.store.Identifiers().ListByUser(ctx, a.tenant, user.ID)
	if err != nil {
		return fmt.Errorf("limb: list the identifiers: %w", err)
	}
	if len(a.deliveryChannels(identifiers, true)) == 0 {
		return ErrVerificationRequired
	}
	return nil
}

func (a *Auth) reportFailedLogin(ctx context.Context, c Credentials, userID string, err error) {
	var reason string
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		reason = "invalid_credentials"
	case errors.Is(err, ErrUserBlocked):
		reason = "blocked"
	case errors.Is(err, ErrVerificationRequired):
		reason = "verification_required"
	default:
		return
	}
	a.emit(ctx, Event{
		Type: EventLoginFailed, UserID: userID, Address: maskValue(cutAtRune(strings.TrimSpace(c.Login), maxRawLoginKey)), IP: eventAddress(c.IP),
		Details: map[string]string{"reason": reason},
	})
}

func (a *Auth) openCookieSession(ctx context.Context, user store.User, c Credentials, now time.Time) (Login, error) {
	id, err := a.newID()
	if err != nil {
		return Login{}, err
	}
	text, hash, err := newSecret()
	if err != nil {
		return Login{}, err
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

func (a *Auth) openTokenSession(ctx context.Context, user store.User, c Credentials, now time.Time) (Login, error) {
	if _, err := a.ring.signer(ctx); err != nil {
		return Login{}, err
	}
	id, err := a.newID()
	if err != nil {
		return Login{}, err
	}
	session := store.Session{
		TenantID:   a.tenant,
		ID:         id,
		Kind:       store.SessionToken,
		UserID:     user.ID,
		IP:         addressText(c.IP),
		UserAgent:  cleanUserAgent(c.UserAgent),
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(a.absolute),
	}
	refresh, err := a.newRefreshToken(session, now)
	if err != nil {
		return Login{}, err
	}
	err = a.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if createErr := tx.Sessions().Create(ctx, session); createErr != nil {
			return createErr
		}
		return tx.RefreshTokens().Add(ctx, refresh.record)
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Login{}, ErrInvalidCredentials
		}
		return Login{}, fmt.Errorf("limb: create the session: %w", err)
	}
	access, accessExpires, err := a.issueAccessToken(ctx, user.ID, id, user.MustChangePassword, now)
	if err != nil {
		return Login{}, err
	}
	return Login{
		Principal: Principal{
			UserID:             UserID(user.ID),
			SessionID:          id,
			SessionKind:        store.SessionToken,
			MustChangePassword: user.MustChangePassword,
		},
		Tokens: Tokens{
			AccessToken:      access,
			AccessExpiresAt:  accessExpires,
			RefreshToken:     refresh.text,
			RefreshExpiresAt: refresh.record.ExpiresAt,
		},
		ExpiresAt: session.ExpiresAt,
	}, nil
}

type newRefresh struct {
	text   string
	record store.RefreshToken
}

func newSecret() (string, []byte, error) {
	text, err := secret.New()
	if err != nil {
		return "", nil, fmt.Errorf("limb: %w", err)
	}
	hash, err := secret.Hash(text)
	if err != nil {
		return "", nil, fmt.Errorf("limb: %w", err)
	}
	return text, hash, nil
}

func (a *Auth) newRefreshToken(session store.Session, now time.Time) (newRefresh, error) {
	text, hash, err := newSecret()
	if err != nil {
		return newRefresh{}, err
	}
	expires := now.Add(a.idle)
	if expires.After(session.ExpiresAt) {
		expires = session.ExpiresAt
	}
	return newRefresh{text: text, record: store.RefreshToken{
		TenantID: a.tenant, Hash: hash, SessionID: session.ID, ExpiresAt: expires,
	}}, nil
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
