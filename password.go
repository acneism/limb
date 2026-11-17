package limb

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/acneism/limb/store"
)

const changeAttempts = 3

func (a *Auth) passwordToEndSessions(ctx context.Context) (bool, error) {
	value, _, err := a.setting(ctx, settingPasswordToEndSessions)
	switch {
	case err != nil:
		return false, err
	case value == "true":
		return true, nil
	case value == "false":
		return false, nil
	}
	return a.endNeeds, nil
}

func (a *Auth) confirmPassword(ctx context.Context, userID, password string) (store.User, error) {
	var user store.User
	err := a.limited(ctx, a.userAttemptKeys(userID), func() error {
		stored, getErr := a.store.Users().Get(ctx, a.tenant, userID)
		switch {
		case errors.Is(getErr, store.ErrNotFound):
			return a.rejectPassword(ctx, password)
		case getErr != nil:
			return fmt.Errorf("limb: get the user: %w", getErr)
		}
		verified, verifyErr := a.verifyPassword(ctx, stored, password, false)
		user = verified
		return verifyErr
	})
	if errors.Is(err, ErrUserBlocked) {
		return store.User{}, ErrUnauthenticated
	}
	return user, err
}

// ChangePassword sets a new password for the user of the principal, who has to
// give the current one. The check of the current password counts toward the same
// limits on failed attempts as a sign-in. The new password must meet the
// password policy, which also refuses the login identifiers of the user.
//
// The user gets a notice that the password was changed, on every confirmed
// channel, in the background, in the language of ContextWithLanguage.
//
// The change ends every session of the user, including the current one, and
// opens a new one in its place of the same kind. It inherits the time of the
// sign-in, the end of the session, the address and the user agent of the old one,
// so a change of the password does not extend a session, and it has a new secret
// or a new pair of tokens and a new CSRF token, which are returned. The user no
// longer has to change the password after that.
//
// It returns ErrInvalidCredentials for a wrong current password, a
// *PolicyError for a new password that breaks the policy, a *RateLimitError when
// there were too many failed attempts and ErrUnauthenticated when the session of
// the principal is no longer in use.
func (a *Auth) ChangePassword(ctx context.Context, p Principal, current, next string) (Login, error) {
	user, err := a.confirmPassword(ctx, string(p.UserID), current)
	if err != nil {
		return Login{}, err
	}
	identifiers, err := a.store.Identifiers().ListByUser(ctx, a.tenant, user.ID)
	if err != nil {
		return Login{}, fmt.Errorf("limb: list the identifiers: %w", err)
	}
	if rules := a.policy.Check(ctx, next, loginsOf(identifiers)); len(rules) > 0 {
		return Login{}, &PolicyError{Rules: rules}
	}
	hash, err := a.hasher.Hash(ctx, next)
	if err != nil {
		return Login{}, fmt.Errorf("limb: hash the password: %w", err)
	}
	if _, err = a.ring.signer(ctx); err != nil {
		return Login{}, err
	}
	for range changeAttempts {
		var login Login
		login, err = a.replaceSession(ctx, p, user.PasswordHash, hash)
		if err == nil {
			a.emit(ctx, Event{Type: EventPasswordChanged, UserID: string(p.UserID), SessionID: login.Principal.SessionID})
			a.emit(ctx, Event{Type: EventSessionEnded, UserID: string(p.UserID), Details: map[string]string{"reason": "password_changed"}})
			a.notifyPasswordChanged(ctx, string(p.UserID), "")
		}
		if !errors.Is(err, store.ErrStale) {
			return login, err
		}
	}
	return Login{}, fmt.Errorf("limb: change the password: %w", err)
}

func (a *Auth) replaceSession(ctx context.Context, p Principal, verifiedHash, newHash string) (Login, error) {
	now := a.now().UTC().Truncate(time.Microsecond)
	var login Login
	err := a.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		login = Login{}
		user, getErr := tx.Users().Get(ctx, a.tenant, string(p.UserID))
		if getErr != nil {
			return getErr
		}
		if user.PasswordHash != verifiedHash {
			return ErrInvalidCredentials
		}
		old, resolveErr := tx.Sessions().ResolveByID(ctx, a.tenant, p.SessionID)
		switch {
		case errors.Is(resolveErr, store.ErrNotFound):
			return ErrUnauthenticated
		case resolveErr != nil:
			return resolveErr
		}
		if old.Session.UserID != user.ID || !a.sessionActive(old.Session, now) {
			return ErrUnauthenticated
		}
		user.PasswordHash, user.MustChangePassword = newHash, false
		if _, updateErr := tx.Users().Update(ctx, user); updateErr != nil {
			return updateErr
		}
		if _, revokeErr := tx.Sessions().RevokeAllForUser(ctx, a.tenant, user.ID, "", now); revokeErr != nil {
			return revokeErr
		}
		var openErr error
		login, openErr = a.reopenSession(ctx, tx, old.Session, now)
		return openErr
	})
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrUnauthenticated) || errors.Is(err, store.ErrStale) {
			return Login{}, err
		}
		return Login{}, fmt.Errorf("limb: change the password: %w", err)
	}
	return login, nil
}

func (a *Auth) reopenSession(ctx context.Context, tx store.Repositories, old store.Session, now time.Time) (Login, error) {
	id, err := a.newID()
	if err != nil {
		return Login{}, err
	}
	session := store.Session{
		TenantID:   a.tenant,
		ID:         id,
		Kind:       old.Kind,
		UserID:     old.UserID,
		IP:         old.IP,
		UserAgent:  old.UserAgent,
		CreatedAt:  old.CreatedAt,
		LastSeenAt: now,
		ExpiresAt:  old.ExpiresAt,
	}
	login := Login{
		Principal: Principal{UserID: UserID(old.UserID), SessionID: id, SessionKind: old.Kind},
		ExpiresAt: old.ExpiresAt,
	}
	switch old.Kind {
	case store.SessionCookie:
		text, hash, secretErr := newSecret()
		if secretErr != nil {
			return Login{}, secretErr
		}
		session.SecretHash = hash
		login.Secret, login.CSRFToken = text, a.keys.CSRFToken(id)
		if err = tx.Sessions().Create(ctx, session); err != nil {
			return Login{}, err
		}
	case store.SessionToken:
		refresh, refreshErr := a.newRefreshToken(session, now)
		if refreshErr != nil {
			return Login{}, refreshErr
		}
		if err = tx.Sessions().Create(ctx, session); err != nil {
			return Login{}, err
		}
		if err = tx.RefreshTokens().Add(ctx, refresh.record); err != nil {
			return Login{}, err
		}
		access, expires, signErr := a.issueAccessToken(ctx, old.UserID, id, false, now)
		if signErr != nil {
			return Login{}, signErr
		}
		login.Tokens = Tokens{
			AccessToken: access, AccessExpiresAt: expires, RefreshToken: refresh.text, RefreshExpiresAt: refresh.record.ExpiresAt,
		}
	}
	return login, nil
}

func loginsOf(identifiers []store.Identifier) []string {
	logins := make([]string, 0, 2*len(identifiers))
	for _, i := range identifiers {
		logins = append(logins, i.Value, i.DisplayValue)
	}
	return logins
}

// LogoutAll ends every session of the user of the principal, the current one
// as well. With WithPasswordToEndSessions the current password has to be given:
// without it the error is a *ValidationError about the password, and a wrong one
// is ErrInvalidCredentials, counted like a wrong password at sign-in. Without
// the option the password is not checked and may be empty.
func (a *Auth) LogoutAll(ctx context.Context, p Principal, password string) error {
	if err := a.confirmToEndSessions(ctx, p, password); err != nil {
		return err
	}
	ended, err := a.store.Sessions().RevokeAllForUser(ctx, a.tenant, string(p.UserID), "", a.now())
	if err != nil {
		return fmt.Errorf("limb: end the sessions: %w", err)
	}
	if ended > 0 {
		a.emit(ctx, Event{Type: EventSessionEnded, UserID: string(p.UserID), Details: map[string]string{"reason": "logout_all", "count": strconv.Itoa(ended)}})
	}
	return nil
}

// TerminateSession ends the session of the user with the given ID. Ending the
// current session works like Logout and never needs the password. For any other
// session the password is needed with WithPasswordToEndSessions, see LogoutAll,
// and is ignored without it.
//
// It returns ErrSessionNotFound for a session that does not exist, has ended
// already or belongs to someone else, all alike, so it cannot be used to find
// out which sessions exist.
func (a *Auth) TerminateSession(ctx context.Context, p Principal, sessionID, password string) error {
	if sessionID == p.SessionID {
		return a.Logout(ctx, p)
	}
	if err := a.confirmToEndSessions(ctx, p, password); err != nil {
		return err
	}
	err := a.store.Sessions().Revoke(ctx, a.tenant, string(p.UserID), sessionID, a.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrSessionNotFound
	case err != nil:
		return fmt.Errorf("limb: end the session: %w", err)
	}
	a.emit(ctx, Event{Type: EventSessionEnded, UserID: string(p.UserID), SessionID: sessionID, Details: map[string]string{"reason": "terminated", "count": "1"}})
	return nil
}

func (a *Auth) confirmToEndSessions(ctx context.Context, p Principal, password string) error {
	needed, err := a.passwordToEndSessions(ctx)
	if err != nil {
		return err
	}
	if !needed {
		return nil
	}
	if password == "" {
		return &ValidationError{Field: "password", Reason: "required"}
	}
	_, err = a.confirmPassword(ctx, string(p.UserID), password)
	return err
}
