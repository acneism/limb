package limb

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"time"

	"github.com/acneism/limb/store"
)

// ResetRequest asks for a link and a code that let the user choose a new
// password.
type ResetRequest struct {
	// Login is what the user signs in with: an e-mail address, a name or whatever
	// the identifier types of the service allow.
	Login string

	// IP is the address of the client, which the limits use. It may be left
	// unset.
	IP netip.Addr

	// Language is the language of the message, a tag such as "ru" or "en-GB". A
	// language that limb has no texts for, and an empty one, gives English.
	Language string
}

// RequestPasswordReset sends a link and a code that let the user choose a new
// password, to every address and phone number of the account that is confirmed.
// A channel that is not confirmed gets nothing: a mistyped address would hand the
// password of the account to a stranger. An account that has no confirmed channel
// cannot recover access alone, an administrator has to reset the password. A
// blocked account gets the message, the reset does not lift the block, and a
// deleted one does not. A new request ends the secrets that an earlier one made
// for the same address.
//
// The answer is the same for a login that belongs to an account and one that does
// not, and it comes after the same work, see RequestVerification: what can differ
// is only that no message comes. The messages to one user are limited too,
// quietly: five of a kind in an hour.
//
// It returns ErrRecoveryDisabled when the service has no Sender or no delivery
// channel, a *ValidationError for a login that is empty or too long, a
// *RateLimitError when the login or the address asked too often, see
// WithRecoveryLimits, and ErrBusy when the queue of messages is full.
func (a *Auth) RequestPasswordReset(ctx context.Context, r ResetRequest) error {
	return a.requestSecrets(ctx, recoveryJob{purpose: store.PurposeReset, kind: MessagePasswordReset, language: r.Language}, r.Login, r.IP)
}

// ResetPasswordRequest sets a new password with the link or the code that a reset
// sent. Give either Token, or Code together with either Login or Channel, as for
// VerifyRequest.
type ResetPasswordRequest struct {
	// Token is the secret of the link, the text after "#token=".
	Token string

	// Login is the login of the account that the code was sent for.
	Login string

	// Channel is the address or the phone number that the code was sent to.
	Channel string

	// Code is the code of six digits. Spaces around it and one space or hyphen in
	// the middle are ignored.
	Code string

	// Password is the new password.
	Password string

	// IP is the address of the client, which the limits use. It may be left unset.
	IP netip.Addr

	// Language is the language of the notice that the password was changed. When
	// it is empty the language of ContextWithLanguage is used, and then English.
	Language string
}

// ResetPassword sets a new password with the secret that a reset sent. The new
// password has to meet the password policy, which also refuses the logins of the
// user, and a password that does not leaves the link or the code usable, except
// that a code has used up one of its guesses. The secret works once and expires,
// a link after 30 minutes and a code after ten, and all the secrets of resets of
// the user end with it. By default every session of the user ends, see
// WithKeepSessionsAfterReset, and the user does not have to change the password
// again. The reset works only for a channel that is still confirmed, and for a
// user who is not deleted.
//
// The user gets a notice that the password was changed, on every confirmed
// channel, in the background.
//
// The link of an invitation, see AdminAPI.InviteUser, is accepted here too: it
// chooses the first password of an account that has none, confirms the channel
// that the link was sent to and works for seven days. It ends once the account
// has a password, and it gives no notice of a change, because there was none.
//
// It returns ErrInvalidSecret when the secret is not accepted, a *PolicyError for
// a password that breaks the policy, a *RateLimitError when the address sent too
// many wrong secrets and a *ValidationError when the request does not say what to
// check, see Verify.
func (a *Auth) ResetPassword(ctx context.Context, r ResetPasswordRequest) error {
	if err := checkConfirmation(r.Token, r.Login, r.Channel, r.Code); err != nil {
		return err
	}
	var done resetDone
	err := a.guardConfirmation(ctx, store.PurposeReset, r.IP, func() error {
		c := confirmation{token: r.Token, login: r.Login, channel: r.Channel, code: r.Code}
		confirmed := a.confirmSecret(ctx, store.PurposeReset, c, func(ctx context.Context, tx store.Repositories, s store.Secret, now time.Time) error {
			done = resetDone{}
			return a.applyReset(ctx, tx, s, r.Password, now, &done)
		})
		if r.Token == "" || !errors.Is(confirmed, ErrInvalidSecret) {
			return confirmed
		}
		return a.confirmSecret(ctx, store.PurposeInvite, c, func(ctx context.Context, tx store.Repositories, s store.Secret, now time.Time) error {
			done = resetDone{}
			return a.applyInvitation(ctx, tx, s, r.Password, now, &done)
		})
	})
	if err != nil {
		return err
	}
	if done.invited {
		a.emit(ctx, Event{Type: EventChannelVerified, UserID: done.userID, Channel: done.channelType, Address: maskValue(done.channelValue), IP: eventAddress(r.IP)})
		a.emit(ctx, Event{
			Type: EventPasswordReset, UserID: done.userID, Channel: done.channelType, Address: maskValue(done.channelValue), IP: eventAddress(r.IP),
			Details: map[string]string{"kind": "invitation"},
		})
		return nil
	}
	a.emit(ctx, Event{
		Type: EventPasswordReset, UserID: done.userID, Channel: done.channelType, Address: maskValue(done.channelValue), IP: eventAddress(r.IP),
	})
	if done.revoked > 0 {
		a.emit(ctx, Event{
			Type: EventSessionEnded, UserID: done.userID,
			Details: map[string]string{"reason": "password_reset", "count": strconv.Itoa(done.revoked)},
		})
	}
	a.notifyPasswordChanged(ctx, done.userID, r.Language)
	return nil
}

type resetDone struct {
	userID       string
	channelType  string
	channelValue string
	revoked      int
	invited      bool
}

func (a *Auth) applyInvitation(ctx context.Context, tx store.Repositories, s store.Secret, password string, now time.Time, out *resetDone) error {
	user, err := tx.Users().Get(ctx, a.tenant, s.UserID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrInvalidSecret
	case err != nil:
		return err
	case user.Status == store.StatusDeleted, user.PasswordHash != "":
		return ErrInvalidSecret
	}
	channel, err := tx.Identifiers().Find(ctx, a.tenant, s.ChannelType, s.ChannelValue)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrInvalidSecret
	case err != nil:
		return err
	case channel.UserID != user.ID:
		return ErrInvalidSecret
	}
	identifiers, err := tx.Identifiers().ListByUser(ctx, a.tenant, user.ID)
	if err != nil {
		return err
	}
	if rules := a.policy.Check(ctx, password, loginsOf(identifiers)); len(rules) > 0 {
		return &PolicyError{Rules: rules}
	}
	hash, err := a.hasher.Hash(ctx, password)
	if err != nil {
		return err
	}
	user.PasswordHash, user.MustChangePassword = hash, false
	if _, err = tx.Users().Update(ctx, user); err != nil {
		return err
	}
	if err = tx.Identifiers().MarkVerified(ctx, a.tenant, channel.Type, channel.Value, now); err != nil {
		return err
	}
	for _, purpose := range []store.SecretPurpose{store.PurposeInvite, store.PurposeReset} {
		if _, err = tx.Secrets().End(ctx, store.SecretScope{TenantID: a.tenant, UserID: user.ID, Purpose: purpose}, now); err != nil {
			return err
		}
	}
	*out = resetDone{userID: user.ID, channelType: channel.Type, channelValue: channel.Value, invited: true}
	return nil
}

func (a *Auth) applyReset(ctx context.Context, tx store.Repositories, s store.Secret, password string, now time.Time, out *resetDone) error {
	user, err := tx.Users().Get(ctx, a.tenant, s.UserID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrInvalidSecret
	case err != nil:
		return err
	case user.Status == store.StatusDeleted:
		return ErrInvalidSecret
	}
	channel, err := tx.Identifiers().Find(ctx, a.tenant, s.ChannelType, s.ChannelValue)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrInvalidSecret
	case err != nil:
		return err
	case channel.UserID != user.ID, channel.VerifiedAt.IsZero():
		return ErrInvalidSecret
	}
	identifiers, err := tx.Identifiers().ListByUser(ctx, a.tenant, user.ID)
	if err != nil {
		return err
	}
	if rules := a.policy.Check(ctx, password, loginsOf(identifiers)); len(rules) > 0 {
		return &PolicyError{Rules: rules}
	}
	hash, err := a.hasher.Hash(ctx, password)
	if err != nil {
		return err
	}
	user.PasswordHash, user.MustChangePassword = hash, false
	if _, err = tx.Users().Update(ctx, user); err != nil {
		return err
	}
	if _, err = tx.Secrets().End(ctx, store.SecretScope{TenantID: a.tenant, UserID: user.ID, Purpose: store.PurposeReset}, now); err != nil {
		return err
	}
	revoked := 0
	if !a.keepSessions {
		if revoked, err = tx.Sessions().RevokeAllForUser(ctx, a.tenant, user.ID, "", now); err != nil {
			return err
		}
	}
	*out = resetDone{userID: user.ID, channelType: s.ChannelType, channelValue: s.ChannelValue, revoked: revoked}
	return nil
}

// WithKeepSessionsAfterReset keeps the sessions of a user when the user chooses a
// new password with a link or a code of a reset. By default they all end, because
// a reset is what a user does when they fear that someone else has the account,
// and a session of that someone would otherwise survive it.
func WithKeepSessionsAfterReset() Option {
	return func(c *config) {
		c.keepOpen = true
	}
}
