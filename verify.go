package limb

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/store"
)

// VerificationRequest asks for a new link and a new code that confirm the
// addresses and the phone numbers of an account that are not confirmed yet.
type VerificationRequest struct {
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

// RequestVerification sends a link and a code that confirm the addresses and
// the phone numbers that are not confirmed yet, to each of them, in the way that
// WithSender, WithVerifyURL and WithMessageTemplate set up. A new request ends
// the secrets that an earlier one made for the same address.
//
// The answer is the same for a login that belongs to an account and one that does
// not, for an account that has nothing left to confirm and one that has, and it
// comes after the same work: limb counts the request, puts a task in a queue and
// returns, and the account is looked up, the secrets are made and the message is
// sent later, in the background. What can differ is only that no message comes.
// The messages to one user are limited too, quietly: five of a kind in an hour,
// the rest are not sent.
//
// It returns ErrRecoveryDisabled when the service has no Sender or no delivery
// channel, a *ValidationError for a login that is empty or too long, a
// *RateLimitError when the login or the address asked too often, see
// WithRecoveryLimits, and ErrBusy when the queue of messages is full.
func (a *Auth) RequestVerification(ctx context.Context, r VerificationRequest) error {
	return a.requestSecrets(ctx, recoveryJob{purpose: store.PurposeVerify, kind: MessageVerification, language: r.Language}, r.Login, r.IP)
}

func (a *Auth) requestSecrets(ctx context.Context, j recoveryJob, login string, ip netip.Addr) error {
	if !a.recoveryReady() {
		return ErrRecoveryDisabled
	}
	if strings.TrimSpace(login) == "" || len(login) > maxLoginLength {
		return &ValidationError{Field: "login", Reason: "required, at most 1024 bytes"}
	}
	if err := a.admitRequest(ctx, j.purpose, login, ip); err != nil {
		return err
	}
	j.language = a.languageFor(ctx, j.language)
	return a.dispatcher.submit(task{kind: j.kind, run: func(ctx context.Context) error {
		return a.sendSecretsToLogin(ctx, login, j)
	}})
}

// VerifyRequest confirms an address or a phone number with the link or the code
// that was sent to it. Give either Token, or Code together with either Login or
// Channel.
type VerifyRequest struct {
	// Token is the secret of the link, the text after "#token=".
	Token string

	// Login is the login of the account that the code was sent for. It is for a
	// user who asked for the code with it. The code is checked against the codes
	// that wait for confirmation on every address of the account.
	Login string

	// Channel is the address or the phone number that the code was sent to, for a
	// channel that is not a login, such as a phone number that only receives
	// messages.
	Channel string

	// Code is the code of six digits. Spaces around it and one space or hyphen in
	// the middle are ignored.
	Code string

	// IP is the address of the client, which the limits use. It may be left unset.
	IP netip.Addr
}

// Verify confirms an address or a phone number with the secret that was sent to
// it. The link or the code works once, ends the other secret that was sent with
// it, and expires: a link of verification after 24 hours and a code after ten
// minutes. A code survives five guesses, see WithRecoveryLimits.
//
// It returns ErrInvalidSecret when the secret is not accepted, the same error
// for a link or a code that is unknown, expired or used, for a login or a channel
// that nothing was sent to and for a secret that was made for something else, a
// *RateLimitError when the address sent too many wrong secrets and a
// *ValidationError when the request does not say what to check: both a token and
// a code, neither, or a code without a login or a channel or with both.
func (a *Auth) Verify(ctx context.Context, r VerifyRequest) error {
	if err := checkConfirmation(r.Token, r.Login, r.Channel, r.Code); err != nil {
		return err
	}
	var confirmed confirmedChannel
	err := a.guardConfirmation(ctx, store.PurposeVerify, r.IP, func() error {
		return a.confirmSecret(ctx, store.PurposeVerify, confirmation{token: r.Token, login: r.Login, channel: r.Channel, code: r.Code},
			func(ctx context.Context, tx store.Repositories, s store.Secret, now time.Time) error {
				confirmed = confirmedChannel{}
				return a.markVerified(ctx, tx, s, now, &confirmed)
			})
	})
	if err != nil {
		return err
	}
	if confirmed.changed {
		a.emit(ctx, Event{
			Type: EventChannelVerified, UserID: confirmed.secret.UserID, Channel: confirmed.secret.ChannelType,
			Address: maskValue(confirmed.secret.ChannelValue), IP: eventAddress(r.IP),
		})
	}
	return nil
}

type confirmedChannel struct {
	secret  store.Secret
	changed bool
}

func (a *Auth) markVerified(ctx context.Context, tx store.Repositories, s store.Secret, now time.Time, out *confirmedChannel) error {
	found, err := tx.Identifiers().Find(ctx, a.tenant, s.ChannelType, s.ChannelValue)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrInvalidSecret
	case err != nil:
		return err
	case found.UserID != s.UserID:
		return ErrInvalidSecret
	}
	out.secret = s
	if found.VerifiedAt.IsZero() {
		if err = tx.Identifiers().MarkVerified(ctx, a.tenant, s.ChannelType, s.ChannelValue, now); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrInvalidSecret
			}
			return err
		}
		out.changed = true
	}
	_, err = tx.Secrets().End(ctx, store.SecretScope{
		TenantID: a.tenant, UserID: s.UserID, Purpose: store.PurposeVerify, ChannelType: s.ChannelType, ChannelValue: s.ChannelValue,
	}, now)
	return err
}

type confirmation struct {
	token   string
	login   string
	channel string
	code    string
}

func checkConfirmation(token, login, channel, code string) error {
	switch {
	case token != "" && (login != "" || channel != "" || code != ""):
		return &ValidationError{Field: "token", Reason: "give either the token or a code with a login or a channel"}
	case token != "":
		return nil
	case code == "":
		return &ValidationError{Field: "code", Reason: "required when there is no token"}
	case (login == "") == (channel == ""):
		return &ValidationError{Field: "login", Reason: "give either a login or a channel"}
	}
	return nil
}

func (a *Auth) confirmSecret(ctx context.Context, purpose store.SecretPurpose, c confirmation,
	apply func(ctx context.Context, tx store.Repositories, s store.Secret, now time.Time) error) error {
	var err error
	for range changeAttempts {
		if c.token != "" {
			err = a.confirmLink(ctx, purpose, c.token, apply)
		} else {
			err = a.confirmCode(ctx, purpose, c, apply)
		}
		if !errors.Is(err, store.ErrStale) {
			return err
		}
	}
	return err
}

func (a *Auth) confirmLink(ctx context.Context, purpose store.SecretPurpose, token string,
	apply func(ctx context.Context, tx store.Repositories, s store.Secret, now time.Time) error) error {
	hash, err := secret.Hash(token)
	if err != nil {
		return ErrInvalidSecret
	}
	now := a.now().UTC().Truncate(time.Microsecond)
	return a.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		used, useErr := tx.Secrets().UseLink(ctx, a.tenant, purpose, hash, now)
		switch {
		case errors.Is(useErr, store.ErrNotFound):
			return ErrInvalidSecret
		case useErr != nil:
			return useErr
		}
		return apply(ctx, tx, used, now)
	})
}

func (a *Auth) confirmCode(ctx context.Context, purpose store.SecretPurpose, c confirmation,
	apply func(ctx context.Context, tx store.Repositories, s store.Secret, now time.Time) error) error {
	code, ok := secret.ParseCode(c.code)
	if !ok {
		return ErrInvalidSecret
	}
	scope, ok, err := a.codeScope(ctx, purpose, c)
	if err != nil || !ok {
		if err == nil {
			err = ErrInvalidSecret
		}
		return err
	}
	now := a.now().UTC().Truncate(time.Microsecond)
	tried, err := a.store.Secrets().TryCodes(ctx, scope, now, a.recovery.codeAttempts)
	if err != nil {
		return err
	}
	matched := -1
	for i, t := range tried {
		if a.keys.CodeMatches(t.Hash, codeBinding(t), code) {
			matched = i
		}
	}
	if matched < 0 {
		return ErrInvalidSecret
	}
	return a.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		switch useErr := tx.Secrets().UseCode(ctx, a.tenant, tried[matched].ID, now); {
		case errors.Is(useErr, store.ErrNotFound):
			return ErrInvalidSecret
		case useErr != nil:
			return useErr
		}
		return apply(ctx, tx, tried[matched], now)
	})
}

func (a *Auth) codeScope(ctx context.Context, purpose store.SecretPurpose, c confirmation) (store.SecretScope, bool, error) {
	scope := store.SecretScope{TenantID: a.tenant, Purpose: purpose}
	if c.channel != "" {
		found, ok, err := a.findByChannel(ctx, c.channel)
		if err != nil || !ok {
			return scope, false, err
		}
		scope.UserID, scope.ChannelType, scope.ChannelValue = found.UserID, found.Type, found.Value
		return scope, true, nil
	}
	found, ok, err := a.findByLogin(ctx, c.login)
	if err != nil || !ok {
		return scope, false, err
	}
	scope.UserID = found.UserID
	return scope, true, nil
}
