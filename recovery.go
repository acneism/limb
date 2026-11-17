package limb

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/store"
)

const (
	resetLinkLifetime  = 30 * time.Minute
	verifyLinkLifetime = 24 * time.Hour
	codeLifetime       = 10 * time.Minute
	messagesPerHour    = 5
	maxBaseURLLength   = 1024
	maxLoginLength     = 1024
	fragmentPrefix     = "#token="
)

// ErrRecoveryDisabled is returned by the operations that send a link or a code
// when the service cannot send one: it has no Sender, or none of its identifier
// types is a delivery channel. A user who has no channel to be reached at cannot
// recover access alone, an administrator has to do it.
var ErrRecoveryDisabled = errors.New("limb: sending a link or a code needs a Sender and an identifier type that is a delivery channel")

// WithResetURL sets the address of the page of the application where the user
// chooses a new password. The link of a reset message is this address with the
// secret in its fragment, "#token=...": a fragment is not sent to the server and
// is not written to its logs, so the page reads it with a script and sends it in
// the body of its request. The address is absolute, starts with https, or with
// http in the development mode, has no user name, no password and no fragment,
// and New fails for anything else. Without it the message of a reset carries a
// code only.
func WithResetURL(address string) Option {
	return func(c *config) {
		c.resetURL = address
	}
}

// WithVerifyURL does the same as WithResetURL for the page where an address or a
// phone number is confirmed. Without it the message carries a code only.
func WithVerifyURL(address string) Option {
	return func(c *config) {
		c.verifyURL = address
	}
}

func checkBaseURL(option, address string, development bool) error {
	if address == "" {
		return nil
	}
	u, err := url.Parse(address)
	switch {
	case err != nil, len(address) > maxBaseURLLength, hasControl(address), strings.ContainsAny(address, " \t"):
		return fmt.Errorf("limb: the address given to %s is not valid", option)
	case u.Host == "", u.User != nil:
		return fmt.Errorf("limb: the address given to %s must be absolute and must not hold a user name or a password", option)
	case u.Fragment != "" || u.RawFragment != "" || strings.Contains(address, "#"):
		return fmt.Errorf("limb: the address given to %s must not have a fragment, limb adds its own", option)
	case u.Scheme == "https", u.Scheme == "http" && development:
		return nil
	}
	return fmt.Errorf("limb: the address given to %s must start with https", option)
}

type recoveryJob struct {
	purpose  store.SecretPurpose
	kind     MessageKind
	language string
}

func (a *Auth) recoveryReady() bool {
	return a.dispatcher != nil && a.delivers
}

func (a *Auth) baseURL(purpose store.SecretPurpose) string {
	if purpose == store.PurposeReset {
		return a.resetURL
	}
	return a.verifyURL
}

func linkLifetime(purpose store.SecretPurpose) time.Duration {
	if purpose == store.PurposeReset {
		return resetLinkLifetime
	}
	return verifyLinkLifetime
}

func (a *Auth) deliveryChannels(identifiers []store.Identifier, verified bool) []store.Identifier {
	var channels []store.Identifier
	for _, i := range identifiers {
		kind, declared := a.known[i.Type]
		confirmed := !i.VerifiedAt.IsZero()
		if declared && kind.IsDelivery() && confirmed == verified {
			channels = append(channels, i)
		}
	}
	return channels
}

func accepted(kind identifier.Type, value string, err error) (identifier.Type, string, bool) {
	return kind, value, err == nil
}

func (a *Auth) findByLogin(ctx context.Context, login string) (store.Identifier, bool, error) {
	kind, value, ok := accepted(identifier.Resolve(a.types, login))
	if !ok {
		return store.Identifier{}, false, nil
	}
	return a.findIdentifier(ctx, kind.Name(), value)
}

func (a *Auth) findByChannel(ctx context.Context, channel string) (store.Identifier, bool, error) {
	kind, value, ok := accepted(identifier.ResolveDelivery(a.types, channel))
	if !ok {
		return store.Identifier{}, false, nil
	}
	return a.findIdentifier(ctx, kind.Name(), value)
}

func (a *Auth) findIdentifier(ctx context.Context, typ, value string) (store.Identifier, bool, error) {
	found, err := a.store.Identifiers().Find(ctx, a.tenant, typ, value)
	switch {
	case err == nil:
		return found, true, nil
	case errors.Is(err, store.ErrNotFound):
		return store.Identifier{}, false, nil
	}
	return store.Identifier{}, false, fmt.Errorf("limb: find the identifier: %w", err)
}

func (a *Auth) sendSecretsToLogin(ctx context.Context, login string, j recoveryJob) error {
	found, ok, err := a.findByLogin(ctx, login)
	if err != nil || !ok {
		return err
	}
	return a.sendSecretsToUser(ctx, found.UserID, j)
}

func (a *Auth) sendSecretsToUser(ctx context.Context, userID string, j recoveryJob) error {
	user, err := a.store.Users().Get(ctx, a.tenant, userID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("limb: get the user: %w", err)
	case user.Status == store.StatusDeleted:
		return nil
	}
	identifiers, err := a.store.Identifiers().ListByUser(ctx, a.tenant, user.ID)
	if err != nil {
		return fmt.Errorf("limb: list the identifiers: %w", err)
	}
	for _, channel := range a.deliveryChannels(identifiers, j.purpose == store.PurposeReset) {
		if err = a.sendSecretsTo(ctx, user, channel, j); err != nil {
			a.failMessage(ctx, err)
		}
	}
	return nil
}

func (a *Auth) sendSecretsTo(ctx context.Context, user store.User, channel store.Identifier, j recoveryJob) error {
	if !a.allowMessage(ctx, j.kind, user.ID) {
		return nil
	}
	secrets, err := a.issueSecrets(ctx, user, channel, j)
	if err != nil {
		a.logger.ErrorContext(ctx, "limb: the secrets of a message cannot be made", "kind", j.kind, "channel", channel.Type, "error", err)
		return failureFor(user.ID, j.kind, channel, "storage", "the secrets could not be stored")
	}
	if secrets.none {
		return nil
	}
	m := Message{
		Kind: j.kind, UserID: user.ID, Channel: channel.Type, To: channel.Value, Language: normalizeLanguage(j.language),
		Link: secrets.link, Code: secrets.code, LinkExpiresAt: secrets.linkExpires, CodeExpiresAt: secrets.codeExpires,
	}
	data := MessageData{Link: secrets.link, Code: secrets.code, CodeExpiresIn: describeDuration(m.Language, codeLifetime)}
	if secrets.link != "" {
		data.LinkExpiresIn = describeDuration(m.Language, linkLifetime(j.purpose))
	}
	return a.sendMessage(ctx, m, data)
}

func failureFor(userID string, kind MessageKind, channel store.Identifier, code, reason string) error {
	return failureOf(Message{Kind: kind, UserID: userID, Channel: channel.Type, To: channel.Value}, code, reason)
}

func (a *Auth) sendMessage(ctx context.Context, m Message, data MessageData) error {
	rendered, err := a.renderer.render(m.Kind, m.Language, m.Channel, data)
	if err != nil {
		return failureOf(m, "render", "the message cannot be made from its templates")
	}
	m.Subject, m.Text, m.HTML = rendered.subject, rendered.text, rendered.html
	return a.deliver(ctx, m)
}

func (a *Auth) allowMessage(ctx context.Context, kind MessageKind, userID string) bool {
	key := a.keys.AttemptKey("recovery-user", a.tenant, string(kind), userID)
	counter, err := a.store.Attempts().Hit(ctx, key, a.now(), time.Hour)
	if err != nil {
		a.logger.ErrorContext(ctx, "limb: the messages to a user cannot be counted", "error", err)
		return false
	}
	if counter.Count > messagesPerHour {
		a.logger.DebugContext(ctx, "limb: a message was not sent, the user has had too many", "kind", kind)
		return false
	}
	return true
}

type issuedSecrets struct {
	none        bool
	link        string
	code        string
	linkExpires time.Time
	codeExpires time.Time
}

func (a *Auth) issueSecrets(ctx context.Context, user store.User, channel store.Identifier, j recoveryJob) (issuedSecrets, error) {
	now := a.now().UTC().Truncate(time.Microsecond)
	scope := store.SecretScope{TenantID: a.tenant, UserID: user.ID, Purpose: j.purpose, ChannelType: channel.Type, ChannelValue: channel.Value}
	var issued issuedSecrets
	code, err := a.keys.NewCode()
	if err != nil {
		return issued, fmt.Errorf("limb: %w", err)
	}
	codeID, err := a.newID()
	if err != nil {
		return issued, err
	}
	codeSecret := store.Secret{
		TenantID: a.tenant, ID: codeID, Kind: store.SecretCode, UserID: user.ID, Purpose: j.purpose,
		ChannelType: channel.Type, ChannelValue: channel.Value, CreatedAt: now, ExpiresAt: now.Add(codeLifetime),
	}
	codeSecret.Hash = a.keys.CodeHash(codeBinding(codeSecret), code)
	issued.code, issued.codeExpires = code, codeSecret.ExpiresAt
	secrets := []store.Secret{codeSecret}
	if base := a.baseURL(j.purpose); base != "" {
		token, hash, tokenErr := newSecret()
		if tokenErr != nil {
			return issued, tokenErr
		}
		linkID, idErr := a.newID()
		if idErr != nil {
			return issued, idErr
		}
		linkSecret := codeSecret
		linkSecret.ID, linkSecret.Kind, linkSecret.Hash, linkSecret.ExpiresAt = linkID, store.SecretLink, hash, now.Add(linkLifetime(j.purpose))
		secrets = append(secrets, linkSecret)
		issued.link, issued.linkExpires = base+fragmentPrefix+token, linkSecret.ExpiresAt
	}
	err = a.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if _, endErr := tx.Secrets().End(ctx, scope, now); endErr != nil {
			return endErr
		}
		for _, s := range secrets {
			if addErr := tx.Secrets().Add(ctx, s); addErr != nil {
				return addErr
			}
		}
		return nil
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return issuedSecrets{none: true}, nil
	case err != nil:
		return issuedSecrets{}, fmt.Errorf("limb: store the secrets: %w", err)
	}
	return issued, nil
}

func codeBinding(s store.Secret) secret.CodeBinding {
	return secret.CodeBinding{
		TenantID: s.TenantID, ID: s.ID, UserID: s.UserID, Purpose: string(s.Purpose), ChannelType: s.ChannelType, ChannelValue: s.ChannelValue,
	}
}

func (a *Auth) failMessage(ctx context.Context, err error) {
	failure, ok := asDeliveryError(err)
	if !ok {
		a.logger.WarnContext(ctx, "limb: a message was not sent", "error", err)
		return
	}
	a.logger.WarnContext(ctx, "limb: a message was not sent", "kind", failure.kind, "channel", failure.channel, "error", err)
	a.emit(ctx, Event{
		Type: EventMessageFailed, UserID: failure.userID, Channel: failure.channel, Address: failure.recipient,
		Details: map[string]string{"kind": string(failure.kind), "reason": failure.code},
	})
}
