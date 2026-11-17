package limb

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/acneism/limb/store"
)

const (
	maxExtraEntries     = 16
	maxExtraNameLength  = 64
	maxExtraValueLength = 1024
)

// WithSignup opens the registration to visitors: Signup works, and the HTTP
// handler serves POST /register. Without it Signup returns ErrSignupDisabled and
// users are made by the code of the application with Register.
//
// When the service declares an identifier type that is a delivery channel, an
// address or a phone number, a user can sign in only after confirming one of them
// and Login returns ErrVerificationRequired until they do. A registration has to
// give such a value, and limb sends the link and the code that confirm it. Such a
// service needs WithSender, and New fails without it. WithoutVerificationRequired
// turns the requirement off.
func WithSignup() Option {
	return func(c *config) {
		c.signup = true
	}
}

// WithoutVerificationRequired lets users sign in before they confirm an address
// or a phone number, when the registration is open, see WithSignup. Signup still
// sends the message that confirms them when there is a Sender.
func WithoutVerificationRequired() Option {
	return func(c *config) {
		c.unverified = true
	}
}

// SignupRequest is a registration that a visitor asks for.
type SignupRequest struct {
	// Registration is what the visitor gave. Verified must be empty: only the
	// code of the application can confirm an address, with Register.
	Registration

	// IP is the address of the client, which the limits use. It may be left
	// unset.
	IP netip.Addr

	// Language is the language of the messages that the registration sends, a tag
	// such as "ru" or "en-GB". A language that limb has no texts for, and an empty
	// one, gives the language of ContextWithLanguage and then English.
	Language string
}

// Signup registers a visitor. It is what stands behind POST /register, while
// Register is for the code of the application. It checks the values, the extra
// data and the password, counts the request in the limits of recovery, calls the
// hook BeforeRegister and stores the user. The visitor gets no user back: they
// confirm the address that they gave with the link or the code that limb sends
// and then sign in.
//
// The answer does not tell whether an e-mail address or a phone number is taken.
// A registration that uses one that belongs to another user returns nil as one
// that succeeded does, creates nothing and sends the message "signup attempt" to
// that address, so that its owner knows. The password is hashed in both cases and
// the hook is called before the store is asked about users and identifiers, so
// what the hook sees does not depend on it either. A value that is not a delivery
// channel, such as a nickname, has to be chosen, so its being taken is reported
// with a *ValidationError for its type, and it is reported before an address is
// looked at, whatever the address is.
//
// The messages are queued and sent in the background. When the queue is full the
// registration still succeeds and the user asks for a new message with
// RequestVerification.
//
// It returns ErrSignupDisabled without WithSignup, a *ValidationError for a value
// that is rejected, for extra data that breaks its limits, for a registration that
// has Verified, for one that has no address or phone number to confirm when the
// service needs one and for a nickname that is taken, a *PolicyError for a
// password that breaks the policy, a *RateLimitError when the address of the
// client or an e-mail address or phone number was used too often, see
// RecoveryLimits, ErrRegistrationRefused when the hook refused and whatever
// *ValidationError the hook returned.
func (a *Auth) Signup(ctx context.Context, r SignupRequest) error {
	if !a.signup {
		return ErrSignupDisabled
	}
	pending, err := a.checkSignup(r)
	if err != nil {
		return err
	}
	if err = a.enforcePolicy(ctx, r.Password, pending); err != nil {
		return err
	}
	if err = a.admitLabels(ctx, store.PurposeVerify, a.signupLabels(pending), r.IP); err != nil {
		return err
	}
	if err = a.beforeRegister(ctx, hookRegistration(r.Registration, pending)); err != nil {
		return err
	}
	hash, err := a.hasher.Hash(ctx, r.Password)
	if err != nil {
		return fmt.Errorf("limb: hash the password: %w", err)
	}
	id, err := a.newID()
	if err != nil {
		return err
	}
	user, identifiers := a.newAccount(id, hash, pending, nil)
	a.deliveryLast(identifiers)
	language := a.languageFor(ctx, r.Language)
	taken, err := a.storeSignup(ctx, user, identifiers)
	if err != nil {
		return err
	}
	if taken != nil {
		a.queueSignupAttempt(ctx, *taken, language)
		return nil
	}
	a.emitLater(ctx, Event{Type: EventUserCreated, UserID: user.ID, IP: eventAddress(r.IP)})
	a.queueVerification(ctx, user.ID, language)
	return nil
}

func (a *Auth) checkSignup(r SignupRequest) ([]pendingIdentifier, error) {
	if len(r.Verified) > 0 {
		return nil, &ValidationError{Field: "verified", Reason: "a visitor cannot confirm an address by saying so"}
	}
	pending, err := a.collectIdentifiers(r.Identifiers)
	if err != nil {
		return nil, err
	}
	if err = checkExtra(r.Extra); err != nil {
		return nil, err
	}
	if a.needVerified && !slices.ContainsFunc(pending, func(p pendingIdentifier) bool { return p.kind.IsDelivery() }) {
		return nil, &ValidationError{Field: "identifiers", Reason: "an address or a phone number to confirm is required"}
	}
	return pending, nil
}

func checkExtra(extra map[string]string) error {
	if len(extra) > maxExtraEntries {
		return &ValidationError{Field: "extra", Reason: "at most 16 entries are allowed"}
	}
	for _, name := range slices.Sorted(maps.Keys(extra)) {
		if !validExtraName(name) {
			return &ValidationError{Field: "extra", Reason: "the name of an entry is 1 to 64 characters from a-z, 0-9, _, . and -"}
		}
		value := extra[name]
		switch {
		case len(value) > maxExtraValueLength:
			return &ValidationError{Field: "extra", Reason: "the value of " + name + " is longer than 1024 bytes"}
		case !utf8.ValidString(value), hasControl(value):
			return &ValidationError{Field: "extra", Reason: "the value of " + name + " is not text without control characters"}
		}
	}
	return nil
}

func validExtraName(name string) bool {
	if name == "" || len(name) > maxExtraNameLength {
		return false
	}
	return !strings.ContainsFunc(name, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '.' && r != '-'
	})
}

func (a *Auth) signupLabels(pending []pendingIdentifier) []channelLabel {
	var labels []channelLabel
	for _, p := range pending {
		if p.kind.IsDelivery() {
			labels = append(labels, channelLabel{kind: "type:" + p.kind.Name(), value: p.value})
		}
	}
	return labels
}

func hookRegistration(r Registration, pending []pendingIdentifier) Registration {
	identifiers := make(map[string]string, len(pending))
	for _, p := range pending {
		identifiers[p.kind.Name()] = p.value
	}
	return Registration{Identifiers: identifiers, Extra: maps.Clone(r.Extra)}
}

func (a *Auth) beforeRegister(ctx context.Context, r Registration) (err error) {
	if a.hooks.BeforeRegister == nil {
		return nil
	}
	defer func() {
		if p := recover(); p != nil {
			a.logger.ErrorContext(ctx, "limb: the hook before a registration panicked", "panic_type", fmt.Sprintf("%T", p))
			err = ErrRegistrationRefused
		}
	}()
	refusal := a.hooks.BeforeRegister(ctx, r)
	var invalid *ValidationError
	switch {
	case refusal == nil:
		return nil
	case errors.As(refusal, &invalid):
		return invalid
	}
	a.logger.WarnContext(ctx, "limb: the hook before a registration refused it", "error", refusal)
	return ErrRegistrationRefused
}

func (a *Auth) deliveryLast(identifiers []store.Identifier) {
	slices.SortStableFunc(identifiers, func(x, y store.Identifier) int {
		return deliveryRank(a.known[x.Type].IsDelivery()) - deliveryRank(a.known[y.Type].IsDelivery())
	})
}

func deliveryRank(delivery bool) int {
	if delivery {
		return 1
	}
	return 0
}

func (a *Auth) storeSignup(ctx context.Context, user store.User, identifiers []store.Identifier) (*store.Identifier, error) {
	var taken store.Identifier
	conflict := false
	err := a.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		conflict = false
		if err := tx.Users().Create(ctx, user); err != nil {
			return fmt.Errorf("limb: create the user: %w", err)
		}
		for _, i := range identifiers {
			err := tx.Identifiers().Add(ctx, i)
			switch {
			case err == nil:
			case errors.Is(err, store.ErrConflict):
				taken, conflict = i, true
				return err
			default:
				return fmt.Errorf("limb: add the %s identifier: %w", i.Type, err)
			}
		}
		return nil
	})
	switch {
	case conflict && errors.Is(err, store.ErrConflict):
		if !a.known[taken.Type].IsDelivery() {
			return nil, &ValidationError{Field: taken.Type, Reason: "already taken"}
		}
		return &taken, nil
	case err != nil:
		return nil, err
	}
	return nil, nil
}

func (a *Auth) queueVerification(ctx context.Context, userID, language string) {
	if !a.recoveryReady() {
		return
	}
	job := recoveryJob{purpose: store.PurposeVerify, kind: MessageVerification, language: language}
	err := a.dispatcher.submit(task{kind: job.kind, run: func(ctx context.Context) error {
		return a.sendSecretsToUser(ctx, userID, job)
	}})
	if err != nil {
		a.logger.WarnContext(ctx, "limb: the message that confirms a new user is not queued, the user can ask for it again", "error", err)
	}
}

func (a *Auth) queueSignupAttempt(ctx context.Context, taken store.Identifier, language string) {
	if !a.recoveryReady() {
		return
	}
	err := a.dispatcher.submit(task{kind: MessageSignupAttempt, channel: taken.Type, run: func(ctx context.Context) error {
		return a.sendSignupAttempt(ctx, taken.Type, taken.Value, language)
	}})
	if err != nil {
		a.logger.WarnContext(ctx, "limb: the notice of a signup attempt is not queued", "error", err)
	}
}

func (a *Auth) sendSignupAttempt(ctx context.Context, typ, value, language string) error {
	channel, found, err := a.findIdentifier(ctx, typ, value)
	if err != nil || !found {
		return err
	}
	owner, err := a.store.Users().Get(ctx, a.tenant, channel.UserID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("limb: get the user: %w", err)
	case owner.Status == store.StatusDeleted:
		return nil
	}
	return a.sendNoticeTo(ctx, owner.ID, channel, MessageSignupAttempt, language)
}
