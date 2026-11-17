package limb

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

// NewUser is a user that an administrator creates with a password.
type NewUser struct {
	// Identifiers maps the name of an identifier type to its value, as in
	// Registration.
	Identifiers map[string]string

	// Password is the password of the user. It has to meet the password policy.
	Password string

	// KeepPassword says that the user does not have to choose another password
	// when they first sign in. Without it they do.
	KeepPassword bool

	// Verified lists the identifier types whose values the administrator vouches
	// for, as in Registration. It is written to the audit log.
	Verified []string
}

func (a *Auth) createUser(ctx context.Context, by actorRef, n NewUser) (ManagedUser, error) {
	pending, err := a.collectIdentifiers(n.Identifiers)
	if err != nil {
		return ManagedUser{}, err
	}
	confirmed, err := a.checkVerified(n.Verified, pending)
	if err != nil {
		return ManagedUser{}, err
	}
	if err = a.enforcePolicy(ctx, n.Password, pending); err != nil {
		return ManagedUser{}, err
	}
	hash, err := a.hasher.Hash(ctx, n.Password)
	if err != nil {
		return ManagedUser{}, fmt.Errorf("limb: hash the password: %w", err)
	}
	id, err := a.newID()
	if err != nil {
		return ManagedUser{}, err
	}
	user, identifiers := a.newAccount(id, hash, store.CreatedViaAdmin, pending, confirmed)
	user.MustChangePassword = !n.KeepPassword
	details := map[string]any{"identifiers": identifierValues(identifiers), "must_change_password": user.MustChangePassword}
	event := Event{Type: EventUserCreated, UserID: id, IP: by.ip, Details: map[string]string{"via": "admin"}}
	if len(confirmed) > 0 {
		verified := slices.Sorted(maps.Keys(confirmed))
		details["verified"] = verified
		event.Details["verified"] = strings.Join(verified, ",")
	}
	err = a.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if storeErr := storeNewUser(ctx, tx, user, identifiers); storeErr != nil {
			return storeErr
		}
		return a.auditWriter().Add(ctx, tx.Audit(), audit.Entry{
			Actor: by.actor, Action: audit.UserCreated, TargetUserID: id, IP: by.ip, Details: details,
		})
	})
	if err != nil {
		return ManagedUser{}, err
	}
	user.Version = 1
	a.emitHook(ctx, event)
	return a.createdUser(user, identifiers), nil
}

func (a *Auth) kindOf(typ string) (identifier.Type, error) {
	kind, declared := a.known[typ]
	if !declared {
		return identifier.Type{}, &ValidationError{Field: typ, Reason: "unknown identifier type"}
	}
	return kind, nil
}

func (a *Auth) changeIdentifier(ctx context.Context, by actorRef, id UserID, typ, value string) error {
	kind, err := a.kindOf(typ)
	if err != nil {
		return err
	}
	raw := strings.TrimSpace(value)
	if raw == "" {
		return &ValidationError{Field: typ, Reason: "required"}
	}
	normalized, err := kind.Normalize(raw)
	if err != nil {
		return &ValidationError{Field: typ, Reason: err.Error()}
	}
	var told []store.Identifier
	err = a.editUser(ctx, by, id, func(ctx context.Context, tx store.Repositories, u store.User, _ time.Time) (userEdit, error) {
		told = nil
		identifiers, listErr := tx.Identifiers().ListByUser(ctx, a.tenant, u.ID)
		if listErr != nil {
			return userEdit{}, fmt.Errorf("limb: list the identifiers: %w", listErr)
		}
		var old []store.Identifier
		for _, i := range identifiers {
			if i.Type == typ {
				old = append(old, i)
			}
		}
		if len(old) == 1 && old[0].Value == normalized {
			return userEdit{}, nil
		}
		told = a.deliveryChannels(identifiers, true)
		for _, i := range old {
			if removeErr := tx.Identifiers().Remove(ctx, a.tenant, i.Type, i.Value); removeErr != nil {
				return userEdit{}, fmt.Errorf("limb: remove the %s identifier: %w", i.Type, removeErr)
			}
		}
		added := store.Identifier{TenantID: a.tenant, Type: typ, Value: normalized, DisplayValue: raw, UserID: u.ID}
		if addErr := tx.Identifiers().Add(ctx, added); addErr != nil {
			if errors.Is(addErr, store.ErrConflict) {
				return userEdit{}, fmt.Errorf("%w: %s", ErrIdentifierTaken, typ)
			}
			return userEdit{}, fmt.Errorf("limb: add the %s identifier: %w", typ, addErr)
		}
		action, change := audit.UserIdentifierAdded, "identifier_added"
		details := map[string]any{"type": typ, "new": normalized}
		if len(old) > 0 {
			action, change = audit.UserIdentifierChanged, "identifier_changed"
			details["old"] = old[0].Value
			details["old_verified"] = !old[0].VerifiedAt.IsZero()
		}
		return userEdit{
			next: u, update: true, entry: &audit.Entry{Action: action, Details: details},
			events: []Event{{Type: EventUserChanged, Channel: typ, Address: maskValue(normalized), Details: map[string]string{"change": change}}},
		}, nil
	})
	if err == nil && len(told) > 0 {
		a.notifyIdentifierChanged(ctx, string(id), told)
	}
	return err
}

func (a *Auth) removeIdentifier(ctx context.Context, by actorRef, id UserID, typ string) error {
	kind, err := a.kindOf(typ)
	if err != nil {
		return err
	}
	if kind.IsRequired() {
		return &ValidationError{Field: typ, Reason: "required"}
	}
	var told []store.Identifier
	err = a.editUser(ctx, by, id, func(ctx context.Context, tx store.Repositories, u store.User, _ time.Time) (userEdit, error) {
		told = nil
		identifiers, listErr := tx.Identifiers().ListByUser(ctx, a.tenant, u.ID)
		if listErr != nil {
			return userEdit{}, fmt.Errorf("limb: list the identifiers: %w", listErr)
		}
		var old []store.Identifier
		signIn := 0
		for _, i := range identifiers {
			switch {
			case i.Type == typ:
				old = append(old, i)
			case a.known[i.Type].IsLogin():
				signIn++
			}
		}
		switch {
		case len(old) == 0:
			return userEdit{}, &ValidationError{Field: typ, Reason: "the user has no value of this type"}
		case signIn == 0:
			return userEdit{}, &ValidationError{Field: "identifiers", Reason: "at least one value to sign in with is required"}
		}
		told = a.deliveryChannels(identifiers, true)
		for _, i := range old {
			if removeErr := tx.Identifiers().Remove(ctx, a.tenant, i.Type, i.Value); removeErr != nil {
				return userEdit{}, fmt.Errorf("limb: remove the %s identifier: %w", i.Type, removeErr)
			}
		}
		details := map[string]any{"type": typ, "old": old[0].Value, "old_verified": !old[0].VerifiedAt.IsZero()}
		return userEdit{
			next: u, update: true, entry: &audit.Entry{Action: audit.UserIdentifierRemoved, Details: details},
			events: []Event{{Type: EventUserChanged, Channel: typ, Address: maskValue(old[0].Value), Details: map[string]string{"change": "identifier_removed"}}},
		}, nil
	})
	if err == nil && len(told) > 0 {
		a.notifyIdentifierChanged(ctx, string(id), told)
	}
	return err
}

func (a *Auth) verifyIdentifier(ctx context.Context, by actorRef, id UserID, typ string) error {
	kind, err := a.kindOf(typ)
	if err != nil {
		return err
	}
	if !kind.IsDelivery() {
		return &ValidationError{Field: typ, Reason: "only an address or a phone number can be confirmed"}
	}
	return a.editUser(ctx, by, id, func(ctx context.Context, tx store.Repositories, u store.User, now time.Time) (userEdit, error) {
		identifiers, listErr := tx.Identifiers().ListByUser(ctx, a.tenant, u.ID)
		if listErr != nil {
			return userEdit{}, fmt.Errorf("limb: list the identifiers: %w", listErr)
		}
		index := slices.IndexFunc(identifiers, func(i store.Identifier) bool { return i.Type == typ })
		switch {
		case index < 0:
			return userEdit{}, &ValidationError{Field: typ, Reason: "the user has no value of this type"}
		case !identifiers[index].VerifiedAt.IsZero():
			return userEdit{}, nil
		}
		target := identifiers[index]
		if markErr := tx.Identifiers().MarkVerified(ctx, a.tenant, target.Type, target.Value, now); markErr != nil {
			return userEdit{}, fmt.Errorf("limb: confirm the %s identifier: %w", typ, markErr)
		}
		return userEdit{
			next: u, update: true, entry: &audit.Entry{Action: audit.UserIdentifierVerified, Details: map[string]any{"type": typ, "value": target.Value}},
			events: []Event{{Type: EventUserChanged, Channel: typ, Address: maskValue(target.Value), Details: map[string]string{"change": "identifier_verified"}}},
		}, nil
	})
}

func (a *Auth) notifyIdentifierChanged(ctx context.Context, userID string, channels []store.Identifier) {
	if !a.recoveryReady() {
		return
	}
	language := a.languageFor(ctx, "")
	err := a.dispatcher.submit(task{kind: MessageIdentifierChanged, run: func(ctx context.Context) error {
		for _, channel := range channels {
			if sendErr := a.sendNoticeTo(ctx, userID, channel, MessageIdentifierChanged, language); sendErr != nil {
				a.failMessage(ctx, sendErr)
			}
		}
		return nil
	}})
	if err != nil {
		a.logger.WarnContext(ctx, "limb: the notice that the details of a user were changed is not sent", "error", err)
	}
}

// CreateUser creates a user with a password. The user has to choose another
// password when they first sign in unless KeepPassword is set. The checks are
// those of Register, and what the administrator vouches for is written to the
// audit log. It returns a *ValidationError for a rejected value, a *PolicyError
// for a password that breaks the policy and ErrIdentifierTaken if another user
// has one of the values.
func (x *AdminAPI) CreateUser(ctx context.Context, n NewUser) (ManagedUser, error) {
	return x.a.createUser(ctx, apiActor, n)
}

// SetUserIdentifier gives the user a value of an identifier type, or replaces the
// value that they have. The value is checked and normalized as in Register, and
// the new one is not confirmed. A user who has the value already is left as they
// are. The users who had a confirmed address or phone number before the change
// get a notice on it, in the background. It returns a *ValidationError for a type
// that is not declared or a value that is rejected, ErrIdentifierTaken,
// ErrUserNotFound and ErrUserDeleted.
func (x *AdminAPI) SetUserIdentifier(ctx context.Context, id UserID, typ, value string) error {
	return x.a.changeIdentifier(ctx, apiActor, id, typ, value)
}

// RemoveUserIdentifier takes away the value that the user has of an identifier
// type, and tells them on the channels that were confirmed before. It returns a
// *ValidationError for a type that is required, one that the user has no value
// of, and for a removal that would leave no value to sign in with, and
// ErrUserNotFound and ErrUserDeleted.
func (x *AdminAPI) RemoveUserIdentifier(ctx context.Context, id UserID, typ string) error {
	return x.a.removeIdentifier(ctx, apiActor, id, typ)
}

// VerifyUserIdentifier marks the address or the phone number that the user has of
// the type as confirmed, on the word of the administrator, which the audit log
// keeps. It does nothing if it is confirmed already. It returns a
// *ValidationError for a type that is no channel or that the user has no value of,
// and ErrUserNotFound and ErrUserDeleted.
func (x *AdminAPI) VerifyUserIdentifier(ctx context.Context, id UserID, typ string) error {
	return x.a.verifyIdentifier(ctx, apiActor, id, typ)
}
