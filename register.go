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
	"github.com/acneism/limb/store"
)

// Registration is the data of a new user.
type Registration struct {
	// Identifiers maps the name of an identifier type to the value the user
	// gave, for example "email" to "alice@example.com". A blank value counts as
	// missing. At least one type that allows signing in must have a value.
	Identifiers map[string]string

	// Password is the password the user chose.
	Password string
}

type pendingIdentifier struct {
	kind    identifier.Type
	value   string
	display string
}

// Register creates a user. It checks that every given identifier type is
// declared and every required one is present, normalizes the values, checks
// the password against the password policy and stores the user and its
// identifiers in one transaction.
//
// It returns a *ValidationError for a rejected value, a *PolicyError for a
// password that breaks the policy and ErrIdentifierTaken if another user
// already has one of the values. Whoever exposes Register to the internet
// should not tell visitors which e-mail addresses or phone numbers are taken.
func (a *Auth) Register(ctx context.Context, r Registration) (User, error) {
	pending, err := a.collectIdentifiers(r.Identifiers)
	if err != nil {
		return User{}, err
	}
	if err = a.enforcePolicy(ctx, r.Password, pending); err != nil {
		return User{}, err
	}
	hash, err := a.hasher.Hash(ctx, r.Password)
	if err != nil {
		return User{}, fmt.Errorf("limb: hash the password: %w", err)
	}
	id, err := a.newID()
	if err != nil {
		return User{}, err
	}
	user := store.User{
		TenantID:     a.tenant,
		ID:           id,
		Status:       store.StatusActive,
		PasswordHash: hash,
		CreatedAt:    a.now().UTC().Truncate(time.Microsecond),
	}
	identifiers := make([]store.Identifier, 0, len(pending))
	for _, p := range pending {
		identifiers = append(identifiers, store.Identifier{
			TenantID:     a.tenant,
			Type:         p.kind.Name(),
			Value:        p.value,
			DisplayValue: p.display,
			UserID:       id,
		})
	}
	if err = a.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		return storeNewUser(ctx, tx, user, identifiers)
	}); err != nil {
		return User{}, err
	}
	user.Version = 1
	return newUser(user, identifiers), nil
}

func storeNewUser(ctx context.Context, tx store.Repositories, user store.User, identifiers []store.Identifier) error {
	if err := tx.Users().Create(ctx, user); err != nil {
		return fmt.Errorf("limb: create the user: %w", err)
	}
	for _, i := range identifiers {
		err := tx.Identifiers().Add(ctx, i)
		switch {
		case err == nil:
		case errors.Is(err, store.ErrConflict):
			return fmt.Errorf("%w: %s", ErrIdentifierTaken, i.Type)
		default:
			return fmt.Errorf("limb: add the %s identifier: %w", i.Type, err)
		}
	}
	return nil
}

func (a *Auth) collectIdentifiers(given map[string]string) ([]pendingIdentifier, error) {
	for _, name := range slices.Sorted(maps.Keys(given)) {
		if _, declared := a.known[name]; !declared {
			return nil, &ValidationError{Field: name, Reason: "unknown identifier type"}
		}
	}
	var pending []pendingIdentifier
	canSignIn := false
	for _, kind := range a.types {
		raw := strings.TrimSpace(given[kind.Name()])
		if raw == "" {
			if kind.IsRequired() {
				return nil, &ValidationError{Field: kind.Name(), Reason: "required"}
			}
			continue
		}
		value, err := kind.Normalize(raw)
		if err != nil {
			return nil, &ValidationError{Field: kind.Name(), Reason: err.Error()}
		}
		pending = append(pending, pendingIdentifier{kind: kind, value: value, display: raw})
		canSignIn = canSignIn || kind.IsLogin()
	}
	if !canSignIn {
		return nil, &ValidationError{Field: "identifiers", Reason: "at least one value to sign in with is required"}
	}
	return pending, nil
}

func (a *Auth) enforcePolicy(ctx context.Context, password string, pending []pendingIdentifier) error {
	logins := make([]string, 0, 2*len(pending))
	for _, p := range pending {
		logins = append(logins, p.value, p.display)
	}
	if rules := a.policy.Check(ctx, password, logins); len(rules) > 0 {
		return &PolicyError{Rules: rules}
	}
	return nil
}
