package limb

import (
	"context"

	"github.com/acneism/limb/internal/password"
)

// PasswordPolicy sets what a password must look like. The zero value is the
// default policy: 12 to 128 characters after Unicode NFKC normalization, no
// rules about the kinds of characters, no password from the list of common
// passwords and no password equal to one of the user's login identifiers.
type PasswordPolicy struct {
	// MinLength is the least number of characters, 12 if zero. It must not be
	// below 8.
	MinLength int

	// MaxLength is the greatest number of characters, 128 if zero. It must not
	// be below MinLength or above 1024.
	MaxLength int

	// AllowCommon lets users choose a password from the built-in list of common
	// passwords.
	AllowCommon bool

	// AllowLoginIdentifier lets users choose a password that is equal to one of
	// their login identifiers.
	AllowLoginIdentifier bool

	// Checks are extra rules, for example a lookup in a database of leaked
	// passwords. A check receives the password after NFKC normalization and
	// returns an error to reject it. The text of the error is added to the
	// rules of the PolicyError and may be shown to the user or sent to the
	// clients of an HTTP API, so return a short code such as "breached" and
	// never a sentence with details or a part of the password.
	Checks []func(ctx context.Context, password string) error
}

func (p PasswordPolicy) internal() password.Policy {
	return password.Policy{
		MinLength:   p.MinLength,
		MaxLength:   p.MaxLength,
		AllowCommon: p.AllowCommon,
		AllowLogin:  p.AllowLoginIdentifier,
		Custom:      p.Checks,
	}.WithDefaults()
}
