package limb

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInvalidCredentials is returned when the login or the password is
	// wrong. It is the same for an unknown login, a wrong password and an
	// account that cannot sign in, so it reveals nothing about which accounts
	// exist.
	ErrInvalidCredentials = errors.New("limb: invalid credentials")

	// ErrUserBlocked is returned when the password is right but the account is
	// blocked. It is never returned for a wrong password.
	ErrUserBlocked = errors.New("limb: user is blocked")

	// ErrIdentifierTaken is returned by Register when a value is already used
	// by another user. The error text names the type of the identifier.
	ErrIdentifierTaken = errors.New("limb: identifier is taken")
)

// ValidationError reports a value that was rejected. Field is the name of the
// identifier type, or "identifiers" when the set of values as a whole is wrong,
// and Reason says why. Functions return it as a *ValidationError, so use
// errors.As with a variable of that type.
type ValidationError struct {
	Field  string
	Reason string
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	return fmt.Sprintf("limb: invalid %s: %s", e.Field, e.Reason)
}

// PolicyError reports a password that breaks the password policy. Rules lists
// every rule that was broken: "min_length", "max_length", "common_password"
// and "login_identifier" for the built-in rules, followed by the texts of the
// errors returned by the custom checks of the policy. Functions return it as a
// *PolicyError, so use errors.As with a variable of that type.
type PolicyError struct {
	Rules []string
}

// Error implements the error interface.
func (e *PolicyError) Error() string {
	return "limb: password does not meet the policy: " + strings.Join(e.Rules, ", ")
}
