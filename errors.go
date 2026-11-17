package limb

import (
	"errors"
	"fmt"
	"strings"
	"time"
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

	// ErrUnauthenticated is returned when a request has no valid session or
	// token. It is the same whatever the reason is: no cookie, a damaged or
	// expired token, a session that was ended, a user who is blocked or deleted.
	ErrUnauthenticated = errors.New("limb: unauthenticated")

	// ErrRateLimited is the error that matches a *RateLimitError, which says
	// when to try again. Compare with errors.Is.
	ErrRateLimited = errors.New("limb: too many attempts")

	// ErrPasswordChangeRequired is returned when the user must choose a new
	// password before doing anything else.
	ErrPasswordChangeRequired = errors.New("limb: password change required")

	// ErrCSRF is returned when a request that changes data with a cookie session
	// does not pass the check that it comes from the page of the application.
	ErrCSRF = errors.New("limb: cross-site request check failed")

	// ErrSessionNotFound is returned when the user has no active session with the
	// given ID. It is the same for a session that belongs to someone else.
	ErrSessionNotFound = errors.New("limb: session not found")

	// ErrInvalidSecret is returned when a link or a code that confirms an address
	// or resets a password is not accepted. It is the same for a link that is
	// unknown, expired or used, a code that is wrong, expired or used up, a login
	// or a channel that no code was sent to and a secret meant for something
	// else, so it reveals nothing about which accounts exist.
	ErrInvalidSecret = errors.New("limb: the link or the code is not valid")
)

// RateLimitError reports that there were too many failed attempts and says how
// long to wait. It matches ErrRateLimited with errors.Is. Functions return it as
// a *RateLimitError, so use errors.As with a variable of that type.
type RateLimitError struct {
	// RetryAfter is how long to wait before the next attempt, rounded up to a
	// whole second.
	RetryAfter time.Duration
}

// Error implements the error interface.
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("limb: too many attempts, try again in %s", e.RetryAfter)
}

// Is makes a *RateLimitError match ErrRateLimited.
func (e *RateLimitError) Is(target error) bool {
	return target == ErrRateLimited
}

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
