// Package admin holds the accounts of the administrators of the service, which
// are kept apart from the accounts of users: how they are made, changed and
// removed, and the second factor that they sign in with. The administrators are
// made and removed only from the code of the application or from the command
// line, never from the web.
package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/store"
)

const (
	// MinLoginLength is the shortest login of an administrator.
	MinLoginLength = 3

	maxChangeAttempts = 3
)

var (
	// ErrNotFound is returned for an administrator that does not exist.
	ErrNotFound = errors.New("admin: the administrator does not exist")

	// ErrLoginTaken is returned when another administrator has the login.
	ErrLoginTaken = errors.New("admin: the login is taken")

	// ErrConcurrent is returned when the account kept changing under the call,
	// which means that another change won the race again and again.
	ErrConcurrent = errors.New("admin: the account kept changing under the call")
)

// LoginError reports a login that breaks the rules for the logins of
// administrators.
type LoginError struct {
	// Reason says which rule was broken.
	Reason string
}

// Error implements the error interface.
func (e *LoginError) Error() string {
	return "admin: the login is not valid: " + e.Reason
}

// PolicyError reports a password that breaks the password policy. Rules lists
// the rules that it broke.
type PolicyError struct {
	Rules []string
}

// Error implements the error interface.
func (e *PolicyError) Error() string {
	return "admin: the password does not meet the policy: " + strings.Join(e.Rules, ", ")
}

// Hasher makes and checks the hashes of passwords.
type Hasher interface {
	// Hash returns the encoded hash of the password.
	Hash(ctx context.Context, password string) (string, error)
	// Verify checks the password against an encoded hash and says whether the
	// hash was made with weaker parameters than the current ones.
	Verify(ctx context.Context, password, encoded string) (ok, needsRehash bool, err error)
	// DummyVerify does the work of Verify for an account that does not exist.
	DummyVerify(ctx context.Context, password string) error
}

// Config is what the service needs from the application.
type Config struct {
	// Store is the storage.
	Store store.Store
	// Keys are the keys derived from the master key.
	Keys *secret.Keys
	// Hasher hashes the passwords.
	Hasher Hasher
	// Policy returns the rules that a password breaks, given the logins that it may
	// not equal. It returns nothing for a password that is good.
	Policy func(ctx context.Context, password string, logins []string) []string
	// Tenant is the tenant of the administrators.
	Tenant string
	// Issuer is the name that an authenticator application shows with the account.
	Issuer string
	// Now gives the current time.
	Now func() time.Time
	// NewID gives the ID of a new administrator and of a record of the audit log.
	NewID func() (string, error)
	// SessionAbsolute is how long a session lasts whatever its activity is.
	SessionAbsolute time.Duration
	// SessionIdle is how long a session lasts without being used.
	SessionIdle time.Duration
	// WithoutTOTP lets an administrator in with the password alone, for the
	// development mode.
	WithoutTOTP bool
}

// Service manages the administrators.
type Service struct {
	store  store.Store
	keys   *secret.Keys
	hasher Hasher
	policy func(ctx context.Context, password string, logins []string) []string
	tenant string
	issuer string
	now    func() time.Time
	newID  func() (string, error)
	audit  audit.Writer

	absolute time.Duration
	idle     time.Duration
	noTOTP   bool
}

// New creates the service.
func New(c Config) *Service {
	return &Service{
		store:  c.Store,
		keys:   c.Keys,
		hasher: c.Hasher,
		policy: c.Policy,
		tenant: c.Tenant,
		issuer: c.Issuer,
		now:    c.Now,
		newID:  c.NewID,
		audit:  audit.Writer{Tenant: c.Tenant, Now: c.Now, NewID: c.NewID},

		absolute: c.SessionAbsolute,
		idle:     c.SessionIdle,
		noTOTP:   c.WithoutTOTP,
	}
}

// Account is an administrator as it is shown. It holds nothing that signs in.
type Account struct {
	// ID is the identifier of the administrator.
	ID string
	// Login is the normalized login.
	Login string
	// Disabled tells that the administrator cannot sign in.
	Disabled bool
	// TOTPBound tells that the administrator has bound an authenticator and
	// confirmed it.
	TOTPBound bool
	// RecoveryCodes is how many recovery codes the administrator has not used.
	RecoveryCodes int
	// CreatedAt is when the account was made.
	CreatedAt time.Time
	// LastLoginAt is when the administrator last signed in, the zero time if they
	// never did.
	LastLoginAt time.Time
}

func accountOf(a store.Admin, recoveryCodes int) Account {
	return Account{
		ID:            a.ID,
		Login:         a.Login,
		Disabled:      a.Status == store.AdminDisabled,
		TOTPBound:     !a.TOTPConfirmedAt.IsZero(),
		RecoveryCodes: recoveryCodes,
		CreatedAt:     a.CreatedAt,
		LastLoginAt:   a.LastLoginAt,
	}
}

// NormalizeLogin returns the form of a login in which it is stored and compared:
// the text without the spaces around it, in NFKC and in lower case. It has from
// MinLoginLength to store.MaxAdminLoginLength characters from a to z, 0 to 9, the
// dot, the underscore and the hyphen, and begins with a letter or a digit, so
// that it cannot be taken for an option of a command line.
func NormalizeLogin(login string) (string, error) {
	text := strings.ToLower(norm.NFKC.String(strings.TrimSpace(login)))
	if len(text) < MinLoginLength || len(text) > store.MaxAdminLoginLength {
		return "", &LoginError{Reason: fmt.Sprintf("it has from %d to %d characters", MinLoginLength, store.MaxAdminLoginLength)}
	}
	for i := range len(text) {
		c := text[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return "", &LoginError{Reason: "it has only the letters a to z, the digits, the dot, the underscore and the hyphen"}
		}
	}
	if first := text[0]; first == '.' || first == '_' || first == '-' {
		return "", &LoginError{Reason: "it begins with a letter or a digit"}
	}
	return text, nil
}
