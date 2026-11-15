package store

import (
	"context"
	"time"
)

// Status is the state of a user account.
type Status string

// The states of a user account.
const (
	// StatusActive is an account that can sign in.
	StatusActive Status = "active"
	// StatusBlocked is an account that is blocked until BlockedUntil, or
	// without a time limit when BlockedUntil is not set.
	StatusBlocked Status = "blocked"
	// StatusDeleted is an account that was deleted but is kept until
	// PurgeAfter, so that it can be restored and its identifiers stay taken.
	StatusDeleted Status = "deleted"
)

// User is an account. The pair of TenantID and ID identifies it.
type User struct {
	// TenantID is the tenant the user belongs to.
	TenantID string
	// ID is the identifier of the user, a UUID in text form.
	ID string
	// Status is the state of the account.
	Status Status
	// PasswordHash is the encoded password hash, empty if the user has none.
	PasswordHash string
	// MustChangePassword requires the user to choose a new password before
	// using the service.
	MustChangePassword bool
	// BlockedReason is why the account was blocked, empty if it was not.
	BlockedReason string
	// BlockedUntil is when a block ends, the zero time if there is none.
	BlockedUntil time.Time
	// DeletedAt is when the account was deleted, the zero time if it was not.
	DeletedAt time.Time
	// PurgeAfter is when a deleted account is removed for good.
	PurgeAfter time.Time
	// CreatedAt is when the account was created.
	CreatedAt time.Time
	// LastLoginAt is the time of the last sign-in, the zero time if there was
	// none.
	LastLoginAt time.Time
	// Version counts the changes of the record. Create stores 1 and every
	// successful Update adds one; Update refuses a record whose version is not
	// the stored one.
	Version int64
}

// Identifier is a value a user signs in with or is reached at, such as an
// e-mail address. The triple of TenantID, Type and Value is unique.
type Identifier struct {
	// TenantID is the tenant the identifier belongs to.
	TenantID string
	// Type is the name of the identifier type, for example "email".
	Type string
	// Value is the normalized value that is stored and searched by.
	Value string
	// DisplayValue is the value as the user wrote it.
	DisplayValue string
	// UserID is the user the identifier belongs to.
	UserID string
	// VerifiedAt is when ownership of the value was confirmed, the zero time
	// if it was not.
	VerifiedAt time.Time
}

// Users stores user accounts.
type Users interface {
	// Create stores a new user with version 1, whatever u.Version is. It
	// returns ErrConflict if the user already exists.
	Create(ctx context.Context, u User) error

	// Get returns the user or ErrNotFound.
	Get(ctx context.Context, tenantID, id string) (User, error)

	// Update replaces the mutable fields of the user, that is everything except
	// the tenant, the ID and CreatedAt, if the stored version equals u.Version,
	// and returns u with the version increased. It returns ErrNotFound if
	// there is no such user and ErrStale if the version differs.
	Update(ctx context.Context, u User) (User, error)

	// Delete removes the user together with its identifiers, or returns
	// ErrNotFound.
	Delete(ctx context.Context, tenantID, id string) error
}

// Identifiers stores the identifiers of users.
type Identifiers interface {
	// Add stores a new identifier. It returns ErrConflict if the value is
	// taken in its tenant and type, and ErrNotFound if the user does not exist.
	Add(ctx context.Context, i Identifier) error

	// Find returns the identifier with the given value or ErrNotFound.
	Find(ctx context.Context, tenantID, typ, value string) (Identifier, error)

	// ListByUser returns the identifiers of the user ordered by type and value.
	ListByUser(ctx context.Context, tenantID, userID string) ([]Identifier, error)

	// Remove deletes the identifier or returns ErrNotFound.
	Remove(ctx context.Context, tenantID, typ, value string) error

	// MarkVerified records that ownership of the value was confirmed at the
	// given time, or returns ErrNotFound.
	MarkVerified(ctx context.Context, tenantID, typ, value string, at time.Time) error
}
