package limb

import (
	"time"

	"github.com/acneism/limb/store"
)

// UserID identifies a user. It is a UUID in text form, so it can be kept as a
// string in the tables of the application.
type UserID string

// Status is the state of a user account.
type Status = store.Status

// The states of a user account.
const (
	// StatusActive is an account that can sign in.
	StatusActive = store.StatusActive
	// StatusBlocked is an account that was blocked.
	StatusBlocked = store.StatusBlocked
	// StatusDeleted is an account that was deleted but is still kept.
	StatusDeleted = store.StatusDeleted
)

// User is an account without its secrets.
type User struct {
	// ID identifies the user.
	ID UserID
	// Status is the state of the account.
	Status Status
	// Identifiers are the values the user signs in with and is reached at.
	Identifiers []UserIdentifier
	// MustChangePassword is set when the user has to choose a new password
	// before using the service.
	MustChangePassword bool
	// CreatedAt is when the account was created, in UTC.
	CreatedAt time.Time
	// LastLoginAt is when the user signed in last, the zero time if never.
	LastLoginAt time.Time
}

// UserIdentifier is a value of one of the identifier types of a user.
type UserIdentifier struct {
	// Type is the name of the identifier type, for example "email".
	Type string
	// Value is the normalized value that is stored and compared.
	Value string
	// DisplayValue is the value as the user wrote it.
	DisplayValue string
	// VerifiedAt is when the user proved to own the value, the zero time if
	// they did not.
	VerifiedAt time.Time
}

func newUser(u store.User, identifiers []store.Identifier) User {
	user := User{
		ID:                 UserID(u.ID),
		Status:             u.Status,
		MustChangePassword: u.MustChangePassword,
		CreatedAt:          u.CreatedAt,
		LastLoginAt:        u.LastLoginAt,
		Identifiers:        make([]UserIdentifier, 0, len(identifiers)),
	}
	for _, i := range identifiers {
		user.Identifiers = append(user.Identifiers, UserIdentifier{
			Type:         i.Type,
			Value:        i.Value,
			DisplayValue: i.DisplayValue,
			VerifiedAt:   i.VerifiedAt,
		})
	}
	return user
}
