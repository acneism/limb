package store

import "time"

// UserOrder tells what a listing of users is ordered by. The users that have the
// same value are ordered by ID.
type UserOrder string

// The orders of a listing of users.
const (
	// OrderUsersByCreation orders by the time the account was created. It is what
	// an empty order means.
	OrderUsersByCreation UserOrder = "created"
	// OrderUsersByLastLogin orders by the time of the last sign-in. The users
	// that never signed in come after all the others, whichever way the order
	// goes.
	OrderUsersByLastLogin UserOrder = "last_login"
	// OrderUsersByStatus orders by the status of the account, which is the order
	// of its name.
	OrderUsersByStatus UserOrder = "status"
)

// IdentifierRef names one identifier by its type and its normalized value.
type IdentifierRef struct {
	// Type is the name of the identifier type.
	Type string
	// Value is the normalized value.
	Value string
}

// UserQuery picks users and orders them. The conditions that are set all have to
// hold.
type UserQuery struct {
	// TenantID is the tenant of the users.
	TenantID string
	// Statuses keeps the users whose status is one of these.
	Statuses []Status
	// Confirmed keeps the users that have, when it points at true, or have not,
	// when it points at false, an identifier whose ownership was confirmed.
	Confirmed *bool
	// CreatedVia keeps the users that were made this way.
	CreatedVia CreatedVia
	// CreatedFrom keeps the users made at this moment or later, the zero time sets
	// no bound.
	CreatedFrom time.Time
	// CreatedBefore keeps the users made before this moment, the zero time sets no
	// bound.
	CreatedBefore time.Time
	// LastLoginFrom keeps the users who signed in last at this moment or later,
	// the zero time sets no bound. A user who never signed in does not match.
	LastLoginFrom time.Time
	// LastLoginBefore keeps the users who signed in last before this moment, the
	// zero time sets no bound. A user who never signed in does not match.
	LastLoginBefore time.Time
	// NeverLoggedIn keeps the users who never signed in.
	NeverLoggedIn bool
	// PurgeBefore keeps the users whose time of removal is before this moment, the
	// zero time sets no bound. A user that has no time of removal does not match.
	PurgeBefore time.Time
	// Identifiers keeps the users that have at least one of these identifiers,
	// at most MaxUserIdentifierRefs of them.
	Identifiers []IdentifierRef
	// ValuePrefix keeps the users that have an identifier of any type whose
	// normalized value starts with it, byte by byte. A percent sign, an underscore
	// and an exclamation mark in it stand for themselves.
	ValuePrefix string
	// Order is what the listing is ordered by.
	Order UserOrder
	// Descending turns the order around.
	Descending bool
	// After continues a listing: only the users that come after this one in the
	// order of the query are returned. Only the fields that the order and the ID
	// use count.
	After *User
	// Limit is how many users to return, from 1 to MaxUsersPage.
	Limit int
}
