package store

import (
	"context"
	"time"
)

// ActorKind tells who did what an audit record says.
type ActorKind string

// The kinds of actors.
const (
	// ActorAdmin is an administrator. ActorID is the ID of the administrator.
	ActorAdmin ActorKind = "admin"
	// ActorUser is a user. ActorID is the ID of the user.
	ActorUser ActorKind = "user"
	// ActorSystem is the service itself or the code of the application, such as
	// the command line or the background maintenance. ActorID names which.
	ActorSystem ActorKind = "system"
)

// AuditRecord is one entry of the audit log. It is written once and never
// changes. The pair of TenantID and ID identifies it.
type AuditRecord struct {
	// TenantID is the tenant the record belongs to.
	TenantID string
	// ID is the identifier of the record, a UUID in text form. The records of a
	// moment are ordered by it.
	ID string
	// At is when it happened.
	At time.Time
	// ActorKind says who did it.
	ActorKind ActorKind
	// ActorID identifies the actor, empty if there is none to name.
	ActorID string
	// Action names what was done, for example "user.blocked".
	Action string
	// TargetUserID is the user it was done to, empty if it was done to no user. It
	// is not tied to the users table, so a record outlives the user.
	TargetUserID string
	// IP is the address the actor came from, empty if it is unknown.
	IP string
	// Details is a text of at most MaxAuditDetailsLength bytes, usually JSON,
	// that the store keeps as it is, empty if there is none.
	Details string
}

// AuditQuery picks audit records. The conditions that are set all have to hold.
type AuditQuery struct {
	// TenantID is the tenant of the records.
	TenantID string
	// TargetUserID keeps the records about this user.
	TargetUserID string
	// ActorKind keeps the records of this kind of actor.
	ActorKind ActorKind
	// ActorID keeps the records of this actor.
	ActorID string
	// Actions keeps the records of these actions, at most MaxAuditActions of them.
	Actions []string
	// From keeps the records at this moment and later, the zero time sets no
	// bound.
	From time.Time
	// To keeps the records before this moment, the zero time sets no bound.
	To time.Time
	// After continues a listing: only the records that come after this one are
	// returned. Only its At and ID count.
	After *AuditRecord
	// Limit is how many records to return, from 1 to MaxAuditPage.
	Limit int
}

// Audit stores the audit log. Records are added and, once they are old enough,
// removed in bulk. There is no way to change one or to remove it by itself.
type Audit interface {
	// Add stores a record. It returns ErrConflict if the ID is taken.
	Add(ctx context.Context, r AuditRecord) error

	// List returns the records that match the query, the newest first: ordered by
	// time and then by ID, both descending. The IDs that limb makes are lower
	// case UUIDs, which every collation of a database orders alike. A value to
	// match that cannot be stored matches nothing.
	List(ctx context.Context, q AuditQuery) ([]AuditRecord, error)

	// DeleteBefore removes the oldest records of the tenant that happened before
	// the given time, at most limit of them, from 1 to MaxAuditPage, and returns
	// how many it removed. Call it until it returns less than limit.
	DeleteBefore(ctx context.Context, tenantID string, before time.Time, limit int) (int, error)
}
