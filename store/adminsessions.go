package store

import (
	"context"
	"time"
)

// AdminSessionStage tells how far an administrator is on the way in.
type AdminSessionStage string

// The stages of a session of an administrator.
const (
	// AdminStagePassword is a sign-in that has passed the password and waits for
	// the one-time password or a recovery code. It lives for minutes, takes a few
	// attempts and gives no access.
	AdminStagePassword AdminSessionStage = "password"
	// AdminStageFull is a session that gives access to the administration.
	AdminStageFull AdminSessionStage = "full"
)

// AdminSession is a sign-in of an administrator, in progress or complete. The
// pair of TenantID and ID identifies it.
type AdminSession struct {
	// TenantID is the tenant the session belongs to.
	TenantID string
	// ID is the identifier of the session, a UUID in text form.
	ID string
	// AdminID is the administrator the session belongs to.
	AdminID string
	// Stage says how far the sign-in is.
	Stage AdminSessionStage
	// SecretHash is the SHA-256 of the secret of the cookie, SecretHashLength
	// bytes. It is unique among all sessions of administrators.
	SecretHash []byte
	// AdminVersion is the version of the administrator that the session was made
	// for or last bound to. A session whose version is not the version of the
	// administrator is not valid.
	AdminVersion int64
	// Attempts is how many guesses of the second step TryAttempt counted.
	Attempts int
	// IP is the address the administrator came from, empty if it is unknown.
	IP string
	// UserAgent is the user agent of the client, empty if it is unknown.
	UserAgent string
	// CreatedAt is when the sign-in began.
	CreatedAt time.Time
	// LastSeenAt is when the session was last used. It is kept roughly: Touch
	// updates it, and callers use Touch at most once in a while.
	LastSeenAt time.Time
	// ExpiresAt is the end of the session whatever its activity is.
	ExpiresAt time.Time
}

// AdminState is the part of the account of an administrator that decides
// whether its sessions work. It is read together with a session.
type AdminState struct {
	// Login is the login of the administrator.
	Login string
	// Status is the state of the account.
	Status AdminStatus
	// Version is the version of the account.
	Version int64
	// TOTPConfirmed tells that the administrator has a confirmed authenticator.
	TOTPConfirmed bool
}

// ResolvedAdminSession is a session together with the state of its
// administrator, read in one query.
type ResolvedAdminSession struct {
	Session AdminSession
	Admin   AdminState
}

// AdminSessions stores the sessions of administrators.
type AdminSessions interface {
	// Create stores a new session that has no attempts. It returns ErrConflict if
	// the session or its secret hash exists, and ErrNotFound if the administrator
	// does not exist.
	Create(ctx context.Context, s AdminSession) error

	// ResolveBySecret returns the session whose secret has the given hash
	// together with the state of its administrator, or ErrNotFound. An expired
	// session is returned as it is: it is up to the caller to look at ExpiresAt.
	ResolveBySecret(ctx context.Context, tenantID string, secretHash []byte) (ResolvedAdminSession, error)

	// Touch records that the session was used at the given time. It never moves
	// LastSeenAt back, and it does nothing for a session that does not exist.
	Touch(ctx context.Context, tenantID, id string, at time.Time) error

	// TryAttempt counts one guess of the second step on the session that is at
	// the password stage and has had fewer than limit of them, and reports whether
	// it counted. The counting is atomic: of any number of calls at once only as
	// many succeed as the limit leaves, so a caller that checks a guess only when
	// this reports true cannot be made to check more than limit of them. It
	// reports false, with no error, for a session that does not exist, is at
	// another stage or has used its attempts.
	TryAttempt(ctx context.Context, tenantID, id string, limit int) (bool, error)

	// Rebind makes the session valid for the given version of its administrator,
	// which a change of the account that the session survives needs. It returns
	// ErrNotFound if the administrator has no such session.
	Rebind(ctx context.Context, tenantID, adminID, id string, version int64) error

	// Delete ends the session of the administrator. It returns ErrNotFound if the
	// administrator has no such session.
	Delete(ctx context.Context, tenantID, adminID, id string) error

	// DeleteForAdmin ends every session of the administrator, except the one with
	// ID exceptID if it is not empty, and returns how many it ended.
	DeleteForAdmin(ctx context.Context, tenantID, adminID, exceptID string) (int, error)

	// ListByAdmin returns the sessions of the administrator that are complete and
	// expire after now, ordered by CreatedAt and then by ID, comparing the bytes
	// of the IDs whatever the collation of the database is.
	ListByAdmin(ctx context.Context, tenantID, adminID string, now time.Time) ([]AdminSession, error)

	// DeleteStale removes the sessions that expired before expiredBefore or were
	// last seen before idleBefore. It returns how many it removed.
	DeleteStale(ctx context.Context, tenantID string, expiredBefore, idleBefore time.Time) (int, error)
}
