package store

import (
	"context"
	"time"
)

// SessionKind tells how the client of a session proves that it owns it.
type SessionKind string

// The kinds of sessions.
const (
	// SessionCookie is a session that the browser carries in a cookie. The
	// store keeps the hash of the cookie's secret and finds the session by it.
	SessionCookie SessionKind = "cookie"
	// SessionToken is a session that access tokens refer to by its ID and that
	// refresh tokens keep alive. It has no secret of its own.
	SessionToken SessionKind = "token"
)

// Session is one sign-in of a user. The pair of TenantID and ID identifies it.
type Session struct {
	// TenantID is the tenant the session belongs to.
	TenantID string
	// ID is the identifier of the session, a UUID in text form.
	ID string
	// Kind says whether the session is carried by a cookie or by tokens.
	Kind SessionKind
	// SecretHash is the SHA-256 of the cookie secret, SecretHashLength bytes. It
	// is unique among all sessions and is set exactly for cookie sessions.
	SecretHash []byte
	// UserID is the user the session belongs to.
	UserID string
	// IP is the address the user signed in from, empty if it is unknown.
	IP string
	// UserAgent is the user agent of the client, empty if it is unknown.
	UserAgent string
	// CreatedAt is when the user signed in.
	CreatedAt time.Time
	// LastSeenAt is when the session was last used. It is kept roughly: it is
	// updated by Touch, which callers use at most once in a while.
	LastSeenAt time.Time
	// ExpiresAt is the end of the session whatever its activity is.
	ExpiresAt time.Time
	// RevokedAt is when the session was ended, the zero time if it was not.
	RevokedAt time.Time
}

// UserState is the part of a user account that decides whether its sessions
// work. It is read together with a session on every request.
type UserState struct {
	// Status is the state of the account.
	Status Status
	// BlockedUntil is when a block ends, the zero time if there is none.
	BlockedUntil time.Time
	// MustChangePassword tells that the user has to choose a new password.
	MustChangePassword bool
}

// ResolvedSession is a session together with the state of its user, read in
// one query.
type ResolvedSession struct {
	Session Session
	User    UserState
}

// Sessions stores the sessions of users.
type Sessions interface {
	// Create stores a new session. It returns ErrConflict if the session or its
	// secret hash already exists, and ErrNotFound if the user does not exist.
	Create(ctx context.Context, s Session) error

	// ResolveByID returns the session with the given ID together with the state
	// of its user, or ErrNotFound. A revoked or expired session is returned as
	// it is: it is up to the caller to look at RevokedAt and ExpiresAt.
	ResolveByID(ctx context.Context, tenantID, id string) (ResolvedSession, error)

	// ResolveBySecret does the same for the session whose secret has the given
	// hash.
	ResolveBySecret(ctx context.Context, tenantID string, secretHash []byte) (ResolvedSession, error)

	// Touch records that the session was used at the given time. It never moves
	// LastSeenAt back, and it does nothing for a session that does not exist.
	Touch(ctx context.Context, tenantID, id string, at time.Time) error

	// Revoke ends the session of the user. It returns ErrNotFound if the user
	// has no such session, or if the session was revoked already.
	Revoke(ctx context.Context, tenantID, userID, id string, at time.Time) error

	// RevokeAllForUser ends every session of the user that is not revoked yet,
	// except the one with ID exceptID if it is not empty. It returns how many
	// sessions it ended.
	RevokeAllForUser(ctx context.Context, tenantID, userID, exceptID string, at time.Time) (int, error)

	// ListByUser returns the sessions of the user that are not revoked and
	// expire after now, ordered by CreatedAt and then by ID, comparing the bytes
	// of the IDs whatever the collation of the database is.
	ListByUser(ctx context.Context, tenantID, userID string, now time.Time) ([]Session, error)

	// DeleteInactive removes the sessions that expired before expiredBefore, or
	// were last seen before idleBefore, or were revoked before revokedBefore,
	// together with their refresh tokens. It returns how many it removed.
	DeleteInactive(ctx context.Context, tenantID string, expiredBefore, idleBefore, revokedBefore time.Time) (int, error)
}

// RefreshToken is a refresh token of a session. Only its hash is stored.
type RefreshToken struct {
	// TenantID is the tenant the token belongs to.
	TenantID string
	// Hash is the SHA-256 of the token, SecretHashLength bytes. It is unique.
	Hash []byte
	// SessionID is the session the token keeps alive.
	SessionID string
	// ExpiresAt is when the token stops being accepted.
	ExpiresAt time.Time
	// UsedAt is when the token was exchanged for a new one, the zero time if it
	// was not.
	UsedAt time.Time
}

// RefreshUse is the result of using a refresh token.
type RefreshUse struct {
	// Token is the stored token after the call.
	Token RefreshToken
	// Reused tells that the token had been used before the call. Token.UsedAt is
	// then the time of that earlier use.
	Reused bool
}

// RefreshTokens stores the refresh tokens of sessions.
type RefreshTokens interface {
	// Add stores a new token that has not been used. It returns ErrConflict if
	// the hash already exists, and ErrNotFound if the session does not exist.
	Add(ctx context.Context, t RefreshToken) error

	// Use marks the token as used at the given time. The marking is atomic: when
	// several calls use the same token at once, exactly one of them gets Reused
	// false. It returns ErrNotFound if there is no such token.
	Use(ctx context.Context, tenantID string, hash []byte, at time.Time) (RefreshUse, error)

	// DeleteExpired removes the tokens that expired before the given time and
	// returns how many it removed.
	DeleteExpired(ctx context.Context, tenantID string, before time.Time) (int, error)
}
