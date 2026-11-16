package limb

import (
	"net/netip"
	"time"

	"github.com/acneism/limb/store"
)

// SessionKind tells how the client of a session proves that it owns it.
type SessionKind = store.SessionKind

// The kinds of sessions.
const (
	// SessionCookie is a session that the browser carries in a cookie.
	SessionCookie = store.SessionCookie
	// SessionToken is a session that access tokens refer to and refresh tokens
	// keep alive.
	SessionToken = store.SessionToken
)

// Principal is who makes a request: a user and the session they signed in
// with. It is small on purpose, because it is read on every request.
type Principal struct {
	// UserID is the user.
	UserID UserID
	// SessionID is the session, which is also the sid claim of its tokens.
	SessionID string
	// SessionKind tells whether the session is carried by a cookie or by tokens.
	SessionKind SessionKind
	// MustChangePassword is set while the user has to choose a new password. The
	// session can then only be used to change it.
	MustChangePassword bool
}

// Credentials is what a user presents to sign in.
type Credentials struct {
	// Login is any value the user signs in with, such as an e-mail address or a
	// nickname.
	Login string
	// Password is the password.
	Password string
	// IP is the address of the client. The limits on failed attempts per address
	// do not apply when it is the zero Addr.
	IP netip.Addr
	// UserAgent is the user agent of the client, shown to the user in the list of
	// their sessions. It is cut to 512 bytes.
	UserAgent string
	// Kind is the kind of session to open, SessionCookie or SessionToken.
	Kind SessionKind
}

// Tokens is a pair of tokens of a token session.
type Tokens struct {
	// AccessToken is the JWT that authenticates requests.
	AccessToken string
	// AccessExpiresAt is when the access token expires.
	AccessExpiresAt time.Time
	// RefreshToken is the single-use token that is exchanged for a new pair.
	RefreshToken string
	// RefreshExpiresAt is when the refresh token expires.
	RefreshExpiresAt time.Time
}

// Login is the result of a successful sign-in or of a password change.
type Login struct {
	// Principal identifies the user and the new session.
	Principal Principal
	// Secret is the value of the session cookie. It is set for cookie sessions
	// only.
	Secret string
	// CSRFToken is the token that the page sends in the X-CSRF-Token header of
	// requests that change data. It is set for cookie sessions only.
	CSRFToken string
	// Tokens are the tokens of a token session; the zero value for a cookie
	// session.
	Tokens Tokens
	// ExpiresAt is when the session ends whatever its activity is.
	ExpiresAt time.Time
}

// Session is a session as the user sees it in the list of their sessions.
type Session struct {
	// ID identifies the session.
	ID string
	// Kind tells whether the session is carried by a cookie or by tokens.
	Kind SessionKind
	// IP is the address the user signed in from, empty if it is unknown.
	IP string
	// UserAgent is the user agent of the client that signed in, empty if it is
	// unknown.
	UserAgent string
	// CreatedAt is when the user signed in.
	CreatedAt time.Time
	// LastSeenAt is when the session was last used, to the minute.
	LastSeenAt time.Time
	// ExpiresAt is when the session ends whatever its activity is.
	ExpiresAt time.Time
	// Current tells that this is the session that made the request.
	Current bool
}
