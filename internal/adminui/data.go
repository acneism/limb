package adminui

import (
	"html/template"
	"time"
)

// LoginData is what the page of the password needs.
type LoginData struct {
	// Login is what was typed before, so that a mistake of the password does not
	// make the administrator type it again.
	Login string
}

// CodeData is what the page of the second step needs.
type CodeData struct {
	// Login is the login of the administrator who signs in.
	Login string
}

// EnrollData is what the page that binds an authenticator needs.
type EnrollData struct {
	// Login is the login of the administrator who signs in.
	Login string
	// QR is the QR code of the key, an image that is part of the page.
	QR template.HTML
	// Secret is the key to type by hand, in groups.
	Secret string
	// URI is the address that opens the key in an authenticator app on the same
	// device.
	URI template.URL
}

// RecoveryData is what the page of the recovery codes needs.
type RecoveryData struct {
	// Codes are the recovery codes, in the form to be written down.
	Codes []string
}

// HomeData is what the first page needs.
type HomeData struct {
	// Login is the login of the administrator.
	Login string
	// SignedAt is when they signed in.
	SignedAt time.Time
	// RecoveryCodes is how many recovery codes they have left.
	RecoveryCodes int
}

// SessionRow is a session of the administrator as the page of the account lists
// it.
type SessionRow struct {
	// ID identifies the session, for the form that ends it.
	ID string
	// SignedAt is when the administrator signed in, and LastSeenAt when the
	// session was last used.
	SignedAt, LastSeenAt time.Time
	// IP and UserAgent are what the sign-in came with.
	IP, UserAgent string
	// Current tells that it is the session that looks at the page.
	Current bool
}

// AccountData is what the page of the account needs.
type AccountData struct {
	// Login is the login of the administrator.
	Login string
	// CreatedAt is when the account was made.
	CreatedAt time.Time
	// SecondFactor tells that the service asks for a second factor, so that there
	// are an authenticator and recovery codes to change.
	SecondFactor bool
	// RecoveryCodes is how many recovery codes they have left.
	RecoveryCodes int
	// Sessions are the sessions that work, the oldest first.
	Sessions []SessionRow
	// HasOthers tells that there are sessions besides the one that looks.
	HasOthers bool
}

// RebindData is what the page that binds another authenticator needs.
type RebindData struct {
	// Login is the login of the administrator.
	Login string
	// QR is the QR code of the key, an image that is part of the page.
	QR template.HTML
	// Secret is the key to type by hand, in groups.
	Secret string
	// URI is the address that opens the key in an authenticator app on the same
	// device.
	URI template.URL
	// Token is what the form sends back with the one-time password.
	Token string
}

// ErrorData is what the page of an error needs.
type ErrorData struct {
	// Title and Text say what happened, in the language of the page.
	Title, Text string
}
