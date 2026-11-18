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

// ErrorData is what the page of an error needs.
type ErrorData struct {
	// Title and Text say what happened, in the language of the page.
	Title, Text string
}
