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

// Option is an entry of a list to choose from.
type Option struct {
	// Value is what the form sends, and Label what the administrator reads.
	Value, Label string
	// Selected tells that the entry is the one that is chosen.
	Selected bool
}

// Choice is a box to tick.
type Choice struct {
	// Name is the name of the field and Value what it sends when it is ticked.
	Name, Value string
	// Label is what the administrator reads.
	Label string
	// Checked tells that the box is ticked.
	Checked bool
}

// IdentifierView is a value that a user signs in with, as a list shows it.
type IdentifierView struct {
	// Type is the name of the type of the value and Value the value.
	Type, Value string
	// Verified tells that the owner proved to own it.
	Verified bool
}

// UserRow is a user as the list of users shows them.
type UserRow struct {
	// Href is the address of the card of the user and Title what the link says.
	Href, Title string
	// Identifiers are the values that the user signs in with.
	Identifiers []IdentifierView
	// Status is "active", "blocked" or "deleted", and StatusLabel says it in the
	// language of the page.
	Status, StatusLabel string
	// BlockedUntil is when a block ends, the zero time if it has no end or there
	// is none.
	BlockedUntil time.Time
	// CreatedAt and LastLoginAt are when the account was made and when the user
	// signed in last, the zero time if never.
	CreatedAt, LastLoginAt time.Time
	// Via says how the account came to be, in the language of the page.
	Via string
	// MustChangePassword tells that the user has to choose another password.
	MustChangePassword bool
}

// SortLink is the link in the head of a column that orders the list by it.
type SortLink struct {
	// Href is where the link goes.
	Href string
	// State is "none", "ascending" or "descending", as aria-sort has it.
	State string
}

// UsersForm is the form that searches and filters the list of users, filled in
// with what was asked for.
type UsersForm struct {
	// Search is the text that was searched for.
	Search string
	// Statuses are the boxes of the statuses.
	Statuses []Choice
	// Confirmed, Via, Order, Direction and Limit are the lists to choose from.
	Confirmed, Via, Order, Direction, Limit []Option
	// CreatedFrom, CreatedTo, LoginFrom and LoginTo are the dates of the periods,
	// as the form sends them.
	CreatedFrom, CreatedTo, LoginFrom, LoginTo string
	// Never tells that only the users who never signed in are asked for.
	Never bool
}

// UsersData is what the page of the list of users needs.
type UsersData struct {
	// Form is the form with what was asked for.
	Form UsersForm
	// Rows are the users of the page.
	Rows []UserRow
	// ByCreated, ByLastLogin and ByStatus are the links of the heads of the
	// columns that can order the list.
	ByCreated, ByLastLogin, ByStatus SortLink
	// Next is the address of the page that follows, empty on the last page, and
	// First the address of the first page, empty on the first.
	Next, First string
	// Filtered tells that something was asked for, so that an empty list can say
	// that nobody matches.
	Filtered bool
}

// IdentifierRow is a value that a user signs in with, as the card of the user
// shows it.
type IdentifierRow struct {
	// Type is the name of the type of the value and Value the value as the user
	// wrote it.
	Type, Value string
	// Verified tells that the owner proved to own it, and VerifiedAt is when.
	Verified   bool
	VerifiedAt time.Time
	// Editable tells that the type of the value is one that the service knows, so
	// that the value can be changed. CanConfirm tells that an administrator can
	// mark it as confirmed and CanRemove that it can be taken away.
	Editable, CanConfirm, CanRemove bool
}

// UserSessionRow is a session of a user as the card of the user shows it.
type UserSessionRow struct {
	// ID identifies the session.
	ID string
	// Kind says in the language of the page whether a cookie or tokens carry the
	// session.
	Kind string
	// IP and UserAgent are where the user signed in from.
	IP, UserAgent string
	// CreatedAt is when the user signed in, LastSeenAt when the session was used
	// last and ExpiresAt when it ends whatever it does.
	CreatedAt, LastSeenAt, ExpiresAt time.Time
}

// DetailPair is one thing that a record of the audit log says, a name and what
// it is.
type DetailPair struct {
	Key, Value string
}

// AuditRow is a record of the audit log as a page shows it.
type AuditRow struct {
	// At is when it happened.
	At time.Time
	// Actor says who did it, in the language of the page.
	Actor string
	// Action is the name of the action and Label says it in the language of the
	// page.
	Action, Label string
	// UserID is the user it was done to, empty if it was done to none, and
	// UserHref is the address of their card.
	UserID, UserHref string
	// IP is where the actor came from.
	IP string
	// Details are what the record says changed.
	Details []DetailPair
}

// UserData is what the card of a user needs.
type UserData struct {
	// ID identifies the user and Title is what the page calls them.
	ID, Title string
	// Status is "active", "blocked" or "deleted", and StatusLabel says it in the
	// language of the page.
	Status, StatusLabel string
	// BlockedReason is why the account was blocked, and BlockedUntil when the block
	// ends, the zero time if it has no end.
	BlockedReason string
	BlockedUntil  time.Time
	// DeletedAt is when the account was deleted and PurgeAfter when it is removed
	// for good, the zero time for an account that is not deleted.
	DeletedAt, PurgeAfter time.Time
	// CreatedAt is when the account was made and LastLoginAt when the user signed
	// in last, the zero time if never.
	CreatedAt, LastLoginAt time.Time
	// Via says how the account came to be, in the language of the page.
	Via string
	// MustChangePassword tells that the user has to choose another password.
	MustChangePassword bool
	// Identifiers are the values that the user signs in with.
	Identifiers []IdentifierRow
	// Sessions are the sessions that are in use.
	Sessions []UserSessionRow
	// SignIns are the last records of signing in and out, and Journal the last
	// records of what was changed.
	SignIns, Journal []AuditRow
	// Immediate tells that a deletion erases the user at once, so that nothing is
	// left to restore.
	Immediate bool
	// ReasonLimit is the longest reason of a block, in bytes.
	ReasonLimit int
	// HasPassword tells that the user has a password.
	HasPassword bool
	// CanSend tells that the service can send a message to the user, so that a link
	// to choose a password can be sent.
	CanSend bool
	// MessageLanguages are the languages that a message to the user can be in.
	MessageLanguages []Option
	// MissingTypes are the types of values that the user has none of, which can be
	// added.
	MissingTypes []Option
	// BlockReason and BlockUntil are what the form of a block was sent with, kept
	// to be shown again when the block was refused.
	BlockReason, BlockUntil string
}

// TemporaryData is what the page that shows a temporary password needs.
type TemporaryData struct {
	// UserHref is the address of the card of the user and Title what the page
	// calls them.
	UserHref, Title string
	// Password is the temporary password, which is shown this once.
	Password string
}

// ErrorData is what the page of an error needs.
type ErrorData struct {
	// Title and Text say what happened, in the language of the page.
	Title, Text string
}
