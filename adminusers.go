package limb

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/acneism/limb/store"
)

const (
	defaultUsersPage = 50
	largestUsersPage = 200
	shortestPrefix   = 3
	longestSearch    = 128
)

// UserOrder tells what a list of users is ordered by. The users that have the
// same value are ordered by their ID.
type UserOrder string

// The orders of a list of users.
const (
	// UserOrderCreated orders by the time the account was created. It is what an
	// empty order means.
	UserOrderCreated UserOrder = "created"
	// UserOrderLastLogin orders by the time of the last sign-in. The users that
	// never signed in come last, whichever way the order goes.
	UserOrderLastLogin UserOrder = "last_login"
	// UserOrderStatus orders by the name of the status of the account.
	UserOrderStatus UserOrder = "status"
)

// ManagedUser is a user as the administration shows them.
type ManagedUser struct {
	User

	// CreatedVia tells how the account came to be: "api" for Register, "signup"
	// for a visitor, "admin" for an administrator who gave a password and "invite"
	// for one who invited the holder to a channel.
	CreatedVia string

	// BlockedReason is why an administrator blocked the account, empty if none did.
	BlockedReason string

	// BlockedUntil is when the block ends, the zero time if there is none or if it
	// has no end. User.Status says whether it still holds.
	BlockedUntil time.Time

	// DeletedAt is when the account was deleted, the zero time if it was not.
	DeletedAt time.Time

	// PurgeAfter is when a deleted account is removed for good, the zero time if
	// it is not deleted. The account can be restored until then.
	PurgeAfter time.Time
}

// UserFilter picks the users of a list and orders them. The conditions that are
// set all have to hold.
type UserFilter struct {
	// Statuses keeps the users whose stored status is one of these. A block that
	// has run out is lifted by the maintenance, so for a while an account whose
	// block ended is still found as blocked.
	Statuses []Status

	// Confirmed keeps the users that have, when it points at true, or have not,
	// when it points at false, an address or a phone number that is confirmed.
	Confirmed *bool

	// CreatedVia keeps the users that came to be this way, see
	// ManagedUser.CreatedVia.
	CreatedVia string

	// CreatedFrom and CreatedBefore keep the users made in the period, the zero
	// time sets no bound.
	CreatedFrom, CreatedBefore time.Time

	// LastLoginFrom and LastLoginBefore keep the users who signed in last in the
	// period, the zero time sets no bound. A user who never signed in is not kept.
	LastLoginFrom, LastLoginBefore time.Time

	// NeverLoggedIn keeps the users who never signed in.
	NeverLoggedIn bool

	// Search finds the users by what they sign in with. A text of at least three
	// characters finds the users that have a value, of any type, that starts with
	// it: an e-mail address starts with the text in lower case, a phone number is
	// found by the text that a user would type, with spaces and hyphens, and a
	// value that a type normalizes differently, such as a number in the national
	// form, is searched in its normalized form. A shorter text finds the user that
	// has exactly that value. The test of the text for the percent sign and the
	// underscore is literal.
	Search string

	// Order is what the list is ordered by, UserOrderCreated by default.
	Order UserOrder

	// Descending turns the order around.
	Descending bool

	// Cursor continues a list: it is the Next of the page before, with the same
	// filter. It cannot be used with another order.
	Cursor string

	// Limit is how many users a page holds, from 1 to 200, 50 by default.
	Limit int
}

// UserPage is a page of a list of users.
type UserPage struct {
	// Users are the users of the page, in the order of the list.
	Users []ManagedUser

	// Next is the cursor of the page that follows, empty when this is the last.
	Next string
}

type userCursor struct {
	Order      UserOrder `json:"o"`
	Descending bool      `json:"d,omitempty"`
	ID         string    `json:"i"`
	Created    int64     `json:"c,omitempty"`
	LastLogin  int64     `json:"l,omitempty"`
	Status     Status    `json:"s,omitempty"`
}

func validStatus(s Status) bool {
	return s == store.StatusActive || s == store.StatusBlocked || s == store.StatusDeleted
}

func validCreatedVia(v store.CreatedVia) bool {
	switch v {
	case store.CreatedViaAPI, store.CreatedViaSignup, store.CreatedViaAdmin, store.CreatedViaInvite:
		return true
	}
	return false
}

func (a *Auth) userQuery(f UserFilter) (store.UserQuery, bool, error) {
	limit := f.Limit
	switch {
	case limit == 0:
		limit = defaultUsersPage
	case limit < 0 || limit > largestUsersPage:
		return store.UserQuery{}, false, &ValidationError{Field: "limit", Reason: fmt.Sprintf("must be from 1 to %d", largestUsersPage)}
	}
	order := f.Order
	switch order {
	case "":
		order = UserOrderCreated
	case UserOrderCreated, UserOrderLastLogin, UserOrderStatus:
	default:
		return store.UserQuery{}, false, &ValidationError{Field: "order", Reason: "unknown order"}
	}
	for _, status := range f.Statuses {
		if !validStatus(status) {
			return store.UserQuery{}, false, &ValidationError{Field: "statuses", Reason: "unknown status"}
		}
	}
	via := store.CreatedVia(f.CreatedVia)
	if via != "" && !validCreatedVia(via) {
		return store.UserQuery{}, false, &ValidationError{Field: "created_via", Reason: "unknown way"}
	}
	q := store.UserQuery{
		TenantID: a.tenant, Statuses: f.Statuses, Confirmed: f.Confirmed, CreatedVia: via,
		CreatedFrom: f.CreatedFrom, CreatedBefore: f.CreatedBefore, LastLoginFrom: f.LastLoginFrom, LastLoginBefore: f.LastLoginBefore,
		NeverLoggedIn: f.NeverLoggedIn, Order: store.UserOrder(order), Descending: f.Descending, Limit: limit + 1,
	}
	found, err := a.applySearch(&q, f.Search)
	if err != nil || !found {
		return q, found, err
	}
	if f.Cursor != "" {
		q.After, err = decodeUserCursor(f.Cursor, order, f.Descending)
		if err != nil {
			return q, false, err
		}
	}
	return q, true, nil
}

func (a *Auth) applySearch(q *store.UserQuery, text string) (bool, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return true, nil
	}
	if utf8.RuneCountInString(text) > longestSearch {
		return false, &ValidationError{Field: "search", Reason: fmt.Sprintf("must be at most %d characters", longestSearch)}
	}
	light := lightNormalize(text)
	if utf8.RuneCountInString(light) >= shortestPrefix {
		q.ValuePrefix = a.searchPrefix(text, light)
		return true, nil
	}
	for _, kind := range a.types {
		if value, err := kind.Normalize(text); err == nil {
			ref := store.IdentifierRef{Type: kind.Name(), Value: value}
			if !slices.Contains(q.Identifiers, ref) {
				q.Identifiers = append(q.Identifiers, ref)
			}
		}
	}
	return len(q.Identifiers) > 0, nil
}

func (a *Auth) searchPrefix(text, light string) string {
	for _, kind := range a.types {
		if value, err := kind.Normalize(text); err == nil && value != light {
			return value
		}
	}
	if typed := typedNumber(light); typed != "" {
		return typed
	}
	return light
}

func lightNormalize(text string) string {
	return strings.ToLower(norm.NFKC.String(strings.TrimSpace(text)))
}

func typedNumber(text string) string {
	formatted := false
	var digits strings.Builder
	for i, r := range text {
		switch {
		case r >= '0' && r <= '9':
			digits.WriteRune(r)
		case r == '+' && i == 0:
			digits.WriteRune(r)
			formatted = true
		case r == ' ' || r == '(' || r == ')':
			formatted = true
		case r == '-':
		default:
			return ""
		}
	}
	if !formatted {
		return ""
	}
	return digits.String()
}

func encodeUserCursor(u store.User, order UserOrder, descending bool) string {
	c := userCursor{Order: order, Descending: descending, ID: u.ID}
	switch order {
	case UserOrderLastLogin:
		if !u.LastLoginAt.IsZero() {
			c.LastLogin = u.LastLoginAt.UnixMicro()
		}
	case UserOrderStatus:
		c.Status = u.Status
	case UserOrderCreated:
		c.Created = u.CreatedAt.UnixMicro()
	}
	raw, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeUserCursor(text string, order UserOrder, descending bool) (*store.User, error) {
	invalid := &ValidationError{Field: "cursor", Reason: "is not valid for this list"}
	raw, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		return nil, invalid
	}
	var c userCursor
	if err = json.Unmarshal(raw, &c); err != nil || c.Order != order || c.Descending != descending || c.ID == "" {
		return nil, invalid
	}
	after := &store.User{ID: c.ID, Status: c.Status}
	if c.Created != 0 {
		after.CreatedAt = time.UnixMicro(c.Created).UTC()
	}
	if c.LastLogin != 0 {
		after.LastLoginAt = time.UnixMicro(c.LastLogin).UTC()
	}
	return after, nil
}

func (a *Auth) listUsers(ctx context.Context, f UserFilter) (UserPage, error) {
	q, found, err := a.userQuery(f)
	if err != nil || !found {
		return UserPage{}, err
	}
	users, err := a.store.Users().List(ctx, q)
	if err != nil {
		return UserPage{}, fmt.Errorf("limb: list the users: %w", err)
	}
	limit := q.Limit - 1
	page := UserPage{}
	if len(users) > limit {
		users = users[:limit]
		page.Next = encodeUserCursor(users[limit-1], UserOrder(q.Order), q.Descending)
	}
	now := a.now()
	page.Users = make([]ManagedUser, 0, len(users))
	for _, u := range users {
		identifiers, listErr := a.store.Identifiers().ListByUser(ctx, a.tenant, u.ID)
		if listErr != nil {
			return UserPage{}, fmt.Errorf("limb: list the identifiers: %w", listErr)
		}
		page.Users = append(page.Users, managedUser(u, identifiers, now))
	}
	return page, nil
}

func managedUser(u store.User, identifiers []store.Identifier, now time.Time) ManagedUser {
	user := newUser(u, identifiers)
	if u.Status == store.StatusBlocked && !u.BlockedUntil.IsZero() && !u.BlockedUntil.After(now) {
		user.Status = store.StatusActive
	}
	return ManagedUser{
		User: user, CreatedVia: string(u.CreatedVia), BlockedReason: u.BlockedReason, BlockedUntil: u.BlockedUntil,
		DeletedAt: u.DeletedAt, PurgeAfter: u.PurgeAfter,
	}
}

func (a *Auth) managedUserByID(ctx context.Context, id UserID) (ManagedUser, error) {
	u, err := a.store.Users().Get(ctx, a.tenant, string(id))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ManagedUser{}, ErrUserNotFound
	case err != nil:
		return ManagedUser{}, fmt.Errorf("limb: get the user: %w", err)
	}
	identifiers, err := a.store.Identifiers().ListByUser(ctx, a.tenant, u.ID)
	if err != nil {
		return ManagedUser{}, fmt.Errorf("limb: list the identifiers: %w", err)
	}
	return managedUser(u, identifiers, a.now()), nil
}

func (a *Auth) userSessions(ctx context.Context, userID, currentID string) ([]Session, error) {
	now := a.now()
	listed, err := a.store.Sessions().ListByUser(ctx, a.tenant, userID, now)
	if err != nil {
		return nil, fmt.Errorf("limb: list the sessions: %w", err)
	}
	sessions := make([]Session, 0, len(listed))
	for _, s := range listed {
		if !a.sessionActive(s, now) {
			continue
		}
		sessions = append(sessions, Session{
			ID: s.ID, Kind: s.Kind, IP: s.IP, UserAgent: s.UserAgent, CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt,
			ExpiresAt: s.ExpiresAt, Current: currentID != "" && s.ID == currentID,
		})
	}
	return sessions, nil
}

// ListUsers returns a page of the users that match the filter. It returns a
// *ValidationError for a filter that cannot be applied, naming the field.
func (x *AdminAPI) ListUsers(ctx context.Context, f UserFilter) (UserPage, error) {
	return x.a.listUsers(ctx, f)
}

// User returns the user with the ID, whatever the status of the account is. It
// returns ErrUserNotFound if there is none.
func (x *AdminAPI) User(ctx context.Context, id UserID) (ManagedUser, error) {
	return x.a.managedUserByID(ctx, id)
}

// UserSessions lists the sessions of the user that are still in use, the oldest
// first, as Sessions does for a user themselves. It returns ErrUserNotFound if
// there is no such user.
func (x *AdminAPI) UserSessions(ctx context.Context, id UserID) ([]Session, error) {
	if _, err := x.a.managedUserByID(ctx, id); err != nil {
		return nil, err
	}
	return x.a.userSessions(ctx, string(id), "")
}
