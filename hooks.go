package limb

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"time"
)

// EventType names what happened.
type EventType string

// The events that limb reports to Hooks.OnEvent.
const (
	// EventUserCreated is reported when a user was created, by Register or by
	// Signup. The user is in UserID.
	EventUserCreated EventType = "user_created"

	// EventUserChanged is reported when an administrator changes a user. It is
	// declared for the administration of users, which comes later, and limb does
	// not report it yet.
	EventUserChanged EventType = "user_changed"

	// EventLogin is reported when a user signed in. Details["kind"] is "cookie" or
	// "token".
	EventLogin EventType = "login"

	// EventLoginFailed is reported when a sign-in was refused for a login or a
	// password that is wrong or for an account that is blocked. UserID is set when
	// the login belongs to an account and is empty when it does not, Address is
	// the login that was tried, masked, and Details["reason"] is
	// "invalid_credentials" or "blocked". Attempts that the limits turn down
	// before the password is looked at are not reported.
	EventLoginFailed EventType = "login_failed"

	// EventLogout is reported when a user ended their own session.
	EventLogout EventType = "logout"

	// EventPasswordChanged is reported when a user changed their password. The
	// session that replaced the old ones is in SessionID.
	EventPasswordChanged EventType = "password_changed"

	// EventPasswordReset is reported when a user chose a new password with a link
	// or a code of a reset. Channel and Address say where the secret was sent.
	EventPasswordReset EventType = "password_reset"

	// EventSessionEnded is reported when sessions of a user were ended otherwise
	// than by a logout: Details["reason"] is "logout_all", "terminated",
	// "password_changed", "password_reset" or "refresh_token_reused", and
	// Details["count"] is how many sessions ended when it is known.
	EventSessionEnded EventType = "session_ended"

	// EventRefreshTokenReused is reported when a refresh token that was used long
	// ago was used again, which means that it was stolen. The session was ended.
	EventRefreshTokenReused EventType = "refresh_token_reused"

	// EventChannelVerified is reported when a user proved that they own an
	// address or a phone number. Channel and Address say which.
	EventChannelVerified EventType = "channel_verified"

	// EventMessageFailed is reported when a message could not be sent: the Sender
	// returned an error, panicked or timed out, a template broke a rule or the
	// storage failed. Details["kind"] is the kind of the message and
	// Details["reason"] says what went wrong without the text of the message.
	EventMessageFailed EventType = "message_failed"
)

// Event is something that happened and has been saved. It never holds a
// password, a link, a token or a code.
type Event struct {
	// Type says what happened.
	Type EventType

	// At is when it happened, in UTC.
	At time.Time

	// UserID is the user the event is about, empty when no user is known.
	UserID string

	// SessionID is the session the event is about, empty when there is none.
	SessionID string

	// Channel is the name of the identifier type that the event is about, for
	// example "email", empty when there is none.
	Channel string

	// Address is the value of that identifier in a masked form, or for a failed
	// sign-in the login that was tried: an e-mail address shows its first
	// character and its domain, a***@example.com, any other value its first two
	// and its last two characters, and a value of six characters or fewer is
	// hidden altogether.
	Address string

	// IP is the address of the client, empty when it is not known.
	IP string

	// Details is what else is worth knowing, see the types of events.
	Details map[string]string
}

// Hooks are the functions of the application that limb calls. A field that is
// nil is not called.
type Hooks struct {
	// BeforeRegister is called by Signup, before anything is stored, with the
	// registration as it has been checked and normalized: the identifiers are in
	// their normalized form, the password is cleared and Extra is a copy. It can
	// refuse the registration by returning an error. A *ValidationError is passed
	// to the caller as it is, so that the user can be told which value is wrong,
	// for example Field "extra.invite"; any other error is logged and refuses the
	// registration with ErrRegistrationRefused, and so does a panic. The hook does
	// not know whether the address is taken, and its answer must not depend on it.
	BeforeRegister func(ctx context.Context, r Registration) error

	// BeforeDelete is declared for the deletion of users, which comes later with
	// the administration of users. limb does not call it yet.
	BeforeDelete func(ctx context.Context, u User) error

	// OnEvent is called after an operation has been committed, in the goroutine of
	// the request, so a slow hook slows the request down. It cannot undo what
	// happened. A panic is contained and logged and does not touch the operation.
	OnEvent func(ctx context.Context, e Event)
}

// WithHooks sets the functions of the application that limb calls, see Hooks.
func WithHooks(h Hooks) Option {
	return func(c *config) {
		c.hooks = h
	}
}

func (a *Auth) emit(ctx context.Context, e Event) {
	if a.hooks.OnEvent == nil {
		return
	}
	e.At = a.now().UTC()
	e.Details = maps.Clone(e.Details)
	defer func() {
		if r := recover(); r != nil {
			a.logger.ErrorContext(ctx, "limb: the hook of events panicked", "event", e.Type, "panic_type", fmt.Sprintf("%T", r))
		}
	}()
	a.hooks.OnEvent(ctx, e)
}

func eventAddress(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	return ip.String()
}

func (a *Auth) reportMessageFailure(ctx context.Context, t task, err error) {
	event := Event{Type: EventMessageFailed, Channel: t.channel, Details: map[string]string{"kind": string(t.kind), "reason": "failed"}}
	if failure, ok := asDeliveryError(err); ok {
		event.UserID, event.Channel, event.Address = failure.userID, failure.channel, failure.recipient
		event.Details["kind"], event.Details["reason"] = string(failure.kind), failure.code
	}
	a.emit(ctx, event)
}
