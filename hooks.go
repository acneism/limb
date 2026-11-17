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
	// Signup. The user is in UserID. Signup reports it in the background, see
	// Hooks.OnEvent.
	EventUserCreated EventType = "user_created"

	// EventUserChanged is reported when an administrator changes a user in a way
	// that has no event of its own: Details["change"] is "password_reset_sent" for a
	// link that was sent and "password_temporary" for a temporary password.
	EventUserChanged EventType = "user_changed"

	// EventUserBlocked is reported when an administrator blocked a user. Details
	// holds the "reason" and, for a block that ends, the time "until" in RFC 3339.
	EventUserBlocked EventType = "user_blocked"

	// EventUserUnblocked is reported when an administrator lifted a block.
	EventUserUnblocked EventType = "user_unblocked"

	// EventUserDeleted is reported when an administrator deleted a user.
	// Details["mode"] is "soft", and then Details["purge_after"] is the time in RFC
	// 3339 when the record is removed for good, or "immediate", when it is gone at
	// once together with what belongs to it.
	EventUserDeleted EventType = "user_deleted"

	// EventUserRestored is reported when an administrator restored a deleted user.
	EventUserRestored EventType = "user_restored"

	// EventLogin is reported when a user signed in. Details["kind"] is "cookie" or
	// "token".
	EventLogin EventType = "login"

	// EventLoginFailed is reported when a sign-in was refused for a login or a
	// password that is wrong, for an account that is blocked or for an account
	// that has no confirmed address or phone number where the service asks for
	// one. UserID is set when the login belongs to an account and is empty when it
	// does not, Address is the login that was tried, masked, and Details["reason"]
	// is "invalid_credentials", "blocked" or "verification_required". Attempts
	// that the limits turn down before the password is looked at are not reported.
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
//
// The events of users are also written to the audit log, as the records with the
// action "auth." and the type of the event: EventUserCreated, EventLogin,
// EventLoginFailed, EventLogout, EventPasswordChanged, EventPasswordReset,
// EventSessionEnded, EventRefreshTokenReused and EventChannelVerified. The record
// holds what the event holds, so a login is masked there too. A record that cannot
// be written is logged and does not touch the operation. EventLoginFailed and the
// EventUserCreated of Signup are written by a worker after the answer, so that the
// time of the answer does not tell whether a login or an address exists. The
// worker has a queue of 256 records, drops a record that finds it full and logs
// that, and Auth.Shutdown waits for the rest.
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

	// BeforeDelete is called by AdminAPI.DeleteUser, before anything is changed, with
	// the user that is about to be deleted, in the soft mode and in the immediate
	// one. It can refuse the deletion by returning an error, which DeleteUser
	// returns wrapped in ErrDeletionRefused, so the administrator can be told why;
	// a panic refuses it too, and only the type of its value is logged. It is not
	// called when the retention of a deleted user ends and the record is removed
	// for good, nor when an account that nobody confirmed is removed: the
	// application had its say when the user was deleted, and EventUserDeleted and
	// EventUserPurged let it clear what it keeps of the user.
	BeforeDelete func(ctx context.Context, u User) error

	// OnEvent is called after an operation has been committed, in the goroutine of
	// the request, so a slow hook slows the request down. It cannot undo what
	// happened. A panic is contained and logged and does not touch the operation.
	//
	// The exception is EventUserCreated of Signup, which a worker of limb delivers
	// after the registration has been answered. A registration that uses an address
	// that is taken creates no user and has no such event, so a hook that runs in the
	// request and is slow would show which addresses are taken. The events wait in a
	// queue of 256 and go to the hook one at a time, in the order of their
	// registrations, with a context that carries the values of the request but not
	// its cancellation and ends after 30 seconds. An event that finds the queue full
	// is dropped and logged, and Auth.Shutdown waits for the others.
	OnEvent func(ctx context.Context, e Event)
}

// WithHooks sets the functions of the application that limb calls, see Hooks.
func WithHooks(h Hooks) Option {
	return func(c *config) {
		c.hooks = h
	}
}

func (a *Auth) emit(ctx context.Context, e Event) {
	e = a.stamped(e)
	a.auditEvent(ctx, e)
	if a.hooks.OnEvent != nil {
		a.callHook(ctx, e)
	}
}

func (a *Auth) emitHook(ctx context.Context, e Event) {
	if a.hooks.OnEvent == nil {
		return
	}
	a.callHook(ctx, a.stamped(e))
}

func (a *Auth) emitLater(ctx context.Context, e Event) {
	e = a.stamped(e)
	if auditedEvents[e.Type] {
		a.queueAudit(ctx, e)
	}
	if a.events == nil {
		return
	}
	if !a.events.add(ctx, e) {
		a.logger.WarnContext(ctx, "limb: an event was dropped, the queue of events is full or stopped", "event", e.Type)
	}
}

func (a *Auth) stamped(e Event) Event {
	e.At = a.now().UTC()
	e.Details = maps.Clone(e.Details)
	return e
}

func (a *Auth) callHook(ctx context.Context, e Event) {
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
