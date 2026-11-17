package limb

import (
	"context"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

var auditedEvents = map[EventType]bool{
	EventUserCreated:        true,
	EventLogin:              true,
	EventLoginFailed:        true,
	EventLogout:             true,
	EventPasswordChanged:    true,
	EventPasswordReset:      true,
	EventSessionEnded:       true,
	EventRefreshTokenReused: true,
	EventChannelVerified:    true,
}

func (a *Auth) auditWriter() audit.Writer {
	return audit.Writer{Tenant: a.tenant, Now: a.now, NewID: a.newID}
}

func (a *Auth) auditEvent(ctx context.Context, e Event) {
	if !auditedEvents[e.Type] {
		return
	}
	if e.Type == EventLoginFailed {
		a.queueAudit(ctx, e)
		return
	}
	a.recordEvent(ctx, e)
}

func (a *Auth) queueAudit(ctx context.Context, e Event) {
	if !a.auditing.add(ctx, e) {
		a.logger.WarnContext(ctx, "limb: an audit record was dropped, the queue of records is full or stopped", "event", e.Type)
	}
}

func (a *Auth) recordEvent(ctx context.Context, e Event) {
	entry := audit.Entry{
		Actor:        audit.Actor{Kind: store.ActorUser, ID: e.UserID},
		Action:       audit.AuthPrefix + string(e.Type),
		TargetUserID: e.UserID,
		IP:           e.IP,
		At:           e.At,
		Details:      eventDetails(e),
	}
	if err := a.auditWriter().Add(ctx, a.store.Audit(), entry); err != nil {
		a.logger.ErrorContext(ctx, "limb: the audit record of an event could not be written", "event", e.Type, "error", err)
	}
}

func eventDetails(e Event) map[string]any {
	details := make(map[string]any, len(e.Details)+3)
	for key, value := range e.Details {
		details[key] = value
	}
	if e.SessionID != "" {
		details["session"] = e.SessionID
	}
	if e.Channel != "" {
		details["channel"] = e.Channel
	}
	if e.Address != "" {
		details["address"] = e.Address
	}
	return details
}
