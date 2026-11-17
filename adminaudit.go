package limb

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/acneism/limb/store"
)

const (
	defaultAuditPage = 50
	largestAuditPage = 200
)

// AuditFilter picks the records of the audit log. The conditions that are set all
// have to hold.
type AuditFilter struct {
	// UserID keeps the records about this user: what happened to them and what
	// they did.
	UserID UserID

	// AdminID keeps the records of the actions of this administrator.
	AdminID string

	// Actions keeps the records of these actions, at most 32 of them, for example
	// "auth.login_failed" or "user.blocked".
	Actions []string

	// From keeps the records at this moment and later, To those before it. The
	// zero time sets no bound.
	From, To time.Time

	// Cursor continues a list: it is the Next of the page before, with the same
	// filter.
	Cursor string

	// Limit is how many records a page holds, from 1 to 200, 50 by default.
	Limit int
}

// AuditEntry is a record of the audit log. Nothing in it can be changed, and a
// record holds no password, secret, code or token.
type AuditEntry struct {
	// ID identifies the record.
	ID string

	// At is when it happened, in UTC.
	At time.Time

	// ActorKind is who did it: "admin", "user" or "system".
	ActorKind string

	// ActorID is the ID of the administrator or of the user, or the name of the
	// part of the system, "cli", "api" or "maintenance". It is empty when the
	// actor is not known, as for a sign-in with a login that no account has.
	ActorID string

	// Action says what was done, for example "user.blocked".
	Action string

	// UserID is the user it was done to, empty if it was done to none.
	UserID UserID

	// IP is the address the actor came from, empty if it is not known.
	IP string

	// Details are what changed, with the old and the new value where there are
	// both.
	Details map[string]any
}

// AuditPage is a page of the audit log, the newest record first.
type AuditPage struct {
	// Entries are the records of the page.
	Entries []AuditEntry

	// Next is the cursor of the page that follows, empty when this is the last.
	Next string
}

type auditCursor struct {
	At int64  `json:"t"`
	ID string `json:"i"`
}

func (a *Auth) listAudit(ctx context.Context, f AuditFilter) (AuditPage, error) {
	limit := f.Limit
	switch {
	case limit == 0:
		limit = defaultAuditPage
	case limit < 0 || limit > largestAuditPage:
		return AuditPage{}, &ValidationError{Field: "limit", Reason: fmt.Sprintf("must be from 1 to %d", largestAuditPage)}
	}
	if len(f.Actions) > store.MaxAuditActions {
		return AuditPage{}, &ValidationError{Field: "actions", Reason: fmt.Sprintf("at most %d", store.MaxAuditActions)}
	}
	q := store.AuditQuery{
		TenantID: a.tenant, TargetUserID: string(f.UserID), ActorID: f.AdminID, Actions: f.Actions, From: f.From, To: f.To, Limit: limit + 1,
	}
	if f.AdminID != "" {
		q.ActorKind = store.ActorAdmin
	}
	if f.Cursor != "" {
		after, err := decodeAuditCursor(f.Cursor)
		if err != nil {
			return AuditPage{}, err
		}
		q.After = after
	}
	records, err := a.store.Audit().List(ctx, q)
	if err != nil {
		return AuditPage{}, fmt.Errorf("limb: list the audit log: %w", err)
	}
	page := AuditPage{}
	if len(records) > limit {
		records = records[:limit]
		page.Next = encodeAuditCursor(records[limit-1])
	}
	page.Entries = make([]AuditEntry, 0, len(records))
	for _, r := range records {
		page.Entries = append(page.Entries, auditEntry(r))
	}
	return page, nil
}

func auditEntry(r store.AuditRecord) AuditEntry {
	entry := AuditEntry{
		ID: r.ID, At: r.At, ActorKind: string(r.ActorKind), ActorID: r.ActorID, Action: r.Action, UserID: UserID(r.TargetUserID), IP: r.IP,
	}
	if r.Details != "" {
		if err := json.Unmarshal([]byte(r.Details), &entry.Details); err != nil {
			entry.Details = map[string]any{"text": r.Details}
		}
	}
	return entry
}

func encodeAuditCursor(r store.AuditRecord) string {
	raw, _ := json.Marshal(auditCursor{At: r.At.UnixMicro(), ID: r.ID})
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeAuditCursor(text string) (*store.AuditRecord, error) {
	invalid := &ValidationError{Field: "cursor", Reason: "is not valid"}
	raw, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		return nil, invalid
	}
	var c auditCursor
	if err = json.Unmarshal(raw, &c); err != nil || c.ID == "" {
		return nil, invalid
	}
	return &store.AuditRecord{At: time.UnixMicro(c.At).UTC(), ID: c.ID}, nil
}

// ListAudit returns a page of the audit log that matches the filter, the newest
// record first. It returns a *ValidationError for a filter that cannot be
// applied, naming the field.
func (x *AdminAPI) ListAudit(ctx context.Context, f AuditFilter) (AuditPage, error) {
	return x.a.listAudit(ctx, f)
}
