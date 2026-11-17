// Package audit builds the records of the audit log and writes them. A record
// says who did what to whom and when, with the old and the new value of what
// changed, and never holds a password, a secret, a code or a token: the callers
// put into the details only what may be read by whoever reads the log.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/acneism/limb/store"
)

// AuthPrefix starts the action of a record that is made of an event of a user,
// such as a sign-in. The rest of the action is the type of the event.
const AuthPrefix = "auth."

// The actions that administrators and the maintenance leave in the log.
const (
	AdminCreated       = "admin.created"
	AdminDeleted       = "admin.deleted"
	AdminDisabled      = "admin.disabled"
	AdminEnabled       = "admin.enabled"
	AdminPasswordReset = "admin.password_reset"
	AdminTOTPReset     = "admin.totp_reset"
	SettingChanged     = "setting.changed"

	UserCreated            = "user.created"
	UserInvited            = "user.invited"
	UserInvitationResent   = "user.invitation_resent"
	UserIdentifierAdded    = "user.identifier_added"
	UserIdentifierChanged  = "user.identifier_changed"
	UserIdentifierRemoved  = "user.identifier_removed"
	UserIdentifierVerified = "user.identifier_verified"

	UserBlocked           = "user.blocked"
	UserUnblocked         = "user.unblocked"
	UserSessionEnded      = "user.session_ended"
	UserSessionsEnded     = "user.sessions_ended"
	UserPasswordResetSent = "user.password_reset_sent"
	UserPasswordTemporary = "user.password_temporary"
)

const (
	longestValue = 64
	truncatedKey = "truncated"
	ellipsis     = "…"
)

// Actor is who did what a record says.
type Actor struct {
	// Kind is the kind of the actor.
	Kind store.ActorKind
	// ID identifies the actor: the ID of an administrator or of a user, or the
	// name of the part of the system.
	ID string
}

// The actors that are not people.
var (
	// CLI is the command line that the application connects with RunCommand.
	CLI = Actor{Kind: store.ActorSystem, ID: "cli"}
	// API is the code of the application that calls the methods of Admin.
	API = Actor{Kind: store.ActorSystem, ID: "api"}
)

// Entry is what a record is made of, apart from its ID and its time.
type Entry struct {
	// Actor is who did it.
	Actor Actor
	// Action names what was done.
	Action string
	// TargetUserID is the user it was done to, empty if it was done to none.
	TargetUserID string
	// IP is the address the actor came from, empty if it is unknown.
	IP string
	// At is when it happened, the time of the writer when it is not set.
	At time.Time
	// Details are what changed. The values are strings, numbers, booleans, lists
	// and maps of them.
	Details map[string]any
}

// Writer writes the entries as records of one tenant.
type Writer struct {
	// Tenant is the tenant of the records.
	Tenant string
	// Now gives the time of a record.
	Now func() time.Time
	// NewID gives the ID of a record.
	NewID func() (string, error)
}

// Add writes the entry to the repository, which is the one of a transaction when
// the record has to stand or fall with a change.
func (w Writer) Add(ctx context.Context, repo store.Audit, e Entry) error {
	id, err := w.NewID()
	if err != nil {
		return fmt.Errorf("audit: make the ID of a record: %w", err)
	}
	details, err := Encode(e.Details)
	if err != nil {
		return err
	}
	at := e.At
	if at.IsZero() {
		at = w.Now()
	}
	err = repo.Add(ctx, store.AuditRecord{
		TenantID:     w.Tenant,
		ID:           id,
		At:           at,
		ActorKind:    e.Actor.Kind,
		ActorID:      e.Actor.ID,
		Action:       e.Action,
		TargetUserID: e.TargetUserID,
		IP:           e.IP,
		Details:      details,
	})
	if err != nil {
		return fmt.Errorf("audit: write the record of %s: %w", e.Action, err)
	}
	return nil
}

// Encode writes the details as a JSON object of at most MaxAuditDetailsLength
// bytes, or as an empty text when there are none. When they are too long the
// strings are cut to a short length and, if that is not enough, the last keys in
// the alphabet are dropped, and the key "truncated" says so.
func Encode(details map[string]any) (string, error) {
	if len(details) == 0 {
		return "", nil
	}
	text, err := marshal(details)
	if err != nil || len(text) <= store.MaxAuditDetailsLength {
		return text, err
	}
	shortened := map[string]any{}
	for key, value := range details {
		shortened[key] = shorten(value)
	}
	shortened[truncatedKey] = true
	for {
		if text, err = marshal(shortened); err != nil || len(text) <= store.MaxAuditDetailsLength {
			return text, err
		}
		keys := slices.Sorted(maps.Keys(shortened))
		keys = slices.DeleteFunc(keys, func(key string) bool { return key == truncatedKey })
		if len(keys) == 0 {
			return `{"` + truncatedKey + `":true}`, nil
		}
		delete(shortened, keys[len(keys)-1])
	}
}

func marshal(details map[string]any) (string, error) {
	text, err := json.Marshal(details)
	if err != nil {
		return "", fmt.Errorf("audit: write the details: %w", err)
	}
	return string(text), nil
}

func shorten(value any) any {
	switch v := value.(type) {
	case string:
		if len(v) <= longestValue {
			return v
		}
		cut := longestValue
		for cut > 0 && !utf8.RuneStart(v[cut]) {
			cut--
		}
		return v[:cut] + ellipsis
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, inner := range v {
			out[key] = shorten(inner)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, inner := range v {
			out[i] = shorten(inner)
		}
		return out
	}
	return value
}
