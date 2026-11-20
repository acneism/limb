package limb

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/acneism/limb/internal/adminui"
	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

const (
	longestDetail  = 6
	shortenedActor = 8
)

func authAction(event EventType) string {
	return audit.AuthPrefix + string(event)
}

var (
	adminActions = []string{
		audit.AdminCreated, audit.AdminDeleted, audit.AdminDisabled, audit.AdminEnabled, audit.AdminPasswordReset, audit.AdminTOTPReset,
		audit.AdminLogin, audit.AdminLoginFailed, audit.AdminLogout, audit.AdminTOTPEnrolled, audit.AdminTOTPRebound, audit.AdminRecoveryCodeUsed,
		audit.AdminRecoveryCodesRenewed, audit.AdminPasswordChanged, audit.AdminSessionEnded, audit.AdminSessionsEnded, audit.SettingChanged,
	}
	signInActions  = []string{authAction(EventLogin), authAction(EventLoginFailed), authAction(EventLogout)}
	journalActions = []string{
		audit.UserCreated, audit.UserPurged, audit.UserDeleted, audit.UserRestored, audit.UserInvited, audit.UserInvitationResent,
		audit.UserIdentifierAdded, audit.UserIdentifierChanged, audit.UserIdentifierRemoved, audit.UserIdentifierVerified, audit.UserBlocked,
		audit.UserUnblocked, audit.UserSessionEnded, audit.UserSessionsEnded, audit.UserPasswordResetSent, audit.UserPasswordTemporary,
		authAction(EventUserCreated), authAction(EventPasswordChanged), authAction(EventPasswordReset), authAction(EventSessionEnded),
		authAction(EventRefreshTokenReused), authAction(EventChannelVerified),
	}
	auditActions = slices.Concat(adminActions, journalActions, signInActions)
)

func detailText(value any, depth int) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case []any:
		if depth >= longestDetail {
			return "…"
		}
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, detailText(item, depth+1))
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		if depth >= longestDetail {
			return "…"
		}
		parts := make([]string, 0, len(v))
		for _, key := range slices.Sorted(maps.Keys(v)) {
			parts = append(parts, key+": "+detailText(v[key], depth+1))
		}
		return strings.Join(parts, ", ")
	}
	return fmt.Sprint(value)
}

func detailPairs(details map[string]any) []adminui.DetailPair {
	pairs := make([]adminui.DetailPair, 0, len(details))
	for _, key := range slices.Sorted(maps.Keys(details)) {
		pairs = append(pairs, adminui.DetailPair{Key: key, Value: detailText(details[key], 0)})
	}
	return pairs
}

type actorNames struct {
	c      *adminCall
	p      *adminui.Page
	admins map[string]string
}

func (n *actorNames) admin(id string) (string, error) {
	if login, known := n.admins[id]; known {
		return login, nil
	}
	found, err := n.c.auth().store.Admins().Get(n.c.ctx(), n.c.auth().tenant, id)
	login := found.Login
	switch {
	case errors.Is(err, store.ErrNotFound):
		login = n.p.T("audit.actor.admin.gone", shorten(id))
	case err != nil:
		return "", fmt.Errorf("limb: get the administrator of a record: %w", err)
	}
	n.admins[id] = login
	return login, nil
}

func shorten(id string) string {
	if len(id) <= shortenedActor {
		return id
	}
	return id[:shortenedActor]
}

func (n *actorNames) name(e AuditEntry) (string, error) {
	switch store.ActorKind(e.ActorKind) {
	case store.ActorAdmin:
		return n.admin(e.ActorID)
	case store.ActorUser:
		return n.p.T("audit.actor.user"), nil
	case store.ActorSystem:
		if text := n.p.T("audit.actor." + e.ActorID); e.ActorID != "" && text != "audit.actor."+e.ActorID {
			return text, nil
		}
		return cmpOrUnknown(n.p, e.ActorID), nil
	}
	return cmpOrUnknown(n.p, e.ActorID), nil
}

func cmpOrUnknown(p *adminui.Page, id string) string {
	if id == "" {
		return p.T("audit.actor.unknown")
	}
	return id
}

func (c *adminCall) auditRows(p *adminui.Page, entries []AuditEntry) ([]adminui.AuditRow, error) {
	names := &actorNames{c: c, p: p, admins: map[string]string{}}
	rows := make([]adminui.AuditRow, 0, len(entries))
	for _, e := range entries {
		actor, err := names.name(e)
		if err != nil {
			return nil, err
		}
		label := p.T("audit.action." + e.Action)
		if label == "audit.action."+e.Action {
			label = e.Action
		}
		row := adminui.AuditRow{At: e.At, Actor: actor, Action: e.Action, Label: label, IP: e.IP, Details: detailPairs(e.Details)}
		if e.UserID != "" {
			row.UserID, row.UserHref = string(e.UserID), c.s.base+"/users/"+string(e.UserID)
		}
		rows = append(rows, row)
	}
	return rows, nil
}
