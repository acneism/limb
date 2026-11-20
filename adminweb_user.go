package limb

import (
	"cmp"
	"errors"
	"net/http"
	"net/url"

	"github.com/acneism/limb/internal/admin"
	"github.com/acneism/limb/internal/adminui"
	"github.com/acneism/limb/store"
)

const historyRows = 20

var userNotices = map[string]string{
	"blocked":    "user.notice.blocked",
	"unblocked":  "user.notice.unblocked",
	"session":    "user.notice.session",
	"sessions":   "user.notice.sessions",
	"deleted":    "user.notice.deleted",
	"restored":   "user.notice.restored",
	"link":       "user.notice.link",
	"created":    "user.notice.created",
	"invited":    "user.notice.invited",
	"invitebusy": "user.notice.invitebusy",
	"invitation": "user.notice.invitation",
	"value":      "user.notice.identifier",
	"removed":    "user.notice.removed",
	"confirmed":  "user.notice.confirmed",
}

func shownValue(i UserIdentifier) string {
	return cmp.Or(i.DisplayValue, i.Value)
}

func titleOf(u ManagedUser) string {
	if len(u.Identifiers) > 0 {
		return shownValue(u.Identifiers[0])
	}
	return string(u.ID)
}

func (c *adminCall) history(id UserID, actions []string) ([]AuditEntry, error) {
	page, err := c.auth().listAudit(c.ctx(), AuditFilter{UserID: id, Actions: actions, Limit: historyRows})
	return page.Entries, err
}

func (c *adminCall) userData(p *adminui.Page, u ManagedUser) adminui.UserData {
	data := adminui.UserData{
		ID: string(u.ID), Title: titleOf(u), Status: string(u.Status), StatusLabel: p.T("status." + string(u.Status)),
		BlockedReason: u.BlockedReason, DeletedAt: u.DeletedAt, PurgeAfter: u.PurgeAfter, CreatedAt: u.CreatedAt, LastLoginAt: u.LastLoginAt,
		Via: viaText(p, u.CreatedVia), MustChangePassword: u.MustChangePassword, Immediate: c.auth().immediate, ReasonLimit: store.MaxBlockedReasonLength,
		HasPassword: u.HasPassword, CanSend: c.auth().recoveryReady(), MessageLanguages: messageLanguages(p),
		Invited: u.CreatedVia == string(store.CreatedViaInvite) && !u.HasPassword, CanInvite: c.auth().invitationsReady(),
		AuditHref: c.s.base + "/audit?user=" + string(u.ID),
	}
	if u.Status == store.StatusBlocked {
		data.BlockedUntil = u.BlockedUntil
	}
	data.Identifiers, data.MissingTypes = c.identifierRows(u)
	return data
}

func (c *adminCall) identifierRows(u ManagedUser) ([]adminui.IdentifierRow, []adminui.Option) {
	a := c.auth()
	signIn := 0
	held := make(map[string]bool, len(u.Identifiers))
	for _, i := range u.Identifiers {
		held[i.Type] = true
		if kind, declared := a.known[i.Type]; declared && kind.IsLogin() {
			signIn++
		}
	}
	rows := make([]adminui.IdentifierRow, 0, len(u.Identifiers))
	for _, i := range u.Identifiers {
		kind, declared := a.known[i.Type]
		verified := !i.VerifiedAt.IsZero()
		editable := declared && u.Status != store.StatusDeleted
		rows = append(rows, adminui.IdentifierRow{
			Type: i.Type, Value: shownValue(i), Verified: verified, VerifiedAt: i.VerifiedAt, Editable: editable,
			CanConfirm: editable && kind.IsDelivery() && !verified, CanRemove: editable && !kind.IsRequired() && (!kind.IsLogin() || signIn > 1),
		})
	}
	var missing []adminui.Option
	for _, kind := range a.types {
		if !held[kind.Name()] && u.Status != store.StatusDeleted {
			missing = append(missing, adminui.Option{Value: kind.Name(), Label: kind.Name()})
		}
	}
	return rows, missing
}

func sessionRows(p *adminui.Page, sessions []Session) []adminui.UserSessionRow {
	rows := make([]adminui.UserSessionRow, 0, len(sessions))
	for _, s := range sessions {
		kind := p.T("session.kind." + string(s.Kind))
		rows = append(rows, adminui.UserSessionRow{
			ID: s.ID, Kind: kind, IP: s.IP, UserAgent: s.UserAgent, CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt, ExpiresAt: s.ExpiresAt,
		})
	}
	return rows
}

func (c *adminCall) userCard(p *adminui.Page, u ManagedUser) (adminui.UserData, error) {
	data := c.userData(p, u)
	sessions, err := c.auth().userSessions(c.ctx(), string(u.ID), "")
	if err != nil {
		return data, err
	}
	data.Sessions = sessionRows(p, sessions)
	for _, part := range []struct {
		actions []string
		into    *[]adminui.AuditRow
	}{{signInActions, &data.SignIns}, {journalActions, &data.Journal}} {
		entries, historyErr := c.history(u.ID, part.actions)
		if historyErr != nil {
			return data, historyErr
		}
		if *part.into, historyErr = c.auditRows(p, entries); historyErr != nil {
			return data, historyErr
		}
	}
	return data, nil
}

func (c *adminCall) userPage(ses admin.Session, status int, flash func(p *adminui.Page) string, form url.Values) {
	user, err := c.auth().managedUserByID(c.ctx(), UserID(c.userID))
	switch {
	case errors.Is(err, ErrUserNotFound):
		c.fail(http.StatusNotFound)
		return
	case err != nil:
		c.internal(err)
		return
	}
	p := c.signedPage(ses)
	data, err := c.userCard(p, user)
	if err != nil {
		c.internal(err)
		return
	}
	data.BlockReason, data.BlockUntil = form.Get("reason"), form.Get("until")
	if flash != nil {
		p.Flash, p.FlashKind = flash(p), "notice"
		if status >= http.StatusBadRequest {
			p.FlashKind = "error"
		}
	}
	p.Title, p.Data = data.Title, data
	c.render(status, "user", p)
}

func (c *adminCall) showUser() {
	ses, ok := c.requireSession()
	if !ok {
		return
	}
	var flash func(p *adminui.Page) string
	if key, known := userNotices[c.r.URL.Query().Get("done")]; known {
		flash = textOf(key)
	}
	c.userPage(ses, http.StatusOK, flash, nil)
}

func messageLanguages(p *adminui.Page) []adminui.Option {
	chosen := normalizeLanguage(p.Lang)
	options := make([]adminui.Option, 0, len(supportedLanguages))
	for _, language := range supportedLanguages {
		options = append(options, adminui.Option{Value: language, Label: adminui.LanguageName(language), Selected: language == chosen})
	}
	return options
}
