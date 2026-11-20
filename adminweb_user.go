package limb

import (
	"cmp"
	"errors"
	"net/http"

	"github.com/acneism/limb/internal/adminui"
	"github.com/acneism/limb/store"
)

const historyRows = 20

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
		Via: viaText(p, u.CreatedVia), MustChangePassword: u.MustChangePassword,
	}
	if u.Status == store.StatusBlocked {
		data.BlockedUntil = u.BlockedUntil
	}
	for _, i := range u.Identifiers {
		data.Identifiers = append(data.Identifiers, adminui.IdentifierRow{Type: i.Type, Value: shownValue(i), Verified: !i.VerifiedAt.IsZero(), VerifiedAt: i.VerifiedAt})
	}
	return data
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

func (c *adminCall) showUser() {
	ses, ok := c.requireSession()
	if !ok {
		return
	}
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
	p.Title, p.Data = data.Title, data
	c.render(http.StatusOK, "user", p)
}
