package limb

import (
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/acneism/limb/internal/admin"
	"github.com/acneism/limb/internal/adminui"
	"github.com/acneism/limb/internal/audit"
)

func settingChosen(form url.Values) (enabled, valid bool) {
	switch values := form[settingPasswordToEndSessions]; {
	case len(values) == 0:
		return false, true
	case len(values) == 1 && values[0] == "1":
		return true, true
	}
	return false, false
}

func settingsNotice(p *adminui.Page, done string) (string, bool) {
	if done != "saved" {
		return "", false
	}
	return p.T("settings.notice.saved", int(settingsTTL/time.Second)), true
}

func (c *adminCall) settingsPage(ses admin.Session) (*adminui.Page, bool) {
	required, err := c.auth().currentPasswordToEndSessions(c.ctx())
	if err != nil {
		c.internal(err)
		return nil, false
	}
	p := c.signedPage(ses)
	p.Title = p.T("settings.title")
	p.Data = adminui.SettingsData{
		PasswordToEndSessions: required,
		AuditHref:             c.auditLink(auditQuery{action: audit.SettingChanged, limit: defaultAuditPage}),
	}
	return p, true
}

func (c *adminCall) showSettings() {
	ses, ok := c.requireSession()
	if !ok {
		return
	}
	p, ok := c.settingsPage(ses)
	if !ok {
		return
	}
	if text, done := settingsNotice(p, c.r.URL.Query().Get("done")); done {
		p.Flash, p.FlashKind = text, "notice"
	}
	c.render(http.StatusOK, "settings", p)
}

func (c *adminCall) refuseSettings(ses admin.Session) {
	p, ok := c.settingsPage(ses)
	if !ok {
		return
	}
	p.Flash, p.FlashKind = p.T("settings.error.invalid"), "error"
	c.render(http.StatusUnprocessableEntity, "settings", p)
}

func (c *adminCall) submitSettings() {
	ses, form, ok := c.signedForm()
	if !ok {
		return
	}
	required, valid := settingChosen(form)
	if !valid {
		c.refuseSettings(ses)
		return
	}
	if err := c.auth().setSetting(c.ctx(), c.by(ses), settingPasswordToEndSessions, strconv.FormatBool(required)); err != nil {
		c.internal(err)
		return
	}
	c.redirect("/settings?done=saved")
}
