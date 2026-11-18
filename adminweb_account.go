package limb

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/acneism/limb/internal/admin"
	"github.com/acneism/limb/internal/adminui"
)

var accountNotices = map[string]string{
	"password": "account.notice.password",
	"session":  "account.notice.session",
	"sessions": "account.notice.sessions",
}

var knownRules = []string{"min_length", "max_length", "common_password", "login_identifier", admin.RuleSameAsCurrent}

func ruleTexts(p *adminui.Page, rules []string) string {
	var parts []string
	for _, rule := range rules {
		key := "password.rule.other"
		if slices.Contains(knownRules, rule) {
			key = "password.rule." + rule
		}
		if text := p.T(key); !slices.Contains(parts, text) {
			parts = append(parts, text)
		}
	}
	return p.T("password.rules", strings.Join(parts, ", "))
}

func (c *adminCall) sessionGone() {
	c.clearSession()
	c.redirect("/login")
}

func (c *adminCall) accountPage(ses admin.Session) (*adminui.Page, bool) {
	profile, err := c.auth().admins.Profile(c.ctx(), ses)
	switch {
	case errors.Is(err, admin.ErrNoSession):
		c.sessionGone()
		return nil, false
	case err != nil:
		c.internal(err)
		return nil, false
	}
	p := c.signedPage(ses)
	p.Title = p.T("account.title")
	data := adminui.AccountData{
		Login: profile.Account.Login, CreatedAt: profile.Account.CreatedAt,
		SecondFactor: !c.auth().admins.WithoutSecondFactor(), RecoveryCodes: profile.Account.RecoveryCodes,
	}
	for _, s := range profile.Sessions {
		data.Sessions = append(data.Sessions, adminui.SessionRow{
			ID: s.ID, SignedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt, IP: s.IP, UserAgent: s.UserAgent, Current: s.Current,
		})
		data.HasOthers = data.HasOthers || !s.Current
	}
	p.Data = data
	return p, true
}

func (c *adminCall) accountError(ses admin.Session, status int, text func(p *adminui.Page) string) {
	p, ok := c.accountPage(ses)
	if !ok {
		return
	}
	p.Flash, p.FlashKind = text(p), "error"
	if status == http.StatusUnauthorized {
		c.w.Header().Set("WWW-Authenticate", `Form realm="administration"`)
	}
	c.render(status, "account", p)
}

func textOf(key string) func(p *adminui.Page) string {
	return func(p *adminui.Page) string { return p.T(key) }
}

func (c *adminCall) showAccount() {
	ses, ok := c.requireSession()
	if !ok {
		return
	}
	p, ok := c.accountPage(ses)
	if !ok {
		return
	}
	if key, known := accountNotices[c.r.URL.Query().Get("done")]; known {
		p.Flash, p.FlashKind = p.T(key), "notice"
	}
	c.render(http.StatusOK, "account", p)
}

func (c *adminCall) accountForm() (admin.Session, url.Values, bool) {
	form, ok := c.form()
	if !ok {
		return admin.Session{}, nil, false
	}
	ses, ok := c.requireSession()
	if !ok {
		return admin.Session{}, nil, false
	}
	if !c.csrfOK(form, ses.ID) {
		c.fail(http.StatusForbidden)
		return admin.Session{}, nil, false
	}
	return ses, form, true
}

func (c *adminCall) reauthenticated(ses admin.Session, password string, run func() error) error {
	a := c.auth()
	keys := a.adminAttemptKeys(ses.Login, c.ip)
	var refusal *admin.CredentialsError
	err := a.limitedOver(c.ctx(), keys, a.adminLimits, func() error {
		if len(password) > maxAdminPasswordInput {
			refusal = &admin.CredentialsError{Reason: "too_long", AdminID: ses.AdminID}
			return ErrInvalidCredentials
		}
		runErr := run()
		if errors.As(runErr, &refusal) {
			return ErrInvalidCredentials
		}
		return runErr
	})
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		c.recordFailure(ses.Login, refusal, "account")
	case err == nil:
		a.clearFailures(c.ctx(), keys.accountIP)
	}
	return err
}

func (c *adminCall) accountFailure(ses admin.Session, err error) {
	var wait *RateLimitError
	var policy *admin.PolicyError
	switch {
	case errors.As(err, &wait):
		c.limited(wait.RetryAfter)
	case errors.Is(err, ErrInvalidCredentials):
		c.accountError(ses, http.StatusUnauthorized, textOf("password.wrong"))
	case errors.As(err, &policy):
		c.accountError(ses, http.StatusUnprocessableEntity, func(p *adminui.Page) string { return ruleTexts(p, policy.Rules) })
	case errors.Is(err, admin.ErrNoSession):
		c.sessionGone()
	case errors.Is(err, admin.ErrNoSecondFactor):
		c.fail(http.StatusNotFound)
	default:
		c.internal(err)
	}
}

func (c *adminCall) changePassword() {
	ses, form, ok := c.accountForm()
	if !ok {
		return
	}
	current, next := form.Get("current"), form.Get("new")
	switch {
	case next != form.Get("again"):
		c.accountError(ses, http.StatusUnprocessableEntity, textOf("password.differ"))
		return
	case len(next) > maxAdminPasswordInput:
		c.accountError(ses, http.StatusUnprocessableEntity, func(p *adminui.Page) string { return ruleTexts(p, []string{"max_length"}) })
		return
	}
	err := c.reauthenticated(ses, current, func() error {
		return c.auth().admins.ChangePassword(c.ctx(), ses, current, next, c.client)
	})
	if err != nil {
		c.accountFailure(ses, err)
		return
	}
	c.redirect("/account?done=password")
}

func (c *adminCall) recoveryPage(ses admin.Session, codes []string) {
	p := c.signedPage(ses)
	p.Title, p.Data = p.T("recovery.title"), adminui.RecoveryData{Codes: codes}
	c.render(http.StatusOK, "recovery", p)
}

func (c *adminCall) renewRecoveryCodes() {
	ses, form, ok := c.accountForm()
	if !ok {
		return
	}
	password := form.Get("password")
	var codes []string
	err := c.reauthenticated(ses, password, func() error {
		var renewErr error
		codes, renewErr = c.auth().admins.RenewRecoveryCodes(c.ctx(), ses, password, c.client)
		return renewErr
	})
	if err != nil {
		c.accountFailure(ses, err)
		return
	}
	c.recoveryPage(ses, codes)
}

func (c *adminCall) rebindPage(ses admin.Session, status int, rebinding admin.Rebinding, flashKey string) {
	p := c.signedPage(ses)
	p.Title = p.T("rebind.title")
	image, err := adminui.QR(rebinding.URI, p.T("enroll.qr"))
	if err != nil {
		c.internal(err)
		return
	}
	if flashKey != "" {
		p.Flash, p.FlashKind = p.T(flashKey), "error"
	}
	p.Data = adminui.RebindData{
		Login: ses.Login, QR: image, Secret: groupSecret(rebinding.Secret), URI: template.URL(rebinding.URI), Token: rebinding.Token, //nolint:gosec
	}
	if status == http.StatusUnauthorized {
		c.w.Header().Set("WWW-Authenticate", `Form realm="administration"`)
	}
	c.render(status, "rebind", p)
}

func (c *adminCall) beginRebind() {
	ses, form, ok := c.accountForm()
	if !ok {
		return
	}
	password := form.Get("password")
	var rebinding admin.Rebinding
	err := c.reauthenticated(ses, password, func() error {
		var beginErr error
		rebinding, beginErr = c.auth().admins.BeginRebind(c.ctx(), ses, password)
		return beginErr
	})
	if err != nil {
		c.accountFailure(ses, err)
		return
	}
	c.rebindPage(ses, http.StatusOK, rebinding, "")
}

func (c *adminCall) confirmRebind() {
	ses, form, ok := c.accountForm()
	if !ok {
		return
	}
	a := c.auth()
	token, input := form.Get("token"), strings.TrimSpace(form.Get("code"))
	keys := a.adminAttemptKeys(ses.Login, c.ip)
	var codes []string
	err := a.limitedOver(c.ctx(), keys, a.adminLimits, func() error {
		var confirmErr error
		codes, confirmErr = a.admins.ConfirmRebind(c.ctx(), ses, token, input, c.client)
		if errors.Is(confirmErr, admin.ErrBadFactor) {
			return ErrInvalidCredentials
		}
		return confirmErr
	})
	var wait *RateLimitError
	switch {
	case errors.As(err, &wait):
		c.limited(wait.RetryAfter)
	case errors.Is(err, ErrInvalidCredentials):
		c.recordFailure(ses.Login, &admin.CredentialsError{AdminID: ses.AdminID, Reason: "wrong_code"}, "account")
		c.rebindAgain(ses, token)
	case errors.Is(err, admin.ErrNoRebind):
		c.accountError(ses, http.StatusUnprocessableEntity, textOf("rebind.expired"))
	case errors.Is(err, admin.ErrNoSession):
		c.sessionGone()
	case errors.Is(err, admin.ErrNoSecondFactor):
		c.fail(http.StatusNotFound)
	case err != nil:
		c.internal(err)
	default:
		a.clearFailures(c.ctx(), keys.accountIP)
		c.recoveryPage(ses, codes)
	}
}

func (c *adminCall) rebindAgain(ses admin.Session, token string) {
	rebinding, err := c.auth().admins.OpenRebind(c.ctx(), ses, token)
	switch {
	case err == nil:
		c.rebindPage(ses, http.StatusUnauthorized, rebinding, "enroll.failed")
	case errors.Is(err, admin.ErrNoRebind):
		c.accountError(ses, http.StatusUnprocessableEntity, textOf("rebind.expired"))
	case errors.Is(err, admin.ErrNoSession):
		c.sessionGone()
	default:
		c.internal(err)
	}
}

func (c *adminCall) endSession() {
	ses, form, ok := c.accountForm()
	if !ok {
		return
	}
	err := c.auth().admins.EndSession(c.ctx(), ses, form.Get("session"), c.client)
	switch {
	case err == nil, errors.Is(err, admin.ErrNoSuchSession):
		c.redirect("/account?done=session")
	case errors.Is(err, admin.ErrNoSession):
		c.sessionGone()
	default:
		c.internal(err)
	}
}

func (c *adminCall) endOtherSessions() {
	ses, _, ok := c.accountForm()
	if !ok {
		return
	}
	_, err := c.auth().admins.EndOtherSessions(c.ctx(), ses, c.client)
	switch {
	case err == nil:
		c.redirect("/account?done=sessions")
	case errors.Is(err, admin.ErrNoSession):
		c.sessionGone()
	default:
		c.internal(err)
	}
}
