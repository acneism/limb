package limb

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/netip"
	"strings"

	"github.com/acneism/limb/internal/admin"
	"github.com/acneism/limb/internal/adminui"
	"github.com/acneism/limb/store"
)

type sessionState int

const (
	signedOut sessionState = iota
	signedIn
	sessionFailed
)

func (a *Auth) adminAttemptKeys(login string, ip netip.Addr) attemptKeys {
	label := rawLoginKey(login)
	if normalized, err := admin.NormalizeLogin(login); err == nil {
		label = normalized
	}
	keys := attemptKeys{account: a.keys.AttemptKey("admin-account", a.tenant, label)}
	if ip.IsValid() {
		address := limitedAddress(ip)
		keys.ip = a.keys.AttemptKey("admin-ip", a.tenant, address)
		keys.accountIP = a.keys.AttemptKey("admin-account-ip", a.tenant, label, address)
	}
	return keys
}

func (c *adminCall) resolveSession() (admin.Session, sessionState) {
	cookie, err := c.r.Cookie(c.auth().adminCookieName(adminSessionCookie))
	if err != nil || cookie.Value == "" {
		return admin.Session{}, signedOut
	}
	ses, err := c.auth().admins.Resolve(c.ctx(), cookie.Value)
	switch {
	case err == nil:
		return ses, signedIn
	case errors.Is(err, admin.ErrNoSession):
		c.clearSession()
		return admin.Session{}, signedOut
	}
	c.internal(err)
	return admin.Session{}, sessionFailed
}

func (c *adminCall) requireSession() (admin.Session, bool) {
	ses, state := c.resolveSession()
	switch state {
	case signedIn:
		return ses, true
	case signedOut:
		c.redirect("/login")
	case sessionFailed:
	}
	return admin.Session{}, false
}

func (c *adminCall) signedPage(ses admin.Session) *adminui.Page {
	p := c.newPage()
	p.Login, p.CSRF = ses.Login, c.csrf(ses.ID)
	return p
}

func (c *adminCall) pending() (admin.SignIn, bool) {
	cookie, err := c.r.Cookie(c.auth().adminCookieName(adminPendingCookie))
	if err != nil || cookie.Value == "" {
		c.redirect("/login")
		return admin.SignIn{}, false
	}
	in, err := c.auth().admins.Pending(c.ctx(), cookie.Value)
	switch {
	case err == nil:
		return in, true
	case errors.Is(err, admin.ErrNoSignIn):
		c.expired()
	default:
		c.internal(err)
	}
	return admin.SignIn{}, false
}

func (c *adminCall) expired() {
	c.clearPending()
	c.loginPage(http.StatusUnauthorized, "", "login.expired")
}

func (c *adminCall) loginPage(status int, login, flashKey string) {
	p := c.newPage()
	p.Title = p.T("login.title")
	if flashKey != "" {
		p.Flash, p.FlashKind = p.T(flashKey), "error"
	}
	p.Data = adminui.LoginData{Login: login}
	if status == http.StatusUnauthorized {
		c.w.Header().Set("WWW-Authenticate", `Form realm="administration"`)
	}
	c.render(status, "login", p)
}

func (c *adminCall) showLogin() {
	switch _, state := c.resolveSession(); state {
	case signedIn:
		c.redirect("/")
	case signedOut:
		c.loginPage(http.StatusOK, "", "")
	case sessionFailed:
	}
}

func (c *adminCall) recordFailure(login string, refusal *admin.CredentialsError, stage, reason string) {
	adminID := ""
	if refusal != nil {
		adminID, reason = refusal.AdminID, refusal.Reason
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.ctx()), recordTimeout)
	defer cancel()
	if err := c.auth().admins.RecordFailure(ctx, c.client, login, adminID, stage, reason); err != nil {
		c.auth().logger.ErrorContext(ctx, "limb: a failed sign-in to the administration cannot be recorded", "error", err)
	}
}

func (c *adminCall) submitLogin() {
	form, ok := c.form()
	if !ok {
		return
	}
	a := c.auth()
	login, password := form.Get("login"), form.Get("password")
	keys := a.adminAttemptKeys(login, c.ip)
	var found store.Admin
	var refusal *admin.CredentialsError
	err := a.limitedOver(c.ctx(), keys, a.adminLimits, func() error {
		if len(login) > maxAdminLoginInput || len(password) > maxAdminPasswordInput {
			refusal = &admin.CredentialsError{Reason: "too_long"}
			return ErrInvalidCredentials
		}
		var checkErr error
		found, checkErr = a.admins.CheckPassword(c.ctx(), login, password)
		if errors.As(checkErr, &refusal) {
			return ErrInvalidCredentials
		}
		return checkErr
	})
	var wait *RateLimitError
	switch {
	case errors.As(err, &wait):
		c.limited(wait.RetryAfter)
	case errors.Is(err, ErrInvalidCredentials):
		c.recordFailure(login, refusal, "password", "")
		c.loginPage(http.StatusUnauthorized, cutAtRune(login, maxAdminLoginInput), "login.failed")
	case err != nil:
		c.internal(err)
	default:
		c.passwordAccepted(found, keys)
	}
}

func (c *adminCall) passwordAccepted(found store.Admin, keys attemptKeys) {
	a := c.auth()
	if a.admins.WithoutSecondFactor() {
		opened, err := a.admins.Open(c.ctx(), found, c.client)
		if err != nil {
			c.internal(err)
			return
		}
		a.clearFailures(c.ctx(), keys.accountIP)
		c.setSession(opened.Secret)
		c.redirect("/")
		return
	}
	pending, err := a.admins.Begin(c.ctx(), found, c.client)
	switch {
	case errors.Is(err, admin.ErrNoSignIn):
		c.loginPage(http.StatusUnauthorized, "", "login.expired")
		return
	case err != nil:
		c.internal(err)
		return
	}
	c.setPending(pending.Secret, pending.ExpiresAt)
	if found.TOTPConfirmedAt.IsZero() {
		c.redirect("/login/totp")
		return
	}
	c.redirect("/login/code")
}

func (c *adminCall) codePage(status int, in admin.SignIn, flashKey string) {
	p := c.newPage()
	p.Title, p.CSRF = p.T("code.title"), c.csrf(in.Session.ID)
	if flashKey != "" {
		p.Flash, p.FlashKind = p.T(flashKey), "error"
	}
	p.Data = adminui.CodeData{Login: in.Admin.Login}
	if status == http.StatusUnauthorized {
		c.w.Header().Set("WWW-Authenticate", `Form realm="administration"`)
	}
	c.render(status, "code", p)
}

func (c *adminCall) showCode() {
	in, ok := c.pending()
	if !ok {
		return
	}
	if in.NeedsEnrollment() {
		c.redirect("/login/totp")
		return
	}
	c.codePage(http.StatusOK, in, "")
}

func (c *adminCall) submitCode() {
	form, ok := c.form()
	if !ok {
		return
	}
	in, ok := c.pending()
	if !ok {
		return
	}
	if !c.csrfOK(form, in.Session.ID) {
		c.fail(http.StatusForbidden)
		return
	}
	if in.NeedsEnrollment() {
		c.redirect("/login/totp")
		return
	}
	a := c.auth()
	input := strings.TrimSpace(form.Get("code"))
	keys := a.adminAttemptKeys(in.Admin.Login, c.ip)
	var opened admin.Opened
	err := a.limitedOver(c.ctx(), keys, a.adminLimits, func() error {
		var completeErr error
		opened, completeErr = a.admins.Complete(c.ctx(), in, input, c.client)
		if errors.Is(completeErr, admin.ErrBadFactor) {
			return ErrInvalidCredentials
		}
		return completeErr
	})
	var wait *RateLimitError
	switch {
	case errors.As(err, &wait):
		c.limited(wait.RetryAfter)
	case errors.Is(err, ErrInvalidCredentials):
		c.recordFailure(in.Admin.Login, &admin.CredentialsError{AdminID: in.Admin.ID, Reason: "wrong_code"}, "second_factor", "")
		c.codePage(http.StatusUnauthorized, in, "code.failed")
	case errors.Is(err, admin.ErrNoSignIn):
		c.expired()
	case err != nil:
		c.internal(err)
	default:
		a.clearFailures(c.ctx(), keys.accountIP)
		c.clearPending()
		c.setSession(opened.Secret)
		c.redirect("/")
	}
}

func groupSecret(text string) string {
	var out strings.Builder
	for i := 0; i < len(text); i += 4 {
		if i > 0 {
			out.WriteByte(' ')
		}
		out.WriteString(text[i:min(i+4, len(text))])
	}
	return out.String()
}

func (c *adminCall) enrollPage(status int, in admin.SignIn, flashKey string) {
	enrollment, err := c.auth().admins.Enroll(c.ctx(), in)
	switch {
	case errors.Is(err, admin.ErrNoSignIn):
		c.expired()
		return
	case err != nil:
		c.internal(err)
		return
	}
	p := c.newPage()
	p.Title, p.CSRF = p.T("enroll.title"), c.csrf(in.Session.ID)
	image, err := adminui.QR(enrollment.URI, p.T("enroll.qr"))
	if err != nil {
		c.internal(err)
		return
	}
	if flashKey != "" {
		p.Flash, p.FlashKind = p.T(flashKey), "error"
	}
	p.Data = adminui.EnrollData{Login: in.Admin.Login, QR: image, Secret: groupSecret(enrollment.Secret), URI: template.URL(enrollment.URI)} //nolint:gosec
	if status == http.StatusUnauthorized {
		c.w.Header().Set("WWW-Authenticate", `Form realm="administration"`)
	}
	c.render(status, "enroll", p)
}

func (c *adminCall) showEnroll() {
	in, ok := c.pending()
	if !ok {
		return
	}
	if !in.NeedsEnrollment() {
		c.redirect("/login/code")
		return
	}
	c.enrollPage(http.StatusOK, in, "")
}

func (c *adminCall) submitEnroll() {
	form, ok := c.form()
	if !ok {
		return
	}
	in, ok := c.pending()
	if !ok {
		return
	}
	if !c.csrfOK(form, in.Session.ID) {
		c.fail(http.StatusForbidden)
		return
	}
	if !in.NeedsEnrollment() {
		c.redirect("/login/code")
		return
	}
	a := c.auth()
	input := form.Get("code")
	keys := a.adminAttemptKeys(in.Admin.Login, c.ip)
	var opened admin.Opened
	var codes []string
	err := a.limitedOver(c.ctx(), keys, a.adminLimits, func() error {
		var completeErr error
		opened, codes, completeErr = a.admins.CompleteEnrollment(c.ctx(), in, input, c.client)
		if errors.Is(completeErr, admin.ErrBadFactor) {
			return ErrInvalidCredentials
		}
		return completeErr
	})
	var wait *RateLimitError
	switch {
	case errors.As(err, &wait):
		c.limited(wait.RetryAfter)
	case errors.Is(err, ErrInvalidCredentials):
		c.recordFailure(in.Admin.Login, &admin.CredentialsError{AdminID: in.Admin.ID, Reason: "wrong_code"}, "second_factor", "")
		c.enrollPage(http.StatusUnauthorized, in, "enroll.failed")
	case errors.Is(err, admin.ErrNoSignIn):
		c.expired()
	case err != nil:
		c.internal(err)
	default:
		a.clearFailures(c.ctx(), keys.accountIP)
		c.clearPending()
		c.setSession(opened.Secret)
		p := c.signedPage(opened.Session)
		p.Title, p.Data = p.T("recovery.title"), adminui.RecoveryData{Codes: codes}
		c.render(http.StatusOK, "recovery", p)
	}
}

func (c *adminCall) home() {
	ses, ok := c.requireSession()
	if !ok {
		return
	}
	left := admin.RecoveryCodeCount
	if !c.auth().admins.WithoutSecondFactor() {
		var err error
		if left, err = c.auth().admins.RecoveryCodesLeft(c.ctx(), ses.AdminID); err != nil {
			c.internal(err)
			return
		}
	}
	p := c.signedPage(ses)
	p.Title, p.Data = p.T("home.title"), adminui.HomeData{Login: ses.Login, SignedAt: ses.CreatedAt, RecoveryCodes: left}
	c.render(http.StatusOK, "home", p)
}

func (c *adminCall) logout() {
	form, ok := c.form()
	if !ok {
		return
	}
	ses, state := c.resolveSession()
	switch state {
	case sessionFailed:
		return
	case signedOut:
		c.redirect("/login")
		return
	case signedIn:
	}
	if !c.csrfOK(form, ses.ID) {
		c.fail(http.StatusForbidden)
		return
	}
	if err := c.auth().admins.End(c.ctx(), ses, c.client); err != nil {
		c.internal(err)
		return
	}
	c.clearSession()
	c.redirect("/login")
}
