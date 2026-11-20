package limb

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/acneism/limb/internal/admin"
	"github.com/acneism/limb/internal/adminui"
	"github.com/acneism/limb/store"
)

const (
	maxAdminForm          = 16 << 10
	maxAdminLoginInput    = 256
	maxAdminPasswordInput = 1024
	adminCSRFField        = "csrf"
	adminLanguageCookie   = "limb_admin_lang"
	adminLanguageLifetime = 365 * 24 * time.Hour
	adminPendingCookie    = "limb_admin_login"
	adminSessionCookie    = "limb_admin"
	adminAssetsPrefix     = "/assets/"
)

const adminContentSecurityPolicy = "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; img-src 'self'; style-src 'self'"

const adminPermissionsPolicy = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()"

type adminRoute struct {
	method string
	path   string
	run    func(c *adminCall)
}

type adminSite struct {
	a         *Auth
	templates *adminui.Templates
	base      string
	asset     string
	routes    []adminRoute
}

// AdminHandler returns the web administration: a handler that has pages to sign
// in with a password and the one-time password of an authenticator, to manage the
// account of the administrator who signed in and, later, the users and the audit
// log. The application mounts it under the path that it gave to
// WithAdminMountPath and strips that path, for example
//
//	mux.Handle("/admin/", http.StripPrefix("/admin", auth.AdminHandler()))
//
// AdminHandler panics when there is no mount path, because the cookies of the
// administration are scoped to it and its pages link to it, and a mistake of that
// kind is one to find when the application starts.
//
// The administrators are made with Admin().CreateAdmin or the command
// line and never from the web. The first sign-in of an administrator binds an
// authenticator: a page shows a QR code, and the one-time password that the
// authenticator shows confirms it and brings ten recovery codes, shown once. After
// that the sign-in has two steps, the password and then a one-time password or a
// recovery code, and a one-time password works once.
//
// The pages are server-side HTML with a stylesheet that the library serves
// itself. They run no script and ask nothing of another site, so every response
// carries a Content-Security-Policy that allows only the stylesheet of the
// administration and its own forms and forbids framing, and the headers that tell
// a browser to keep nothing, guess no type and send no referrer. A form is
// sent with POST, from the origin of the application, which the browser says in
// Sec-Fetch-Site or in Origin, and the forms of a signed-in administrator carry a
// token of the session as well. Behind a proxy that ends TLS, WithTrustedProxies
// lets limb take the scheme and the address of the client from its headers.
//
// The cookie of the session is HttpOnly, Secure and SameSite=Strict, scoped to the
// mount path and called __Secure-limb_admin, and it has no prefix and is not
// Secure in the development mode. The second step of a sign-in has a cookie of its
// own, scoped to the path of the sign-in, that lives five minutes. A session ends
// after 12 hours and after 30 minutes without a request, see WithAdminSessionTTL,
// when the administrator signs out, when their password or authenticator is
// changed or reset and when the account is disabled or deleted. A wrong password,
// code or recovery code counts against the limits of WithAdminLoginLimits, and
// WithAdminIPs lets only some addresses in.
//
// The language is the one of the Accept-Language header, or the one that the
// administrator chose with the links at the foot of every page, which is kept in a
// cookie. Russian and English are built in, and WithAdminTexts replaces texts and
// adds languages.
func (a *Auth) AdminHandler() http.Handler {
	if a.adminMount == "" {
		panic("limb: AdminHandler needs WithAdminMountPath, the path that the administration is mounted at as the browser sees it, because its cookies and its links use it")
	}
	templates, err := adminui.Parse()
	if err != nil {
		panic(fmt.Sprintf("limb: the templates of the administration are broken: %v", err))
	}
	s := &adminSite{a: a, templates: templates, base: strings.TrimSuffix(a.adminMount, "/"), asset: adminui.StylesheetName()}
	s.routes = []adminRoute{
		{http.MethodGet, "/", (*adminCall).home},
		{http.MethodGet, "/login", (*adminCall).showLogin},
		{http.MethodPost, "/login", (*adminCall).submitLogin},
		{http.MethodGet, "/login/code", (*adminCall).showCode},
		{http.MethodPost, "/login/code", (*adminCall).submitCode},
		{http.MethodGet, "/login/totp", (*adminCall).showEnroll},
		{http.MethodPost, "/login/totp", (*adminCall).submitEnroll},
		{http.MethodPost, "/logout", (*adminCall).logout},
		{http.MethodGet, "/users", (*adminCall).showUsers},
		{http.MethodGet, "/users/{id}", (*adminCall).showUser},
		{http.MethodPost, "/users/{id}/block", (*adminCall).submitBlock},
		{http.MethodPost, "/users/{id}/unblock", (*adminCall).submitUnblock},
		{http.MethodPost, "/users/{id}/sessions/end", (*adminCall).submitEndSession},
		{http.MethodPost, "/users/{id}/sessions/end-all", (*adminCall).submitEndSessions},
		{http.MethodPost, "/users/{id}/delete", (*adminCall).submitDelete},
		{http.MethodPost, "/users/{id}/restore", (*adminCall).submitRestore},
		{http.MethodGet, "/account", (*adminCall).showAccount},
		{http.MethodPost, "/account/password", (*adminCall).changePassword},
		{http.MethodPost, "/account/recovery", (*adminCall).renewRecoveryCodes},
		{http.MethodPost, "/account/authenticator", (*adminCall).beginRebind},
		{http.MethodPost, "/account/authenticator/confirm", (*adminCall).confirmRebind},
		{http.MethodPost, "/account/sessions/end", (*adminCall).endSession},
		{http.MethodPost, "/account/sessions/end-others", (*adminCall).endOtherSessions},
		{http.MethodGet, adminAssetsPrefix + s.asset, (*adminCall).stylesheet},
	}
	return s
}

type adminCall struct {
	s      *adminSite
	w      http.ResponseWriter
	r      *http.Request
	lang   string
	ip     netip.Addr
	client admin.Client
	userID string
}

func (c *adminCall) auth() *Auth {
	return c.s.a
}

func (c *adminCall) ctx() context.Context {
	return c.r.Context()
}

func (s *adminSite) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c := &adminCall{s: s, w: w, r: r, ip: s.a.clientIP(r)}
	c.client = admin.Client{IP: addressText(c.ip), UserAgent: r.UserAgent()}
	c.serve() //nolint:contextcheck
}

func (c *adminCall) serve() {
	defer c.recoverPanic()
	c.s.setHeaders(c.w.Header())
	c.lang = c.chooseLanguage()
	if !c.auth().adminAllowed(c.r) {
		c.fail(http.StatusNotFound)
		return
	}
	if c.switchLanguage() {
		return
	}
	path := c.r.URL.Path
	if path == "" {
		path = "/"
	}
	var allowed []string
	for _, route := range c.s.routes {
		id, matched := matchRoute(route.path, path)
		if !matched {
			continue
		}
		if route.method == c.r.Method || (c.r.Method == http.MethodHead && route.method == http.MethodGet) {
			c.userID = id
			route.run(c)
			return
		}
		allowed = append(allowed, route.method)
	}
	if len(allowed) == 0 {
		c.fail(http.StatusNotFound)
		return
	}
	c.w.Header().Set("Allow", allowHeader(allowed))
	c.fail(http.StatusMethodNotAllowed)
}

func matchRoute(pattern, path string) (string, bool) {
	before, after, hasID := strings.Cut(pattern, "{id}")
	if !hasID {
		return "", pattern == path
	}
	if len(path) <= len(before)+len(after) || !strings.HasPrefix(path, before) || !strings.HasSuffix(path, after) {
		return "", false
	}
	id := path[len(before) : len(path)-len(after)]
	if !validPathID(id) {
		return "", false
	}
	return id, true
}

func validPathID(id string) bool {
	if id == "" || len(id) > store.MaxIDLength {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func (c *adminCall) by(ses admin.Session) actorRef {
	return actorRef{actor: adminActor(ses.AdminID), ip: c.client.IP}
}

func (c *adminCall) recoverPanic() {
	if p := recover(); p != nil {
		c.auth().logger.ErrorContext(c.ctx(), "limb: a page of the administration panicked", "panic_type", fmt.Sprintf("%T", p))
		c.fail(http.StatusInternalServerError)
	}
}

func (s *adminSite) setHeaders(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", adminContentSecurityPolicy)
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", adminPermissionsPolicy)
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	if s.a.secure {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
}

func (a *Auth) adminAllowed(r *http.Request) bool {
	if len(a.adminIPs) == 0 {
		return true
	}
	ip := a.clientIP(r)
	if !ip.IsValid() {
		return false
	}
	for _, prefix := range a.adminIPs {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *Auth) adminCookieName(base string) string {
	if a.secure {
		return "__Secure-" + base
	}
	return base
}

func (c *adminCall) cookie(name, path string) *http.Cookie {
	return c.auth().newCookie(c.auth().adminCookieName(name), path, http.SameSiteStrictMode)
}

func (c *adminCall) sessionCookie() *http.Cookie {
	return c.cookie(adminSessionCookie, c.s.base+"/")
}

func (c *adminCall) pendingCookie() *http.Cookie {
	return c.cookie(adminPendingCookie, c.s.base+"/login")
}

func (c *adminCall) setSession(value string) {
	cookie := c.sessionCookie() //nolint:gosec
	cookie.Value = value
	http.SetCookie(c.w, cookie)
}

func (c *adminCall) setPending(value string, expires time.Time) {
	cookie := c.pendingCookie() //nolint:gosec
	cookie.Value = value
	cookie.Expires = expires.UTC().Truncate(time.Second)
	cookie.MaxAge = cookieLifetime(expires, c.auth().now())
	http.SetCookie(c.w, cookie)
}

func (c *adminCall) clearSession() {
	clearCookie(c.w, c.sessionCookie())
}

func (c *adminCall) clearPending() {
	clearCookie(c.w, c.pendingCookie())
}

func (c *adminCall) csrf(id string) string {
	return c.auth().keys.CSRFToken("admin:" + id)
}

func (c *adminCall) csrfOK(form url.Values, id string) bool {
	return c.auth().keys.CheckCSRF("admin:"+id, form.Get(adminCSRFField))
}

func (c *adminCall) chooseLanguage() string {
	catalog := c.auth().adminCatalog
	if cookie, err := c.r.Cookie(adminLanguageCookie); err == nil && catalog.Has(cookie.Value) {
		return cookie.Value
	}
	return negotiateAmong(c.r.Header.Get("Accept-Language"), catalog.Has, adminui.DefaultLanguage)
}

func (c *adminCall) switchLanguage() bool {
	if c.r.Method != http.MethodGet && c.r.Method != http.MethodHead {
		return false
	}
	asked := c.r.URL.Query()["lang"]
	if len(asked) != 1 || !c.auth().adminCatalog.Has(asked[0]) {
		return false
	}
	cookie := c.auth().newCookie(adminLanguageCookie, c.s.base+"/", http.SameSiteStrictMode) //nolint:gosec
	cookie.Value = asked[0]
	cookie.MaxAge = int(adminLanguageLifetime / time.Second)
	http.SetCookie(c.w, cookie)
	target := c.r.URL.Path
	if target == "" {
		target = "/"
	}
	rest := c.r.URL.Query()
	rest.Del("lang")
	if len(rest) > 0 {
		target += "?" + rest.Encode()
	}
	c.redirect(target)
	return true
}

func (c *adminCall) languageHref(code string) string {
	query := c.r.URL.Query()
	query.Set("lang", code)
	return "?" + query.Encode()
}

func (c *adminCall) redirect(path string) {
	if path == "" {
		path = "/"
	}
	http.Redirect(c.w, c.r, c.s.base+path, http.StatusSeeOther)
}

func (c *adminCall) newPage() *adminui.Page {
	catalog := c.auth().adminCatalog
	p := adminui.NewPage(catalog, c.lang)
	p.Service, p.Base, p.Stylesheet = c.auth().brand, c.s.base, c.s.base+adminAssetsPrefix+c.s.asset
	for _, code := range catalog.Languages() {
		p.Languages = append(p.Languages, adminui.LanguageLink{Code: code, Name: adminui.LanguageName(code), Current: code == c.lang, Href: c.languageHref(code)})
	}
	return p
}

func (c *adminCall) render(status int, name string, p *adminui.Page) {
	out, err := c.s.templates.Render(name, p)
	if err != nil {
		c.auth().logger.ErrorContext(c.ctx(), "limb: a page of the administration cannot be rendered", "page", name, "error", err)
		http.Error(c.w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	c.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	c.w.WriteHeader(status)
	_, _ = c.w.Write(out)
}

func (c *adminCall) fail(status int) {
	p := c.newPage()
	key := "error." + strconv.Itoa(status)
	p.Title = p.T(key)
	p.Data = adminui.ErrorData{Title: p.T(key), Text: p.T(key + ".text")}
	c.render(status, "error", p)
}

func (c *adminCall) limited(wait time.Duration) {
	wait = wholeSeconds(wait)
	c.w.Header().Set("Retry-After", retryAfterSeconds(wait))
	p := c.newPage()
	p.Title = p.T("error.429")
	p.Data = adminui.ErrorData{Title: p.T("error.429"), Text: p.T("error.429.text", waitText(p, wait))}
	c.render(http.StatusTooManyRequests, "error", p)
}

func waitText(p *adminui.Page, wait time.Duration) string {
	switch {
	case wait < time.Minute:
		return p.T("error.seconds", int(wait/time.Second))
	case wait < time.Hour:
		return p.T("error.minutes", int((wait+time.Minute-1)/time.Minute))
	}
	return p.T("error.hours", int((wait+time.Hour-1)/time.Hour))
}

func (c *adminCall) internal(err error) {
	c.auth().logger.ErrorContext(c.ctx(), "limb: the administration failed", "error", err)
	c.fail(http.StatusInternalServerError)
}

func (c *adminCall) sameOrigin() bool {
	site := c.r.Header.Get("Sec-Fetch-Site")
	switch site {
	case "same-origin":
		return true
	case "":
	default:
		return false
	}
	origins := c.r.Header.Values("Origin")
	if len(origins) != 1 {
		return false
	}
	origin, ok := parseOrigin(origins[0])
	return ok && origin == c.auth().requestOrigin(c.r)
}

func (c *adminCall) form() (url.Values, bool) {
	if !c.sameOrigin() {
		c.fail(http.StatusForbidden)
		return nil, false
	}
	mediaType, _, err := mime.ParseMediaType(c.r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		c.fail(http.StatusUnsupportedMediaType)
		return nil, false
	}
	c.r.Body = http.MaxBytesReader(c.w, c.r.Body, maxAdminForm)
	if err = c.r.ParseForm(); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			c.fail(http.StatusRequestEntityTooLarge)
		} else {
			c.fail(http.StatusBadRequest)
		}
		return nil, false
	}
	return c.r.PostForm, true
}

func (c *adminCall) stylesheet() {
	h := c.w.Header()
	h.Set("Cache-Control", "public, max-age=31536000, immutable")
	h.Set("Content-Type", "text/css; charset=utf-8")
	body := adminui.Stylesheet()
	h.Set("Content-Length", strconv.Itoa(len(body)))
	c.w.WriteHeader(http.StatusOK)
	_, _ = c.w.Write(body)
}
