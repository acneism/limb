package limb

import (
	"net/http"
	"strings"
	"time"
)

const (
	refreshCookieBase = "limb_refresh"
	refreshRoute      = "/token/refresh"
)

func refreshCookieName(development bool) string {
	if development {
		return refreshCookieBase
	}
	return "__Secure-" + refreshCookieBase
}

func refreshCookiePath(mountPath string) string {
	return strings.TrimSuffix(mountPath, "/") + refreshRoute
}

func cookieLifetime(expires, now time.Time) int {
	return max(1, int(expires.Sub(now)/time.Second))
}

func (a *Auth) newCookie(name, path string, sameSite http.SameSite) *http.Cookie {
	return &http.Cookie{ //nolint:gosec
		Name:     name,
		Path:     path,
		HttpOnly: true,
		Secure:   a.secure,
		SameSite: sameSite,
	}
}

func (a *Auth) sessionCookie() *http.Cookie {
	return a.newCookie(a.cookie, "/", a.sameSite)
}

func (a *Auth) refreshCookieOf() *http.Cookie {
	return a.newCookie(a.refreshCookie, a.refreshPath, http.SameSiteStrictMode)
}

func (a *Auth) setCookie(w http.ResponseWriter, c *http.Cookie, value string, expires time.Time) { //nolint:gosec
	c.Value = value
	c.Expires = expires.UTC().Truncate(time.Second)
	c.MaxAge = cookieLifetime(expires, a.now())
	http.SetCookie(w, c)
}

func clearCookie(w http.ResponseWriter, c *http.Cookie) { //nolint:gosec
	c.Expires = time.Unix(0, 0)
	c.MaxAge = -1
	http.SetCookie(w, c)
}

func (a *Auth) setSessionCookie(w http.ResponseWriter, value string, expires time.Time) {
	a.setCookie(w, a.sessionCookie(), value, expires)
}

func (a *Auth) clearSessionCookie(w http.ResponseWriter) {
	clearCookie(w, a.sessionCookie())
}

func (a *Auth) setRefreshCookie(w http.ResponseWriter, value string, expires time.Time) {
	a.setCookie(w, a.refreshCookieOf(), value, expires)
}

func (a *Auth) clearRefreshCookie(w http.ResponseWriter) {
	clearCookie(w, a.refreshCookieOf())
}
