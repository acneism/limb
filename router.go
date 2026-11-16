package limb

import (
	"net/http"
	"slices"
	"strings"
)

const sessionsPrefix = "/sessions/"

type route struct {
	endpoint Endpoint
	method   string
	path     string
	byID     bool
	run      http.HandlerFunc
}

func (rt route) matches(path string) (string, bool) {
	if !rt.byID {
		return "", path == rt.path
	}
	id, found := strings.CutPrefix(path, rt.path)
	if !found || id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

type router struct {
	auth   *Auth
	routes []route
}

// Handler returns the HTTP API of limb. The application mounts it under a path of
// its choice and strips that path, for example
//
//	mux.Handle("/auth/", http.StripPrefix("/auth", auth.Handler()))
//
// and tells limb the path with WithMountPath if it uses WithRefreshCookie. The
// routes below are relative to the mount path. A request for another path gets a
// 404 and one with another method a 405 with the Allow header; OPTIONS is a
// method like any other, so a CORS preflight request gets a 405. HEAD works
// wherever GET does. The key set is at /.well-known/jwks.json under the mount
// path; an application that wants it at the root of the site mounts the same
// handler there too.
//
//	POST   /login                    sign in with a cookie session
//	POST   /token                    sign in with tokens
//	POST   /token/refresh            exchange a refresh token for a new pair of tokens
//	POST   /token/introspect         ask whether an access token is still good
//	POST   /logout                   end the current session
//	POST   /logout/all               end every session of the user
//	POST   /password/change          change the password
//	GET    /sessions                 list the sessions of the user
//	GET    /sessions/current         describe the current session
//	DELETE /sessions/{id}            end a session of the user
//	GET    /.well-known/jwks.json    the public keys that verify access tokens
//
// The introspection route exists only when a service key is given with
// WithServiceKey, and WithoutEndpoints removes any of the others.
//
// Requests and responses are JSON with the names of the fields in snake_case. A
// request with a body must have the content type application/json, may not be
// larger than 64 KiB and may not have a field that the route does not know. Every
// response is marked Cache-Control: no-store, except the key set, which clients
// may keep for five minutes, and carries the headers that tell a browser to do
// nothing with it: X-Content-Type-Options: nosniff, a Content-Security-Policy
// that allows nothing and forbids framing, and Referrer-Policy: no-referrer. The
// bodies of the requests are
//
//	/login, /token             {"login", "password"}
//	/token/refresh             {"refresh_token"}, or none with WithRefreshCookie
//	/password/change           {"current_password", "new_password"}
//	/logout/all, DELETE /sessions/{id}
//	                           none, or {"password"} when WithPasswordToEndSessions asks for it
//	/token/introspect          {"token"}, with the key of the service as a Bearer token
//
// and the bodies of the answers are, with every time in RFC 3339, in UTC and to
// the second:
//
//	/login, and /password/change of a cookie session
//	    {"user_id", "session_id", "csrf_token", "expires_at", "password_change_required"}
//	/token, and /password/change of a token session
//	    {"user_id", "session_id", "token_type", "access_token", "access_expires_at",
//	     "refresh_token", "refresh_expires_at", "expires_at", "password_change_required"}
//	/token/refresh
//	    {"token_type", "access_token", "access_expires_at", "refresh_token", "refresh_expires_at"}
//	/sessions
//	    {"sessions": [{"id", "kind", "ip", "user_agent", "created_at", "last_seen_at", "expires_at", "current"}]}
//	/sessions/current
//	    {"user_id", "session_id", "kind", "expires_at", "csrf_token", "password_change_required"}
//	/token/introspect
//	    {"active": false}, or {"active": true, "sub", "sid", "iat", "exp"} with the times in seconds
//	/.well-known/jwks.json
//	    {"keys": [...]}, the JWKS of RFC 7517
//	/logout, /logout/all, DELETE /sessions/{id}
//	    204 with no body
//
// expires_at is when the session ends whatever its activity is, and
// access_expires_at and refresh_expires_at are the ends of the tokens. The
// token_type is always "Bearer". csrf_token is only for a cookie session, and
// refresh_token is not there with WithRefreshCookie.
//
// A failure is a status code and an object that holds the code programs should
// look at and a message for people, in Russian when the Accept-Language header
// prefers it and in English otherwise:
//
//	{"error": {"code": "invalid_credentials", "message": "..."}}
//
// The codes with their statuses are invalid_request 400 (413 for a body that is
// too large), invalid_credentials 401, unauthenticated 401 (with the header
// WWW-Authenticate: Bearer error="invalid_token" when the request carried a
// Bearer token), user_blocked 403, password_change_required 403, csrf_failed 403,
// not_found 404, method_not_allowed 405, unsupported_media_type 415,
// policy_violation 422 with the broken rules of the policy in "rules",
// rate_limited 429 with the Retry-After header and internal_error 500. The reason
// of a failure of limb itself is never in the answer, it goes to the log.
//
// A cookie session is opened by /login, whose answer holds the CSRF token of the
// session and sets the session cookie. The cookie is HttpOnly, Secure and
// SameSite=Lax unless WithCookieSameSite says otherwise, and it is called
// __Host-limb_session; in the development mode it is not Secure and has no
// prefix. The page sends the CSRF token in the header X-CSRF-Token with every
// request that changes data, and such a request has to come from the origin of
// the application, which the browser says in Sec-Fetch-Site or in Origin, or
// from an origin that WithTrustedOrigins allows. Behind a proxy that ends TLS,
// WithTrustedProxies lets limb take the scheme of the origin from
// X-Forwarded-Proto. /login has no session yet, so it only checks where the
// request comes from. Signing in ends the session that the request came with. A
// page that was reloaded gets the CSRF token of its session from
// /sessions/current.
//
// A token session is opened by /token, which answers with an access token and a
// refresh token. Requests carry the access token in the header
// "Authorization: Bearer <access token>", need no CSRF token, and are never
// taken for cookie requests, whatever cookies they have. A refresh token works
// once: /token/refresh answers with a new pair. Two requests with the same
// refresh token that come within ten seconds are taken for one client that asked
// twice, and the second one gets 401 while the session goes on, so a client sends
// one refresh at a time and, when it gets 401 and has just refreshed, looks at
// its own result before it signs the user out. A refresh token used again later
// ends the session. With WithRefreshCookie the refresh token is not in the
// answers but in a cookie that is HttpOnly, SameSite=Strict and sent to the
// refresh route only; /token and /token/refresh then check the origin of the
// request as /login does, /token/refresh takes no token in its body, and the
// cookie is cleared when a refresh fails.
//
// While a user has to choose a new password, every session of theirs can only be
// used to change it, to read the current session and to sign out. Any other route
// of the handler, and any handler behind RequireAuth, answers 403
// password_change_required.
//
// Handler never sets CORS headers. A single-page application on another origin
// needs them, and adding them for the origins it allows is the job of the
// application, in front of this handler. Those origins also go to
// WithTrustedOrigins, and the cookie may have to be SameSite=None, see
// WithCookieSameSite.
func (a *Auth) Handler() http.Handler {
	return &router{auth: a, routes: a.routes()}
}

func (a *Auth) routes() []route {
	all := []route{
		{EndpointLogin, http.MethodPost, "/login", false, a.handleLogin},
		{EndpointToken, http.MethodPost, "/token", false, a.handleToken},
		{EndpointRefresh, http.MethodPost, "/token/refresh", false, a.handleRefresh},
		{EndpointIntrospect, http.MethodPost, "/token/introspect", false, a.handleIntrospect},
		{EndpointLogout, http.MethodPost, "/logout", false, a.handleLogout},
		{EndpointLogoutAll, http.MethodPost, "/logout/all", false, a.handleLogoutAll},
		{EndpointPasswordChange, http.MethodPost, "/password/change", false, a.handlePasswordChange},
		{EndpointSessions, http.MethodGet, "/sessions", false, a.handleSessions},
		{EndpointSessions, http.MethodGet, "/sessions/current", false, a.handleCurrentSession},
		{EndpointSessions, http.MethodDelete, sessionsPrefix, true, a.handleEndSession},
		{EndpointJWKS, http.MethodGet, "/.well-known/jwks.json", false, a.handleJWKS},
	}
	return slices.DeleteFunc(all, func(rt route) bool {
		return a.disabled[rt.endpoint] || (rt.endpoint == EndpointIntrospect && len(a.services) == 0)
	})
}

func (rt *router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setCommonHeaders(w.Header())
	var allowed []string
	for _, candidate := range rt.routes {
		id, found := candidate.matches(r.URL.Path)
		if !found {
			continue
		}
		if candidate.method == r.Method || (r.Method == http.MethodHead && candidate.method == http.MethodGet) {
			if candidate.byID {
				r.SetPathValue("id", id)
			}
			candidate.run(w, r)
			return
		}
		allowed = append(allowed, candidate.method)
	}
	if len(allowed) == 0 {
		writeError(w, r, newAPIError(codeNotFound))
		return
	}
	writeError(w, r, newAPIError(codeMethodNotAllowed).with("Allow", allowHeader(allowed)))
}

func allowHeader(methods []string) string {
	if slices.Contains(methods, http.MethodGet) {
		methods = append(methods, http.MethodHead)
	}
	slices.Sort(methods)
	return strings.Join(methods, ", ")
}
