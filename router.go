package limb

import (
	"net/http"
	"slices"
	"strings"
)

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
// routes are relative to the mount path. A request for another path gets a 404
// and one with another method a 405 with the Allow header, both in JSON.
func (a *Auth) Handler() http.Handler {
	return &router{auth: a, routes: a.routes()}
}

func (a *Auth) routes() []route {
	all := []route{
		{EndpointLogin, http.MethodPost, "/login", false, a.handleLogin},
		{EndpointToken, http.MethodPost, "/token", false, a.handleToken},
		{EndpointRefresh, http.MethodPost, "/token/refresh", false, a.handleRefresh},
		{EndpointLogout, http.MethodPost, "/logout", false, a.handleLogout},
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
