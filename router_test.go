package limb

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

var routeMethods = map[string][]string{
	"/login":                 {http.MethodPost},
	"/token":                 {http.MethodPost},
	"/token/refresh":         {http.MethodPost},
	"/token/introspect":      {http.MethodPost},
	"/logout":                {http.MethodPost},
	"/logout/all":            {http.MethodPost},
	"/password/change":       {http.MethodPost},
	"/sessions":              {http.MethodGet, http.MethodHead},
	"/sessions/current":      {http.MethodGet, http.MethodHead, http.MethodDelete},
	"/sessions/someone":      {http.MethodDelete},
	"/.well-known/jwks.json": {http.MethodGet, http.MethodHead},
}

var everyMethod = []string{
	http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
	http.MethodDelete, http.MethodOptions, http.MethodTrace,
}

func newServicesAPIFixture(t *testing.T, opts ...Option) *apiFixture {
	t.Helper()
	all := append([]Option{WithServiceKey("billing", serviceKeyOf("billing"))}, opts...)
	return newAPIFixture(t, all...)
}

func TestARouteRefusesTheMethodsThatItDoesNotHave(t *testing.T) {
	f := newServicesAPIFixture(t)
	for path, allowed := range routeMethods {
		want := slices.Clone(allowed)
		slices.Sort(want)
		for _, method := range everyMethod {
			rec := f.send(t, method, path, nil)
			if slices.Contains(allowed, method) {
				if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
					t.Errorf("%s %s = %d, want the route to run", method, path, rec.Code)
				}
				continue
			}
			f.expectError(t, rec, http.StatusMethodNotAllowed, "method_not_allowed")
			if got := rec.Header().Get("Allow"); got != strings.Join(want, ", ") {
				t.Errorf("%s %s: Allow = %q, want %q", method, path, got, strings.Join(want, ", "))
			}
		}
	}
}

func TestAPathThatIsNotARouteIsNotFound(t *testing.T) {
	f := newServicesAPIFixture(t)
	paths := []string{
		"/", "/nope", "/login/", "/LOGIN", "/sessions/", "/sessions/a/b", "/token/refresh/x",
		"/token/", "/logout/all/", "/password", "/.well-known/", "/.well-known/jwks.json/",
		"/.well-known/jwks", "/%2e%2e/login", "/sessions/%2F",
	}
	for _, path := range paths {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
			rec := f.send(t, method, path, nil)
			f.expectError(t, rec, http.StatusNotFound, "not_found")
			if rec.Header().Get("Allow") != "" {
				t.Errorf("%s %s: a path that is not found has Allow %q", method, path, rec.Header().Get("Allow"))
			}
		}
	}
}

func TestEveryAnswerIsMarkedAsNotToBeStoredOrSniffed(t *testing.T) {
	f := newServicesAPIFixture(t)
	for path := range routeMethods {
		for _, method := range everyMethod {
			rec := f.send(t, method, path, nil)
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("%s %s: X-Content-Type-Options = %q", method, path, got)
			}
			if got := rec.Header().Get("Content-Security-Policy"); got != "default-src 'none'; frame-ancestors 'none'" {
				t.Errorf("%s %s: Content-Security-Policy = %q", method, path, got)
			}
			if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
				t.Errorf("%s %s: Referrer-Policy = %q", method, path, got)
			}
			cacheControl := rec.Header().Get("Cache-Control")
			if path == "/.well-known/jwks.json" && rec.Code == http.StatusOK {
				continue
			}
			if cacheControl != "no-store" {
				t.Errorf("%s %s: Cache-Control = %q", method, path, cacheControl)
			}
		}
	}
}

var endpointRoutes = []struct {
	name      string
	off       Endpoint
	turnedOff []string
}{
	{"login", EndpointLogin, []string{"/login"}},
	{"token", EndpointToken, []string{"/token"}},
	{"refresh", EndpointRefresh, []string{"/token/refresh"}},
	{"logout", EndpointLogout, []string{"/logout"}},
	{"logout all", EndpointLogoutAll, []string{"/logout/all"}},
	{"password change", EndpointPasswordChange, []string{"/password/change"}},
	{"sessions", EndpointSessions, []string{"/sessions", "/sessions/current", "/sessions/someone"}},
	{"jwks", EndpointJWKS, []string{"/.well-known/jwks.json"}},
	{"introspect", EndpointIntrospect, []string{"/token/introspect"}},
}

func TestEndpointsCanBeTurnedOff(t *testing.T) {
	for _, tc := range endpointRoutes {
		t.Run(tc.name, func(t *testing.T) {
			f := newServicesAPIFixture(t, WithoutEndpoints(tc.off))
			for path, methods := range routeMethods {
				for _, method := range methods {
					rec := f.send(t, method, path, nil)
					if slices.Contains(tc.turnedOff, path) {
						f.expectError(t, rec, http.StatusNotFound, "not_found")
						continue
					}
					if rec.Code == http.StatusNotFound {
						t.Errorf("%s %s = 404 although only %s is off", method, path, tc.name)
					}
				}
			}
		})
	}
}

func TestNoAnswerCarriesCORSHeaders(t *testing.T) {
	f := newServicesAPIFixture(t)
	login, _ := f.signIn(t)
	for path, methods := range routeMethods {
		for _, method := range append(everyMethod, methods...) {
			opts := append(f.signed(login), fromOrigin("https://spa.example.net"), header("Access-Control-Request-Method", "POST"), header("Access-Control-Request-Headers", "content-type"))
			rec := f.send(t, method, path, nil, opts...)
			for name := range rec.Header() {
				if strings.HasPrefix(strings.ToLower(name), "access-control-") {
					t.Errorf("%s %s sets %s", method, path, name)
				}
			}
			for _, vary := range rec.Header().Values("Vary") {
				if strings.Contains(strings.ToLower(vary), "origin") {
					t.Errorf("%s %s says Vary: %s", method, path, vary)
				}
			}
		}
	}
}
