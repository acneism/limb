package limb

import (
	"context"
	"errors"
	"net/http"
)

type principalKey struct{}

// CurrentUser returns the principal that RequireAuth or OptionalAuth found for
// the request. The second result is false for a request that is not signed in.
func CurrentUser(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalKey{}).(Principal)
	return principal, ok
}

func withPrincipal(r *http.Request, p Principal) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
}

// RequireAuth wraps a handler so that it only runs for a request that is signed
// in, and puts who made it in the context, see CurrentUser. The check is the one
// of Authenticate, so a request with a Bearer header is a token request and any
// other is a cookie request, which must also pass the cross-site check when it
// changes data.
//
// Any other request is answered with a JSON error, as the routes of Handler are:
// 401 unauthenticated, with the header WWW-Authenticate: Bearer
// error="invalid_token" when the request had a Bearer token; 403 csrf_failed;
// 403 password_change_required for a user who has to choose a new password
// first, whatever the route is; and 500 internal_error when the session cannot
// be read, without the reason.
//
// A request for a CORS preflight has no credentials and is answered with 401, so
// the CORS middleware of the application has to be in front of RequireAuth.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := a.Authenticate(r)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		next.ServeHTTP(w, withPrincipal(r, principal))
	})
}

// OptionalAuth wraps a handler for pages that look different for a user who is
// signed in and for one who is not. A request that is signed in gets its
// principal in the context, see CurrentUser. Every other request, whatever the
// reason is, reaches the handler as an anonymous one, including a request of a
// user who has to choose a new password and one that failed the cross-site check:
// neither may act as the user. A failure to read the session is logged and also
// leaves the request anonymous.
func (a *Auth) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := a.Authenticate(r)
		switch {
		case err == nil:
			r = withPrincipal(r, principal)
		case !errors.Is(err, ErrUnauthenticated) && !errors.Is(err, ErrPasswordChangeRequired) && !errors.Is(err, ErrCSRF):
			a.logFailure(r, err)
		}
		next.ServeHTTP(w, r)
	})
}
