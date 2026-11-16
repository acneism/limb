package limb

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
)

func (a *Auth) failure(r *http.Request, err error) *apiError {
	var (
		rate       *RateLimitError
		policy     *PolicyError
		validation *ValidationError
	)
	switch {
	case errors.As(err, &rate):
		return newAPIError(codeRateLimited).with("Retry-After", retryAfterSeconds(rate.RetryAfter))
	case errors.Is(err, ErrInvalidCredentials):
		return newAPIError(codeInvalidCredentials)
	case errors.Is(err, ErrUserBlocked):
		return newAPIError(codeUserBlocked)
	case errors.Is(err, ErrUnauthenticated):
		e := newAPIError(codeUnauthenticated)
		if _, bearer := bearerToken(r); bearer {
			e.with("WWW-Authenticate", `Bearer error="invalid_token"`)
		}
		return e
	case errors.Is(err, ErrPasswordChangeRequired):
		return newAPIError(codePasswordChangeRequired)
	case errors.Is(err, ErrCSRF):
		return newAPIError(codeCSRFFailed)
	case errors.Is(err, ErrSessionNotFound):
		return newAPIError(codeNotFound)
	case errors.As(err, &policy):
		e := newAPIError(codePolicyViolation)
		e.rules = policy.Rules
		return e
	case errors.As(err, &validation):
		return newAPIError(codeInvalidRequest)
	}
	return newAPIError(codeInternal)
}

func (a *Auth) fail(w http.ResponseWriter, r *http.Request, err error) {
	e := a.failure(r, err)
	if e.code == codeInternal {
		a.logFailure(r, err)
	}
	writeError(w, r, e)
}

func (a *Auth) logFailure(r *http.Request, err error) {
	level := slog.LevelError
	if errors.Is(err, context.Canceled) {
		level = slog.LevelDebug
	}
	a.logger.Log(r.Context(), level, "limb: a request failed", "method", r.Method, "error", err)
}
