package limb

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/store"
)

const tokenType = "Bearer"

type credentialsRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type cookieSessionBody struct {
	UserID                 string    `json:"user_id"`
	SessionID              string    `json:"session_id"`
	CSRFToken              string    `json:"csrf_token"`
	ExpiresAt              time.Time `json:"expires_at"`
	PasswordChangeRequired bool      `json:"password_change_required"`
}

type tokensBody struct {
	TokenType        string    `json:"token_type"`
	AccessToken      string    `json:"access_token"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshToken     string    `json:"refresh_token,omitempty"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

type tokenSessionBody struct {
	UserID                 string    `json:"user_id"`
	SessionID              string    `json:"session_id"`
	ExpiresAt              time.Time `json:"expires_at"`
	PasswordChangeRequired bool      `json:"password_change_required"`
	tokensBody
}

func inSeconds(t time.Time) time.Time {
	return t.UTC().Truncate(time.Second)
}

func (a *Auth) tokensOf(tokens Tokens) tokensBody {
	body := tokensBody{
		TokenType:        tokenType,
		AccessToken:      tokens.AccessToken,
		AccessExpiresAt:  inSeconds(tokens.AccessExpiresAt),
		RefreshToken:     tokens.RefreshToken,
		RefreshExpiresAt: inSeconds(tokens.RefreshExpiresAt),
	}
	if a.refreshJar {
		body.RefreshToken = ""
	}
	return body
}

func (a *Auth) answerLogin(w http.ResponseWriter, login Login) {
	if login.Principal.SessionKind == SessionCookie {
		a.setSessionCookie(w, login.Secret, login.ExpiresAt)
		writeJSON(w, http.StatusOK, cookieSessionBody{
			UserID:                 string(login.Principal.UserID),
			SessionID:              login.Principal.SessionID,
			CSRFToken:              login.CSRFToken,
			ExpiresAt:              inSeconds(login.ExpiresAt),
			PasswordChangeRequired: login.Principal.MustChangePassword,
		})
		return
	}
	if a.refreshJar {
		a.setRefreshCookie(w, login.Tokens.RefreshToken, login.Tokens.RefreshExpiresAt)
	}
	writeJSON(w, http.StatusOK, tokenSessionBody{
		UserID:                 string(login.Principal.UserID),
		SessionID:              login.Principal.SessionID,
		ExpiresAt:              inSeconds(login.ExpiresAt),
		PasswordChangeRequired: login.Principal.MustChangePassword,
		tokensBody:             a.tokensOf(login.Tokens),
	})
}

func (a *Auth) readCredentials(w http.ResponseWriter, r *http.Request, kind SessionKind) (Credentials, bool) {
	var body credentialsRequest
	if e := readJSON(w, r, &body, true); e != nil {
		writeError(w, r, e)
		return Credentials{}, false
	}
	if body.Login == "" || body.Password == "" {
		writeError(w, r, newAPIError(codeInvalidRequest))
		return Credentials{}, false
	}
	return Credentials{
		Login:     body.Login,
		Password:  body.Password,
		IP:        a.clientIP(r),
		UserAgent: r.UserAgent(),
		Kind:      kind,
	}, true
}

func (a *Auth) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := a.checkOrigin(r); err != nil {
		a.fail(w, r, err)
		return
	}
	credentials, ok := a.readCredentials(w, r, SessionCookie)
	if !ok {
		return
	}
	login, err := a.Login(r.Context(), credentials)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.endPresentedSession(r)
	a.answerLogin(w, login)
}

func (a *Auth) endPresentedSession(r *http.Request) {
	cookie, err := r.Cookie(a.cookie)
	if err != nil {
		return
	}
	hash, err := secret.Hash(cookie.Value)
	if err != nil {
		return
	}
	ctx := context.WithoutCancel(r.Context())
	resolved, err := a.store.Sessions().ResolveBySecret(ctx, a.tenant, hash)
	if err == nil {
		err = a.store.Sessions().Revoke(ctx, a.tenant, resolved.Session.UserID, resolved.Session.ID, a.now())
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		a.logger.WarnContext(ctx, "limb: the session that the sign-in replaced could not be ended", "error", err)
	}
}

func (a *Auth) handleToken(w http.ResponseWriter, r *http.Request) {
	if a.refreshJar {
		if err := a.checkOrigin(r); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	credentials, ok := a.readCredentials(w, r, SessionToken)
	if !ok {
		return
	}
	login, err := a.Login(r.Context(), credentials)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.answerLogin(w, login)
}

func (a *Auth) refreshTokenOf(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !a.refreshJar {
		var body refreshRequest
		if e := readJSON(w, r, &body, true); e != nil {
			writeError(w, r, e)
			return "", false
		}
		if body.RefreshToken == "" {
			writeError(w, r, newAPIError(codeInvalidRequest))
			return "", false
		}
		return body.RefreshToken, true
	}
	if err := a.checkOrigin(r); err != nil {
		a.fail(w, r, err)
		return "", false
	}
	if e := readJSON(w, r, &struct{}{}, false); e != nil {
		writeError(w, r, e)
		return "", false
	}
	cookie, err := r.Cookie(a.refreshCookie)
	if err != nil || cookie.Value == "" {
		a.fail(w, r, ErrUnauthenticated)
		return "", false
	}
	return cookie.Value, true
}

func (a *Auth) handleRefresh(w http.ResponseWriter, r *http.Request) {
	token, ok := a.refreshTokenOf(w, r)
	if !ok {
		return
	}
	tokens, outcome, err := a.refresh(r.Context(), token)
	if err != nil {
		if a.refreshJar && outcome != refreshRaced && errors.Is(err, ErrUnauthenticated) {
			a.clearRefreshCookie(w)
		}
		a.fail(w, r, err)
		return
	}
	if a.refreshJar {
		a.setRefreshCookie(w, tokens.RefreshToken, tokens.RefreshExpiresAt)
	}
	writeJSON(w, http.StatusOK, a.tokensOf(tokens))
}

func (a *Auth) clearCredentials(w http.ResponseWriter, kind SessionKind) {
	switch {
	case kind == SessionCookie:
		a.clearSessionCookie(w)
	case a.refreshJar:
		a.clearRefreshCookie(w)
	}
}

func (a *Auth) handleLogout(w http.ResponseWriter, r *http.Request) {
	principal, err := a.Authenticate(r)
	switch {
	case err == nil || errors.Is(err, ErrPasswordChangeRequired):
		if err = a.Logout(r.Context(), principal); err != nil {
			a.fail(w, r, err)
			return
		}
		a.clearCredentials(w, principal.SessionKind)
	case errors.Is(err, ErrUnauthenticated):
		a.clearSessionCookie(w)
		if a.refreshJar {
			a.clearRefreshCookie(w)
		}
	default:
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
