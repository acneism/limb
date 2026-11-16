package limb

import (
	"errors"
	"net/http"
	"time"
)

type sessionBody struct {
	ID         string      `json:"id"`
	Kind       SessionKind `json:"kind"`
	IP         string      `json:"ip"`
	UserAgent  string      `json:"user_agent"`
	CreatedAt  time.Time   `json:"created_at"`
	LastSeenAt time.Time   `json:"last_seen_at"`
	ExpiresAt  time.Time   `json:"expires_at"`
	Current    bool        `json:"current"`
}

type sessionsBody struct {
	Sessions []sessionBody `json:"sessions"`
}

type currentSessionBody struct {
	UserID                 string      `json:"user_id"`
	SessionID              string      `json:"session_id"`
	Kind                   SessionKind `json:"kind"`
	ExpiresAt              time.Time   `json:"expires_at"`
	CSRFToken              string      `json:"csrf_token,omitempty"`
	PasswordChangeRequired bool        `json:"password_change_required"`
}

func (a *Auth) handleSessions(w http.ResponseWriter, r *http.Request) {
	principal, ok := a.authenticated(w, r, false)
	if !ok {
		return
	}
	sessions, err := a.Sessions(r.Context(), principal)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	body := sessionsBody{Sessions: make([]sessionBody, 0, len(sessions))}
	for _, s := range sessions {
		body.Sessions = append(body.Sessions, sessionBody{
			ID:         s.ID,
			Kind:       s.Kind,
			IP:         s.IP,
			UserAgent:  s.UserAgent,
			CreatedAt:  inSeconds(s.CreatedAt),
			LastSeenAt: inSeconds(s.LastSeenAt),
			ExpiresAt:  inSeconds(s.ExpiresAt),
			Current:    s.Current,
		})
	}
	writeJSON(w, http.StatusOK, body)
}

func (a *Auth) handleCurrentSession(w http.ResponseWriter, r *http.Request) {
	principal, ok := a.authenticated(w, r, true)
	if !ok {
		return
	}
	sessions, err := a.Sessions(r.Context(), principal)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	for _, s := range sessions {
		if !s.Current {
			continue
		}
		body := currentSessionBody{
			UserID:                 string(principal.UserID),
			SessionID:              s.ID,
			Kind:                   s.Kind,
			ExpiresAt:              inSeconds(s.ExpiresAt),
			PasswordChangeRequired: principal.MustChangePassword,
		}
		if s.Kind == SessionCookie {
			body.CSRFToken = a.keys.CSRFToken(s.ID)
		}
		writeJSON(w, http.StatusOK, body)
		return
	}
	a.fail(w, r, ErrUnauthenticated)
}

func (a *Auth) handleEndSession(w http.ResponseWriter, r *http.Request) {
	principal, ok := a.authenticated(w, r, false)
	if !ok {
		return
	}
	var body confirmRequest
	if e := readJSON(w, r, &body, false); e != nil {
		writeError(w, r, e)
		return
	}
	id := r.PathValue("id")
	if err := a.TerminateSession(r.Context(), principal, id, body.Password); err != nil {
		a.fail(w, r, err)
		return
	}
	if id == principal.SessionID {
		a.clearCredentials(w, principal.SessionKind)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Auth) authenticated(w http.ResponseWriter, r *http.Request, allowRestricted bool) (Principal, bool) {
	principal, err := a.Authenticate(r)
	if err == nil || (allowRestricted && errors.Is(err, ErrPasswordChangeRequired)) {
		return principal, true
	}
	a.fail(w, r, err)
	return Principal{}, false
}

type passwordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type confirmRequest struct {
	Password string `json:"password"`
}

func (a *Auth) handleLogoutAll(w http.ResponseWriter, r *http.Request) {
	principal, ok := a.authenticated(w, r, false)
	if !ok {
		return
	}
	var body confirmRequest
	if e := readJSON(w, r, &body, false); e != nil {
		writeError(w, r, e)
		return
	}
	if err := a.LogoutAll(r.Context(), principal, body.Password); err != nil {
		a.fail(w, r, err)
		return
	}
	a.clearCredentials(w, principal.SessionKind)
	w.WriteHeader(http.StatusNoContent)
}

func (a *Auth) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	principal, ok := a.authenticated(w, r, true)
	if !ok {
		return
	}
	var body passwordChangeRequest
	if e := readJSON(w, r, &body, true); e != nil {
		writeError(w, r, e)
		return
	}
	if body.CurrentPassword == "" || body.NewPassword == "" {
		writeError(w, r, newAPIError(codeInvalidRequest))
		return
	}
	login, err := a.ChangePassword(r.Context(), principal, body.CurrentPassword, body.NewPassword)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.answerLogin(w, login)
}
