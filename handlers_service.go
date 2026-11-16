package limb

import (
	"net/http"
	"strconv"
	"time"
)

type keySetBody struct {
	Keys []jwk `json:"keys"`
}

type introspectRequest struct {
	Token string `json:"token"`
}

type introspectionBody struct {
	Active    bool   `json:"active"`
	Subject   string `json:"sub,omitempty"`
	SessionID string `json:"sid,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
}

func (a *Auth) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if _, err := a.ring.signer(r.Context()); err != nil {
		a.fail(w, r, err)
		return
	}
	keys, err := a.publishedKeys(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(jwksMaxAge/time.Second)))
	writeJSON(w, http.StatusOK, keySetBody{Keys: keys})
}

func (a *Auth) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	key, _ := bearerToken(r)
	if _, known := a.serviceName(key); !known {
		w.Header().Set("WWW-Authenticate", tokenType)
		a.fail(w, r, ErrUnauthenticated)
		return
	}
	var body introspectRequest
	if e := readJSON(w, r, &body, true); e != nil {
		writeError(w, r, e)
		return
	}
	if body.Token == "" {
		writeError(w, r, newAPIError(codeInvalidRequest))
		return
	}
	result, err := a.introspect(r.Context(), key, body.Token)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !result.Active {
		writeJSON(w, http.StatusOK, introspectionBody{})
		return
	}
	writeJSON(w, http.StatusOK, introspectionBody{
		Active:    true,
		Subject:   result.Subject,
		SessionID: result.SessionID,
		IssuedAt:  result.IssuedAt.Unix(),
		ExpiresAt: result.ExpiresAt.Unix(),
	})
}
