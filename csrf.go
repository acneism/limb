package limb

import (
	"net/http"
	"strings"
)

const csrfHeader = "X-CSRF-Token"

func changesData(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	}
	return true
}

func (a *Auth) checkCSRF(r *http.Request, p Principal) error {
	if err := a.checkOrigin(r); err != nil {
		return err
	}
	if !a.keys.CheckCSRF(p.SessionID, r.Header.Get(csrfHeader)) {
		return ErrCSRF
	}
	return nil
}

func (a *Auth) checkOrigin(r *http.Request) error {
	if r.Header.Get("Sec-Fetch-Site") == "same-origin" {
		return nil
	}
	origins := r.Header.Values("Origin")
	if len(origins) != 1 {
		return ErrCSRF
	}
	origin, ok := parseOrigin(origins[0])
	if !ok {
		return ErrCSRF
	}
	if origin == a.requestOrigin(r) {
		return nil
	}
	if _, trusted := a.origins[origin]; trusted {
		return nil
	}
	return ErrCSRF
}

func (a *Auth) requestOrigin(r *http.Request) string {
	scheme := "http"
	switch {
	case r.TLS != nil:
		scheme = "https"
	case a.fromTrustedProxy(r):
		if forwarded := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))); forwarded == "https" {
			scheme = "https"
		}
	}
	origin, _ := parseOrigin(scheme + "://" + r.Host)
	return origin
}
