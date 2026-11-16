package limb

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/acneism/limb/store"
)

func segmentOf(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("%q is not base64url: %v", value, err)
	}
	return raw
}

func publicKeyOfJWK(t *testing.T, key map[string]any) any {
	t.Helper()
	field := func(name string) []byte {
		value, ok := key[name].(string)
		if !ok {
			t.Fatalf("the key has no %q: %v", name, key)
		}
		return segmentOf(t, value)
	}
	switch key["kty"] {
	case "OKP":
		return ed25519.PublicKey(field("x"))
	case "EC":
		point := append([]byte{4}, append(field("x"), field("y")...)...)
		public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			t.Fatal(err)
		}
		return public
	case "RSA":
		return &rsa.PublicKey{N: new(big.Int).SetBytes(field("n")), E: int(new(big.Int).SetBytes(field("e")).Int64())}
	}
	t.Fatalf("unknown key type in %v", key)
	return nil
}

func (f *apiFixture) publishedKeys(t *testing.T) []map[string]any {
	t.Helper()
	rec := f.send(t, http.MethodGet, "/.well-known/jwks.json", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /.well-known/jwks.json = %d: %s", rec.Code, rec.Body.String())
	}
	return decodeBody[struct {
		Keys []map[string]any `json:"keys"`
	}](t, rec).Keys
}

func TestTheKeySetIsPublishedWithoutAnyoneSigningIn(t *testing.T) {
	f := newAPIFixture(t)
	rec := f.send(t, http.MethodGet, "/.well-known/jwks.json", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /.well-known/jwks.json = %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("Content-Type = %q", ct)
	}
	keys := f.publishedKeys(t)
	if len(keys) != 1 || keys[0]["kty"] != "OKP" || keys[0]["crv"] != "Ed25519" || keys[0]["use"] != "sig" || keys[0]["alg"] != "EdDSA" || keys[0]["kid"] == "" {
		t.Fatalf("keys = %v", keys)
	}
	if len(segmentOf(t, keys[0]["x"].(string))) != ed25519.PublicKeySize { //nolint:forcetypeassert
		t.Fatalf("x = %v", keys[0]["x"])
	}
	stored, err := f.a.store.SigningKeys().List(t.Context())
	if err != nil || len(stored) != 1 || stored[0].KID != keys[0]["kid"] {
		t.Fatalf("stored keys = %+v, %v", stored, err)
	}
	if head := f.send(t, http.MethodHead, "/.well-known/jwks.json", nil); head.Code != http.StatusOK || head.Header().Get("Cache-Control") != "public, max-age=300" {
		t.Fatalf("HEAD = %d, Cache-Control = %q", head.Code, head.Header().Get("Cache-Control"))
	}
}

func TestThePublishedKeysVerifyTheTokensOfEveryAlgorithm(t *testing.T) {
	for _, algorithm := range []SigningAlgorithm{SigningEdDSA, SigningES256, SigningRS256} {
		t.Run(string(algorithm), func(t *testing.T) {
			f := newAPIFixture(t, WithSigningAlgorithm(algorithm))
			tokens, _ := f.signInWithTokens(t)
			keys := f.publishedKeys(t)
			if len(keys) != 1 {
				t.Fatalf("keys = %v", keys)
			}
			for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
				if _, found := keys[0][private]; found {
					t.Fatalf("the key set has the private parameter %q", private)
				}
			}
			parser := jwt.NewParser(jwt.WithValidMethods([]string{string(algorithm)}), jwt.WithoutClaimsValidation())
			parsed, err := parser.Parse(tokens.AccessToken, func(token *jwt.Token) (any, error) {
				if token.Header["kid"] != keys[0]["kid"] {
					t.Fatalf("kid = %v, the key set has %v", token.Header["kid"], keys[0]["kid"])
				}
				return publicKeyOfJWK(t, keys[0]), nil
			})
			if err != nil || !parsed.Valid {
				t.Fatalf("the published key does not verify the token: %v", err)
			}
		})
	}
}

func TestTheKeySetShowsTheNextKeyBeforeItSigns(t *testing.T) {
	f := newAPIFixture(t)
	f.signInWithTokens(t)
	if keys := f.publishedKeys(t); len(keys) != 1 {
		t.Fatalf("keys = %v", keys)
	}
	f.clock.advance(keyRotation - publishDelay)
	keys := f.publishedKeys(t)
	if len(keys) != 2 || keys[0]["kid"] == keys[1]["kid"] {
		t.Fatalf("a key must be published ahead of its use: %v", keys)
	}
	if again := f.publishedKeys(t); len(again) != 2 {
		t.Fatalf("the second look made more keys: %v", again)
	}
}

func TestTheKeySetFailsWithoutTellingWhy(t *testing.T) {
	logger, logs := capturingLogger()
	f := newAPIFixture(t, WithLogger(logger))
	f.a.store = &keysFaultStore{Store: f.a.store, listErr: errors.New(secretReason)}
	rec := f.send(t, http.MethodGet, "/.well-known/jwks.json", nil)
	f.expectError(t, rec, http.StatusInternalServerError, "internal_error")
	if strings.Contains(rec.Body.String(), "fire") || !strings.Contains(logs.String(), secretReason) {
		t.Fatalf("body = %s\nlog = %s", rec.Body.String(), logs.String())
	}
}

func bearerOf(label string) requestOption {
	return bearer(serviceKeyOf(label))
}

func introspectBody(token string) map[string]string {
	return map[string]string{"token": token}
}

func TestAServiceLearnsWhoAnActiveTokenIsFor(t *testing.T) {
	f := newServicesAPIFixture(t, WithServiceKey("search", serviceKeyOf("search")))
	tokens, _ := f.signInWithTokens(t)
	f.clock.advance(time.Minute)
	for _, service := range []string{"billing", "search"} {
		rec := f.send(t, http.MethodPost, "/token/introspect", introspectBody(tokens.AccessToken), bearerOf(service))
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: POST /token/introspect = %d, Cache-Control = %q: %s", service, rec.Code, rec.Header().Get("Cache-Control"), rec.Body.String())
		}
		want := introspectionBody{
			Active: true, Subject: string(f.user.ID), SessionID: tokens.SessionID,
			IssuedAt:  f.clock.now().Add(-time.Minute).Unix(),
			ExpiresAt: f.clock.now().Add(-time.Minute).Add(10 * time.Minute).Unix(),
		}
		if got := decodeBody[introspectionBody](t, rec); got != want {
			t.Fatalf("%s: answer = %+v, want %+v", service, got, want)
		}
		fields := decodeMap(t, rec)
		if len(fields) != 5 {
			t.Fatalf("%s: fields = %v", service, fields)
		}
	}
}

func TestAServiceIsToldNothingAboutATokenThatIsNotActive(t *testing.T) {
	f := newServicesAPIFixture(t)
	login, _ := f.signIn(t)
	ended, _ := f.signInWithTokens(t)
	f.send(t, http.MethodPost, "/logout", nil, bearer(ended.AccessToken))
	old, _ := f.signInWithTokens(t)
	f.clock.advance(11 * time.Minute)
	f.change(t, func(u *store.User) { u.MustChangePassword = true })
	restricted, _ := f.signInWithTokens(t)
	tests := map[string]string{
		"damaged":                      "damaged",
		"not even a token":             "x",
		"the secret of a cookie":       login.Secret,
		"a token of an ended session":  ended.AccessToken,
		"an expired token":             old.AccessToken,
		"a token that is restricted":   restricted.AccessToken,
		"a token with a stray newline": old.AccessToken + "\n",
	}
	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			rec := f.send(t, http.MethodPost, "/token/introspect", introspectBody(token), bearerOf("billing"))
			if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"active":false}` {
				t.Fatalf("POST /token/introspect = %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestOnlyAServiceWithAKeyMayIntrospect(t *testing.T) {
	f := newServicesAPIFixture(t)
	tokens, _ := f.signInWithTokens(t)
	body := introspectBody(tokens.AccessToken)
	tests := []struct {
		name      string
		opts      []requestOption
		challenge string
	}{
		{"no key", nil, "Bearer"},
		{"a wrong key", []requestOption{bearerOf("other")}, `Bearer error="invalid_token"`},
		{"an empty key", []requestOption{header("Authorization", "Bearer ")}, `Bearer error="invalid_token"`},
		{"an access token as the key", []requestOption{bearer(tokens.AccessToken)}, `Bearer error="invalid_token"`},
		{"another scheme", []requestOption{header("Authorization", "Digest "+serviceKeyOf("billing"))}, "Bearer"},
		{"the key in the wrong place", []requestOption{header("X-Api-Key", serviceKeyOf("billing"))}, "Bearer"},
		{"a session cookie", []requestOption{withCookie(f.a.cookie, "x")}, "Bearer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.send(t, http.MethodPost, "/token/introspect", body, tc.opts...)
			f.expectError(t, rec, http.StatusUnauthorized, "unauthenticated")
			if got := rec.Header().Get("WWW-Authenticate"); got != tc.challenge {
				t.Fatalf("WWW-Authenticate = %q, want %q", got, tc.challenge)
			}
			if strings.Contains(rec.Body.String(), "sub") || strings.Contains(rec.Body.String(), "active") {
				t.Fatalf("the answer to a stranger says too much: %s", rec.Body.String())
			}
		})
	}
}

func TestTheKeyOfAServiceIsCheckedBeforeTheBodyIsRead(t *testing.T) {
	f := newServicesAPIFixture(t)
	f.expectError(t, f.send(t, http.MethodPost, "/token/introspect", "not JSON", bearerOf("other")), http.StatusUnauthorized, "unauthenticated")
	f.expectError(t, f.send(t, http.MethodPost, "/token/introspect", strings.Repeat("x", 70<<10), bearerOf("other")), http.StatusUnauthorized, "unauthenticated")
}

func TestIntrospectionReadsOnlyAWellFormedRequest(t *testing.T) {
	f := newServicesAPIFixture(t)
	tests := []struct {
		name string
		body any
		opts []requestOption
		want int
		code string
	}{
		{"no body", nil, nil, http.StatusBadRequest, "invalid_request"},
		{"an empty token", `{"token":""}`, nil, http.StatusBadRequest, "invalid_request"},
		{"no token", `{}`, nil, http.StatusBadRequest, "invalid_request"},
		{"an unknown field", `{"token":"x","hint":"access_token"}`, nil, http.StatusBadRequest, "invalid_request"},
		{"a number", `{"token":1}`, nil, http.StatusBadRequest, "invalid_request"},
		{"a form", `token=x`, []requestOption{header("Content-Type", "application/x-www-form-urlencoded")}, http.StatusUnsupportedMediaType, "unsupported_media_type"},
		{"a body that is too large", `{"token":"` + strings.Repeat("a", 65<<10) + `"}`, nil, http.StatusRequestEntityTooLarge, "invalid_request"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := append([]requestOption{bearerOf("billing")}, tc.opts...)
			f.expectError(t, f.send(t, http.MethodPost, "/token/introspect", tc.body, opts...), tc.want, tc.code)
		})
	}
}

func TestIntrospectionOfARevokedSessionIsInstantEvenWhenTokensAreNotCheckedAnywhereElse(t *testing.T) {
	f := newServicesAPIFixture(t, WithRevocation(RevocationAfterTTL))
	tokens, _ := f.signInWithTokens(t)
	if rec := f.send(t, http.MethodGet, "/sessions", nil, bearer(tokens.AccessToken)); rec.Code != http.StatusOK {
		t.Fatalf("GET /sessions = %d", rec.Code)
	}
	if err := f.a.store.Sessions().Revoke(t.Context(), f.a.tenant, string(f.user.ID), tokens.SessionID, f.clock.now()); err != nil {
		t.Fatal(err)
	}
	rec := f.send(t, http.MethodPost, "/token/introspect", introspectBody(tokens.AccessToken), bearerOf("billing"))
	if strings.TrimSpace(rec.Body.String()) != `{"active":false}` {
		t.Fatalf("the answer = %s", rec.Body.String())
	}
	if rec = f.send(t, http.MethodGet, "/sessions", nil, bearer(tokens.AccessToken)); rec.Code != http.StatusOK {
		t.Fatalf("with the revocation after the lifetime the token still works elsewhere: %d", rec.Code)
	}
}

func TestIntrospectionFailsWithoutTellingWhy(t *testing.T) {
	logger, logs := capturingLogger()
	f := newServicesAPIFixture(t, WithLogger(logger))
	tokens, _ := f.signInWithTokens(t)
	f.breakSessions(func(s *sessionsFault) { s.resolveErr = errors.New(secretReason) })
	rec := f.send(t, http.MethodPost, "/token/introspect", introspectBody(tokens.AccessToken), bearerOf("billing"))
	f.expectError(t, rec, http.StatusInternalServerError, "internal_error")
	if strings.Contains(rec.Body.String(), "fire") || !strings.Contains(logs.String(), secretReason) {
		t.Fatalf("body = %s\nlog = %s", rec.Body.String(), logs.String())
	}
}

func TestTheIntrospectionRouteExistsOnlyWithAServiceKey(t *testing.T) {
	without := newAPIFixture(t)
	without.expectError(t, without.send(t, http.MethodPost, "/token/introspect", map[string]string{"token": "x"}), http.StatusNotFound, "not_found")
	with := newServicesAPIFixture(t)
	if rec := with.send(t, http.MethodPost, "/token/introspect", map[string]string{"token": "x"}); rec.Code == http.StatusNotFound {
		t.Fatalf("the introspection route is missing although a service key is set")
	}
}

func TestAKeyThatCannotBePublishedIsAFailureOfOurs(t *testing.T) {
	logger, logs := capturingLogger()
	f := newAPIFixture(t, WithLogger(logger))
	f.signInWithTokens(t)
	f.a.ring.mu.Lock()
	f.a.ring.keys[0].public = 42
	f.a.ring.mu.Unlock()
	rec := f.send(t, http.MethodGet, "/.well-known/jwks.json", nil)
	f.expectError(t, rec, http.StatusInternalServerError, "internal_error")
	if !strings.Contains(logs.String(), "unknown type") || strings.Contains(rec.Body.String(), "unknown type") {
		t.Fatalf("body = %s\nlog = %s", rec.Body.String(), logs.String())
	}
}
