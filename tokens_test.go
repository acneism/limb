package limb

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/acneism/limb/store"
)

const (
	tokenUser    = "00000000-0000-7000-8000-0000000000a1"
	tokenSession = "00000000-0000-7000-8000-0000000000b2"
)

func newTokenAuth(t *testing.T, opts ...Option) (*Auth, *fakeClock) {
	t.Helper()
	return newLimitedAuth(t, opts...)
}

func (a *Auth) mustIssue(t *testing.T, restricted bool) (string, time.Time) {
	t.Helper()
	token, expires, err := a.issueAccessToken(t.Context(), tokenUser, tokenSession, restricted, a.now())
	if err != nil {
		t.Fatalf("issueAccessToken failed: %v", err)
	}
	return token, expires
}

func decodeSegment(t *testing.T, segment string, into any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("segment %q is not base64url: %v", segment, err)
	}
	if err = json.Unmarshal(raw, into); err != nil {
		t.Fatalf("segment %q is not JSON: %v", raw, err)
	}
}

func (a *Auth) forge(t *testing.T, method jwt.SigningMethod, key any, header, claims map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(method, jwt.MapClaims(claims))
	for name, value := range header {
		if value == nil {
			delete(token.Header, name)
			continue
		}
		token.Header[name] = value
	}
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("forging a token failed: %v", err)
	}
	return signed
}

func (a *Auth) goodClaims() map[string]any {
	now := a.now().UTC().Truncate(time.Second)
	return map[string]any{
		"iss": a.issuer, "sub": tokenUser, "aud": []string{a.audience}, "sid": tokenSession,
		"iat": now.Unix(), "exp": now.Add(a.accessTTL).Unix(),
	}
}

func (a *Auth) ourKey(t *testing.T) *signingKey {
	t.Helper()
	key, err := a.ring.signer(t.Context())
	if err != nil {
		t.Fatalf("signer failed: %v", err)
	}
	return key
}

func (a *Auth) signWithOurKey(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	key := a.ourKey(t)
	merged := map[string]any{"kid": key.record.KID, "typ": accessTokenType}
	for name, value := range header {
		merged[name] = value
	}
	return a.forge(t, signingMethod(key.algorithm()), key.private, merged, claims)
}

func TestAnAccessTokenHasTheDocumentedFormat(t *testing.T) {
	a, clock := newTokenAuth(t)
	token, expires := a.mustIssue(t, false)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q has %d parts", token, len(parts))
	}
	var header map[string]any
	decodeSegment(t, parts[0], &header)
	key := a.ourKey(t)
	if len(header) != 3 || header["alg"] != "EdDSA" || header["typ"] != "at+jwt" || header["kid"] != key.record.KID {
		t.Fatalf("header = %v, want exactly alg, typ and kid", header)
	}
	var claims map[string]any
	decodeSegment(t, parts[1], &claims)
	issued := clock.now().UTC().Truncate(time.Second)
	want := map[string]any{
		"iss": "limb", "sub": tokenUser, "sid": tokenSession,
		"aud": []any{"limb"}, "iat": float64(issued.Unix()), "exp": float64(issued.Add(10 * time.Minute).Unix()),
	}
	if len(claims) != len(want) {
		t.Fatalf("claims = %v, want exactly %v: no personal data and no other fields", claims, want)
	}
	for name, value := range want {
		if got := claims[name]; !equalJSON(got, value) {
			t.Errorf("claim %s = %v, want %v", name, got, value)
		}
	}
	if !expires.Equal(issued.Add(10 * time.Minute)) {
		t.Fatalf("expires = %v, want %v", expires, issued.Add(10*time.Minute))
	}
	if len(token) > 400 {
		t.Fatalf("an EdDSA token has %d bytes, it should stay small", len(token))
	}
}

func equalJSON(a, b any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}

func TestARestrictedSessionGetsTheServiceClaim(t *testing.T) {
	a, _ := newTokenAuth(t)
	token, _ := a.mustIssue(t, true)
	var claims map[string]any
	decodeSegment(t, strings.Split(token, ".")[1], &claims)
	if claims["cpw"] != true {
		t.Fatalf("claims = %v, want cpw: true", claims)
	}
	got, err := a.verifyAccessToken(t.Context(), token)
	if err != nil || !got.ChangePassword {
		t.Fatalf("verifyAccessToken = %+v, %v", got, err)
	}
	plain, _ := a.mustIssue(t, false)
	got, err = a.verifyAccessToken(t.Context(), plain)
	if err != nil || got.ChangePassword {
		t.Fatalf("verifyAccessToken = %+v, %v; an ordinary session has no cpw", got, err)
	}
}

func TestVerifyAccessTokenReturnsTheClaimsOfAValidToken(t *testing.T) {
	a, clock := newTokenAuth(t)
	token, _ := a.mustIssue(t, false)
	clock.advance(9 * time.Minute)
	claims, err := a.verifyAccessToken(t.Context(), token)
	if err != nil {
		t.Fatalf("verifyAccessToken failed: %v", err)
	}
	if claims.Subject != tokenUser || claims.SessionID != tokenSession || claims.Issuer != "limb" ||
		len(claims.Audience) != 1 || claims.Audience[0] != "limb" || claims.IssuedAt == nil || claims.ExpiresAt == nil {
		t.Fatalf("claims = %+v", claims)
	}
}

func TestVerifyAccessTokenChecksTheClaims(t *testing.T) {
	a, _ := newTokenAuth(t)
	now := a.now().UTC().Truncate(time.Second)
	with := func(edit func(map[string]any)) map[string]any {
		claims := a.goodClaims()
		edit(claims)
		return claims
	}
	cases := []struct {
		name   string
		claims map[string]any
		header map[string]any
		ok     bool
	}{
		{"a good token", a.goodClaims(), nil, true},
		{"audience as a string", with(func(c map[string]any) { c["aud"] = a.audience }), nil, true},
		{"our audience among others", with(func(c map[string]any) { c["aud"] = []string{"other", a.audience} }), nil, true},
		{"another issuer", with(func(c map[string]any) { c["iss"] = "someone" }), nil, false},
		{"no issuer", with(func(c map[string]any) { delete(c, "iss") }), nil, false},
		{"another audience", with(func(c map[string]any) { c["aud"] = []string{"other"} }), nil, false},
		{"no audience", with(func(c map[string]any) { delete(c, "aud") }), nil, false},
		{"an empty audience", with(func(c map[string]any) { c["aud"] = []string{} }), nil, false},
		{"expired", with(func(c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() }), nil, false},
		{"expired within the leeway", with(func(c map[string]any) { c["exp"] = now.Add(-4 * time.Second).Unix() }), nil, true},
		{"expired beyond the leeway", with(func(c map[string]any) { c["exp"] = now.Add(-6 * time.Second).Unix() }), nil, false},
		{"no expiry", with(func(c map[string]any) { delete(c, "exp") }), nil, false},
		{"issued in the future within the leeway", with(func(c map[string]any) { c["iat"] = now.Add(4 * time.Second).Unix() }), nil, true},
		{"issued in the future", with(func(c map[string]any) { c["iat"] = now.Add(6 * time.Second).Unix() }), nil, false},
		{"no issue time", with(func(c map[string]any) { delete(c, "iat") }), nil, false},
		{"not yet valid", with(func(c map[string]any) { c["nbf"] = now.Add(time.Minute).Unix() }), nil, false},
		{"already valid", with(func(c map[string]any) { c["nbf"] = now.Add(-time.Minute).Unix() }), nil, true},
		{"no subject", with(func(c map[string]any) { delete(c, "sub") }), nil, false},
		{"an empty subject", with(func(c map[string]any) { c["sub"] = "" }), nil, false},
		{"no session", with(func(c map[string]any) { delete(c, "sid") }), nil, false},
		{"an empty session", with(func(c map[string]any) { c["sid"] = "" }), nil, false},
		{"a session that is not text", with(func(c map[string]any) { c["sid"] = 7 }), nil, false},
		{"no type", a.goodClaims(), map[string]any{"typ": nil}, false},
		{"the type of an ordinary JWT", a.goodClaims(), map[string]any{"typ": "JWT"}, false},
		{"the type in capitals", a.goodClaims(), map[string]any{"typ": "AT+JWT"}, true},
		{"the type as a media type", a.goodClaims(), map[string]any{"typ": "application/at+jwt"}, false},
		{"a critical header", a.goodClaims(), map[string]any{"crit": []string{"exp"}}, false},
		{"headers about keys are ignored", a.goodClaims(), map[string]any{"jku": "https://evil.example/keys", "x5u": "https://evil.example/x5", "x5c": []string{"AAAA"}}, true},
		{"no key ID", a.goodClaims(), map[string]any{"kid": nil}, false},
		{"an unknown key ID", a.goodClaims(), map[string]any{"kid": "unknown"}, false},
		{"a key ID that is not text", a.goodClaims(), map[string]any{"kid": 7}, false},
		{"extra claims", with(func(c map[string]any) { c["role"] = "admin"; c["jti"] = "x" }), nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := a.signWithOurKey(t, tc.header, tc.claims)
			_, err := a.verifyAccessToken(t.Context(), token)
			switch {
			case tc.ok && err != nil:
				t.Fatalf("verifyAccessToken = %v, want success", err)
			case !tc.ok && err != ErrUnauthenticated: //nolint:errorlint
				t.Fatalf("verifyAccessToken = %v, want ErrUnauthenticated exactly", err)
			}
		})
	}
}

func TestVerifyAccessTokenRefusesForeignSignatures(t *testing.T) {
	a, _ := newTokenAuth(t)
	our := a.ourKey(t)
	ourPublic, ok := our.public.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("the public key is %T", our.public)
	}
	_, foreign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := a.goodClaims()
	header := map[string]any{"kid": our.record.KID, "typ": accessTokenType}
	good := a.signWithOurKey(t, nil, claims)
	parts := strings.Split(good, ".")
	cases := map[string]string{
		"signed by another key":      a.forge(t, jwt.SigningMethodEdDSA, foreign, header, claims),
		"another key with our jwk":   a.forge(t, jwt.SigningMethodEdDSA, foreign, map[string]any{"kid": our.record.KID, "typ": accessTokenType, "jwk": map[string]any{"kty": "OKP"}}, claims),
		"no signature":               parts[0] + "." + parts[1] + ".",
		"a damaged signature":        parts[0] + "." + parts[1] + "." + flipFirst(parts[2]),
		"a signature of nothing":     parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
		"the claims of another":      parts[0] + "." + a.signWithOurKey(t, nil, with(claims, "sub", "someone-else")) + "." + parts[2],
		"the header of another":      a.signWithOurKey(t, map[string]any{"kid": "x"}, claims),
		"none":                       a.forge(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, header, claims),
		"HMAC with the public key":   a.forge(t, jwt.SigningMethodHS256, []byte(ourPublic), header, claims),
		"HMAC with an empty key":     a.forge(t, jwt.SigningMethodHS256, []byte("k"), header, claims),
		"another method of ours":     a.forge(t, jwt.SigningMethodES256, mustECKey(t), header, claims),
		"a fifth part":               good + ".extra",
		"only two parts":             parts[0] + "." + parts[1],
		"nothing":                    "",
		"a dot":                      ".",
		"dots":                       "..",
		"junk":                       "not a token",
		"junk in parts":              "a.b.c",
		"junk in base64":             "!!!.!!!.!!!",
		"whitespace":                 " " + good,
		"a trailing newline":         good + "\n",
		"a bearer prefix":            "Bearer " + good,
		"too long":                   good + strings.Repeat("A", maxTokenLength),
		"a huge header":              strings.Repeat("A", maxTokenLength+1) + ".e30.e30",
		"JSON that is not an object": base64.RawURLEncoding.EncodeToString([]byte("[1]")) + "." + base64.RawURLEncoding.EncodeToString([]byte("[1]")) + "." + parts[2],
	}
	for name, token := range cases {
		if _, err := a.verifyAccessToken(t.Context(), token); err != ErrUnauthenticated { //nolint:errorlint
			t.Errorf("%s: verifyAccessToken = %v, want ErrUnauthenticated exactly", name, err)
		}
	}
	if _, err := a.verifyAccessToken(t.Context(), good); err != nil {
		t.Fatalf("the good token must still verify: %v", err)
	}
}

func with(claims map[string]any, name string, value any) map[string]any {
	copied := make(map[string]any, len(claims)+1)
	for k, v := range claims {
		copied[k] = v
	}
	copied[name] = value
	return copied
}

func flipFirst(segment string) string {
	if segment[0] == 'A' {
		return "B" + segment[1:]
	}
	return "A" + segment[1:]
}

func TestAnAlgorithmThatIsNotConfiguredIsRefused(t *testing.T) {
	a, _ := newTokenAuth(t)
	_ = a.ourKey(t)
	rsaToken := a.forge(t, jwt.SigningMethodES256, mustECKey(t), map[string]any{"kid": a.ourKey(t).record.KID, "typ": accessTokenType}, a.goodClaims())
	if _, err := a.verifyAccessToken(t.Context(), rsaToken); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("verifyAccessToken = %v, want ErrUnauthenticated", err)
	}
}

func TestVerifyAccessTokenReportsAFailureToReadTheKeys(t *testing.T) {
	a, _ := newTokenAuth(t)
	token, _ := a.mustIssue(t, false)
	boom := errors.New("database is down")
	other, _ := newTokenAuth(t)
	other.store = &keysFaultStore{Store: other.store, listErr: boom}
	if _, err := other.verifyAccessToken(t.Context(), token); !errors.Is(err, boom) || errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("verifyAccessToken = %v, want the failure of the store and not ErrUnauthenticated", err)
	}
}

type keysFaultStore struct {
	store.Store
	listErr error
	addErr  error
	lists   *int
}

func (s *keysFaultStore) SigningKeys() store.SigningKeys {
	return keysFault{SigningKeys: s.Store.SigningKeys(), s: s}
}

func (s *keysFaultStore) InTx(ctx context.Context, fn func(ctx context.Context, tx store.Repositories) error) error {
	return s.Store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		return fn(ctx, keysFaultRepositories{Repositories: tx, s: s})
	})
}

type keysFaultRepositories struct {
	store.Repositories
	s *keysFaultStore
}

func (r keysFaultRepositories) SigningKeys() store.SigningKeys {
	return keysFault{SigningKeys: r.Repositories.SigningKeys(), s: r.s}
}

type keysFault struct {
	store.SigningKeys
	s *keysFaultStore
}

func (k keysFault) List(ctx context.Context) ([]store.SigningKey, error) {
	if k.s.lists != nil {
		*k.s.lists++
	}
	if k.s.listErr != nil {
		return nil, k.s.listErr
	}
	return k.SigningKeys.List(ctx)
}

func (k keysFault) Add(ctx context.Context, key store.SigningKey) error {
	if k.s.addErr != nil {
		return k.s.addErr
	}
	return k.SigningKeys.Add(ctx, key)
}

func mustECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestAnAliasOfATokenIsRefused(t *testing.T) {
	a, _ := newTokenAuth(t)
	token, _ := a.mustIssue(t, false)
	if _, err := a.verifyAccessToken(t.Context(), token); err != nil {
		t.Fatal(err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := token[len(token)-1]
	group := strings.IndexByte(alphabet, last) >> 4
	aliased := false
	for i := range len(alphabet) {
		if i>>4 != group || alphabet[i] == last {
			continue
		}
		alias := token[:len(token)-1] + string(alphabet[i])
		if _, err := a.verifyAccessToken(t.Context(), alias); err != ErrUnauthenticated { //nolint:errorlint
			t.Fatalf("a token that differs in the unused bits of the signature = %v, want ErrUnauthenticated: the same signature must have one spelling", err)
		}
		aliased = true
	}
	if !aliased {
		t.Fatal("test setup: no alias was made")
	}
}

func TestATokenThatIsTooLongIsRefusedEvenIfItIsValid(t *testing.T) {
	a, _ := newTokenAuth(t)
	claims := a.goodClaims()
	claims["pad"] = strings.Repeat("x", maxTokenLength)
	token := a.signWithOurKey(t, nil, claims)
	if len(token) <= maxTokenLength {
		t.Fatalf("test setup: the token has only %d bytes", len(token))
	}
	if _, err := a.verifyAccessToken(t.Context(), token); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("verifyAccessToken = %v, want ErrUnauthenticated: a token of %d bytes is refused before it is parsed", err, len(token))
	}
	claims["pad"] = strings.Repeat("x", maxTokenLength/2)
	if _, err := a.verifyAccessToken(t.Context(), a.signWithOurKey(t, nil, claims)); err != nil {
		t.Fatalf("a token below the limit must work: %v", err)
	}
}

func FuzzVerifyAccessToken(f *testing.F) {
	a, err := NewWithStore(newTestMemory(), []byte(testKey), WithAutoMigrate(), WithLogger(discardingLogger()))
	if err != nil {
		f.Fatal(err)
	}
	clock := newFakeClock()
	a.now = clock.now
	valid, _, err := a.issueAccessToken(context.Background(), tokenUser, tokenSession, false, clock.now())
	if err != nil {
		f.Fatal(err)
	}
	restricted, _, err := a.issueAccessToken(context.Background(), tokenUser, tokenSession, true, clock.now())
	if err != nil {
		f.Fatal(err)
	}
	parts := strings.Split(valid, ".")
	for _, seed := range []string{
		valid, restricted, "", ".", "..", "a.b.c", parts[0] + "." + parts[1], parts[0] + "." + parts[1] + ".",
		parts[0] + "." + parts[1] + "." + parts[2] + ".", parts[1] + "." + parts[0] + "." + parts[2], parts[0] + ".e30." + parts[2],
		"e30.e30.e30", strings.Repeat("A", maxTokenLength) + "..", valid + "A", " " + valid, valid + "\n", flipFirst(valid),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		claims, err := a.verifyAccessToken(context.Background(), raw)
		if raw == valid {
			if err != nil || claims.Subject != tokenUser {
				t.Fatalf("the valid token = %+v, %v", claims, err)
			}
			return
		}
		if raw == restricted {
			if err != nil || !claims.ChangePassword {
				t.Fatalf("the restricted token = %+v, %v", claims, err)
			}
			return
		}
		if err != ErrUnauthenticated { //nolint:errorlint
			t.Fatalf("verifyAccessToken(%q) = %+v, %v; any text that is not a token we issued must be ErrUnauthenticated", raw, claims, err)
		}
	})
}
