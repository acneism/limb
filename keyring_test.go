package limb

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/store"
)

func (a *Auth) storedKeys(t *testing.T) []store.SigningKey {
	t.Helper()
	keys, err := a.store.SigningKeys().List(t.Context())
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	return keys
}

func (a *Auth) sibling(t *testing.T, clock *fakeClock, opts ...Option) *Auth {
	t.Helper()
	all := append([]Option{WithLogger(discardingLogger())}, opts...)
	b, err := NewWithStore(a.store, []byte(testKey), all...)
	if err != nil {
		t.Fatalf("NewWithStore failed: %v", err)
	}
	b.hasher = a.hasher
	b.now = clock.now
	return b
}

func tokenKID(t *testing.T, token string) string {
	t.Helper()
	var header map[string]any
	decodeSegment(t, strings.Split(token, ".")[0], &header)
	kid, _ := header["kid"].(string)
	return kid
}

func TestTheFirstUseCreatesAKeyThatSignsAtOnce(t *testing.T) {
	a, clock := newTokenAuth(t)
	if keys := a.storedKeys(t); len(keys) != 0 {
		t.Fatalf("keys exist before the first use: %v", keys)
	}
	token, _ := a.mustIssue(t, false)
	keys := a.storedKeys(t)
	if len(keys) != 1 {
		t.Fatalf("%d keys after the first use, want 1", len(keys))
	}
	key := keys[0]
	if key.Generation != 1 || key.Algorithm != "EdDSA" || !key.RetireAfter.IsZero() ||
		!key.CreatedAt.Equal(clock.now().UTC().Truncate(time.Microsecond)) || tokenKID(t, token) != key.KID {
		t.Fatalf("key = %+v, token kid = %q", key, tokenKID(t, token))
	}
	if _, err := a.verifyAccessToken(t.Context(), token); err != nil {
		t.Fatalf("the first key must sign and verify at once: %v", err)
	}
	again, _ := a.mustIssue(t, false)
	if tokenKID(t, again) != key.KID || len(a.storedKeys(t)) != 1 {
		t.Fatal("a second token must use the same key")
	}
}

func TestTheSealedKeyOpensOnlyWithTheMasterKeyAndItsContext(t *testing.T) {
	a, _ := newTokenAuth(t)
	a.mustIssue(t, false)
	key := a.storedKeys(t)[0]
	if bytes.Contains(key.PrivateKey, key.PublicKey[len(key.PublicKey)-32:]) {
		t.Fatal("the private key must not be stored in the clear")
	}
	if _, err := a.keys.Open(key.PrivateKey, key.KID, key.Algorithm); err != nil {
		t.Fatalf("the master key must open the key: %v", err)
	}
	for name, context := range map[string][]string{
		"another kid": {"another", key.Algorithm}, "another algorithm": {key.KID, "ES256"}, "no context": nil,
		"swapped": {key.Algorithm, key.KID},
	} {
		if _, err := a.keys.Open(key.PrivateKey, context...); !errors.Is(err, secret.ErrOpen) {
			t.Errorf("%s: Open = %v, want ErrOpen: the key is bound to its kid and algorithm", name, err)
		}
	}
	otherMaster, err := secret.NewKeys([]byte("another master key of 32 bytes!!"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = otherMaster.Open(key.PrivateKey, key.KID, key.Algorithm); !errors.Is(err, secret.ErrOpen) {
		t.Fatalf("another master key opened the signing key: %v", err)
	}
}

func jwkX(t *testing.T, entry jwk) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(entry.X)
	if err != nil {
		t.Fatalf("x of %+v is not base64url: %v", entry, err)
	}
	return raw
}

func TestEverySigningAlgorithmSignsAndIsPublished(t *testing.T) {
	for _, alg := range []SigningAlgorithm{SigningEdDSA, SigningES256, SigningRS256} {
		t.Run(string(alg), func(t *testing.T) {
			a, _ := newTokenAuth(t, WithSigningAlgorithm(alg))
			token, _ := a.mustIssue(t, false)
			claims, err := a.verifyAccessToken(t.Context(), token)
			if err != nil || claims.Subject != tokenUser {
				t.Fatalf("verifyAccessToken = %+v, %v", claims, err)
			}
			var header map[string]any
			decodeSegment(t, strings.Split(token, ".")[0], &header)
			if header["alg"] != string(alg) {
				t.Fatalf("header = %v, want alg %s", header, alg)
			}
			stored := a.storedKeys(t)
			if len(stored) != 1 || stored[0].Algorithm != string(alg) {
				t.Fatalf("stored = %+v", stored)
			}
			keys, err := a.publishedKeys(t.Context())
			if err != nil || len(keys) != 1 {
				t.Fatalf("publishedKeys = %v, %v", keys, err)
			}
			entry := keys[0]
			if entry.Use != "sig" || entry.Algorithm != string(alg) || entry.KeyID != stored[0].KID {
				t.Fatalf("entry = %+v", entry)
			}
			public, err := x509.ParsePKIXPublicKey(stored[0].PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			switch key := public.(type) {
			case ed25519.PublicKey:
				if entry.KeyType != "OKP" || entry.Curve != "Ed25519" || !bytes.Equal(jwkX(t, entry), key) || entry.Y != "" || entry.N != "" {
					t.Fatalf("entry = %+v", entry)
				}
			case *ecdsa.PublicKey:
				y, _ := base64.RawURLEncoding.DecodeString(entry.Y)
				point, err := key.Bytes()
				if err != nil {
					t.Fatal(err)
				}
				if entry.KeyType != "EC" || entry.Curve != "P-256" || len(jwkX(t, entry)) != 32 || len(y) != 32 ||
					!bytes.Equal(point, append(append([]byte{4}, jwkX(t, entry)...), y...)) {
					t.Fatalf("entry = %+v", entry)
				}
			case *rsa.PublicKey:
				n, _ := base64.RawURLEncoding.DecodeString(entry.N)
				e, _ := base64.RawURLEncoding.DecodeString(entry.E)
				if entry.KeyType != "RSA" || new(big.Int).SetBytes(n).Cmp(key.N) != 0 || int(new(big.Int).SetBytes(e).Int64()) != key.E ||
					key.N.BitLen() < 3072 || entry.X != "" {
					t.Fatalf("entry = %+v", entry)
				}
			default:
				t.Fatalf("unexpected key %T", public)
			}
		})
	}
}

func TestKeysAreRotatedAheadOfTime(t *testing.T) {
	a, clock := newTokenAuth(t)
	ctx := t.Context()
	end := clock.now().Add(65 * 24 * time.Hour)

	type issued struct {
		kid     string
		expires time.Time
	}
	var live []issued
	service := map[string]bool{}
	var fetched time.Time
	firstKID := ""
	lastCreated := time.Time{}

	for clock.now().Before(end) {
		token, expires := a.mustIssue(t, false)
		now := clock.now()
		kid := tokenKID(t, token)
		if firstKID == "" {
			firstKID = kid
		}
		published, err := a.ring.published(ctx)
		if err != nil {
			t.Fatal(err)
		}
		inJWKS := map[string]time.Time{}
		for _, key := range published {
			inJWKS[key.record.KID] = key.record.CreatedAt
			if key.record.CreatedAt.After(lastCreated) {
				lastCreated = key.record.CreatedAt
			}
		}
		if service == nil || fetched.IsZero() || now.Sub(fetched) >= jwksMaxAge {
			service = map[string]bool{}
			for kid := range inJWKS {
				service[kid] = true
			}
			fetched = now
		}
		if !service[kid] {
			t.Fatalf("at %v a service whose JWKS is at most %v old does not know the key %s that signed a token", now, jwksMaxAge, kid)
		}
		created, published1 := inJWKS[kid]
		if !published1 {
			t.Fatalf("at %v the key %s that signs is not published", now, kid)
		}
		if kid != firstKID && now.Sub(created) < publishDelay {
			t.Fatalf("at %v the key %s signs %v after its publication, want at least %v", now, kid, now.Sub(created), publishDelay)
		}
		live = append(live, issued{kid, expires})
		kept := live[:0]
		for _, token := range live {
			if token.expires.Add(tokenLeeway).After(now) {
				kept = append(kept, token)
				if _, still := inJWKS[token.kid]; !still {
					t.Fatalf("at %v a token that is valid until %v was signed by %s, which left the JWKS", now, token.expires, token.kid)
				}
			}
		}
		live = kept
		step := 20 * time.Minute
		dueSoon := !lastCreated.IsZero() && now.Sub(lastCreated) >= keyRotation-publishDelay-time.Hour
		if !lastCreated.IsZero() && (now.Sub(lastCreated) < time.Hour || dueSoon) {
			step = time.Minute
		}
		clock.advance(step)
	}

	keys := a.storedKeys(t)
	if len(keys) != 3 {
		t.Fatalf("%d keys after 65 days, want 3: one at the start and one each 30 days", len(keys))
	}
	for i, key := range keys {
		if key.Generation != int64(i+1) {
			t.Fatalf("generations = %+v", keys)
		}
		if i+1 < len(keys) && key.RetireAfter.IsZero() {
			t.Fatalf("key %d was replaced and must be retired: %+v", i+1, key)
		}
		if i > 0 {
			gap := key.CreatedAt.Sub(keys[i-1].CreatedAt)
			if gap < keyRotation-publishDelay || gap > keyRotation-publishDelay+2*time.Minute {
				t.Fatalf("key %d was made %v after the previous one, want about %v", i+1, gap, keyRotation-publishDelay)
			}
		}
	}
	if !keys[len(keys)-1].RetireAfter.IsZero() {
		t.Fatalf("the newest key must not be retired: %+v", keys[len(keys)-1])
	}
}

func TestARetiredKeyStaysPublishedUntilItsTokensAreGone(t *testing.T) {
	a, clock := newTokenAuth(t)
	first, _ := a.mustIssue(t, false)
	firstKID := tokenKID(t, first)
	clock.advance(keyRotation - publishDelay)
	a.mustIssue(t, false)
	keys := a.storedKeys(t)
	if len(keys) != 2 {
		t.Fatalf("%d keys, want 2", len(keys))
	}
	wantRetire := keys[1].CreatedAt.Add(publishDelay + a.accessTTL + tokenLeeway + keyRefresh)
	if !keys[0].RetireAfter.Equal(wantRetire) {
		t.Fatalf("RetireAfter = %v, want %v: counted from the moment the new key starts to sign", keys[0].RetireAfter, wantRetire)
	}
	published := func() []string {
		list, err := a.publishedKeys(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		var kids []string
		for _, entry := range list {
			kids = append(kids, entry.KeyID)
		}
		return kids
	}
	if len(published()) != 2 {
		t.Fatalf("both keys must be published during the rotation: %v", published())
	}
	clock.advance(wantRetire.Sub(clock.now()) - time.Second)
	if kids := published(); len(kids) != 2 {
		t.Fatalf("the old key must stay until its retirement: %v", kids)
	}
	if _, err := a.verifyAccessToken(t.Context(), a.forgeFor(t, firstKID)); err != nil {
		t.Fatalf("a token of the old key must verify until the key is retired: %v", err)
	}
	clock.advance(time.Second)
	if kids := published(); len(kids) != 1 || kids[0] == firstKID {
		t.Fatalf("published = %v, want only the new key", kids)
	}
	if _, err := a.verifyAccessToken(t.Context(), a.forgeFor(t, firstKID)); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("a token of a retired key = %v, want ErrUnauthenticated", err)
	}
}

func (a *Auth) forgeFor(t *testing.T, kid string) string {
	t.Helper()
	a.ring.mu.Lock()
	var key *signingKey
	for _, k := range a.ring.keys {
		if k.record.KID == kid {
			key = k
		}
	}
	a.ring.mu.Unlock()
	if key == nil {
		t.Fatalf("no key %s", kid)
	}
	if err := a.ring.open(key); err != nil {
		t.Fatal(err)
	}
	claims := a.goodClaims()
	return a.forge(t, signingMethod(key.algorithm()), key.private, map[string]any{"kid": kid, "typ": accessTokenType}, claims)
}

func TestInstancesCreateTheFirstKeyOnce(t *testing.T) {
	a, clock := newTokenAuth(t)
	const instances = 8
	auths := []*Auth{a}
	for range instances - 1 {
		auths = append(auths, a.sibling(t, clock))
	}
	tokens := make([]string, instances)
	var wg sync.WaitGroup
	for i, instance := range auths {
		wg.Go(func() {
			token, _, err := instance.issueAccessToken(t.Context(), "user-of-instance", "session-of-instance", false, clock.now())
			if err != nil {
				t.Errorf("instance %d: %v", i, err)
			}
			tokens[i] = token
		})
	}
	wg.Wait()
	if keys := a.storedKeys(t); len(keys) != 1 {
		t.Fatalf("%d keys were stored by %d instances that started at once, want 1", len(keys), instances)
	}
	for i, token := range tokens {
		for j, instance := range auths {
			if _, err := instance.verifyAccessToken(t.Context(), token); err != nil {
				t.Errorf("instance %d does not accept the token of instance %d: %v", j, i, err)
			}
		}
	}
}

func TestInstancesRotateTheKeysOnce(t *testing.T) {
	a, clock := newTokenAuth(t)
	a.mustIssue(t, false)
	const instances = 8
	auths := []*Auth{a}
	for range instances - 1 {
		auths = append(auths, a.sibling(t, clock))
	}
	clock.advance(keyRotation - publishDelay + time.Minute)
	var wg sync.WaitGroup
	for _, instance := range auths {
		wg.Go(func() {
			if _, _, err := instance.issueAccessToken(t.Context(), tokenUser, tokenSession, false, clock.now()); err != nil {
				t.Errorf("issueAccessToken failed: %v", err)
			}
		})
	}
	wg.Wait()
	keys := a.storedKeys(t)
	if len(keys) != 2 || keys[1].Generation != 2 {
		t.Fatalf("keys = %+v, want exactly one new key", keys)
	}
}

func TestAnUnknownKeyIDDoesNotLoadTheDatabaseOften(t *testing.T) {
	a, clock := newTokenAuth(t)
	a.mustIssue(t, false)
	lists := 0
	a.store = &keysFaultStore{Store: a.store, lists: &lists}
	a.ring.mu.Lock()
	a.ring.loaded = clock.now()
	a.ring.mu.Unlock()
	bogus := a.forge(t, jwt.SigningMethodEdDSA, mustEdKey(t), map[string]any{"kid": "random", "typ": accessTokenType}, a.goodClaims())
	before := lists
	for range 50 {
		if _, err := a.verifyAccessToken(t.Context(), bogus); err != ErrUnauthenticated { //nolint:errorlint
			t.Fatal(err)
		}
	}
	if got := lists - before; got != 1 {
		t.Fatalf("%d reads of the keys for 50 tokens with an unknown key ID, want 1", got)
	}
	clock.advance(unknownKeyRetry)
	for range 50 {
		_, _ = a.verifyAccessToken(t.Context(), bogus)
	}
	if got := lists - before; got != 2 {
		t.Fatalf("%d reads after the retry time, want 2", got)
	}
}

func TestAKeyOfAnotherInstanceIsFoundOnDemand(t *testing.T) {
	a, clock := newTokenAuth(t)
	b := a.sibling(t, clock)
	a.mustIssue(t, false)
	if _, err := b.verifyAccessToken(t.Context(), a.signWithOurKey(t, nil, a.goodClaims())); err != nil {
		t.Fatalf("an instance that has not loaded the keys yet must find the key: %v", err)
	}
	clock.advance(keyRotation - publishDelay + time.Minute)
	a.mustIssue(t, false)
	clock.advance(publishDelay)
	token := a.signWithOurKey(t, nil, a.goodClaims())
	if tokenKID(t, token) == a.storedKeys(t)[0].KID {
		t.Fatal("test setup: the new key must be the one that signs")
	}
	b.ring.mu.Lock()
	b.ring.loaded, b.ring.lastMiss = clock.now(), time.Time{}
	b.ring.mu.Unlock()
	if _, err := b.verifyAccessToken(t.Context(), token); err != nil {
		t.Fatalf("a key that was made after the cache was filled must be found on demand: %v", err)
	}
}

func TestTheCacheOfKeysIsRefreshedEveryMinute(t *testing.T) {
	a, clock := newTokenAuth(t)
	a.mustIssue(t, false)
	lists := 0
	a.store = &keysFaultStore{Store: a.store, lists: &lists}
	a.mustIssue(t, false)
	before := lists
	for range 20 {
		a.mustIssue(t, false)
	}
	if lists != before {
		t.Fatalf("the keys were read %d times within a minute", lists-before)
	}
	clock.advance(keyRefresh)
	a.mustIssue(t, false)
	if lists != before+1 {
		t.Fatalf("the keys were read %d times after a minute, want 1", lists-before)
	}
}

func TestAKeyThatCannotBeOpenedStopsSigningAndNothingIsRotatedOverIt(t *testing.T) {
	a, clock := newTokenAuth(t)
	token, _ := a.mustIssue(t, false)
	wrong, err := NewWithStore(a.store, []byte("another master key of 32 bytes!!"), WithLogger(discardingLogger()))
	if err != nil {
		t.Fatal(err)
	}
	wrong.now = clock.now
	_, _, err = wrong.issueAccessToken(t.Context(), tokenUser, tokenSession, false, clock.now())
	if err == nil || !strings.Contains(err.Error(), "master key") {
		t.Fatalf("issueAccessToken = %v, want an error about the master key", err)
	}
	clock.advance(keyRotation)
	if _, _, err = wrong.issueAccessToken(t.Context(), tokenUser, tokenSession, false, clock.now()); err == nil {
		t.Fatal("an instance with another master key must not sign")
	}
	if keys := a.storedKeys(t); len(keys) != 1 {
		t.Fatalf("%d keys, an instance that cannot open the key must not make a new one: %+v", len(keys), keys)
	}
	clock.advance(-keyRotation)
	if _, err = wrong.verifyAccessToken(t.Context(), token); err != nil {
		t.Fatalf("verifying needs only the public key: %v", err)
	}
}

func TestChangingTheAlgorithmMakesANewKeyThatSignsAtOnce(t *testing.T) {
	a, clock := newTokenAuth(t)
	old, _ := a.mustIssue(t, false)
	b := a.sibling(t, clock, WithSigningAlgorithm(SigningES256))
	token, _, err := b.issueAccessToken(t.Context(), tokenUser, tokenSession, false, clock.now())
	if err != nil {
		t.Fatal(err)
	}
	keys := a.storedKeys(t)
	if len(keys) != 2 || keys[1].Algorithm != "ES256" || keys[1].Generation != 2 || keys[0].RetireAfter.IsZero() {
		t.Fatalf("keys = %+v, want an ES256 key and the EdDSA key retired", keys)
	}
	if _, err = b.verifyAccessToken(t.Context(), token); err != nil {
		t.Fatalf("the token of the new algorithm must verify: %v", err)
	}
	if _, err = b.verifyAccessToken(t.Context(), old); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("a token of the old algorithm = %v, want ErrUnauthenticated", err)
	}
	if _, err = a.verifyAccessToken(t.Context(), token); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("a token of another algorithm = %v, want ErrUnauthenticated", err)
	}
}

func TestADamagedKeyIsIgnoredAndLogged(t *testing.T) {
	logger, logs := capturingLogger()
	a, clock := newTokenAuth(t, WithLogger(logger))
	a.mustIssue(t, false)
	broken := store.SigningKey{
		KID: "broken", Algorithm: "EdDSA", Generation: 2, PrivateKey: []byte{1}, PublicKey: []byte("not a key"), CreatedAt: clock.now(),
	}
	if err := a.store.SigningKeys().Add(t.Context(), broken); err != nil {
		t.Fatal(err)
	}
	clock.advance(keyRefresh)
	token, _ := a.mustIssue(t, false)
	if _, err := a.verifyAccessToken(t.Context(), token); err != nil {
		t.Fatalf("a damaged key must not break the others: %v", err)
	}
	if !strings.Contains(logs.String(), "damaged") || !strings.Contains(logs.String(), "broken") {
		t.Fatalf("the damaged key must be logged:\n%s", logs.String())
	}
	if keys, err := a.publishedKeys(t.Context()); err != nil || len(keys) != 1 {
		t.Fatalf("publishedKeys = %v, %v; a damaged key must not be published", keys, err)
	}
}

func TestCachedKeysServeWhileTheDatabaseIsDown(t *testing.T) {
	logger, logs := capturingLogger()
	a, clock := newTokenAuth(t, WithLogger(logger))
	token, _ := a.mustIssue(t, false)
	boom := errors.New("database is down")
	a.store = &keysFaultStore{Store: a.store, listErr: boom}
	clock.advance(2 * keyRefresh)
	if _, err := a.verifyAccessToken(t.Context(), token); err != nil {
		t.Fatalf("the cached keys must keep verifying: %v", err)
	}
	if _, _, err := a.issueAccessToken(t.Context(), tokenUser, tokenSession, false, clock.now()); err != nil {
		t.Fatalf("the cached key must keep signing: %v", err)
	}
	if !strings.Contains(logs.String(), "cached ones are used") {
		t.Fatalf("the problem must be logged:\n%s", logs.String())
	}
	fresh, _ := newTokenAuth(t)
	fresh.store = &keysFaultStore{Store: fresh.store, listErr: boom}
	if _, _, err := fresh.issueAccessToken(t.Context(), tokenUser, tokenSession, false, fresh.now()); !errors.Is(err, boom) {
		t.Fatalf("issueAccessToken without a cache = %v, want %v", err, boom)
	}
}

func TestAFailureToStoreTheKeyIsReported(t *testing.T) {
	a, _ := newTokenAuth(t)
	boom := errors.New("database is down")
	a.store = &keysFaultStore{Store: a.store, addErr: boom}
	if _, _, err := a.issueAccessToken(t.Context(), tokenUser, tokenSession, false, a.now()); !errors.Is(err, boom) {
		t.Fatalf("issueAccessToken = %v, want %v", err, boom)
	}
}

func TestTokenOptionsAreValidated(t *testing.T) {
	bad := map[string]Option{
		"algorithm":        WithSigningAlgorithm("HS256"),
		"empty algorithm":  WithSigningAlgorithm(""),
		"short ttl":        WithAccessTokenTTL(30 * time.Second),
		"long ttl":         WithAccessTokenTTL(25 * time.Hour),
		"negative ttl":     WithAccessTokenTTL(-time.Minute),
		"revocation mode":  WithRevocation(RevocationMode(9)),
		"empty issuer":     WithTokenIssuer(""),
		"long issuer":      WithTokenIssuer(strings.Repeat("a", 257)),
		"control issuer":   WithTokenIssuer("a\nb"),
		"empty audience":   WithTokenAudience(""),
		"control audience": WithTokenAudience("a\x00b"),
	}
	for name, option := range bad {
		if err := newFixtureErr(t, option); err == nil || !strings.HasPrefix(err.Error(), "limb: ") {
			t.Errorf("%s: New = %v, want a configuration error", name, err)
		}
	}
	a, _ := newTokenAuth(t, WithTokenIssuer("https://auth.example.com"), WithAccessTokenTTL(time.Hour), WithRevocation(RevocationAfterTTL))
	if a.issuer != "https://auth.example.com" || a.audience != "https://auth.example.com" || a.accessTTL != time.Hour || a.revocation != RevocationAfterTTL {
		t.Fatalf("issuer %q, audience %q, ttl %v, revocation %v", a.issuer, a.audience, a.accessTTL, a.revocation)
	}
	b, _ := newTokenAuth(t, WithTokenAudience("api"))
	if b.issuer != "limb" || b.audience != "api" || b.algorithm != SigningEdDSA || b.accessTTL != 10*time.Minute || b.revocation != RevocationInstant {
		t.Fatalf("defaults: issuer %q, audience %q, algorithm %q, ttl %v", b.issuer, b.audience, b.algorithm, b.accessTTL)
	}
	token, _ := b.mustIssue(t, false)
	other, _ := newTokenAuth(t, WithTokenAudience("api"))
	if _, err := other.verifyAccessToken(t.Context(), token); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("another deployment with its own keys = %v, want ErrUnauthenticated", err)
	}
}

func mustEdKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestAKeyOfTheWrongTypeIsNotUsed(t *testing.T) {
	logger, logs := capturingLogger()
	a, clock := newTokenAuth(t, WithLogger(logger))
	token, _ := a.mustIssue(t, false)
	good := a.storedKeys(t)[0]
	record := good
	record.KID, record.Generation, record.Algorithm = "mismatch", 2, "ES256"
	if err := a.store.SigningKeys().Add(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	clock.advance(keyRefresh)
	if _, err := a.verifyAccessToken(t.Context(), token); err != nil {
		t.Fatalf("the good key must keep working: %v", err)
	}
	if !strings.Contains(logs.String(), "mismatch") {
		t.Fatalf("the key whose material does not fit its algorithm must be reported:\n%s", logs.String())
	}
	if _, err := parsePrivateKey(SigningES256, mustPKCS8(t, mustEdKey(t))); err == nil {
		t.Fatal("an Ed25519 key was taken for ES256")
	}
	if _, err := parsePrivateKey(SigningEdDSA, mustPKCS8(t, mustECKey(t))); err == nil {
		t.Fatal("an ECDSA key was taken for EdDSA")
	}
	if _, err := parsePrivateKey(SigningEdDSA, []byte("garbage")); err == nil {
		t.Fatal("garbage was taken for a key")
	}
	if _, err := parsePublicKey(SigningRS256, mustPKIX(t, mustEdKey(t).Public())); err == nil {
		t.Fatal("an Ed25519 key was taken for RS256")
	}
	other, err := ecdsa.GenerateKey(elliptic.P384(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = parsePrivateKey(SigningES256, mustPKCS8(t, other)); err == nil {
		t.Fatal("a P-384 key was taken for ES256")
	}
	if _, err = parsePublicKey(SigningES256, mustPKIX(t, &other.PublicKey)); err == nil {
		t.Fatal("a P-384 public key was taken for ES256")
	}
}

func mustPKCS8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func mustPKIX(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestASmallRSAKeyIsNotAccepted(t *testing.T) {
	small, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = parsePrivateKey(SigningRS256, mustPKCS8(t, small)); err == nil {
		t.Fatal("a 2048 bit RSA key was accepted for signing")
	}
	if _, err = parsePublicKey(SigningRS256, mustPKIX(t, &small.PublicKey)); err == nil {
		t.Fatal("a 2048 bit RSA key was accepted for verifying")
	}
}
