package limb

import (
	"cmp"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/acneism/limb/store"
)

const (
	keyRotation     = 30 * 24 * time.Hour
	jwksMaxAge      = 300 * time.Second
	keyRefresh      = time.Minute
	publishDelay    = jwksMaxAge + keyRefresh
	unknownKeyRetry = 10 * time.Second
	rsaBits         = 3072
)

// SigningAlgorithm is the JWT algorithm that signs access tokens.
type SigningAlgorithm string

// The algorithms access tokens can be signed with.
const (
	// SigningEdDSA is EdDSA over Ed25519, the default.
	SigningEdDSA SigningAlgorithm = "EdDSA"
	// SigningES256 is ECDSA over P-256 with SHA-256.
	SigningES256 SigningAlgorithm = "ES256"
	// SigningRS256 is RSASSA-PKCS1-v1_5 with SHA-256 and a key of 3072 bits.
	SigningRS256 SigningAlgorithm = "RS256"
)

type signingKey struct {
	record  store.SigningKey
	public  crypto.PublicKey
	private crypto.Signer
}

func (k *signingKey) algorithm() SigningAlgorithm {
	return SigningAlgorithm(k.record.Algorithm)
}

type keyring struct {
	a        *Auth
	mu       sync.Mutex
	loaded   time.Time
	lastMiss time.Time
	keys     []*signingKey
}

func newKeyring(a *Auth) *keyring {
	return &keyring{a: a}
}

func (k *keyring) signer(ctx context.Context) (*signingKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.a.now()
	if err := k.refresh(ctx, now, false); err != nil {
		return nil, err
	}
	current := k.pick(now)
	if current != nil {
		if err := k.open(current); err != nil {
			return nil, err
		}
	}
	if current == nil || k.rotationDue(now, current) {
		if err := k.rotate(ctx, now); err != nil {
			return nil, err
		}
		current = k.pick(now)
	}
	if current == nil {
		return nil, errors.New("limb: there is no signing key")
	}
	if err := k.open(current); err != nil {
		return nil, err
	}
	return current, nil
}

func (k *keyring) maintain(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.a.now()
	if err := k.refresh(ctx, now, false); err != nil {
		return err
	}
	current := k.pick(now)
	if current == nil || !k.rotationDue(now, current) {
		return nil
	}
	return k.rotate(ctx, now)
}

func (k *keyring) lookup(ctx context.Context, kid string) (*signingKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.a.now()
	if err := k.refresh(ctx, now, false); err != nil {
		return nil, err
	}
	if key := k.find(kid, now); key != nil {
		return key, nil
	}
	if now.Sub(k.lastMiss) < unknownKeyRetry {
		return nil, nil
	}
	k.lastMiss = now
	if err := k.refresh(ctx, now, true); err != nil {
		return nil, err
	}
	return k.find(kid, now), nil
}

func (k *keyring) published(ctx context.Context) ([]*signingKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.a.now()
	if err := k.refresh(ctx, now, false); err != nil {
		return nil, err
	}
	var live []*signingKey
	for _, key := range k.keys {
		if key.record.RetireAfter.IsZero() || key.record.RetireAfter.After(now) {
			live = append(live, key)
		}
	}
	return live, nil
}

func (k *keyring) find(kid string, now time.Time) *signingKey {
	for _, key := range k.keys {
		if key.record.KID != kid {
			continue
		}
		if !key.record.RetireAfter.IsZero() && !key.record.RetireAfter.After(now) {
			return nil
		}
		return key
	}
	return nil
}

func (k *keyring) pick(now time.Time) *signingKey {
	var first, ready *signingKey
	for _, key := range k.keys {
		if key.algorithm() != k.a.algorithm {
			continue
		}
		if first == nil {
			first = key
		}
		if !key.record.CreatedAt.After(now.Add(-publishDelay)) {
			ready = key
		}
	}
	if ready != nil {
		return ready
	}
	return first
}

func (k *keyring) newest() *signingKey {
	var newest *signingKey
	for _, key := range k.keys {
		if key.algorithm() == k.a.algorithm {
			newest = key
		}
	}
	return newest
}

func (k *keyring) rotationDue(now time.Time, current *signingKey) bool {
	if k.newest() != current {
		return false
	}
	return !now.Before(current.record.CreatedAt.Add(keyRotation - publishDelay))
}

func (k *keyring) refresh(ctx context.Context, now time.Time, force bool) error {
	if !force && !k.loaded.IsZero() && now.Sub(k.loaded) < keyRefresh {
		return nil
	}
	stored, err := k.a.store.SigningKeys().List(ctx)
	if err != nil {
		if len(k.keys) > 0 && !force {
			k.a.logger.ErrorContext(ctx, "limb: the signing keys cannot be read, the cached ones are used", "error", err)
			k.loaded = now.Add(unknownKeyRetry - keyRefresh)
			return nil
		}
		return fmt.Errorf("limb: read the signing keys: %w", err)
	}
	previous := make(map[string]*signingKey, len(k.keys))
	for _, key := range k.keys {
		previous[key.record.KID] = key
	}
	keys := make([]*signingKey, 0, len(stored))
	for _, record := range stored {
		if known, ok := previous[record.KID]; ok && known.record.Generation == record.Generation {
			known.record = record
			keys = append(keys, known)
			continue
		}
		public, parseErr := parsePublicKey(SigningAlgorithm(record.Algorithm), record.PublicKey)
		if parseErr != nil {
			k.a.logger.ErrorContext(ctx, "limb: a signing key is damaged and is ignored", "kid", record.KID, "error", parseErr)
			continue
		}
		keys = append(keys, &signingKey{record: record, public: public})
	}
	k.keys = keys
	k.loaded = now
	return nil
}

func (k *keyring) open(key *signingKey) error {
	if key.private != nil {
		return nil
	}
	der, err := k.a.keys.Open(key.record.PrivateKey, key.record.KID, key.record.Algorithm)
	if err != nil {
		return fmt.Errorf("limb: the signing key %s cannot be opened, is the master key the one the key was made with: %w", key.record.KID, err)
	}
	private, err := parsePrivateKey(key.algorithm(), der)
	if err != nil {
		return fmt.Errorf("limb: the signing key %s is damaged: %w", key.record.KID, err)
	}
	key.private = private
	return nil
}

func (k *keyring) rotate(ctx context.Context, now time.Time) error {
	private, err := generateKey(k.a.algorithm)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return fmt.Errorf("limb: encode the new signing key: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		return fmt.Errorf("limb: encode the new signing key: %w", err)
	}
	kid, err := k.a.newID()
	if err != nil {
		return err
	}
	sealed, err := k.a.keys.Seal(der, kid, string(k.a.algorithm))
	if err != nil {
		return fmt.Errorf("limb: seal the new signing key: %w", err)
	}
	generation := int64(1)
	if len(k.keys) > 0 {
		generation = slices.MaxFunc(k.keys, func(a, b *signingKey) int {
			return cmp.Compare(a.record.Generation, b.record.Generation)
		}).record.Generation + 1
	}
	record := store.SigningKey{
		KID:        kid,
		Algorithm:  string(k.a.algorithm),
		Generation: generation,
		PrivateKey: sealed,
		PublicKey:  publicDER,
		CreatedAt:  now.UTC().Truncate(time.Microsecond),
	}
	retireAt := record.CreatedAt.Add(publishDelay + k.a.accessTTL + tokenLeeway + keyRefresh)
	err = k.a.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if addErr := tx.SigningKeys().Add(ctx, record); addErr != nil {
			return addErr
		}
		for _, old := range k.keys {
			if !old.record.RetireAfter.IsZero() {
				continue
			}
			if retireErr := tx.SigningKeys().Retire(ctx, old.record.KID, retireAt); retireErr != nil && !errors.Is(retireErr, store.ErrNotFound) {
				return retireErr
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, store.ErrConflict) {
		return fmt.Errorf("limb: store the new signing key: %w", err)
	}
	return k.refresh(ctx, now, true)
}

func generateKey(alg SigningAlgorithm) (crypto.Signer, error) {
	switch alg {
	case SigningEdDSA:
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("limb: generate a signing key: %w", err)
		}
		return private, nil
	case SigningES256:
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("limb: generate a signing key: %w", err)
		}
		return private, nil
	case SigningRS256:
		private, err := rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			return nil, fmt.Errorf("limb: generate a signing key: %w", err)
		}
		return private, nil
	}
	return nil, fmt.Errorf("limb: unknown signing algorithm %q", alg)
}

func parsePrivateKey(alg SigningAlgorithm, der []byte) (crypto.Signer, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	switch key := parsed.(type) {
	case ed25519.PrivateKey:
		if alg == SigningEdDSA {
			return key, nil
		}
	case *ecdsa.PrivateKey:
		if alg == SigningES256 && key.Curve == elliptic.P256() {
			return key, nil
		}
	case *rsa.PrivateKey:
		if alg == SigningRS256 && key.N.BitLen() >= rsaBits {
			return key, nil
		}
	}
	return nil, fmt.Errorf("the key does not fit the algorithm %s", alg)
}

func parsePublicKey(alg SigningAlgorithm, der []byte) (crypto.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	switch key := parsed.(type) {
	case ed25519.PublicKey:
		if alg == SigningEdDSA {
			return key, nil
		}
	case *ecdsa.PublicKey:
		if alg == SigningES256 && key.Curve == elliptic.P256() {
			return key, nil
		}
	case *rsa.PublicKey:
		if alg == SigningRS256 && key.N.BitLen() >= rsaBits {
			return key, nil
		}
	}
	return nil, fmt.Errorf("the key does not fit the algorithm %s", alg)
}
