package store

import (
	"context"
	"time"
)

// SigningKey is a key that signs access tokens. The private part is stored
// sealed under the master key; the public part is published in the JWKS.
type SigningKey struct {
	// KID is the identifier of the key, which tokens carry in their header.
	KID string
	// Algorithm is the JWT algorithm of the key, for example "EdDSA".
	Algorithm string
	// Generation orders the keys: a newer key has a greater generation, and no
	// two keys share one. That is what keeps instances that rotate the keys at
	// the same time from both succeeding.
	Generation int64
	// PrivateKey is the private key, sealed.
	PrivateKey []byte
	// PublicKey is the public key in the PKIX DER form.
	PublicKey []byte
	// CreatedAt is when the key was created.
	CreatedAt time.Time
	// RetireAfter is when the key may be removed because no token signed with it
	// is valid any more, the zero time while the key is the one that signs.
	RetireAfter time.Time
}

// SigningKeys stores the keys that sign access tokens. They belong to the whole
// installation, not to a tenant.
type SigningKeys interface {
	// Add stores a new key that is not retired. It returns ErrConflict if the
	// KID or the generation is taken.
	Add(ctx context.Context, k SigningKey) error

	// List returns all the keys ordered by generation, the oldest first.
	List(ctx context.Context) ([]SigningKey, error)

	// Retire sets the time after which the key may be removed, unless it is set
	// already. It returns ErrNotFound if there is no such key.
	Retire(ctx context.Context, kid string, retireAfter time.Time) error

	// DeleteRetired removes the keys whose retirement time is before the given
	// time and returns how many it removed.
	DeleteRetired(ctx context.Context, before time.Time) (int, error)
}
