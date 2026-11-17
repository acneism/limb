package store

import (
	"context"
	"time"
)

// SecretKind tells how a secret reaches the user.
type SecretKind string

// The kinds of secrets.
const (
	// SecretLink is a token of 256 bits that is sent in a link. The store keeps
	// its SHA-256 and finds the secret by it.
	SecretLink SecretKind = "link"
	// SecretCode is a short code that the user types. A code cannot be found by
	// its hash, because there are only a million of them: the store keeps a keyed
	// hash that is bound to the secret, the user, the purpose and the channel,
	// finds the codes of a user by these and leaves the check of the hash to the
	// caller.
	SecretCode SecretKind = "code"
)

// SecretPurpose tells what a secret lets its holder do.
type SecretPurpose string

// The purposes of secrets.
const (
	// PurposeVerify confirms that the user owns a channel.
	PurposeVerify SecretPurpose = "verify"
	// PurposeReset lets the user choose a new password.
	PurposeReset SecretPurpose = "reset"
	// PurposeInvite lets the holder of a channel that an administrator named
	// choose the first password of the account, which confirms the channel.
	PurposeInvite SecretPurpose = "invite"
)

// Secret is a link token or a code that was sent to a channel of a user. The
// pair of TenantID and ID identifies it. Only a hash of the secret is stored.
type Secret struct {
	// TenantID is the tenant the secret belongs to.
	TenantID string
	// ID is the identifier of the secret, a UUID in text form.
	ID string
	// Kind says whether it is a link token or a code.
	Kind SecretKind
	// Hash is the hash of the secret, SecretHashLength bytes. It is unique.
	Hash []byte
	// UserID is the user the secret was made for.
	UserID string
	// Purpose says what the secret lets the user do.
	Purpose SecretPurpose
	// ChannelType and ChannelValue name the identifier that the secret was sent
	// to. The secret is deleted together with that identifier.
	ChannelType  string
	ChannelValue string
	// Attempts is how many times a guess of the code was counted. It is always 0
	// for a link.
	Attempts int
	// CreatedAt is when the secret was made.
	CreatedAt time.Time
	// ExpiresAt is when the secret stops working.
	ExpiresAt time.Time
	// UsedAt is when the secret was used or ended, the zero time if it was not.
	UsedAt time.Time
}

// SecretScope picks the secrets of one user for one purpose. It reaches every
// channel of the user, or one of them when both ChannelType and ChannelValue
// are set.
type SecretScope struct {
	// TenantID is the tenant of the user.
	TenantID string
	// UserID is the user.
	UserID string
	// Purpose is the purpose of the secrets.
	Purpose SecretPurpose
	// ChannelType and ChannelValue narrow the scope to one identifier. They are
	// set both or not at all.
	ChannelType  string
	ChannelValue string
}

// Secrets stores the secrets of links and codes. A secret is used once: using
// one marks it, and a marked secret never works again.
type Secrets interface {
	// Add stores a new secret that has not been used and has no attempts. It
	// returns ErrConflict if the ID or the hash exists, and ErrNotFound if the
	// user or the identifier of the channel does not exist.
	Add(ctx context.Context, s Secret) error

	// End marks the secrets of the scope that have not been used as used at the
	// given time, so that none of them works any more, and returns how many it
	// marked.
	End(ctx context.Context, scope SecretScope, at time.Time) (int, error)

	// UseLink marks the link of the purpose whose hash is given as used at the
	// given time and returns it. The marking is atomic: when several calls use
	// one link at once, exactly one of them succeeds. It returns ErrNotFound if
	// there is no such link or it was used already or it expires at or before
	// the given time, and a link of another purpose is not touched.
	UseLink(ctx context.Context, tenantID string, purpose SecretPurpose, hash []byte, at time.Time) (Secret, error)

	// TryCodes counts one attempt on every code of the scope that has not been
	// used, has not expired at the given time and has had fewer than limit
	// attempts, and returns these codes. The counting is atomic: a code is
	// returned to at most limit calls in all, however many of them are made at
	// once, so a caller that checks the hash of a code only for the codes that
	// it gets cannot be made to check one more than limit times. Attempts of the
	// codes that are returned is the count from before this call.
	//
	// An attempt that a rolled back transaction counted is rolled back with
	// it, so call TryCodes on the store itself, not inside InTx, wherever a
	// wrong guess must be counted for sure.
	TryCodes(ctx context.Context, scope SecretScope, at time.Time, limit int) ([]Secret, error)

	// UseCode marks the code with the given ID as used at the given time. The
	// marking is atomic: when several calls use one code at once, exactly one of
	// them succeeds. It returns ErrNotFound if there is no such code or it was
	// used already or it expires at or before the given time.
	UseCode(ctx context.Context, tenantID, id string, at time.Time) error

	// DeleteStale removes the secrets that expired or were used before the
	// given time and returns how many it removed.
	DeleteStale(ctx context.Context, tenantID string, before time.Time) (int, error)
}
