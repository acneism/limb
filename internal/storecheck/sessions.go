package storecheck

import (
	"strings"
	"time"

	"github.com/acneism/limb/store"
)

const (
	maxKeyLength    = 255
	maxKIDLength    = 128
	maxAlgorithmLen = 32
)

func NewSession(s store.Session) error {
	for _, f := range []struct{ name, value string }{
		{"session tenant_id", s.TenantID},
		{"session id", s.ID},
		{"session user_id", s.UserID},
	} {
		if err := required(f.name, f.value); err != nil {
			return err
		}
	}
	if err := sessionSecret(s); err != nil {
		return err
	}
	if err := optionalText("session ip", s.IP, store.MaxIPLength); err != nil {
		return err
	}
	if err := optionalText("session user_agent", s.UserAgent, store.MaxUserAgentLength); err != nil {
		return err
	}
	switch {
	case s.CreatedAt.IsZero():
		return invalid("session created_at is required")
	case s.LastSeenAt.IsZero():
		return invalid("session last_seen_at is required")
	case s.ExpiresAt.IsZero():
		return invalid("session expires_at is required")
	case !s.RevokedAt.IsZero():
		return invalid("a new session cannot be revoked")
	}
	return nil
}

func sessionSecret(s store.Session) error {
	switch s.Kind {
	case store.SessionCookie:
		if len(s.SecretHash) != store.SecretHashLength {
			return invalid("a cookie session needs a secret hash of %d bytes", store.SecretHashLength)
		}
	case store.SessionToken:
		if len(s.SecretHash) != 0 {
			return invalid("a token session has no secret hash")
		}
	default:
		return invalid("session kind %q is unknown", string(s.Kind))
	}
	return nil
}

func NewRefreshToken(t store.RefreshToken) error {
	if err := required("refresh token tenant_id", t.TenantID); err != nil {
		return err
	}
	if err := required("refresh token session_id", t.SessionID); err != nil {
		return err
	}
	switch {
	case !ValidHash(t.Hash):
		return invalid("a refresh token hash has %d bytes", store.SecretHashLength)
	case t.ExpiresAt.IsZero():
		return invalid("refresh token expires_at is required")
	case !t.UsedAt.IsZero():
		return invalid("a new refresh token cannot be used")
	}
	return nil
}

func ValidHash(hash []byte) bool {
	return len(hash) == store.SecretHashLength
}

func AttemptKey(key string) error {
	if err := required("attempt key", key); err != nil {
		return err
	}
	if len(key) > maxKeyLength {
		return invalid("attempt key is longer than %d bytes", maxKeyLength)
	}
	return nil
}

func Window(window time.Duration) error {
	if window <= 0 {
		return invalid("the counting window must be positive")
	}
	return nil
}

func ValidAttemptKey(key string) bool {
	return AttemptKey(key) == nil
}

func NewSigningKey(k store.SigningKey) error {
	if err := required("signing key kid", k.KID); err != nil {
		return err
	}
	if err := required("signing key algorithm", k.Algorithm); err != nil {
		return err
	}
	switch {
	case len(k.KID) > maxKIDLength:
		return invalid("signing key kid is longer than %d bytes", maxKIDLength)
	case len(k.Algorithm) > maxAlgorithmLen:
		return invalid("signing key algorithm is longer than %d bytes", maxAlgorithmLen)
	case k.Generation < 1:
		return invalid("signing key generation must be positive")
	case len(k.PrivateKey) == 0 || len(k.PublicKey) == 0:
		return invalid("signing key needs both its private and its public key")
	case k.CreatedAt.IsZero():
		return invalid("signing key created_at is required")
	case !k.RetireAfter.IsZero():
		return invalid("a new signing key cannot be retired")
	}
	return nil
}

func optionalText(name, value string, limit int) error {
	if err := text(name, value); err != nil {
		return err
	}
	if len(value) > limit {
		return invalid("%s is longer than %d bytes", name, limit)
	}
	return nil
}

func CompareSessions(a, b store.Session) int {
	switch {
	case a.CreatedAt.Before(b.CreatedAt):
		return -1
	case a.CreatedAt.After(b.CreatedAt):
		return 1
	}
	return strings.Compare(a.ID, b.ID)
}
