package storecheck

import (
	"strings"
	"time"

	"github.com/acneism/limb/store"
)

func NewSession(s store.Session) error {
	for _, f := range []struct{ name, value string }{
		{"session tenant_id", s.TenantID},
		{"session id", s.ID},
		{"session user_id", s.UserID},
	} {
		if err := required(f.name, f.value, store.MaxIDLength); err != nil {
			return err
		}
	}
	if err := sessionSecret(s); err != nil {
		return err
	}
	if err := optional("session ip", s.IP, store.MaxIPLength); err != nil {
		return err
	}
	if err := optional("session user_agent", s.UserAgent, store.MaxUserAgentLength); err != nil {
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
	if err := required("refresh token tenant_id", t.TenantID, store.MaxTenantIDLength); err != nil {
		return err
	}
	if err := required("refresh token session_id", t.SessionID, store.MaxIDLength); err != nil {
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
	return required("attempt key", key, store.MaxAttemptKeyLength)
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
	if err := required("signing key kid", k.KID, store.MaxKIDLength); err != nil {
		return err
	}
	if err := required("signing key algorithm", k.Algorithm, store.MaxAlgorithmLength); err != nil {
		return err
	}
	switch {
	case k.Generation < 1:
		return invalid("signing key generation must be positive")
	case len(k.PrivateKey) == 0 || len(k.PublicKey) == 0:
		return invalid("signing key needs both its private and its public key")
	case len(k.PrivateKey) > store.MaxKeyMaterialLength || len(k.PublicKey) > store.MaxKeyMaterialLength:
		return invalid("a signing key is longer than %d bytes", store.MaxKeyMaterialLength)
	case k.CreatedAt.IsZero():
		return invalid("signing key created_at is required")
	case !k.RetireAfter.IsZero():
		return invalid("a new signing key cannot be retired")
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
