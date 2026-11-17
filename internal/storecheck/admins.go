package storecheck

import (
	"bytes"
	"strings"

	"github.com/acneism/limb/store"
)

func NewAdmin(a store.Admin) error {
	if err := Admin(a); err != nil {
		return err
	}
	switch {
	case a.CreatedAt.IsZero():
		return invalid("admin created_at is required")
	case a.TOTPLastStep < 0:
		return invalid("admin totp_last_step must not be negative")
	}
	return nil
}

func Admin(a store.Admin) error {
	if err := required("admin tenant_id", a.TenantID, store.MaxTenantIDLength); err != nil {
		return err
	}
	if err := required("admin id", a.ID, store.MaxIDLength); err != nil {
		return err
	}
	if err := required("admin login", a.Login, store.MaxAdminLoginLength); err != nil {
		return err
	}
	if err := required("admin password_hash", a.PasswordHash, store.MaxPasswordHashLength); err != nil {
		return err
	}
	switch a.Status {
	case store.AdminActive, store.AdminDisabled:
	default:
		return invalid("admin status %q is unknown", string(a.Status))
	}
	switch {
	case len(a.TOTPSecret) > store.MaxSealedSecretLength:
		return invalid("an admin totp_secret is longer than %d bytes", store.MaxSealedSecretLength)
	case !a.TOTPConfirmedAt.IsZero() && len(a.TOTPSecret) == 0:
		return invalid("an authenticator cannot be confirmed without a secret")
	}
	return nil
}

func RecoveryHashes(hashes [][]byte) error {
	if len(hashes) > store.MaxRecoveryCodes {
		return invalid("an administrator has at most %d recovery codes", store.MaxRecoveryCodes)
	}
	for i, hash := range hashes {
		if !ValidHash(hash) {
			return invalid("a recovery code hash has %d bytes", store.SecretHashLength)
		}
		for _, other := range hashes[:i] {
			if bytes.Equal(hash, other) {
				return invalid("a recovery code hash is given twice")
			}
		}
	}
	return nil
}

func CompareAdmins(a, b store.Admin) int {
	return strings.Compare(a.Login, b.Login)
}

func NewAdminSession(s store.AdminSession) error {
	for _, f := range []struct{ name, value string }{
		{"admin session tenant_id", s.TenantID},
		{"admin session id", s.ID},
		{"admin session admin_id", s.AdminID},
	} {
		if err := required(f.name, f.value, store.MaxIDLength); err != nil {
			return err
		}
	}
	switch s.Stage {
	case store.AdminStagePassword, store.AdminStageFull:
	default:
		return invalid("admin session stage %q is unknown", string(s.Stage))
	}
	if err := optional("admin session ip", s.IP, store.MaxIPLength); err != nil {
		return err
	}
	if err := optional("admin session user_agent", s.UserAgent, store.MaxUserAgentLength); err != nil {
		return err
	}
	switch {
	case !ValidHash(s.SecretHash):
		return invalid("an admin session needs a secret hash of %d bytes", store.SecretHashLength)
	case s.AdminVersion < 1:
		return invalid("admin session admin_version must be positive")
	case s.Attempts != 0:
		return invalid("a new admin session has no attempts")
	case s.CreatedAt.IsZero():
		return invalid("admin session created_at is required")
	case s.LastSeenAt.IsZero():
		return invalid("admin session last_seen_at is required")
	case s.ExpiresAt.IsZero():
		return invalid("admin session expires_at is required")
	}
	return nil
}

func CompareAdminSessions(a, b store.AdminSession) int {
	switch {
	case a.CreatedAt.Before(b.CreatedAt):
		return -1
	case a.CreatedAt.After(b.CreatedAt):
		return 1
	}
	return strings.Compare(a.ID, b.ID)
}
