package storecheck

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/acneism/limb/store"
)

var ErrInvalid = errors.New("store: invalid record")

func NewUser(u store.User) error {
	if err := User(u); err != nil {
		return err
	}
	if u.CreatedAt.IsZero() {
		return invalid("user created_at is required")
	}
	return nil
}

func User(u store.User) error {
	if err := required("user tenant_id", u.TenantID); err != nil {
		return err
	}
	if err := required("user id", u.ID); err != nil {
		return err
	}
	switch u.Status {
	case store.StatusActive, store.StatusBlocked, store.StatusDeleted:
	default:
		return invalid("user status %q is unknown", string(u.Status))
	}
	if err := text("user password_hash", u.PasswordHash); err != nil {
		return err
	}
	return text("user blocked_reason", u.BlockedReason)
}

func Identifier(i store.Identifier) error {
	fields := []struct{ name, value string }{
		{"identifier tenant_id", i.TenantID},
		{"identifier type", i.Type},
		{"identifier value", i.Value},
		{"identifier display_value", i.DisplayValue},
		{"identifier user_id", i.UserID},
	}
	for _, f := range fields {
		if err := required(f.name, f.value); err != nil {
			return err
		}
	}
	return nil
}

func ValidText(values ...string) bool {
	for _, v := range values {
		if !utf8.ValidString(v) || strings.IndexByte(v, 0) >= 0 {
			return false
		}
	}
	return true
}

func required(name, value string) error {
	if value == "" {
		return invalid("%s is required", name)
	}
	return text(name, value)
}

func text(name, value string) error {
	if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
		return invalid("%s is not valid text", name)
	}
	return nil
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
