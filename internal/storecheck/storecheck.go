package storecheck

import (
	"errors"
	"fmt"
	"strings"
	"time"
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
	if err := required("user tenant_id", u.TenantID, store.MaxTenantIDLength); err != nil {
		return err
	}
	if err := required("user id", u.ID, store.MaxIDLength); err != nil {
		return err
	}
	switch u.Status {
	case store.StatusActive, store.StatusBlocked, store.StatusDeleted:
	default:
		return invalid("user status %q is unknown", string(u.Status))
	}
	if err := optional("user password_hash", u.PasswordHash, store.MaxPasswordHashLength); err != nil {
		return err
	}
	if err := CreatedVia(u.CreatedVia); err != nil {
		return err
	}
	return optional("user blocked_reason", u.BlockedReason, store.MaxBlockedReasonLength)
}

func Identifier(i store.Identifier) error {
	fields := []struct {
		name, value string
		limit       int
	}{
		{"identifier tenant_id", i.TenantID, store.MaxTenantIDLength},
		{"identifier type", i.Type, store.MaxIdentifierTypeLength},
		{"identifier value", i.Value, store.MaxIdentifierValueLength},
		{"identifier display_value", i.DisplayValue, store.MaxDisplayValueLength},
		{"identifier user_id", i.UserID, store.MaxIDLength},
	}
	for _, f := range fields {
		if err := required(f.name, f.value, f.limit); err != nil {
			return err
		}
	}
	return nil
}

func Time(name string, t time.Time) error {
	if t.IsZero() {
		return invalid("%s is required", name)
	}
	return nil
}

func CompareIdentifiers(a, b store.Identifier) int {
	if c := strings.Compare(a.Type, b.Type); c != 0 {
		return c
	}
	return strings.Compare(a.Value, b.Value)
}

func ValidText(values ...string) bool {
	for _, v := range values {
		if !utf8.ValidString(v) || strings.IndexByte(v, 0) >= 0 || len(v) > store.MaxIdentifierValueLength {
			return false
		}
	}
	return true
}

func required(name, value string, limit int) error {
	if value == "" {
		return invalid("%s is required", name)
	}
	return optional(name, value, limit)
}

func optional(name, value string, limit int) error {
	switch {
	case !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0:
		return invalid("%s is not valid text", name)
	case len(value) > limit:
		return invalid("%s is longer than %d bytes", name, limit)
	}
	return nil
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

func CreatedVia(via store.CreatedVia) error {
	switch via {
	case "", store.CreatedViaAPI, store.CreatedViaSignup, store.CreatedViaAdmin, store.CreatedViaInvite:
		return nil
	}
	return invalid("user created_via %q is unknown", string(via))
}

func UserQuery(q store.UserQuery) error {
	if q.Limit < 1 || q.Limit > store.MaxUsersPage {
		return invalid("a page of users has from 1 to %d users, not %d", store.MaxUsersPage, q.Limit)
	}
	for _, status := range q.Statuses {
		switch status {
		case store.StatusActive, store.StatusBlocked, store.StatusDeleted:
		default:
			return invalid("user status %q is unknown", string(status))
		}
	}
	if err := CreatedVia(q.CreatedVia); err != nil {
		return err
	}
	switch q.Order {
	case "", store.OrderUsersByCreation, store.OrderUsersByLastLogin, store.OrderUsersByStatus:
	default:
		return invalid("the order of users %q is unknown", string(q.Order))
	}
	if len(q.Identifiers) > store.MaxUserIdentifierRefs {
		return invalid("a query of users asks for at most %d identifiers", store.MaxUserIdentifierRefs)
	}
	if q.After == nil {
		return nil
	}
	if q.After.ID == "" {
		return invalid("the user that a listing continues after has no ID")
	}
	switch q.Order {
	case "", store.OrderUsersByCreation:
		if q.After.CreatedAt.IsZero() {
			return invalid("the user that a listing continues after has no creation time")
		}
	case store.OrderUsersByStatus:
		if q.After.Status == "" {
			return invalid("the user that a listing continues after has no status")
		}
	case store.OrderUsersByLastLogin:
	}
	return nil
}

func IdentifierRefs(refs []store.IdentifierRef) []store.IdentifierRef {
	var valid []store.IdentifierRef
	for _, ref := range refs {
		if ref.Type != "" && ref.Value != "" && len(ref.Type) <= store.MaxIdentifierTypeLength && ValidText(ref.Type, ref.Value) {
			valid = append(valid, ref)
		}
	}
	return valid
}

func ValidUserQuery(q store.UserQuery) bool {
	if !ValidText(q.TenantID, q.ValuePrefix) || (q.After != nil && !ValidText(q.After.ID, string(q.After.Status))) {
		return false
	}
	return len(q.Identifiers) == 0 || len(IdentifierRefs(q.Identifiers)) > 0
}
