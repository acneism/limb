package storecheck

import (
	"strings"

	"github.com/acneism/limb/store"
)

func NewSecret(s store.Secret) error {
	for _, f := range []struct {
		name, value string
		limit       int
	}{
		{"secret tenant_id", s.TenantID, store.MaxTenantIDLength},
		{"secret id", s.ID, store.MaxIDLength},
		{"secret user_id", s.UserID, store.MaxIDLength},
		{"secret channel type", s.ChannelType, store.MaxIdentifierTypeLength},
		{"secret channel value", s.ChannelValue, store.MaxIdentifierValueLength},
	} {
		if err := required(f.name, f.value, f.limit); err != nil {
			return err
		}
	}
	if err := secretKind(s.Kind); err != nil {
		return err
	}
	if err := Purpose(s.Purpose); err != nil {
		return err
	}
	switch {
	case !ValidHash(s.Hash):
		return invalid("a secret hash has %d bytes", store.SecretHashLength)
	case s.Attempts != 0:
		return invalid("a new secret has no attempts")
	case s.CreatedAt.IsZero():
		return invalid("secret created_at is required")
	case s.ExpiresAt.IsZero():
		return invalid("secret expires_at is required")
	case !s.ExpiresAt.After(s.CreatedAt):
		return invalid("a secret must expire after it was created")
	case !s.UsedAt.IsZero():
		return invalid("a new secret cannot be used")
	}
	return nil
}

func SecretScope(scope store.SecretScope) error {
	if err := Purpose(scope.Purpose); err != nil {
		return err
	}
	if (scope.ChannelType == "") != (scope.ChannelValue == "") {
		return invalid("a secret scope names a channel by its type and its value, both or none")
	}
	return nil
}

func ValidScope(scope store.SecretScope) bool {
	return ValidText(scope.TenantID, scope.UserID, scope.ChannelType, scope.ChannelValue)
}

func Attempts(limit int) error {
	if limit < 1 {
		return invalid("the limit of attempts must be positive")
	}
	return nil
}

func CompareSecrets(a, b store.Secret) int {
	switch {
	case a.CreatedAt.Before(b.CreatedAt):
		return -1
	case a.CreatedAt.After(b.CreatedAt):
		return 1
	}
	return strings.Compare(a.ID, b.ID)
}

func secretKind(kind store.SecretKind) error {
	switch kind {
	case store.SecretLink, store.SecretCode:
		return nil
	}
	return invalid("secret kind %q is unknown", string(kind))
}

func Purpose(purpose store.SecretPurpose) error {
	switch purpose {
	case store.PurposeVerify, store.PurposeReset:
		return nil
	}
	return invalid("secret purpose %q is unknown", string(purpose))
}
