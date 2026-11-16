package limb

import (
	"strings"
	"testing"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/internal/password"
	"github.com/acneism/limb/store"
)

func TestLimitsOfTheCoreMatchTheLimitsOfTheStores(t *testing.T) {
	if identifier.MaxValueLength != store.MaxIdentifierValueLength {
		t.Errorf("identifier values are limited to %d bytes, the stores keep %d", identifier.MaxValueLength, store.MaxIdentifierValueLength)
	}
	if identifier.MaxInputLength != store.MaxDisplayValueLength {
		t.Errorf("identifier input is limited to %d bytes, the stores keep %d of a display value", identifier.MaxInputLength, store.MaxDisplayValueLength)
	}
	if password.MaxEncodedLength > store.MaxPasswordHashLength {
		t.Errorf("a password hash takes up to %d bytes, the stores keep %d", password.MaxEncodedLength, store.MaxPasswordHashLength)
	}
	if err := identifier.Custom(strings.Repeat("a", store.MaxIdentifierTypeLength)).Err(); err != nil {
		t.Errorf("a type name of %d bytes is rejected: %v", store.MaxIdentifierTypeLength, err)
	}
	if err := identifier.Custom(strings.Repeat("a", store.MaxIdentifierTypeLength+1)).Err(); err == nil {
		t.Errorf("a type name of %d bytes is accepted, the stores keep %d", store.MaxIdentifierTypeLength+1, store.MaxIdentifierTypeLength)
	}
}

func TestValuesOfTheCoreFitTheStores(t *testing.T) {
	a := newTestAuth(t)
	id, err := a.newID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) > store.MaxIDLength || len(id) > store.MaxKIDLength {
		t.Errorf("a generated ID has %d bytes", len(id))
	}
	if len(a.tenant) > store.MaxTenantIDLength || len(store.DefaultTenant) > store.MaxTenantIDLength {
		t.Errorf("the tenant %q is longer than %d bytes", a.tenant, store.MaxTenantIDLength)
	}
	for _, algorithm := range []SigningAlgorithm{SigningEdDSA, SigningES256, SigningRS256} {
		if len(algorithm) > store.MaxAlgorithmLength {
			t.Errorf("the algorithm %q is longer than %d bytes", algorithm, store.MaxAlgorithmLength)
		}
	}
	key := a.keys.AttemptKey("account", a.tenant, "email", strings.Repeat("a", 4096))
	if len(key) > store.MaxAttemptKeyLength {
		t.Errorf("an attempt key has %d bytes, the stores keep %d", len(key), store.MaxAttemptKeyLength)
	}
}
