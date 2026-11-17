package storecheck

import (
	"strings"

	"github.com/acneism/limb/store"
)

func Setting(s store.Setting) error {
	if err := required("setting tenant_id", s.TenantID, store.MaxTenantIDLength); err != nil {
		return err
	}
	if err := required("setting name", s.Name, store.MaxSettingNameLength); err != nil {
		return err
	}
	if err := required("setting value", s.Value, store.MaxSettingValueLength); err != nil {
		return err
	}
	if err := optional("setting updated_by", s.UpdatedBy, store.MaxIDLength); err != nil {
		return err
	}
	if s.UpdatedAt.IsZero() {
		return invalid("setting updated_at is required")
	}
	return nil
}

func CompareSettings(a, b store.Setting) int {
	return strings.Compare(a.Name, b.Name)
}
