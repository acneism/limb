package storecheck

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func validSetting() store.Setting {
	return store.Setting{TenantID: "default", Name: "name", Value: "value", UpdatedAt: time.Now(), UpdatedBy: "admin-1"}
}

func TestSettingRules(t *testing.T) {
	if err := Setting(validSetting()); err != nil {
		t.Fatalf("a valid setting was rejected: %v", err)
	}
	bare := validSetting()
	bare.UpdatedBy = ""
	if err := Setting(bare); err != nil {
		t.Fatalf("a setting written by the code of the application was rejected: %v", err)
	}
	cases := map[string]func(*store.Setting){
		"no tenant":           func(s *store.Setting) { s.TenantID = "" },
		"no name":             func(s *store.Setting) { s.Name = "" },
		"no value":            func(s *store.Setting) { s.Value = "" },
		"no time":             func(s *store.Setting) { s.UpdatedAt = time.Time{} },
		"a long tenant":       func(s *store.Setting) { s.TenantID = strings.Repeat("a", store.MaxTenantIDLength+1) },
		"a long name":         func(s *store.Setting) { s.Name = strings.Repeat("a", store.MaxSettingNameLength+1) },
		"a long value":        func(s *store.Setting) { s.Value = strings.Repeat("a", store.MaxSettingValueLength+1) },
		"a long author":       func(s *store.Setting) { s.UpdatedBy = strings.Repeat("a", store.MaxIDLength+1) },
		"a NUL in the name":   func(s *store.Setting) { s.Name = "a\x00" },
		"a bad UTF-8 value":   func(s *store.Setting) { s.Value = "\xff" },
		"a bad UTF-8 author":  func(s *store.Setting) { s.UpdatedBy = "\xff" },
		"a NUL in the tenant": func(s *store.Setting) { s.TenantID = "\x00" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			s := validSetting()
			edit(&s)
			if err := Setting(s); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Setting = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestSettingsAreComparedByTheBytesOfTheirNames(t *testing.T) {
	names := func(a, b string) int {
		return CompareSettings(store.Setting{Name: a}, store.Setting{Name: b})
	}
	if names("a", "b") >= 0 || names("b", "a") <= 0 || names("a", "a") != 0 || names("Z", "a") >= 0 || names("é", "z") <= 0 {
		t.Fatal("the names must be compared byte by byte")
	}
}
