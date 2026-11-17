package storetest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

var settingBase = time.Date(2026, 9, 10, 11, 12, 13, 123456789, time.UTC)

func newSetting(tenant, name, value string) store.Setting {
	return store.Setting{TenantID: tenant, Name: name, Value: value, UpdatedAt: settingBase, UpdatedBy: id(1)}
}

func mustSetSetting(t *testing.T, s store.Store, setting store.Setting) {
	t.Helper()
	if err := s.Settings().Set(t.Context(), setting); err != nil {
		t.Fatalf("Set(%q) failed: %v", setting.Name, err)
	}
}

func checkSetting(t *testing.T, got, want store.Setting) {
	t.Helper()
	if got.TenantID != want.TenantID || got.Name != want.Name || got.Value != want.Value || got.UpdatedBy != want.UpdatedBy {
		t.Fatalf("setting differs:\n got %+v\nwant %+v", got, want)
	}
	if !sameTime(got.UpdatedAt, want.UpdatedAt) {
		t.Fatalf("setting time differs, it must be UTC with microsecond precision:\n got %+v\nwant %+v", got, want)
	}
}

func testSettingLifecycle(t *testing.T, s store.Store) {
	ctx := t.Context()
	local := time.FixedZone("UTC+3", 3*3600)
	first := newSetting(tenantA, "password_to_end_sessions", "true")
	first.UpdatedAt = settingBase.In(local)
	mustSetSetting(t, s, first)
	got, err := s.Settings().Get(ctx, tenantA, first.Name)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	checkSetting(t, got, first)

	second := first
	second.Value = "false"
	second.UpdatedAt = settingBase.Add(time.Hour)
	second.UpdatedBy = id(2)
	mustSetSetting(t, s, second)
	if got, err = s.Settings().Get(ctx, tenantA, first.Name); err != nil {
		t.Fatal(err)
	}
	checkSetting(t, got, second)

	bare := second
	bare.UpdatedBy = ""
	bare.UpdatedAt = settingBase.Add(2 * time.Hour)
	mustSetSetting(t, s, bare)
	if got, err = s.Settings().Get(ctx, tenantA, first.Name); err != nil || got.UpdatedBy != "" {
		t.Fatalf("a setting written by the code of the application has no administrator: %+v, %v", got, err)
	}
	if list, listErr := s.Settings().List(ctx, tenantA); listErr != nil || len(list) != 1 {
		t.Fatalf("a setting that is set again must not be stored twice: %v, %v", list, listErr)
	}

	if err = s.Settings().Delete(ctx, tenantA, first.Name); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err = s.Settings().Get(ctx, tenantA, first.Name); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
	if err = s.Settings().Delete(ctx, tenantA, first.Name); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete of a missing setting = %v, want ErrNotFound", err)
	}
	mustSetSetting(t, s, first)
}

func testSettingList(t *testing.T, s store.Store) {
	ctx := t.Context()
	if list, err := s.Settings().List(ctx, tenantA); err != nil || len(list) != 0 {
		t.Fatalf("List of a new store = %v, %v; want nothing", list, err)
	}
	names := []string{"b", "a-c", "B", "ab", "я", "a", "é", "Z", "a_b"}
	for _, name := range names {
		mustSetSetting(t, s, newSetting(tenantA, name, "v-"+name))
	}
	mustSetSetting(t, s, newSetting(tenantB, "other", "x"))
	want := []string{"B", "Z", "a", "a-c", "a_b", "ab", "b", "é", "я"}
	list, err := s.Settings().List(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(list))
	for _, setting := range list {
		got = append(got, setting.Name)
		checkSetting(t, setting, newSetting(tenantA, setting.Name, "v-"+setting.Name))
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("List must return the settings of the tenant in byte order, whatever the collation of the database is:\n got %q\nwant %q", got, want)
	}
}

func testSettingNamesAreComparedByteByByte(t *testing.T, s store.Store) {
	ctx := t.Context()
	names := []string{"limit", "Limit", "LIMIT", "limit ", " limit", "café", "café", "straße", "strasse", "a%b", "axb", "a_b"}
	for _, name := range names {
		mustSetSetting(t, s, newSetting(tenantA, name, "v:"+name))
	}
	for _, name := range names {
		got, err := s.Settings().Get(ctx, tenantA, name)
		if err != nil || got.Name != name || got.Value != "v:"+name {
			t.Fatalf("Get(%q) = %+v, %v; names must be stored and compared byte by byte", name, got, err)
		}
	}
	for _, name := range []string{"limiT", "limit  ", "CAFÉ", "STRASSE", "a%", "a_"} {
		if _, err := s.Settings().Get(ctx, tenantA, name); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Get(%q) = %v, want ErrNotFound: only the exact name matches", name, err)
		}
	}
	if list, err := s.Settings().List(ctx, tenantA); err != nil || len(list) != len(names) {
		t.Fatalf("List returned %d settings, %v; want %d", len(list), err, len(names))
	}
}

func testSettingInvalidRecords(t *testing.T, s store.Store) {
	ctx := t.Context()
	edits := map[string]func(*store.Setting){
		"no tenant":            func(x *store.Setting) { x.TenantID = "" },
		"no name":              func(x *store.Setting) { x.Name = "" },
		"no value":             func(x *store.Setting) { x.Value = "" },
		"no time":              func(x *store.Setting) { x.UpdatedAt = time.Time{} },
		"NUL in the name":      func(x *store.Setting) { x.Name = "a\x00b" },
		"NUL in the value":     func(x *store.Setting) { x.Value = "a\x00b" },
		"invalid UTF-8 value":  func(x *store.Setting) { x.Value = "a\xffb" },
		"invalid UTF-8 author": func(x *store.Setting) { x.UpdatedBy = "a\xffb" },
	}
	for field, limit := range map[string]int{"tenant": store.MaxTenantIDLength, "name": store.MaxSettingNameLength,
		"value": store.MaxSettingValueLength, "author": store.MaxIDLength} {
		for label, text := range overTheLimit(limit) {
			edits[fmt.Sprintf("a %s %s", field, label)] = func(x *store.Setting) {
				switch field {
				case "tenant":
					x.TenantID = text
				case "name":
					x.Name = text
				case "value":
					x.Value = text
				default:
					x.UpdatedBy = text
				}
			}
		}
	}
	for name, edit := range edits {
		setting := newSetting(tenantA, "name", "value")
		edit(&setting)
		if err := s.Settings().Set(ctx, setting); err == nil || isDomainError(err) {
			t.Errorf("Set with %s = %v, want a validation error", name, err)
		}
	}
	if list, err := s.Settings().List(ctx, tenantA); err != nil || len(list) != 0 {
		t.Fatalf("a rejected setting must not be stored: %v, %v", list, err)
	}
}

func testSettingLongestValues(t *testing.T, s store.Store) {
	for _, c := range characters {
		t.Run(c.name, func(t *testing.T) {
			ctx := t.Context()
			setting := store.Setting{
				TenantID:  fill(c.unit, store.MaxTenantIDLength),
				Name:      fill(c.unit, store.MaxSettingNameLength),
				Value:     fill(c.unit, store.MaxSettingValueLength),
				UpdatedAt: settingBase,
				UpdatedBy: fill(c.unit, store.MaxIDLength),
			}
			mustSetSetting(t, s, setting)
			got, err := s.Settings().Get(ctx, setting.TenantID, setting.Name)
			if err != nil {
				t.Fatalf("Get of the longest setting failed: %v", err)
			}
			checkSetting(t, got, setting)
			setting.Value = fill("z", store.MaxSettingValueLength)
			mustSetSetting(t, s, setting)
			if got, err = s.Settings().Get(ctx, setting.TenantID, setting.Name); err != nil {
				t.Fatal(err)
			}
			checkSetting(t, got, setting)
			if list, listErr := s.Settings().List(ctx, setting.TenantID); listErr != nil || len(list) != 1 {
				t.Fatalf("List = %v, %v; want the longest setting", list, listErr)
			}
		})
	}
}

func testSettingLookupsThatFindNothing(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustSetSetting(t, s, newSetting(tenantA, "name", "value"))
	for _, bad := range []string{"a\x00b", "a\xffb", strings.Repeat("a", store.MaxIdentifierValueLength+1)} {
		if _, err := s.Settings().Get(ctx, bad, "name"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get with tenant %q = %v, want ErrNotFound", bad, err)
		}
		if _, err := s.Settings().Get(ctx, tenantA, bad); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get with name %q = %v, want ErrNotFound", bad, err)
		}
		if err := s.Settings().Delete(ctx, tenantA, bad); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete with name %q = %v, want ErrNotFound", bad, err)
		}
		if err := s.Settings().Delete(ctx, bad, "name"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete with tenant %q = %v, want ErrNotFound", bad, err)
		}
		if list, err := s.Settings().List(ctx, bad); err != nil || len(list) != 0 {
			t.Errorf("List with tenant %q = %v, %v; want nothing", bad, list, err)
		}
	}
	if _, err := s.Settings().Get(ctx, tenantA, ""); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get of an empty name = %v, want ErrNotFound", err)
	}
	if _, err := s.Settings().Get(ctx, "", "name"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get of an empty tenant = %v, want ErrNotFound", err)
	}
}

func testSettingTenantIsolation(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustSetSetting(t, s, newSetting(tenantA, "name", "first"))
	mustSetSetting(t, s, newSetting(tenantB, "name", "second"))
	for tenant, want := range map[string]string{tenantA: "first", tenantB: "second"} {
		got, err := s.Settings().Get(ctx, tenant, "name")
		if err != nil || got.Value != want {
			t.Fatalf("Get in %s = %+v, %v; want %q", tenant, got, err, want)
		}
	}
	if err := s.Settings().Delete(ctx, tenantA, "name"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Settings().Get(ctx, tenantB, "name"); err != nil || got.Value != "second" {
		t.Fatalf("Delete in one tenant touched another: %+v, %v", got, err)
	}
	if list, err := s.Settings().List(ctx, tenantA); err != nil || len(list) != 0 {
		t.Fatalf("List = %v, %v; want nothing", list, err)
	}
}

func testConcurrentSettingSets(t *testing.T, s store.Store) {
	ctx := t.Context()
	const writers = 8
	var failures atomic.Int32
	parallel(writers, func(i int) {
		setting := newSetting(tenantA, "race", fmt.Sprintf("writer %d", i))
		setting.UpdatedAt = settingBase.Add(time.Duration(i) * time.Second)
		if err := s.Settings().Set(ctx, setting); err != nil {
			failures.Add(1)
			t.Errorf("writer %d: Set failed: %v", i, err)
		}
	})
	if failures.Load() != 0 {
		t.FailNow()
	}
	list, err := s.Settings().List(ctx, tenantA)
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %v, %v; want exactly one setting after %d concurrent writes", list, err, writers)
	}
	if !strings.HasPrefix(list[0].Value, "writer ") {
		t.Fatalf("the stored value %q is not the value of a writer", list[0].Value)
	}
}

func testSettingRollback(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustSetSetting(t, s, newSetting(tenantA, "kept", "before"))
	err := s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if err := tx.Settings().Set(ctx, newSetting(tenantA, "kept", "during")); err != nil {
			return err
		}
		if err := tx.Settings().Set(ctx, newSetting(tenantA, "added", "during")); err != nil {
			return err
		}
		got, err := tx.Settings().Get(ctx, tenantA, "kept")
		if err != nil || got.Value != "during" {
			return fmt.Errorf("the transaction must see its own write: %+v, %w", got, err)
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatalf("InTx = %v, want the error of the function", err)
	}
	if got, getErr := s.Settings().Get(ctx, tenantA, "kept"); getErr != nil || got.Value != "before" {
		t.Fatalf("a rolled back write must leave the value: %+v, %v", got, getErr)
	}
	if _, getErr := s.Settings().Get(ctx, tenantA, "added"); !errors.Is(getErr, store.ErrNotFound) {
		t.Fatalf("a rolled back setting must not exist: %v", getErr)
	}
	err = s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		return tx.Settings().Set(ctx, newSetting(tenantA, "kept", "after"))
	})
	if err != nil {
		t.Fatalf("InTx failed: %v", err)
	}
	if got, getErr := s.Settings().Get(ctx, tenantA, "kept"); getErr != nil || got.Value != "after" {
		t.Fatalf("a committed write must be visible: %+v, %v", got, getErr)
	}
}
