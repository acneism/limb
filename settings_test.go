package limb

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

type countingSettings struct {
	store.Settings
	lists atomic.Int64
}

func (c *countingSettings) List(ctx context.Context, tenantID string) ([]store.Setting, error) {
	c.lists.Add(1)
	return c.Settings.List(ctx, tenantID)
}

type countingSettingsStore struct {
	store.Store
	settings *countingSettings
}

func (s countingSettingsStore) Settings() store.Settings { return s.settings }

func countSettingsReads(f *sessionFixture) *countingSettings {
	counting := &countingSettings{Settings: f.a.store.Settings()}
	f.a.store = countingSettingsStore{Store: f.a.store, settings: counting}
	return counting
}

func mustRequire(t *testing.T, a *Auth) bool {
	t.Helper()
	needed, err := a.Admin().PasswordToEndSessions(t.Context())
	if err != nil {
		t.Fatalf("PasswordToEndSessions failed: %v", err)
	}
	return needed
}

func TestASettingIsReadOnceForAWhile(t *testing.T) {
	f := newSessionFixture(t)
	reads := countSettingsReads(f)
	for range 3 {
		mustRequire(t, f.a)
	}
	if got := reads.lists.Load(); got != 1 {
		t.Fatalf("the settings were read %d times in a row, want 1", got)
	}
	f.clock.advance(settingsTTL - time.Second)
	mustRequire(t, f.a)
	if got := reads.lists.Load(); got != 1 {
		t.Fatalf("the settings were read again after %v, which is less than their time to live", settingsTTL-time.Second)
	}
	f.clock.advance(time.Second)
	mustRequire(t, f.a)
	if got := reads.lists.Load(); got != 2 {
		t.Fatalf("the settings were read %d times, want a second read when the time to live is over", got)
	}
	f.clock.advance(-time.Hour)
	mustRequire(t, f.a)
	if got := reads.lists.Load(); got != 3 {
		t.Fatalf("a clock that went back did not make the service read the settings: %d reads", got)
	}
}

func TestAChangeMadeByAnotherInstanceIsSeenWhenTheCacheExpires(t *testing.T) {
	f := newSessionFixture(t)
	if mustRequire(t, f.a) {
		t.Fatal("the password is needed by default")
	}
	other := store.Setting{TenantID: f.a.tenant, Name: settingPasswordToEndSessions, Value: "true", UpdatedAt: f.clock.now()}
	if err := f.a.store.Settings().Set(t.Context(), other); err != nil {
		t.Fatal(err)
	}
	if mustRequire(t, f.a) {
		t.Fatal("a change of another instance was seen before the cache expired")
	}
	f.clock.advance(settingsTTL)
	if !mustRequire(t, f.a) {
		t.Fatal("a change of another instance was not seen after the cache expired")
	}
}

func TestAChangeIsSeenAtOnceByTheInstanceThatMadeIt(t *testing.T) {
	f := newSessionFixture(t)
	if mustRequire(t, f.a) {
		t.Fatal("the password is needed by default")
	}
	if err := f.a.Admin().SetPasswordToEndSessions(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if !mustRequire(t, f.a) {
		t.Fatal("the change is not seen by the instance that made it")
	}
	if err := f.a.Admin().SetPasswordToEndSessions(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if mustRequire(t, f.a) {
		t.Fatal("the second change is not seen")
	}
}

func TestWhatAnAdministratorSetsWinsOverTheOption(t *testing.T) {
	cases := map[string]struct {
		options []Option
		stored  string
		want    bool
	}{
		"nothing at all":                              {nil, "", false},
		"the option":                                  {[]Option{WithPasswordToEndSessions()}, "", true},
		"the setting on":                              {nil, "true", true},
		"the setting off":                             {[]Option{WithPasswordToEndSessions()}, "false", false},
		"the setting on over the option":              {[]Option{WithPasswordToEndSessions()}, "true", true},
		"a value that is no value":                    {[]Option{WithPasswordToEndSessions()}, "maybe", true},
		"a value that is no value without the option": {nil, "maybe", false},
	}
	for name, c := range cases {
		f := newSessionFixture(t, c.options...)
		if c.stored != "" {
			setting := store.Setting{TenantID: f.a.tenant, Name: settingPasswordToEndSessions, Value: c.stored, UpdatedAt: f.clock.now()}
			if err := f.a.store.Settings().Set(t.Context(), setting); err != nil {
				t.Fatal(err)
			}
		}
		if got := mustRequire(t, f.a); got != c.want {
			t.Errorf("%s: the password is needed = %v, want %v", name, got, c.want)
		}
	}
}

func TestAChangeIsWrittenToTheAuditLogOnlyWhenItChangesSomething(t *testing.T) {
	f := newSessionFixture(t)
	admin := f.a.Admin()
	for _, required := range []bool{true, true, false, false, true} {
		f.clock.advance(time.Minute)
		if err := admin.SetPasswordToEndSessions(t.Context(), required); err != nil {
			t.Fatal(err)
		}
	}
	records := recordsOf(t, f.a, "setting.changed")
	if len(records) != 3 {
		t.Fatalf("the audit log holds %d changes, want 3: %+v", len(records), records)
	}
	newest := records[0]
	details := detailsOf(t, newest)
	if newest.ActorKind != store.ActorSystem || newest.ActorID != "api" || newest.TargetUserID != "" ||
		details["name"] != "password_to_end_sessions" || details["old"] != "false" || details["new"] != "true" {
		t.Fatalf("the newest change is recorded as %+v %v", newest, details)
	}
	first := detailsOf(t, records[2])
	if _, hasOld := first["old"]; hasOld || first["new"] != "true" {
		t.Fatalf("the first change is %v: a setting that was not set has no old value", first)
	}
	stored, err := f.a.store.Settings().Get(t.Context(), f.a.tenant, settingPasswordToEndSessions)
	if err != nil || stored.Value != "true" || stored.UpdatedBy != "" || !stored.UpdatedAt.Equal(f.clock.now().Truncate(time.Microsecond)) {
		t.Fatalf("the stored setting is %+v, %v", stored, err)
	}
}

func TestAChangeByAnAdministratorNamesThemAndTheAddress(t *testing.T) {
	f := newSessionFixture(t)
	by := actorRef{actor: adminActor("00000000-0000-7000-8000-0000000000a1"), ip: "198.51.100.4"}
	if err := f.a.setSetting(t.Context(), by, settingPasswordToEndSessions, "true"); err != nil {
		t.Fatal(err)
	}
	records := recordsOf(t, f.a, "setting.changed")
	if len(records) != 1 || records[0].ActorKind != store.ActorAdmin || records[0].ActorID != by.actor.ID || records[0].IP != "198.51.100.4" {
		t.Fatalf("the change is recorded as %+v", records)
	}
	stored, err := f.a.store.Settings().Get(t.Context(), f.a.tenant, settingPasswordToEndSessions)
	if err != nil || stored.UpdatedBy != by.actor.ID {
		t.Fatalf("the stored setting is %+v, %v: it names the administrator", stored, err)
	}
}

func TestAChangeThatCannotBeRecordedIsNotMade(t *testing.T) {
	f := newSessionFixture(t)
	faults := newFaults()
	f.a.store = faultStore{Store: f.a.store, faults: faults}
	broken := errors.New("the audit log is gone")
	faults.set("audit.add", broken)
	if err := f.a.Admin().SetPasswordToEndSessions(t.Context(), true); !errors.Is(err, broken) {
		t.Fatalf("SetPasswordToEndSessions = %v, want the failure of the audit log", err)
	}
	faults.clear()
	if mustRequire(t, f.a) {
		t.Fatal("a change that was not recorded was made")
	}
	if _, err := f.a.store.Settings().Get(t.Context(), f.a.tenant, settingPasswordToEndSessions); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the setting was stored although the change failed: %v", err)
	}
	for _, op := range []string{"settings.get", "settings.set"} {
		faults.set(op, broken)
		if err := f.a.Admin().SetPasswordToEndSessions(t.Context(), true); !errors.Is(err, broken) {
			t.Fatalf("with %s failing SetPasswordToEndSessions = %v", op, err)
		}
		faults.clear()
	}
}

func TestOnlyKnownSettingsAndTheirValuesAreAccepted(t *testing.T) {
	f := newSessionFixture(t)
	var validation *ValidationError
	for _, c := range []struct{ name, value string }{
		{"no_such_setting", "true"}, {"", "true"}, {settingPasswordToEndSessions, "yes"}, {settingPasswordToEndSessions, ""}, {settingPasswordToEndSessions, "TRUE"},
	} {
		if err := f.a.setSetting(t.Context(), apiActor, c.name, c.value); !errors.As(err, &validation) {
			t.Errorf("setSetting(%q, %q) = %v, want a *ValidationError", c.name, c.value, err)
		}
	}
	if list, err := f.a.store.Settings().List(t.Context(), f.a.tenant); err != nil || len(list) != 0 {
		t.Fatalf("a refused setting was stored: %v, %v", list, err)
	}
}

func TestSettingsThatCannotBeReadStopTheOperationUnlessTheyAreCached(t *testing.T) {
	logger, logs := capturingLogger()
	f := newSessionFixture(t, WithLogger(logger))
	faults := newFaults()
	f.a.store = faultStore{Store: f.a.store, faults: faults}
	broken := errors.New("the settings are gone")
	faults.set("settings.list", broken)
	login := f.login(t)
	if err := f.a.LogoutAll(t.Context(), login.Principal, ""); !errors.Is(err, broken) {
		t.Fatalf("LogoutAll = %v, want the failure to read the settings", err)
	}
	if _, err := f.a.Admin().PasswordToEndSessions(t.Context()); !errors.Is(err, broken) {
		t.Fatalf("PasswordToEndSessions = %v, want the failure to read the settings", err)
	}

	faults.clear()
	if err := f.a.Admin().SetPasswordToEndSessions(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if !mustRequire(t, f.a) {
		t.Fatal("the setting is not on")
	}
	f.clock.advance(settingsTTL)
	faults.set("settings.list", broken)
	if !mustRequire(t, f.a) {
		t.Fatal("the cached setting was not used while the settings could not be read")
	}
	if !strings.Contains(logs.String(), "the settings cannot be read, the cached ones are used") {
		t.Fatalf("the failure was not logged: %s", logs.String())
	}
	faults.clear()
	f.clock.advance(settingsRetry - time.Second)
	if err := f.a.store.Settings().Set(t.Context(), store.Setting{
		TenantID: f.a.tenant, Name: settingPasswordToEndSessions, Value: "false", UpdatedAt: f.clock.now(),
	}); err != nil {
		t.Fatal(err)
	}
	if !mustRequire(t, f.a) {
		t.Fatal("the settings were read again before the time of the retry")
	}
	f.clock.advance(time.Second)
	if mustRequire(t, f.a) {
		t.Fatal("the settings were not read again after the time of the retry")
	}
}

func TestEndingSessionsAsksForThePasswordWhenAnAdministratorSaysSo(t *testing.T) {
	f := newSessionFixture(t)
	first := f.login(t)
	second := f.login(t)
	var validation *ValidationError
	if err := f.a.Admin().SetPasswordToEndSessions(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if err := f.a.TerminateSession(t.Context(), first.Principal, second.Principal.SessionID, ""); !errors.As(err, &validation) || validation.Field != "password" {
		t.Fatalf("TerminateSession without the password = %v, want a *ValidationError for the password", err)
	}
	if err := f.a.TerminateSession(t.Context(), first.Principal, second.Principal.SessionID, goodPassword); err != nil {
		t.Fatalf("TerminateSession with the password failed: %v", err)
	}
	third := f.login(t)
	if err := f.a.Admin().SetPasswordToEndSessions(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if err := f.a.TerminateSession(t.Context(), first.Principal, third.Principal.SessionID, ""); err != nil {
		t.Fatalf("TerminateSession after the requirement was lifted failed: %v", err)
	}
}
