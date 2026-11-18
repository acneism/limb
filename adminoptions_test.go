package limb

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func TestTheMountPathOfTheAdministrationFollowsTheRulesOfAMountPath(t *testing.T) {
	for _, mount := range []string{"", "admin", "/admin/", "//admin", "/a//b", "/a/../b", "/a b", "/é", "/a?b", "/a;b"} {
		if err := newFixtureErr(t, WithAdminMountPath(mount)); err == nil || !strings.Contains(err.Error(), "mount path of the administration") {
			t.Errorf("WithAdminMountPath(%q) = %v, want a refusal", mount, err)
		}
	}
	for _, mount := range []string{"/", "/admin", "/ops/admin", "/a.b_c~d-e"} {
		if err := newFixtureErr(t, WithAdminMountPath(mount)); err != nil {
			t.Errorf("WithAdminMountPath(%q) = %v", mount, err)
		}
	}
}

func TestTheAddressesOfTheAdministrationNeedValidPrefixes(t *testing.T) {
	if err := newFixtureErr(t, WithAdminIPs(netip.Prefix{})); err == nil || !strings.Contains(err.Error(), "prefix") {
		t.Fatalf("WithAdminIPs with a prefix that is not valid = %v", err)
	}
	a := newTestAuth(t, WithAdminIPs(netip.MustParsePrefix("203.0.113.77/24"), netip.MustParsePrefix("2001:db8::1/32")))
	want := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	if len(a.adminIPs) != 2 || a.adminIPs[0] != want[0] || a.adminIPs[1] != want[1] {
		t.Fatalf("the networks are %v, want %v: the bits of the host are cleared", a.adminIPs, want)
	}
}

func TestTheLimitsOnTheSignInOfAdministratorsAreStricterThanThoseOfUsers(t *testing.T) {
	a := newTestAuth(t)
	if got, want := a.adminLimits, adminLimitDefaults; got != want {
		t.Fatalf("the limits are %+v, want %+v", got, want)
	}
	if a.adminLimits.accountIP.Attempts != 5 || a.adminLimits.accountIP.Window != 15*time.Minute || a.adminLimits.accountIP.Pause != 30*time.Minute {
		t.Fatalf("an account from an address is %+v, want 5 within 15 minutes and a pause of 30", a.adminLimits.accountIP)
	}
	if a.adminLimits.ip.Attempts != 20 || a.adminLimits.ip.Pause != 30*time.Minute || a.adminLimits.account.Attempts != 10 || a.adminLimits.account.Max != time.Minute {
		t.Fatalf("the limits are %+v", a.adminLimits)
	}
	if a.limits != userLimitDefaults {
		t.Fatalf("the limits of the users changed to %+v", a.limits)
	}
	tuned := newTestAuth(t, WithAdminLoginLimits(LoginLimits{AccountAndIP: Limit{Attempts: 3}, IP: Limit{Pause: time.Hour}}), WithLoginLimits(LoginLimits{AccountAndIP: Limit{Attempts: 9}}))
	if tuned.adminLimits.accountIP.Attempts != 3 || tuned.adminLimits.accountIP.Pause != 30*time.Minute || tuned.adminLimits.ip.Pause != time.Hour || tuned.adminLimits.ip.Attempts != 20 {
		t.Fatalf("the tuned limits are %+v", tuned.adminLimits)
	}
	if tuned.limits.accountIP.Attempts != 9 {
		t.Fatalf("the limits of the users are %+v: the limits of the administration do not touch them", tuned.limits)
	}
	if err := newFixtureErr(t, WithAdminLoginLimits(LoginLimits{IP: Limit{Attempts: -1}})); err == nil {
		t.Fatal("a negative limit was accepted")
	}
}

func TestTheSessionsOfAdministratorsLastTwelveHoursAndThirtyMinutesByDefault(t *testing.T) {
	a := newTestAuth(t)
	if a.adminAbsolute != 12*time.Hour || a.adminIdle != 30*time.Minute {
		t.Fatalf("the sessions last %v and %v", a.adminAbsolute, a.adminIdle)
	}
	tuned := newTestAuth(t, WithAdminSessionTTL(48*time.Hour, 2*time.Hour))
	if tuned.adminAbsolute != 48*time.Hour || tuned.adminIdle != 2*time.Hour {
		t.Fatalf("the tuned sessions last %v and %v", tuned.adminAbsolute, tuned.adminIdle)
	}
	for name, ttl := range map[string][2]time.Duration{
		"too short":         {59 * time.Second, 59 * time.Second},
		"idle too short":    {time.Hour, 59 * time.Second},
		"idle over":         {time.Hour, time.Hour + time.Second},
		"over a week":       {7*24*time.Hour + time.Second, time.Hour},
		"negative":          {-time.Hour, -time.Hour},
		"nothing at all":    {0, 0},
		"absolute only set": {time.Hour, 0},
	} {
		if err := newFixtureErr(t, WithAdminSessionTTL(ttl[0], ttl[1])); err == nil {
			t.Errorf("%s: WithAdminSessionTTL(%v, %v) was accepted", name, ttl[0], ttl[1])
		}
	}
	if err := newFixtureErr(t, WithAdminSessionTTL(7*24*time.Hour, 7*24*time.Hour)); err != nil {
		t.Errorf("a week for both = %v", err)
	}
	if err := newFixtureErr(t, WithAdminSessionTTL(time.Minute, time.Minute)); err != nil {
		t.Errorf("a minute for both = %v", err)
	}
}

func TestCleanupKeepsTheSessionsOfAdministratorsAsLongAsTheirIdleTimeCounts(t *testing.T) {
	f := newSessionFixture(t, WithAdminSessionTTL(24*time.Hour, 6*time.Hour))
	if _, err := f.a.Admin().CreateAdmin(t.Context(), "root", adminPassword); err != nil {
		t.Fatal(err)
	}
	root, err := f.a.store.Admins().FindByLogin(t.Context(), f.a.tenant, "root")
	if err != nil {
		t.Fatal(err)
	}
	now := f.clock.now().UTC().Truncate(time.Microsecond)
	add := func(n uint16, seen time.Time) {
		t.Helper()
		s := store.AdminSession{
			TenantID: f.a.tenant, ID: fmt.Sprintf("00000000-0000-7000-8000-%012d", 8000+int(n)), AdminID: root.ID, Stage: store.AdminStageFull, SecretHash: hashFor(n),
			AdminVersion: root.Version, CreatedAt: now.Add(-72 * time.Hour), LastSeenAt: seen, ExpiresAt: now.Add(6 * time.Hour),
		}
		if createErr := f.a.store.AdminSessions().Create(t.Context(), s); createErr != nil {
			t.Fatal(createErr)
		}
	}
	add(1, now.Add(-25*time.Hour-5*time.Hour))
	add(2, now.Add(-25*time.Hour-7*time.Hour))
	if err = f.a.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	for n, want := range map[uint16]bool{1: true, 2: false} {
		_, resolveErr := f.a.store.AdminSessions().ResolveBySecret(t.Context(), f.a.tenant, hashFor(n))
		if (resolveErr == nil) != want {
			t.Errorf("the session %d is there = %v, want %v: the day of keeping counts from the end of the idle time of six hours", n, resolveErr == nil, want)
		}
	}
}

func TestAnAdministrationWithoutTheSecondFactorIsForTheDevelopmentMode(t *testing.T) {
	if err := newFixtureErr(t, WithoutAdminTOTP()); err == nil || !strings.Contains(err.Error(), "WithDevelopmentMode") {
		t.Fatalf("WithoutAdminTOTP in production = %v, want a refusal that names WithDevelopmentMode", err)
	}
	if err := newFixtureErr(t, WithoutAdminTOTP(), WithDevelopmentMode()); err != nil {
		t.Fatalf("WithoutAdminTOTP in development = %v", err)
	}
	if a := newTestAuth(t, WithoutAdminTOTP(), WithDevelopmentMode()); !a.adminNoTOTP {
		t.Fatal("the option was not taken")
	}
	if a := newTestAuth(t); a.adminNoTOTP {
		t.Fatal("the second factor is off by default")
	}
}
