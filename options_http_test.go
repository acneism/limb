package limb

import (
	"net/http"
	"strings"
	"testing"
)

func TestSameSiteNoneCannotBeUsedInDevelopmentMode(t *testing.T) {
	err := newFixtureErr(t, WithDevelopmentMode(), WithCookieSameSite(http.SameSiteNoneMode))
	if err == nil || !strings.Contains(err.Error(), "Secure") {
		t.Fatalf("New = %v", err)
	}
	if err = newFixtureErr(t, WithCookieSameSite(http.SameSiteDefaultMode)); err == nil {
		t.Fatal("an unknown SameSite mode must be refused")
	}
}

func TestRefreshCookieNeedsAValidMountPath(t *testing.T) {
	if err := newFixtureErr(t, WithRefreshCookie()); err == nil || !strings.Contains(err.Error(), "WithMountPath") {
		t.Fatalf("New without a mount path = %v", err)
	}
	invalid := []string{
		"", "auth", "/auth/", "//auth", "/auth//v1", "/auth/../x", "/auth/./x", "/..", "/.", "/a b", "/a;b",
		"/a?b", "/a#b", "/é", "/a%2Fb", "\\auth", "/auth\n", "/a,b", "/a\"b", "/a=b",
	}
	for _, mount := range invalid {
		if err := newFixtureErr(t, WithMountPath(mount)); err == nil {
			t.Errorf("WithMountPath(%q) was accepted", mount)
		}
	}
	for _, mount := range []string{"/", "/auth", "/auth/v1", "/a.b_c~d-e", "/..."} {
		if err := newFixtureErr(t, WithMountPath(mount)); err != nil {
			t.Errorf("WithMountPath(%q) = %v", mount, err)
		}
	}
	if err := newFixtureErr(t, WithMountPath("/auth")); err != nil {
		t.Fatalf("a mount path without the refresh cookie = %v", err)
	}
}

func FuzzMountPath(f *testing.F) {
	for _, seed := range []string{"/", "/auth", "/auth/", "", "//", "/a/../b", "/a b", "/é", "/a;b", "/.", "/..", "/a/./b"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, mount string) {
		if !validMountPath(mount) {
			return
		}
		if mount != "/" && (strings.HasSuffix(mount, "/") || strings.Contains(mount, "//")) {
			t.Fatalf("%q is accepted", mount)
		}
		if !strings.HasPrefix(mount, "/") {
			t.Fatalf("%q is accepted", mount)
		}
		for _, r := range mount {
			if r <= ' ' || r >= 0x7f || strings.ContainsRune(";,?#%\"\\=", r) {
				t.Fatalf("%q is accepted with %q in it", mount, r)
			}
		}
		for segment := range strings.SplitSeq(strings.TrimPrefix(mount, "/"), "/") {
			if mount != "/" && (segment == "." || segment == ".." || segment == "") {
				t.Fatalf("%q is accepted with the segment %q", mount, segment)
			}
		}
		if got := refreshCookiePath(mount); !strings.HasSuffix(got, "/token/refresh") || strings.Contains(got, "//") {
			t.Fatalf("the cookie path of %q is %q", mount, got)
		}
	})
}

func TestAnUnknownEndpointIsAConfigurationError(t *testing.T) {
	err := newFixtureErr(t, WithoutEndpoints(EndpointLogin, "nope"))
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("New with an unknown endpoint = %v", err)
	}
}

func TestTheRefreshCookiePathFollowsTheMountPath(t *testing.T) {
	tests := map[string]string{
		"":            "/token/refresh",
		"/":           "/token/refresh",
		"/auth":       "/auth/token/refresh",
		"/api/v1/aaa": "/api/v1/aaa/token/refresh",
	}
	for mount, want := range tests {
		if got := refreshCookiePath(mount); got != want {
			t.Errorf("refreshCookiePath(%q) = %q, want %q", mount, got, want)
		}
	}
}

func TestCookieNamesCarryThePrefixesOfTheirScope(t *testing.T) {
	if got := sessionCookieName(false); got != "__Host-limb_session" {
		t.Fatalf("session cookie = %q", got)
	}
	if got := sessionCookieName(true); got != "limb_session" {
		t.Fatalf("session cookie in development = %q", got)
	}
	if got := refreshCookieName(false); got != "__Secure-limb_refresh" {
		t.Fatalf("refresh cookie = %q", got)
	}
	if got := refreshCookieName(true); got != "limb_refresh" {
		t.Fatalf("refresh cookie in development = %q", got)
	}
}
