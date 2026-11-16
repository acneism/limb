package limb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/acneism/limb/internal/memstore"
)

func proxyAuth(t testing.TB) *Auth {
	t.Helper()
	return &Auth{proxies: []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	}}
}

func proxyRequest(remote string, forwarded ...string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	for _, line := range forwarded {
		r.Header.Add("X-Forwarded-For", line)
	}
	return r
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name      string
		remote    string
		forwarded []string
		want      string
		fromProxy bool
	}{
		{"direct connection", "203.0.113.7:5000", nil, "203.0.113.7", false},
		{"header of an untrusted peer is ignored", "203.0.113.7:5000", []string{"198.51.100.1"}, "203.0.113.7", false},
		{"one proxy", "10.0.0.5:443", []string{"198.51.100.1"}, "198.51.100.1", true},
		{"the client cannot spoof the left of the header", "10.0.0.5:443", []string{"6.6.6.6, 198.51.100.1"}, "198.51.100.1", true},
		{"a chain of proxies", "10.0.0.5:443", []string{"198.51.100.1, 10.0.0.9"}, "198.51.100.1", true},
		{"the first untrusted address from the right", "10.0.0.5:443", []string{"6.6.6.6, 198.51.100.1, 10.0.0.9"}, "198.51.100.1", true},
		{"an untrusted address in the middle", "10.0.0.5:443", []string{"198.51.100.1, 6.6.6.6, 10.0.0.9"}, "6.6.6.6", true},
		{"only proxies", "10.0.0.5:443", []string{"10.0.0.1, 10.0.0.9"}, "10.0.0.1", true},
		{"no header", "10.0.0.5:443", nil, "10.0.0.5", true},
		{"several header lines", "10.0.0.5:443", []string{"6.6.6.6", "198.51.100.1"}, "198.51.100.1", true},
		{"several lines of proxies", "10.0.0.5:443", []string{"198.51.100.1", "10.0.0.2", "10.0.0.3"}, "198.51.100.1", true},
		{"a port after the address", "10.0.0.5:443", []string{"198.51.100.1:4000"}, "198.51.100.1", true},
		{"an IPv6 address with a port", "10.0.0.5:443", []string{"[2001:db9::1]:4000"}, "2001:db9::1", true},
		{"IPv6 proxy", "[2001:db8::1]:443", []string{"2001:db9::7"}, "2001:db9::7", true},
		{"IPv6 proxy in the chain", "10.0.0.5:443", []string{"2001:db9::7, 2001:db8::2"}, "2001:db9::7", true},
		{"IPv4 mapped peer", "[::ffff:10.0.0.5]:443", []string{"198.51.100.1"}, "198.51.100.1", true},
		{"IPv4 mapped client", "10.0.0.5:443", []string{"::ffff:198.51.100.1"}, "198.51.100.1", true},
		{"zone is dropped", "[fe80::1%eth0]:443", nil, "fe80::1", false},
		{"zone of a forwarded address", "10.0.0.5:443", []string{"fe80::2%eth1"}, "fe80::2", true},
		{"garbage in the header", "10.0.0.5:443", []string{"198.51.100.1, garbage"}, "10.0.0.5", true},
		{"unknown from a proxy", "10.0.0.5:443", []string{"unknown"}, "10.0.0.5", true},
		{"an empty element", "10.0.0.5:443", []string{"198.51.100.1,,"}, "10.0.0.5", true},
		{"an empty header", "10.0.0.5:443", []string{""}, "10.0.0.5", true},
		{"spaces around elements", "10.0.0.5:443", []string{"  198.51.100.1  ,   10.0.0.9 "}, "198.51.100.1", true},
		{"a connection without a port", "203.0.113.7", nil, "203.0.113.7", false},
		{"a unix socket", "@", []string{"198.51.100.1"}, "", false},
		{"no remote address", "", []string{"198.51.100.1"}, "", false},
	}
	a := proxyAuth(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := proxyRequest(tc.remote, tc.forwarded...)
			got := a.clientIP(r)
			want := netip.Addr{}
			if tc.want != "" {
				want = netip.MustParseAddr(tc.want)
			}
			if got != want {
				t.Fatalf("clientIP = %v, want %v", got, want)
			}
			if got := a.fromTrustedProxy(r); got != tc.fromProxy {
				t.Fatalf("fromTrustedProxy = %v, want %v", got, tc.fromProxy)
			}
		})
	}
}

func TestClientIPStopsAfterTooManyProxies(t *testing.T) {
	a := proxyAuth(t)
	long := strings.Repeat("10.0.0.9, ", maxForwardedHops+5) + "10.0.0.8"
	if got := a.clientIP(proxyRequest("10.0.0.5:443", "198.51.100.1, "+long)); got != netip.MustParseAddr("10.0.0.5") {
		t.Fatalf("clientIP = %v, want the address of the connection", got)
	}
	exact := strings.Repeat("10.0.0.9, ", maxForwardedHops-2) + "10.0.0.8"
	if got := a.clientIP(proxyRequest("10.0.0.5:443", "198.51.100.1, "+exact)); got != netip.MustParseAddr("198.51.100.1") {
		t.Fatalf("clientIP = %v, want the client behind %d proxies", got, maxForwardedHops-1)
	}
}

func TestWithoutProxiesTheHeaderIsNeverRead(t *testing.T) {
	a := &Auth{}
	r := proxyRequest("10.0.0.5:443", "198.51.100.1")
	if got := a.clientIP(r); got != netip.MustParseAddr("10.0.0.5") {
		t.Fatalf("clientIP = %v, want the address of the connection", got)
	}
	if a.fromTrustedProxy(r) {
		t.Fatal("no proxy is trusted without the option")
	}
}

func TestWithTrustedProxiesValidatesPrefixes(t *testing.T) {
	for name, prefixes := range map[string][]netip.Prefix{
		"the zero prefix": {{}},
		"all IPv4":        {netip.MustParsePrefix("0.0.0.0/0")},
		"all IPv6":        {netip.MustParsePrefix("::/0")},
		"one bad of two":  {netip.MustParsePrefix("10.0.0.0/8"), {}},
	} {
		_, err := NewWithStore(memstore.New(), []byte(testKey), WithTrustedProxies(prefixes...))
		if err == nil || !strings.HasPrefix(err.Error(), "limb: ") {
			t.Errorf("%s: NewWithStore = %v, want a configuration error", name, err)
		}
	}
	a, err := NewWithStore(memstore.New(), []byte(testKey), WithAutoMigrate(), WithTrustedProxies(netip.MustParsePrefix("10.1.2.3/8"), netip.MustParsePrefix("192.0.2.1/32")))
	if err != nil {
		t.Fatalf("NewWithStore failed: %v", err)
	}
	if got := a.proxies[0].String(); got != "10.0.0.0/8" {
		t.Fatalf("the prefix must be masked, got %s", got)
	}
	if !a.trusted(netip.MustParseAddr("10.200.1.1")) || !a.trusted(netip.MustParseAddr("192.0.2.1")) || a.trusted(netip.MustParseAddr("192.0.2.2")) {
		t.Fatal("trusted does not follow the prefixes")
	}
}

func FuzzClientIP(f *testing.F) {
	a := proxyAuth(f)
	f.Add("10.0.0.5:443", "198.51.100.1")
	f.Add("10.0.0.5:443", "6.6.6.6, 198.51.100.1, 10.0.0.9")
	f.Add("203.0.113.7:80", "10.0.0.1")
	f.Add("[::ffff:10.0.0.5]:443", "::ffff:1.2.3.4")
	f.Add("[2001:db8::1]:443", "[2001:db9::1]:80, fe80::1%eth0")
	f.Add("10.0.0.5:443", ",,, ,")
	f.Add("@", "1.2.3.4")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, remote, forwarded string) {
		if strings.ContainsAny(remote+forwarded, "\r\n\x00") {
			return
		}
		r := &http.Request{RemoteAddr: remote, Header: http.Header{"X-Forwarded-For": {forwarded}}}
		got := a.clientIP(r)
		if got.IsValid() && (got.Is4In6() || got.Zone() != "") {
			t.Fatalf("clientIP(%q, %q) = %v is not a clean address", remote, forwarded, got)
		}
		peer := peerAddr(r)
		if peer.IsValid() && !a.trusted(peer) && got != peer {
			t.Fatalf("a peer that is not a proxy must not be able to change the address: %v became %v", peer, got)
		}
		if !peer.IsValid() && got.IsValid() {
			t.Fatalf("without a valid peer there is no client, got %v", got)
		}
	})
}
