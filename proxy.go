package limb

import (
	"net/http"
	"net/netip"
	"strings"
)

const maxForwardedHops = 64

func (a *Auth) trusted(addr netip.Addr) bool {
	for _, prefix := range a.proxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func peerAddr(r *http.Request) netip.Addr {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return cleanAddr(ap.Addr())
	}
	if addr, err := netip.ParseAddr(r.RemoteAddr); err == nil {
		return cleanAddr(addr)
	}
	return netip.Addr{}
}

func cleanAddr(addr netip.Addr) netip.Addr {
	return addr.Unmap().WithZone("")
}

func (a *Auth) fromTrustedProxy(r *http.Request) bool {
	peer := peerAddr(r)
	return peer.IsValid() && a.trusted(peer)
}

func (a *Auth) clientIP(r *http.Request) netip.Addr {
	peer := peerAddr(r)
	if !peer.IsValid() || !a.trusted(peer) {
		return peer
	}
	hops := forwardedFor(r)
	for i := len(hops) - 1; i >= 0 && len(hops)-i <= maxForwardedHops; i-- {
		hop, ok := parseHop(hops[i])
		if !ok {
			return peer
		}
		if !a.trusted(hop) || i == 0 {
			return hop
		}
	}
	return peer
}

func forwardedFor(r *http.Request) []string {
	var hops []string
	for _, line := range r.Header.Values("X-Forwarded-For") {
		for hop := range strings.SplitSeq(line, ",") {
			hops = append(hops, strings.TrimSpace(hop))
		}
	}
	return hops
}

func parseHop(hop string) (netip.Addr, bool) {
	if addr, err := netip.ParseAddr(hop); err == nil {
		return cleanAddr(addr), true
	}
	if ap, err := netip.ParseAddrPort(hop); err == nil {
		return cleanAddr(ap.Addr()), true
	}
	return netip.Addr{}, false
}
