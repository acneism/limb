package limb

import (
	"strings"
)

const (
	refreshCookieBase = "limb_refresh"
	refreshRoute      = "/token/refresh"
)

func refreshCookieName(development bool) string {
	if development {
		return refreshCookieBase
	}
	return "__Secure-" + refreshCookieBase
}

func refreshCookiePath(mountPath string) string {
	return strings.TrimSuffix(mountPath, "/") + refreshRoute
}
