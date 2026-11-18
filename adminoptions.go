package limb

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"time"
)

const (
	defaultAdminSessionAbsolute = 12 * time.Hour
	defaultAdminSessionIdle     = 30 * time.Minute
	longestAdminSession         = 7 * 24 * time.Hour
)

type adminConfig struct {
	mountPath string
	ips       []netip.Prefix
	limits    LoginLimits
	absolute  time.Duration
	idle      time.Duration
	noTOTP    bool
	texts     map[string]map[string]string
}

// WithAdminMountPath tells limb where the application mounts AdminHandler, as the
// browser sees it, for example "/admin" for
//
//	mux.Handle("/admin/", http.StripPrefix("/admin", auth.AdminHandler()))
//
// The cookies of the administration are scoped to this path and the pages link to
// it. It starts with a slash, has no slash at the end, unless it is the root, and
// is made of letters, digits and the characters . _ ~ - only. AdminHandler panics
// without this option, and New fails for a path that is not valid.
func WithAdminMountPath(mountPath string) Option {
	return func(c *config) {
		if !validMountPath(mountPath) {
			c.fail(fmt.Errorf("limb: %q is not a mount path of the administration: it starts with a slash, is clean, has no slash at the end and only the characters of a path", mountPath))
			return
		}
		c.admin.mountPath = mountPath
	}
}

// WithAdminIPs lets the administration answer only requests that come from
// these networks, as the address of the client is told by WithTrustedProxies. A
// request from any other address gets the answer for a page that does not exist,
// whatever it asks for. Without this option every address can ask, and the limits
// on the sign-in and the second factor are what stand in the way. New fails for a
// prefix that is not valid.
func WithAdminIPs(prefixes ...netip.Prefix) Option {
	return func(c *config) {
		for _, p := range prefixes {
			if !p.IsValid() {
				c.fail(errors.New("limb: a prefix of the addresses of the administration is not valid"))
				return
			}
			c.admin.ips = append(c.admin.ips, p.Masked())
		}
	}
}

// WithAdminLoginLimits sets the limits on the failed attempts to sign in to the
// administration, a wrong password and a wrong one-time password or recovery code
// alike. A field that is zero keeps its default: 5 failures within 15 minutes of
// one login from one address are followed by a pause of 30 minutes, 20 from one
// address by a pause of 30 minutes, and after 10 within 15 minutes on one login
// from anywhere every attempt waits, up to a minute, so that nobody can lock an
// administrator out by failing to sign in to their account. New fails for a negative
// value. The counters live in the database, apart from those of the users.
func WithAdminLoginLimits(l LoginLimits) Option {
	return func(c *config) {
		c.admin.limits = l
	}
}

// WithAdminSessionTTL sets how long a session of an administrator lasts. A
// session ends absolute after the sign-in whatever the administrator does, and
// idle after the last time it was used if that is earlier. The defaults are 12
// hours and 30 minutes. Both must be at least a minute, idle must not exceed
// absolute and absolute must not exceed a week, or New fails.
func WithAdminSessionTTL(absolute, idle time.Duration) Option {
	return func(c *config) {
		switch {
		case absolute < time.Minute || idle < time.Minute:
			c.fail(errors.New("limb: the session lifetimes of the administration must be at least a minute"))
		case idle > absolute:
			c.fail(errors.New("limb: the idle lifetime of a session of the administration must not exceed its absolute lifetime"))
		case absolute > longestAdminSession:
			c.fail(errors.New("limb: a session of the administration must not last longer than a week"))
		default:
			c.admin.absolute, c.admin.idle = absolute, idle
		}
	}
}

// WithoutAdminTOTP lets an administrator in with the password alone, without
// the one-time password of an authenticator. It exists for a development machine
// and needs WithDevelopmentMode, or New fails: an administration that is open to
// whoever knows a password is not one to run in production.
func WithoutAdminTOTP() Option {
	return func(c *config) {
		c.admin.noTOTP = true
	}
}

// WithAdminTexts replaces texts of the administration, or gives it a language
// that it has no texts for, for example
//
//	limb.WithAdminTexts("ru", map[string]string{"login.title": "Вход для сотрудников"})
//
// texts maps the keys of the texts to their new values, and docs/admin-texts.md
// of the repository lists the keys with the texts that the library has. A text
// that has a %s or a %d in it is given an argument by the page and must use it as
// the original does, in any order, as in %[1]s, and a text that takes none must
// not hold a percent sign. A language that has no texts is added with the texts
// that are given and shows English for the rest, and the page offers it with the
// others. The option can be given for several languages. New fails for a
// language tag that is not two or three lower case letters, for a key that no
// text has, for a text that is empty and for one that does not use its
// arguments.
func WithAdminTexts(language string, texts map[string]string) Option {
	return func(c *config) {
		if c.admin.texts == nil {
			c.admin.texts = map[string]map[string]string{}
		}
		if c.admin.texts[language] == nil {
			c.admin.texts[language] = map[string]string{}
		}
		maps.Copy(c.admin.texts[language], texts)
	}
}
