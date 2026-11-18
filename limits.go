package limb

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/store"
)

const (
	maxRawLoginInput = 1024
	maxRawLoginKey   = 256
	maxDelayExponent = 6
	recordTimeout    = 5 * time.Second
)

// Limit stops attempts for a while after too many of them have failed.
type Limit struct {
	// Attempts is how many failed attempts within Window are allowed. The
	// attempt that reaches the number starts the pause.
	Attempts int
	// Window is the time in which the attempts are counted.
	Window time.Duration
	// Pause is how long every attempt is turned down once Attempts is reached.
	Pause time.Duration
}

// Delay slows attempts down instead of stopping them, so that nobody can lock
// an account of someone else by failing to sign in to it.
type Delay struct {
	// Attempts is how many failed attempts within Window are allowed before the
	// delay starts.
	Attempts int
	// Window is the time in which the attempts are counted.
	Window time.Duration
	// Max is the longest delay. The delay starts at one second after the
	// attempt that reaches Attempts and doubles with every further failure.
	Max time.Duration
}

// LoginLimits sets the limits on failed sign-in attempts. Every field that is
// zero takes its default. The counters live in the database, so several
// instances of an application count together.
type LoginLimits struct {
	// AccountAndIP limits failures on one account from one address: 5 within 15
	// minutes, then a pause of 15 minutes. A successful sign-in clears it.
	AccountAndIP Limit
	// IP limits failures from one address, whatever the accounts are: 100 within
	// 15 minutes, then a pause of 15 minutes. IPv6 addresses are counted by their
	// /64 network.
	IP Limit
	// Account slows failures on one account from anywhere: after 20 within 15
	// minutes every attempt waits, up to 1 minute.
	Account Delay
}

type loginLimits struct {
	accountIP Limit
	ip        Limit
	account   Delay
}

var (
	userLimitDefaults = loginLimits{
		accountIP: Limit{Attempts: 5, Window: 15 * time.Minute, Pause: 15 * time.Minute},
		ip:        Limit{Attempts: 100, Window: 15 * time.Minute, Pause: 15 * time.Minute},
		account:   Delay{Attempts: 20, Window: 15 * time.Minute, Max: time.Minute},
	}
	adminLimitDefaults = loginLimits{
		accountIP: Limit{Attempts: 5, Window: 15 * time.Minute, Pause: 30 * time.Minute},
		ip:        Limit{Attempts: 20, Window: 15 * time.Minute, Pause: 30 * time.Minute},
		account:   Delay{Attempts: 10, Window: 15 * time.Minute, Max: time.Minute},
	}
)

func (l LoginLimits) resolve() (loginLimits, error) {
	return l.resolveOver(userLimitDefaults)
}

func (l LoginLimits) resolveOver(defaults loginLimits) (loginLimits, error) {
	if l.AccountAndIP.negative() || l.IP.negative() || l.Account.negative() {
		return loginLimits{}, errors.New("limb: the limits on failed attempts must not be negative")
	}
	return loginLimits{
		accountIP: l.AccountAndIP.over(defaults.accountIP),
		ip:        l.IP.over(defaults.ip),
		account:   l.Account.over(defaults.account),
	}, nil
}

func (l Limit) negative() bool {
	return l.Attempts < 0 || l.Window < 0 || l.Pause < 0
}

func (l Limit) over(base Limit) Limit {
	if l.Attempts > 0 {
		base.Attempts = l.Attempts
	}
	if l.Window > 0 {
		base.Window = l.Window
	}
	if l.Pause > 0 {
		base.Pause = l.Pause
	}
	return base
}

func (d Delay) negative() bool {
	return d.Attempts < 0 || d.Window < 0 || d.Max < 0
}

func (d Delay) over(base Delay) Delay {
	if d.Attempts > 0 {
		base.Attempts = d.Attempts
	}
	if d.Window > 0 {
		base.Window = d.Window
	}
	if d.Max > 0 {
		base.Max = d.Max
	}
	return base
}

type attemptKeys struct {
	accountIP string
	ip        string
	account   string
}

func (a *Auth) loginAttemptKeys(login string, ip netip.Addr) attemptKeys {
	kind, value := a.accountLabel(login)
	keys := attemptKeys{account: a.keys.AttemptKey("account", a.tenant, kind, value)}
	if ip.IsValid() {
		address := limitedAddress(ip)
		keys.ip = a.keys.AttemptKey("ip", a.tenant, address)
		keys.accountIP = a.keys.AttemptKey("account-ip", a.tenant, kind, value, address)
	}
	return keys
}

func (a *Auth) userAttemptKeys(userID string) attemptKeys {
	return attemptKeys{account: a.keys.AttemptKey("user", a.tenant, userID)}
}

func (a *Auth) accountLabel(login string) (string, string) {
	if kind, value, err := identifier.Resolve(a.types, login); err == nil {
		return "type:" + kind.Name(), value
	}
	return "raw", rawLoginKey(login)
}

func rawLoginKey(login string) string {
	text := strings.ToLower(norm.NFKC.String(cutAtRune(strings.TrimSpace(cutAtRune(login, maxRawLoginInput)), maxRawLoginInput)))
	return cutAtRune(text, maxRawLoginKey)
}

func cutAtRune(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut]
}

func limitedAddress(ip netip.Addr) string {
	ip = cleanAddr(ip)
	if ip.Is6() {
		if prefix, err := ip.Prefix(64); err == nil {
			return prefix.Masked().String()
		}
	}
	return ip.String()
}

func (a *Auth) acquireSlot(ctx context.Context) (func(), error) {
	select {
	case a.slots <- struct{}{}:
		return func() { <-a.slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (a *Auth) limited(ctx context.Context, keys attemptKeys, verify func() error) error {
	return a.limitedOver(ctx, keys, a.limits, verify)
}

func (a *Auth) limitedOver(ctx context.Context, keys attemptKeys, limits loginLimits, verify func() error) error {
	release, err := a.acquireSlot(ctx)
	if err != nil {
		return err
	}
	defer release()
	if err = a.checkLimits(ctx, keys); err != nil {
		return err
	}
	err = verify()
	if errors.Is(err, ErrInvalidCredentials) {
		a.recordFailureOver(ctx, keys, limits)
	}
	return err
}

func (a *Auth) checkLimits(ctx context.Context, keys attemptKeys) error {
	return a.checkKeys(ctx, keys.accountIP, keys.ip, keys.account)
}

func (a *Auth) checkKeys(ctx context.Context, keys ...string) error {
	wanted := make([]string, 0, len(keys))
	for _, key := range keys {
		if key != "" {
			wanted = append(wanted, key)
		}
	}
	if len(wanted) == 0 {
		return nil
	}
	counters, err := a.store.Attempts().Get(ctx, wanted...)
	if err != nil {
		return fmt.Errorf("limb: check the limits on failed attempts: %w", err)
	}
	now := a.now()
	var latest time.Time
	for _, c := range counters {
		latest = laterOf(latest, laterOf(c.BlockedUntil, c.NextAllowedAt))
	}
	if !latest.After(now) {
		return nil
	}
	return &RateLimitError{RetryAfter: wholeSeconds(latest.Sub(now))}
}

func laterOf(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func wholeSeconds(d time.Duration) time.Duration {
	whole := d.Truncate(time.Second)
	if whole < d {
		whole += time.Second
	}
	return max(time.Second, whole)
}

func (a *Auth) recordFailureOver(ctx context.Context, keys attemptKeys, limits loginLimits) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	now := a.now()
	if keys.accountIP != "" {
		a.countFailure(ctx, keys.accountIP, now, limits.accountIP.Window, func(count int) store.Hold {
			if count >= limits.accountIP.Attempts {
				return store.Hold{BlockedUntil: now.Add(limits.accountIP.Pause)}
			}
			return store.Hold{}
		})
	}
	if keys.ip != "" {
		a.countFailure(ctx, keys.ip, now, limits.ip.Window, func(count int) store.Hold {
			if count >= limits.ip.Attempts {
				return store.Hold{BlockedUntil: now.Add(limits.ip.Pause)}
			}
			return store.Hold{}
		})
	}
	a.countFailure(ctx, keys.account, now, limits.account.Window, func(count int) store.Hold {
		if count < limits.account.Attempts {
			return store.Hold{}
		}
		exponent := min(count-limits.account.Attempts, maxDelayExponent)
		return store.Hold{NextAllowedAt: now.Add(min(time.Second<<exponent, limits.account.Max))}
	})
}

func (a *Auth) countFailure(ctx context.Context, key string, now time.Time, window time.Duration, hold func(count int) store.Hold) {
	counter, err := a.store.Attempts().Hit(ctx, key, now, window)
	if err != nil {
		a.logger.ErrorContext(ctx, "limb: a failed attempt cannot be counted", "error", err)
		return
	}
	h := hold(counter.Count)
	if h == (store.Hold{}) {
		return
	}
	if err = a.store.Attempts().Hold(ctx, key, h); err != nil && !errors.Is(err, store.ErrNotFound) {
		a.logger.ErrorContext(ctx, "limb: a pause after failed attempts cannot be recorded", "error", err)
	}
}

func (a *Auth) clearFailures(ctx context.Context, key string) {
	if key == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	if err := a.store.Attempts().Reset(ctx, key); err != nil {
		a.logger.WarnContext(ctx, "limb: the counter of failed attempts cannot be cleared", "error", err)
	}
}
