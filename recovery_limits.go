package limb

import (
	"cmp"
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/acneism/limb/store"
)

const (
	defaultCodeAttempts = 5
	maxCodeAttempts     = 20
)

// RecoveryLimits sets the limits on asking for links and codes and on guessing
// them, for the confirmation of an address and for the reset of a password.
// Every field that is zero takes its default. The two purposes have counters of
// their own, so that a flood of requests for one cannot lock the other, and the
// counters live in the database, so several instances of an application count
// together. A request is counted whether or not the login belongs to an account,
// so the limits tell nothing about which accounts exist.
type RecoveryLimits struct {
	// ChannelRequests limits the requests for one login: 3 within an hour, and
	// then every request is refused until the hour is over. Pause is not used. A
	// registration counts once for each address and phone number that it names, as
	// a request for a confirmation.
	ChannelRequests Limit

	// IPRequests limits the requests from one address, whatever the logins are:
	// 20 within an hour, then a pause of 15 minutes. IPv6 addresses are counted by
	// their /64 network. A registration counts as a request for a confirmation.
	IPRequests Limit

	// IPFailures limits the links and the codes that were wrong, from one address:
	// 30 within 15 minutes, then a pause of 15 minutes.
	IPFailures Limit

	// CodeAttempts is how many guesses a code survives, wrong or right: 5 by
	// default, at most 20. The code is dead after them, and the user asks for a new
	// one.
	CodeAttempts int
}

type recoveryLimits struct {
	channel      Limit
	ip           Limit
	failures     Limit
	codeAttempts int
}

func (l RecoveryLimits) resolve() (recoveryLimits, error) {
	if l.ChannelRequests.negative() || l.IPRequests.negative() || l.IPFailures.negative() || l.CodeAttempts < 0 || l.CodeAttempts > maxCodeAttempts {
		return recoveryLimits{}, errors.New("limb: the limits on recovery must not be negative, and a code can survive at most 20 guesses")
	}
	return recoveryLimits{
		channel:      l.ChannelRequests.over(Limit{Attempts: 3, Window: time.Hour}),
		ip:           l.IPRequests.over(Limit{Attempts: 20, Window: time.Hour, Pause: 15 * time.Minute}),
		failures:     l.IPFailures.over(Limit{Attempts: 30, Window: 15 * time.Minute, Pause: 15 * time.Minute}),
		codeAttempts: cmp.Or(l.CodeAttempts, defaultCodeAttempts),
	}, nil
}

// WithRecoveryLimits sets the limits on the requests and on the guesses of
// links and codes, see RecoveryLimits. New fails for a value that is negative or
// out of range.
func WithRecoveryLimits(l RecoveryLimits) Option {
	return func(c *config) {
		c.recovery = l
	}
}

type channelLabel struct {
	kind  string
	value string
}

func (a *Auth) requestKeys(purpose store.SecretPurpose, labels []channelLabel, ip netip.Addr) (channels []string, address string) {
	for _, l := range labels {
		channels = append(channels, a.keys.AttemptKey("recovery-channel", a.tenant, string(purpose), l.kind, l.value))
	}
	if ip.IsValid() {
		address = a.keys.AttemptKey("recovery-ip", a.tenant, string(purpose), limitedAddress(ip))
	}
	return channels, address
}

func (a *Auth) failureKey(purpose store.SecretPurpose, ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	return a.keys.AttemptKey("recovery-fail", a.tenant, string(purpose), limitedAddress(ip))
}

func (a *Auth) admitRequest(ctx context.Context, purpose store.SecretPurpose, login string, ip netip.Addr) error {
	kind, value := a.accountLabel(login)
	return a.admitLabels(ctx, purpose, []channelLabel{{kind: kind, value: value}}, ip)
}

func (a *Auth) admitLabels(ctx context.Context, purpose store.SecretPurpose, labels []channelLabel, ip netip.Addr) error {
	release, err := a.acquireSlot(ctx)
	if err != nil {
		return err
	}
	defer release()
	channelKeys, addressKey := a.requestKeys(purpose, labels, ip)
	if err = a.checkKeys(ctx, append(slices.Clone(channelKeys), addressKey)...); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	now := a.now()
	for _, channelKey := range channelKeys {
		a.countAttempt(ctx, channelKey, now, a.recovery.channel.Window, func(c store.Attempt) store.Hold {
			if c.Count >= a.recovery.channel.Attempts {
				return store.Hold{BlockedUntil: c.WindowStart.Add(a.recovery.channel.Window)}
			}
			return store.Hold{}
		})
	}
	if addressKey != "" {
		a.countAttempt(ctx, addressKey, now, a.recovery.ip.Window, func(c store.Attempt) store.Hold {
			if c.Count >= a.recovery.ip.Attempts {
				return store.Hold{BlockedUntil: now.Add(a.recovery.ip.Pause)}
			}
			return store.Hold{}
		})
	}
	return nil
}

func (a *Auth) guardConfirmation(ctx context.Context, purpose store.SecretPurpose, ip netip.Addr, confirm func() error) error {
	release, err := a.acquireSlot(ctx)
	if err != nil {
		return err
	}
	defer release()
	key := a.failureKey(purpose, ip)
	if err = a.checkKeys(ctx, key); err != nil {
		return err
	}
	err = confirm()
	if key != "" && errors.Is(err, ErrInvalidSecret) {
		recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
		defer cancel()
		now := a.now()
		a.countAttempt(recordCtx, key, now, a.recovery.failures.Window, func(c store.Attempt) store.Hold {
			if c.Count >= a.recovery.failures.Attempts {
				return store.Hold{BlockedUntil: now.Add(a.recovery.failures.Pause)}
			}
			return store.Hold{}
		})
	}
	return err
}

func (a *Auth) countAttempt(ctx context.Context, key string, now time.Time, window time.Duration, hold func(store.Attempt) store.Hold) {
	counter, err := a.store.Attempts().Hit(ctx, key, now, window)
	if err != nil {
		a.logger.ErrorContext(ctx, "limb: a request of recovery cannot be counted", "error", err)
		return
	}
	h := hold(counter)
	if h == (store.Hold{}) {
		return
	}
	if err = a.store.Attempts().Hold(ctx, key, h); err != nil && !errors.Is(err, store.ErrNotFound) {
		a.logger.ErrorContext(ctx, "limb: a pause of recovery cannot be recorded", "error", err)
	}
}
