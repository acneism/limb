package limb

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/internal/memstore"
	"github.com/acneism/limb/store"
)

type fakeClock struct {
	mu sync.Mutex
	at time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{at: time.Date(2026, 9, 10, 11, 12, 13, 456789000, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

func newLimitedAuth(t *testing.T, opts ...Option) (*Auth, *fakeClock) {
	t.Helper()
	a := newTestAuth(t, opts...)
	clock := newFakeClock()
	a.now = clock.now
	return a, clock
}

func (a *Auth) failedLogin(t *testing.T, login string, ip netip.Addr) error {
	t.Helper()
	keys := a.loginAttemptKeys(login, ip)
	return a.limited(t.Context(), keys, func() error { return ErrInvalidCredentials })
}

func asRateLimit(t *testing.T, err error) time.Duration {
	t.Helper()
	var limit *RateLimitError
	if !errors.As(err, &limit) || !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want a *RateLimitError", err)
	}
	return limit.RetryAfter
}

func TestLoginLimitsHaveSafeDefaults(t *testing.T) {
	got, err := LoginLimits{}.resolve()
	if err != nil {
		t.Fatal(err)
	}
	want := loginLimits{
		accountIP: Limit{Attempts: 5, Window: 15 * time.Minute, Pause: 15 * time.Minute},
		ip:        Limit{Attempts: 100, Window: 15 * time.Minute, Pause: 15 * time.Minute},
		account:   Delay{Attempts: 20, Window: 15 * time.Minute, Max: time.Minute},
	}
	if got != want {
		t.Fatalf("defaults = %+v, want %+v", got, want)
	}
	custom, err := LoginLimits{
		AccountAndIP: Limit{Attempts: 3},
		IP:           Limit{Window: time.Hour, Pause: time.Minute},
		Account:      Delay{Max: 5 * time.Minute},
	}.resolve()
	if err != nil {
		t.Fatal(err)
	}
	if custom.accountIP != (Limit{Attempts: 3, Window: 15 * time.Minute, Pause: 15 * time.Minute}) ||
		custom.ip != (Limit{Attempts: 100, Window: time.Hour, Pause: time.Minute}) ||
		custom.account != (Delay{Attempts: 20, Window: 15 * time.Minute, Max: 5 * time.Minute}) {
		t.Fatalf("a zero field must keep its default and a set one must win: %+v", custom)
	}
	for name, l := range map[string]LoginLimits{
		"attempts":  {AccountAndIP: Limit{Attempts: -1}},
		"window":    {IP: Limit{Window: -time.Second}},
		"pause":     {IP: Limit{Pause: -time.Second}},
		"delay":     {Account: Delay{Attempts: -1}},
		"delay max": {Account: Delay{Max: -time.Second}},
		"delay win": {Account: Delay{Window: -time.Second}},
	} {
		if _, err = NewWithStore(memstore.New(), []byte(testKey), WithLoginLimits(l)); err == nil || !strings.Contains(err.Error(), "negative") {
			t.Errorf("%s: NewWithStore = %v, want an error about a negative value", name, err)
		}
	}
}

func TestAccountAndIPAreLimitedTogether(t *testing.T) {
	a, clock := newLimitedAuth(t)
	ip := netip.MustParseAddr("203.0.113.7")
	for n := 1; n <= 5; n++ {
		if err := a.failedLogin(t, "alice@example.com", ip); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("failure %d: err = %v, want ErrInvalidCredentials", n, err)
		}
	}
	err := a.failedLogin(t, "alice@example.com", ip)
	if got := asRateLimit(t, err); got != 15*time.Minute {
		t.Fatalf("RetryAfter = %v, want the pause of 15 minutes that started with the fifth failure", got)
	}
	clock.advance(10*time.Minute + 500*time.Millisecond)
	if got := asRateLimit(t, a.failedLogin(t, "alice@example.com", ip)); got != 5*time.Minute {
		t.Fatalf("RetryAfter = %v, want 4m59.5s rounded up to 5m0s", got)
	}
	if err = a.failedLogin(t, "alice@example.com", netip.MustParseAddr("203.0.113.8")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("another address must not be affected, got %v", err)
	}
	if err = a.failedLogin(t, "bob@example.com", ip); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("another account from the same address must not be affected by the pair limit, got %v", err)
	}
	clock.advance(5 * time.Minute)
	if err = a.failedLogin(t, "alice@example.com", ip); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("after the pause the account can be tried again, got %v", err)
	}
}

func TestTheFifthFailureOnlyStartsThePause(t *testing.T) {
	a, _ := newLimitedAuth(t)
	ip := netip.MustParseAddr("203.0.113.7")
	attempts := 0
	for range 20 {
		err := a.limited(t.Context(), a.loginAttemptKeys("alice@example.com", ip), func() error {
			attempts++
			return ErrInvalidCredentials
		})
		if errors.Is(err, ErrRateLimited) {
			break
		}
	}
	if attempts != 5 {
		t.Fatalf("%d attempts were evaluated, want exactly 5 before the pause", attempts)
	}
}

func TestRateLimitedAttemptsAreNotEvaluatedOrCounted(t *testing.T) {
	a, clock := newLimitedAuth(t)
	ip := netip.MustParseAddr("203.0.113.7")
	for range 5 {
		_ = a.failedLogin(t, "alice@example.com", ip)
	}
	evaluated := false
	for range 50 {
		err := a.limited(t.Context(), a.loginAttemptKeys("alice@example.com", ip), func() error {
			evaluated = true
			return ErrInvalidCredentials
		})
		asRateLimit(t, err)
	}
	if evaluated {
		t.Fatal("an attempt that is turned down must not reach the password check")
	}
	clock.advance(15*time.Minute + time.Second)
	if err := a.failedLogin(t, "alice@example.com", ip); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("turned down attempts must not extend the pause, got %v", err)
	}
}

func TestIPLimit(t *testing.T) {
	a, clock := newLimitedAuth(t)
	ip := netip.MustParseAddr("203.0.113.7")
	for n := range 100 {
		login := "user" + strings.Repeat("x", n) + "@example.com"
		if err := a.failedLogin(t, login, ip); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("failure %d: err = %v, want ErrInvalidCredentials", n+1, err)
		}
	}
	if got := asRateLimit(t, a.failedLogin(t, "fresh@example.com", ip)); got != 15*time.Minute {
		t.Fatalf("RetryAfter = %v, want 15m0s", got)
	}
	if err := a.failedLogin(t, "fresh@example.com", netip.MustParseAddr("203.0.113.9")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("another address must not be affected, got %v", err)
	}
	clock.advance(15*time.Minute + time.Second)
	if err := a.failedLogin(t, "fresh@example.com", ip); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("after the pause the address can be used again, got %v", err)
	}
}

func TestIPv6AddressesAreCountedByTheirNetwork(t *testing.T) {
	a, _ := newLimitedAuth(t, WithLoginLimits(LoginLimits{IP: Limit{Attempts: 3}}))
	for n, ip := range []string{"2001:db8:1:2::1", "2001:db8:1:2::ffff", "2001:db8:1:2:aaaa:bbbb:cccc:dddd"} {
		if err := a.failedLogin(t, "user"+strings.Repeat("x", n)+"@example.com", netip.MustParseAddr(ip)); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("failure %d: %v", n+1, err)
		}
	}
	asRateLimit(t, a.failedLogin(t, "other@example.com", netip.MustParseAddr("2001:db8:1:2:1111::7")))
	if err := a.failedLogin(t, "other@example.com", netip.MustParseAddr("2001:db8:1:3::1")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("another /64 network must not be affected, got %v", err)
	}
	if limitedAddress(netip.MustParseAddr("::ffff:203.0.113.7")) != "203.0.113.7" {
		t.Fatal("an IPv4-mapped address is an IPv4 address")
	}
}

func TestAccountDelayGrowsAndNeverBlocks(t *testing.T) {
	a, clock := newLimitedAuth(t)
	login := "alice@example.com"
	for n := 1; n < 20; n++ {
		ip := netip.AddrFrom4([4]byte{198, 51, 100, byte(n)})
		if err := a.failedLogin(t, login, ip); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("failure %d: err = %v, want ErrInvalidCredentials", n, err)
		}
	}
	wants := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second,
		time.Minute, time.Minute, time.Minute}
	for i, want := range wants {
		ip := netip.AddrFrom4([4]byte{198, 51, 100, byte(100 + i)})
		if err := a.failedLogin(t, login, ip); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("failure %d: err = %v, want ErrInvalidCredentials", 20+i, err)
		}
		if got := asRateLimit(t, a.failedLogin(t, login, ip)); got != want {
			t.Fatalf("after failure %d RetryAfter = %v, want %v", 20+i, got, want)
		}
		clock.advance(want)
	}
	if err := a.failedLogin(t, "bob@example.com", netip.MustParseAddr("198.51.100.200")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("the delay of one account must not touch another: %v", err)
	}
	clock.advance(15 * time.Minute)
	if err := a.failedLogin(t, login, netip.MustParseAddr("198.51.100.201")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("a new window starts without a delay, got %v", err)
	}
	if err := a.failedLogin(t, login, netip.MustParseAddr("198.51.100.202")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("a new window starts without a delay, got %v", err)
	}
}

func TestDelayedAttemptsDoNotExtendTheDelay(t *testing.T) {
	a, clock := newLimitedAuth(t, WithLoginLimits(LoginLimits{Account: Delay{Attempts: 2}}))
	login := "alice@example.com"
	ip := netip.MustParseAddr("198.51.100.1")
	for range 2 {
		_ = a.failedLogin(t, login, ip)
	}
	first := asRateLimit(t, a.failedLogin(t, login, ip))
	for range 100 {
		asRateLimit(t, a.failedLogin(t, login, ip))
	}
	clock.advance(first)
	if err := a.failedLogin(t, login, ip); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("someone who keeps sending attempts must not keep the owner out: %v", err)
	}
}

func TestLimitsWithoutAnAddress(t *testing.T) {
	a, _ := newLimitedAuth(t)
	keys := a.loginAttemptKeys("alice@example.com", netip.Addr{})
	if keys.ip != "" || keys.accountIP != "" || keys.account == "" {
		t.Fatalf("without an address only the account is limited: %+v", keys)
	}
	for range 30 {
		if err := a.limited(t.Context(), keys, func() error { return ErrInvalidCredentials }); errors.Is(err, ErrRateLimited) {
			return
		}
	}
	t.Fatal("the limit on the account must apply without an address")
}

func TestSuccessAndOtherErrorsDoNotCount(t *testing.T) {
	a, _ := newLimitedAuth(t)
	ip := netip.MustParseAddr("203.0.113.7")
	keys := a.loginAttemptKeys("alice@example.com", ip)
	other := errors.New("database is down")
	for _, result := range []error{nil, ErrUserBlocked, other, context.Canceled} {
		for range 10 {
			err := a.limited(t.Context(), keys, func() error { return result })
			if (result == nil && err != nil) || (result != nil && !errors.Is(err, result)) {
				t.Fatalf("limited returned %v, want %v", err, result)
			}
		}
	}
	for _, key := range []string{keys.accountIP, keys.ip, keys.account} {
		if counters, err := a.store.Attempts().Get(t.Context(), key); err != nil || len(counters) != 0 {
			t.Fatalf("an attempt that did not fail with ErrInvalidCredentials was counted: %v, %v", counters, err)
		}
	}
}

func TestClearFailures(t *testing.T) {
	a, _ := newLimitedAuth(t)
	ip := netip.MustParseAddr("203.0.113.7")
	keys := a.loginAttemptKeys("alice@example.com", ip)
	for range 4 {
		_ = a.limited(t.Context(), keys, func() error { return ErrInvalidCredentials })
	}
	a.clearFailures(t.Context(), keys.accountIP)
	a.clearFailures(t.Context(), "")
	if counters, err := a.store.Attempts().Get(t.Context(), keys.accountIP); err != nil || len(counters) != 0 {
		t.Fatalf("the pair counter must be gone: %v, %v", counters, err)
	}
	if counters, err := a.store.Attempts().Get(t.Context(), keys.ip, keys.account); err != nil || len(counters) != 2 {
		t.Fatalf("the other counters must stay: %v, %v", counters, err)
	}
}

func TestAttemptKeysDoNotRevealOrMixAccounts(t *testing.T) {
	a, _ := newLimitedAuth(t, emailAndUsername())
	ip := netip.MustParseAddr("203.0.113.7")
	same := []string{"Alice@Example.COM", " alice@example.com ", "alice@EXAMPLE.com"}
	first := a.loginAttemptKeys(same[0], ip)
	for _, login := range same[1:] {
		if got := a.loginAttemptKeys(login, ip); got != first {
			t.Fatalf("%q and %q are the same account and must share their counters", same[0], login)
		}
	}
	different := []string{"bob@example.com", "alice", "alice2@example.com", "not a login at all!", ""}
	seen := map[string]string{first.account: same[0]}
	for _, login := range different {
		keys := a.loginAttemptKeys(login, ip)
		if other, taken := seen[keys.account]; taken {
			t.Fatalf("%q shares the account counter with %q", login, other)
		}
		seen[keys.account] = login
	}
	if a.loginAttemptKeys("alice@example.com", netip.MustParseAddr("203.0.113.8")).ip == first.ip {
		t.Fatal("different addresses must have different counters")
	}
	if a.loginAttemptKeys("alice@example.com", netip.MustParseAddr("203.0.113.8")).accountIP == first.accountIP {
		t.Fatal("the pair counter must depend on the address")
	}
	for _, key := range []string{first.accountIP, first.ip, first.account} {
		if strings.Contains(key, "alice") || strings.Contains(key, "203.0.113") {
			t.Fatalf("a counter key must not contain the login or the address: %s", key)
		}
	}
	if first.accountIP == first.ip || first.ip == first.account || first.accountIP == first.account {
		t.Fatalf("the three counters must have different keys: %+v", first)
	}
}

func TestAttemptKeysDifferByTenantAndByUser(t *testing.T) {
	a, _ := newLimitedAuth(t)
	b, _ := newLimitedAuth(t)
	b.tenant = otherTenant
	ip := netip.MustParseAddr("203.0.113.7")
	one, two := a.loginAttemptKeys("alice@example.com", ip), b.loginAttemptKeys("alice@example.com", ip)
	if one.account == two.account || one.ip == two.ip || one.accountIP == two.accountIP {
		t.Fatal("tenants must not share counters")
	}
	if a.userAttemptKeys("u1").account == a.userAttemptKeys("u2").account || a.userAttemptKeys("u1").account == one.account {
		t.Fatal("a user counter must be its own")
	}
	if keys := a.userAttemptKeys("u1"); keys.accountIP != "" || keys.ip != "" {
		t.Fatalf("a user counter has no address part: %+v", keys)
	}
}

func TestRawLoginKey(t *testing.T) {
	long := strings.Repeat("é", 200)
	cases := map[string]string{
		"  Mixed Case  ":           "mixed case",
		"\uff26\uff35\uff2c\uff2c": "full",
		"bad\xffbytes":             "bad\ufffdbytes",
		"":                         "",
	}
	for in, want := range cases {
		if got := rawLoginKey(in); got != want {
			t.Errorf("rawLoginKey(%q) = %q, want %q", in, got, want)
		}
	}
	got := rawLoginKey(long)
	if len(got) > maxRawLoginKey || !strings.HasPrefix(long, got) || len(got) < maxRawLoginKey-1 {
		t.Fatalf("a long login must be cut at a character boundary below %d bytes, got %d bytes", maxRawLoginKey, len(got))
	}
}

func TestWholeSeconds(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{
		0: time.Second, time.Nanosecond: time.Second, time.Second: time.Second, time.Second + 1: 2 * time.Second,
		59*time.Second + 999*time.Millisecond: time.Minute, time.Minute: time.Minute, -time.Hour: time.Second,
	} {
		if got := wholeSeconds(in); got != want {
			t.Errorf("wholeSeconds(%v) = %v, want %v", in, got, want)
		}
	}
}

type failingAttempts struct {
	store.Attempts
	getErr, hitErr, holdErr, resetErr error
}

func (f failingAttempts) Get(ctx context.Context, keys ...string) ([]store.Attempt, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.Attempts.Get(ctx, keys...)
}

func (f failingAttempts) Hit(ctx context.Context, key string, at time.Time, window time.Duration) (store.Attempt, error) {
	if f.hitErr != nil {
		return store.Attempt{}, f.hitErr
	}
	return f.Attempts.Hit(ctx, key, at, window)
}

func (f failingAttempts) Hold(ctx context.Context, key string, h store.Hold) error {
	if f.holdErr != nil {
		return f.holdErr
	}
	return f.Attempts.Hold(ctx, key, h)
}

func (f failingAttempts) Reset(ctx context.Context, key string) error {
	if f.resetErr != nil {
		return f.resetErr
	}
	return f.Attempts.Reset(ctx, key)
}

type brokenAttemptsStore struct {
	store.Store
	attempts failingAttempts
}

func (s brokenAttemptsStore) Attempts() store.Attempts { return s.attempts }

func TestLimitsFailClosedWhenTheCountersCannotBeRead(t *testing.T) {
	a, _ := newLimitedAuth(t)
	boom := errors.New("database is down")
	a.store = brokenAttemptsStore{Store: a.store, attempts: failingAttempts{Attempts: a.store.Attempts(), getErr: boom}}
	evaluated := false
	err := a.limited(t.Context(), a.loginAttemptKeys("alice@example.com", netip.MustParseAddr("203.0.113.7")), func() error {
		evaluated = true
		return nil
	})
	if !errors.Is(err, boom) || evaluated {
		t.Fatalf("limited = %v, evaluated = %v; want the store error and no password check", err, evaluated)
	}
}

func TestFailuresAreAnsweredEvenWhenTheyCannotBeRecorded(t *testing.T) {
	boom := errors.New("database is down")
	cases := map[string]struct {
		damage func(*failingAttempts)
		logged string
	}{
		"hit":  {func(f *failingAttempts) { f.hitErr = boom }, "cannot be counted"},
		"hold": {func(f *failingAttempts) { f.holdErr = boom }, "cannot be recorded"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			logger, logs := capturingLogger()
			a, _ := newLimitedAuth(t, WithLogger(logger))
			broken := failingAttempts{Attempts: a.store.Attempts()}
			tc.damage(&broken)
			a.store = brokenAttemptsStore{Store: a.store, attempts: broken}
			keys := a.loginAttemptKeys("alice@example.com", netip.MustParseAddr("203.0.113.7"))
			for range 6 {
				if err := a.limited(t.Context(), keys, func() error { return ErrInvalidCredentials }); !errors.Is(err, ErrInvalidCredentials) {
					t.Fatalf("err = %v, want ErrInvalidCredentials", err)
				}
			}
			if text := logs.String(); !strings.Contains(text, tc.logged) || !strings.Contains(text, "database is down") {
				t.Fatalf("the problem must be logged:\n%s", text)
			}
		})
	}
}

func TestAFailureIsCountedEvenIfTheClientLeaves(t *testing.T) {
	a, _ := newLimitedAuth(t)
	keys := a.loginAttemptKeys("alice@example.com", netip.MustParseAddr("203.0.113.7"))
	ctx, leave := context.WithCancel(t.Context())
	err := a.limited(ctx, keys, func() error {
		leave()
		return ErrInvalidCredentials
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("limited = %v, want ErrInvalidCredentials", err)
	}
	counters, err := a.store.Attempts().Get(t.Context(), keys.accountIP, keys.ip, keys.account)
	if err != nil || len(counters) != 3 {
		t.Fatalf("Get = %v, %v; a failure of a client that left must still be counted on all three counters", counters, err)
	}
}

func TestClearingWorksEvenIfTheClientLeaves(t *testing.T) {
	a, _ := newLimitedAuth(t)
	keys := a.loginAttemptKeys("alice@example.com", netip.MustParseAddr("203.0.113.7"))
	_ = a.limited(t.Context(), keys, func() error { return ErrInvalidCredentials })
	ctx, leave := context.WithCancel(t.Context())
	leave()
	a.clearFailures(ctx, keys.accountIP)
	if counters, err := a.store.Attempts().Get(t.Context(), keys.accountIP); err != nil || len(counters) != 0 {
		t.Fatalf("the counter must be cleared whatever the client does: %v, %v", counters, err)
	}
}

func TestAFailedResetIsLogged(t *testing.T) {
	logger, logs := capturingLogger()
	a, _ := newLimitedAuth(t, WithLogger(logger))
	a.store = brokenAttemptsStore{Store: a.store, attempts: failingAttempts{Attempts: a.store.Attempts(), resetErr: errors.New("database is down")}}
	a.clearFailures(t.Context(), "key")
	if text := logs.String(); !strings.Contains(text, "cannot be cleared") || !strings.Contains(text, "database is down") {
		t.Fatalf("a failed reset must be logged:\n%s", text)
	}
}

func TestOnlyAsManyAttemptsAsSlotsRunAtOnce(t *testing.T) {
	a, _ := newLimitedAuth(t)
	a.slots = make(chan struct{}, 3)
	keys := a.userAttemptKeys("u1")
	var running, highest atomic.Int32
	release := make(chan struct{})
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			_ = a.limited(t.Context(), keys, func() error {
				now := running.Add(1)
				for {
					seen := highest.Load()
					if now <= seen || highest.CompareAndSwap(seen, now) {
						break
					}
				}
				<-release
				running.Add(-1)
				return nil
			})
		})
	}
	deadline := time.After(5 * time.Second)
	for running.Load() < 3 {
		select {
		case <-deadline:
			t.Fatalf("only %d attempts started", running.Load())
		case <-time.After(time.Millisecond):
		}
	}
	time.Sleep(50 * time.Millisecond)
	if got := running.Load(); got != 3 {
		t.Fatalf("%d attempts run at once, want exactly the 3 slots", got)
	}
	close(release)
	wg.Wait()
	if highest.Load() != 3 {
		t.Fatalf("at most %d attempts ran at once, want 3", highest.Load())
	}
}

func TestWaitingForASlotEndsWithTheContext(t *testing.T) {
	a, _ := newLimitedAuth(t)
	a.slots = make(chan struct{}, 1)
	a.slots <- struct{}{}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	called := false
	err := a.limited(ctx, a.userAttemptKeys("u1"), func() error { called = true; return nil })
	if !errors.Is(err, context.DeadlineExceeded) || called {
		t.Fatalf("limited = %v, called = %v; want the deadline and no attempt", err, called)
	}
}

func TestAParallelBurstCannotGetAroundTheLimit(t *testing.T) {
	a, _ := newLimitedAuth(t)
	a.slots = make(chan struct{}, 2)
	keys := a.loginAttemptKeys("alice@example.com", netip.MustParseAddr("203.0.113.7"))
	var evaluated atomic.Int32
	var wg sync.WaitGroup
	for range 60 {
		wg.Go(func() {
			_ = a.limited(t.Context(), keys, func() error {
				evaluated.Add(1)
				time.Sleep(time.Millisecond)
				return ErrInvalidCredentials
			})
		})
	}
	wg.Wait()
	if got := evaluated.Load(); got < 5 || got > 6 {
		t.Fatalf("%d of 60 parallel attempts were evaluated, want 5, or 6 when the second slot was already running as the limit was reached", got)
	}
}
