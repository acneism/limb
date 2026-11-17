package limb

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/internal/memstore"
	"github.com/acneism/limb/store"
)

var (
	ipOne = netip.MustParseAddr("203.0.113.7")
	ipTwo = netip.MustParseAddr("203.0.113.8")
)

func TestRecoveryLimitsHaveSafeDefaults(t *testing.T) {
	got, err := RecoveryLimits{}.resolve()
	if err != nil {
		t.Fatal(err)
	}
	want := recoveryLimits{
		channel:      Limit{Attempts: 3, Window: time.Hour},
		ip:           Limit{Attempts: 20, Window: time.Hour, Pause: 15 * time.Minute},
		failures:     Limit{Attempts: 30, Window: 15 * time.Minute, Pause: 15 * time.Minute},
		codeAttempts: 5,
	}
	if got != want {
		t.Fatalf("defaults = %+v, want %+v", got, want)
	}
	custom, err := RecoveryLimits{
		ChannelRequests: Limit{Attempts: 10},
		IPRequests:      Limit{Window: time.Minute, Pause: time.Second},
		IPFailures:      Limit{Attempts: 2},
		CodeAttempts:    3,
	}.resolve()
	if err != nil {
		t.Fatal(err)
	}
	want = recoveryLimits{
		channel:      Limit{Attempts: 10, Window: time.Hour},
		ip:           Limit{Attempts: 20, Window: time.Minute, Pause: time.Second},
		failures:     Limit{Attempts: 2, Window: 15 * time.Minute, Pause: 15 * time.Minute},
		codeAttempts: 3,
	}
	if custom != want {
		t.Fatalf("custom = %+v, want %+v", custom, want)
	}
}

func TestNewRejectsBadRecoveryLimits(t *testing.T) {
	for name, limits := range map[string]RecoveryLimits{
		"a negative number of requests": {ChannelRequests: Limit{Attempts: -1}},
		"a negative window":             {IPRequests: Limit{Window: -time.Second}},
		"a negative pause":              {IPFailures: Limit{Pause: -time.Second}},
		"negative attempts at a code":   {CodeAttempts: -1},
		"too many attempts at a code":   {CodeAttempts: 21},
	} {
		if _, err := NewWithStore(memstore.New(), []byte(testKey), WithAutoMigrate(), WithRecoveryLimits(limits)); err == nil {
			t.Errorf("%s: New accepted the limits", name)
		}
	}
	if _, err := NewWithStore(memstore.New(), []byte(testKey), WithAutoMigrate(), WithRecoveryLimits(RecoveryLimits{CodeAttempts: 20})); err != nil {
		t.Errorf("twenty attempts at a code are allowed: %v", err)
	}
}

func TestRequestsForOneLoginAreRefusedUntilTheWindowEnds(t *testing.T) {
	a, clock := newLimitedAuth(t)
	ctx := t.Context()
	for i := range 3 {
		if err := a.admitRequest(ctx, store.PurposeReset, "alice@example.com", ipOne); err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		clock.advance(time.Minute)
	}
	clock.advance(7 * time.Minute)
	got := asRateLimit(t, a.admitRequest(ctx, store.PurposeReset, "alice@example.com", ipOne))
	if want := 50 * time.Minute; got != want {
		t.Fatalf("RetryAfter = %v, want %v: the pause ends with the window that the first request opened", got, want)
	}
	clock.advance(49*time.Minute + 59*time.Second)
	if err := a.admitRequest(ctx, store.PurposeReset, "alice@example.com", ipOne); err == nil {
		t.Fatal("a request a second before the window ends was accepted")
	}
	clock.advance(2 * time.Second)
	if err := a.admitRequest(ctx, store.PurposeReset, "alice@example.com", ipOne); err != nil {
		t.Fatalf("a request after the window: %v", err)
	}
}

func TestTheLimitDoesNotTellWhetherTheAccountExists(t *testing.T) {
	a, clock := newLimitedAuth(t, emailAndUsername())
	mustRegister(t, a, map[string]string{"email": "alice@example.com"}, goodPassword)
	var retry [2]time.Duration
	for i, login := range []string{"alice@example.com", "nobody@example.com"} {
		for range 3 {
			if err := a.admitRequest(t.Context(), store.PurposeVerify, login, ipOne); err != nil {
				t.Fatalf("%s: %v", login, err)
			}
		}
		clock.advance(5 * time.Minute)
		retry[i] = asRateLimit(t, a.admitRequest(t.Context(), store.PurposeVerify, login, ipOne))
		clock.advance(-5 * time.Minute)
	}
	if retry[0] != retry[1] || retry[0] != 55*time.Minute {
		t.Fatalf("the pauses for a known and an unknown login are %v and %v, want the same 55 minutes", retry[0], retry[1])
	}
}

func TestEachLoginAndEachPurposeHasACounterOfItsOwn(t *testing.T) {
	a, _ := newLimitedAuth(t)
	ctx := t.Context()
	for range 3 {
		if err := a.admitRequest(ctx, store.PurposeReset, "alice@example.com", ipOne); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.admitRequest(ctx, store.PurposeReset, "alice@example.com", ipOne); err == nil {
		t.Fatal("the fourth request was accepted")
	}
	if err := a.admitRequest(ctx, store.PurposeVerify, "alice@example.com", ipOne); err != nil {
		t.Fatalf("requests of confirmation must not be locked by those of a reset: %v", err)
	}
	if err := a.admitRequest(ctx, store.PurposeReset, "bob@example.com", ipOne); err != nil {
		t.Fatalf("another login has its own counter: %v", err)
	}
	if err := a.admitRequest(ctx, store.PurposeReset, "  ALICE@example.com ", ipOne); err == nil {
		t.Fatal("the same login in another spelling has a counter of its own")
	}
}

func TestRequestsFromOneAddressAreLimitedWhateverTheLogins(t *testing.T) {
	a, clock := newLimitedAuth(t)
	ctx := t.Context()
	for i := range 20 {
		if err := a.admitRequest(ctx, store.PurposeReset, fmt.Sprintf("user%d@example.com", i), ipOne); err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
	}
	if got := asRateLimit(t, a.admitRequest(ctx, store.PurposeReset, "another@example.com", ipOne)); got != 15*time.Minute {
		t.Fatalf("RetryAfter = %v, want the pause of 15 minutes", got)
	}
	if err := a.admitRequest(ctx, store.PurposeReset, "another@example.com", ipTwo); err != nil {
		t.Fatalf("another address has its own counter: %v", err)
	}
	if err := a.admitRequest(ctx, store.PurposeVerify, "another@example.com", ipOne); err != nil {
		t.Fatalf("the other purpose has its own counter: %v", err)
	}
	clock.advance(15*time.Minute + time.Second)
	if err := a.admitRequest(ctx, store.PurposeReset, "third@example.com", ipOne); err != nil {
		t.Fatalf("the pause is over: %v", err)
	}
}

func TestAnIPv6NetworkIsCountedAsOneAddress(t *testing.T) {
	a, _ := newLimitedAuth(t, WithRecoveryLimits(RecoveryLimits{IPRequests: Limit{Attempts: 2}}))
	ctx := t.Context()
	for _, ip := range []string{"2001:db8:1:2::1", "2001:db8:1:2:ffff::9"} {
		if err := a.admitRequest(ctx, store.PurposeReset, ip, netip.MustParseAddr(ip)); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.admitRequest(ctx, store.PurposeReset, "x@example.com", netip.MustParseAddr("2001:db8:1:2:1234::5")); err == nil {
		t.Fatal("a third address of the same /64 network was accepted")
	}
	if err := a.admitRequest(ctx, store.PurposeReset, "x@example.com", netip.MustParseAddr("2001:db8:1:3::1")); err != nil {
		t.Fatalf("another /64 network has its own counter: %v", err)
	}
}

func TestWithoutAnAddressOnlyTheLoginIsCounted(t *testing.T) {
	a, _ := newLimitedAuth(t, WithRecoveryLimits(RecoveryLimits{IPRequests: Limit{Attempts: 1}}))
	for i := range 3 {
		if err := a.admitRequest(t.Context(), store.PurposeReset, fmt.Sprintf("user%d@example.com", i), netip.Addr{}); err != nil {
			t.Fatalf("request %d without an address: %v", i+1, err)
		}
	}
	for range 3 {
		_ = a.admitRequest(t.Context(), store.PurposeReset, "same@example.com", netip.Addr{})
	}
	if err := a.admitRequest(t.Context(), store.PurposeReset, "same@example.com", netip.Addr{}); err == nil {
		t.Fatal("the login limit does not need an address")
	}
}

func TestWrongSecretsFromOneAddressAreLimited(t *testing.T) {
	a, clock := newLimitedAuth(t, WithRecoveryLimits(RecoveryLimits{IPFailures: Limit{Attempts: 3}}))
	ctx := t.Context()
	wrong := func() error { return ErrInvalidSecret }
	for i := range 3 {
		if err := a.guardConfirmation(ctx, store.PurposeReset, ipOne, wrong); !errors.Is(err, ErrInvalidSecret) {
			t.Fatalf("attempt %d = %v", i+1, err)
		}
	}
	ran := false
	err := a.guardConfirmation(ctx, store.PurposeReset, ipOne, func() error { ran = true; return nil })
	if got := asRateLimit(t, err); got != 15*time.Minute || ran {
		t.Fatalf("a fourth attempt = %v (ran %v), want it refused before it is looked at, for 15 minutes", err, ran)
	}
	if err = a.guardConfirmation(ctx, store.PurposeVerify, ipOne, func() error { return nil }); err != nil {
		t.Fatalf("the other purpose has its own counter: %v", err)
	}
	if err = a.guardConfirmation(ctx, store.PurposeReset, ipTwo, func() error { return nil }); err != nil {
		t.Fatalf("another address has its own counter: %v", err)
	}
	clock.advance(15*time.Minute + time.Second)
	if err = a.guardConfirmation(ctx, store.PurposeReset, ipOne, func() error { return nil }); err != nil {
		t.Fatalf("the pause is over: %v", err)
	}
}

func TestOnlyWrongSecretsCountAsFailures(t *testing.T) {
	a, _ := newLimitedAuth(t, WithRecoveryLimits(RecoveryLimits{IPFailures: Limit{Attempts: 2}}))
	ctx := t.Context()
	boom := errors.New("the database is down")
	for _, result := range []error{nil, boom, ErrRateLimited, nil, boom} {
		if err := a.guardConfirmation(ctx, store.PurposeReset, ipOne, func() error { return result }); !errors.Is(err, result) {
			t.Fatalf("guardConfirmation = %v, want %v", err, result)
		}
	}
	wrapped := fmt.Errorf("wrapped: %w", ErrInvalidSecret)
	for range 2 {
		if err := a.guardConfirmation(ctx, store.PurposeReset, ipOne, func() error { return wrapped }); !errors.Is(err, ErrInvalidSecret) {
			t.Fatal(err)
		}
	}
	if err := a.guardConfirmation(ctx, store.PurposeReset, ipOne, func() error { return nil }); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("two wrong secrets, even wrapped, must lock the address: %v", err)
	}
}

func TestWithoutAnAddressWrongSecretsAreNotCountedByAddress(t *testing.T) {
	a, _ := newLimitedAuth(t, WithRecoveryLimits(RecoveryLimits{IPFailures: Limit{Attempts: 1}}))
	for range 5 {
		if err := a.guardConfirmation(t.Context(), store.PurposeReset, netip.Addr{}, func() error { return ErrInvalidSecret }); !errors.Is(err, ErrInvalidSecret) {
			t.Fatal(err)
		}
	}
}

func TestACounterThatCannotBeWrittenIsLoggedAndDoesNotStopTheRequest(t *testing.T) {
	logger, logs := capturingLogger()
	a, _ := newLimitedAuth(t, WithLogger(logger))
	a.store = brokenAttemptsStore{Store: a.store, attempts: failingAttempts{Attempts: a.store.Attempts(), hitErr: errors.New("the counter is down")}}
	if err := a.admitRequest(t.Context(), store.PurposeReset, "alice@example.com", ipOne); err != nil {
		t.Fatalf("admitRequest = %v, want the request to go on", err)
	}
	if err := a.guardConfirmation(t.Context(), store.PurposeReset, ipOne, func() error { return ErrInvalidSecret }); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("guardConfirmation = %v", err)
	}
	if strings.Count(logs.String(), "cannot be counted") != 3 {
		t.Fatalf("the failures of the counters must be logged:\n%s", logs.String())
	}
}

func TestACounterThatCannotBeReadStopsTheRequest(t *testing.T) {
	a, _ := newLimitedAuth(t)
	boom := errors.New("the database is down")
	a.store = brokenAttemptsStore{Store: a.store, attempts: failingAttempts{Attempts: a.store.Attempts(), getErr: boom}}
	if err := a.admitRequest(t.Context(), store.PurposeReset, "alice@example.com", ipOne); !errors.Is(err, boom) {
		t.Fatalf("admitRequest = %v, want the failure of the counters", err)
	}
	ran := false
	if err := a.guardConfirmation(t.Context(), store.PurposeReset, ipOne, func() error { ran = true; return nil }); !errors.Is(err, boom) || ran {
		t.Fatalf("guardConfirmation = %v (ran %v), want the failure of the counters before the secret is looked at", err, ran)
	}
}

func TestAPauseThatCannotBeRecordedIsLogged(t *testing.T) {
	logger, logs := capturingLogger()
	a, _ := newLimitedAuth(t, WithLogger(logger), WithRecoveryLimits(RecoveryLimits{ChannelRequests: Limit{Attempts: 1}, IPRequests: Limit{Attempts: 1}}))
	a.store = brokenAttemptsStore{Store: a.store, attempts: failingAttempts{Attempts: a.store.Attempts(), holdErr: errors.New("the pause is down")}}
	if err := a.admitRequest(t.Context(), store.PurposeReset, "alice@example.com", ipOne); err != nil {
		t.Fatal(err)
	}
	if strings.Count(logs.String(), "cannot be recorded") != 2 {
		t.Fatalf("the failures of the pauses must be logged:\n%s", logs.String())
	}
}

func TestACanceledRequestDoesNotWaitForASlot(t *testing.T) {
	a, _ := newLimitedAuth(t)
	for range cap(a.slots) {
		a.slots <- struct{}{}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := a.admitRequest(ctx, store.PurposeReset, "alice@example.com", ipOne); !errors.Is(err, context.Canceled) {
		t.Fatalf("admitRequest = %v, want the cancel", err)
	}
	if err := a.guardConfirmation(ctx, store.PurposeReset, ipOne, func() error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("guardConfirmation = %v, want the cancel", err)
	}
}

func TestThePauseAfterWrongSecretsIsNotTheWindow(t *testing.T) {
	a, _ := newLimitedAuth(t, WithRecoveryLimits(RecoveryLimits{IPFailures: Limit{Attempts: 2, Window: time.Hour, Pause: 10 * time.Minute}}))
	for range 2 {
		if err := a.guardConfirmation(t.Context(), store.PurposeVerify, ipOne, func() error { return ErrInvalidSecret }); !errors.Is(err, ErrInvalidSecret) {
			t.Fatal(err)
		}
	}
	err := a.guardConfirmation(t.Context(), store.PurposeVerify, ipOne, func() error { return nil })
	if got := asRateLimit(t, err); got != 10*time.Minute {
		t.Fatalf("RetryAfter = %v, want the pause of 10 minutes and not the window of an hour", got)
	}
}

func TestRequestsAndConfirmationsWaitForASlot(t *testing.T) {
	a, _ := newLimitedAuth(t)
	for range cap(a.slots) {
		a.slots <- struct{}{}
	}
	done := make(chan error, 2)
	go func() { done <- a.admitRequest(t.Context(), store.PurposeReset, "alice@example.com", ipOne) }()
	go func() {
		done <- a.guardConfirmation(t.Context(), store.PurposeReset, ipOne, func() error { return nil })
	}()
	select {
	case err := <-done:
		t.Fatalf("an operation went on without a slot: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	for range 2 {
		<-a.slots
	}
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("the operation failed after a slot was free: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the operation did not go on when a slot was free")
		}
	}
}
