package storetest

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

const attemptWindow = 15 * time.Minute

var attemptBase = time.Date(2026, 7, 8, 9, 10, 11, 123456789, time.UTC)

func attemptKey(n int) string {
	return strings.Repeat("k", 20) + id(n)
}

func mustHit(t *testing.T, s store.Store, key string, at time.Time, window time.Duration) store.Attempt {
	t.Helper()
	counter, err := s.Attempts().Hit(t.Context(), key, at, window)
	if err != nil {
		t.Fatalf("Hit(%s) failed: %v", key, err)
	}
	return counter
}

func mustGetOne(t *testing.T, s store.Store, key string) store.Attempt {
	t.Helper()
	list, err := s.Attempts().Get(t.Context(), key)
	if err != nil || len(list) != 1 {
		t.Fatalf("Get(%s) = %v, %v; want one counter", key, list, err)
	}
	return list[0]
}

func testAttemptsCountInAWindow(t *testing.T, s store.Store) {
	key := attemptKey(1)
	for n := 1; n <= 3; n++ {
		at := attemptBase.Add(time.Duration(n-1) * time.Second)
		counter := mustHit(t, s, key, at, attemptWindow)
		if counter.Key != key || counter.Count != n || !sameTime(counter.WindowStart, attemptBase) ||
			!counter.BlockedUntil.IsZero() || !counter.NextAllowedAt.IsZero() {
			t.Fatalf("hit %d = %+v, want count %d in the window that began at %v with no holds", n, counter, n, attemptBase)
		}
	}
	got := mustGetOne(t, s, key)
	if got.Count != 3 || !sameTime(got.WindowStart, attemptBase) || got.WindowStart.Location() != time.UTC ||
		got.WindowStart.Nanosecond() != 123456000 {
		t.Fatalf("Get = %+v, want 3 hits in a window that began at %v in UTC with microseconds", got, attemptBase)
	}
	local := time.FixedZone("UTC+5", 5*3600)
	if counter := mustHit(t, s, key, attemptBase.In(local).Add(time.Minute), attemptWindow); counter.Count != 4 {
		t.Fatalf("a time in another zone must count the same, got %+v", counter)
	}
}

func testAttemptsWindowEnds(t *testing.T, s store.Store) {
	key := attemptKey(1)
	window := 10 * time.Second
	if counter := mustHit(t, s, key, attemptBase, window); counter.Count != 1 {
		t.Fatalf("first hit = %+v", counter)
	}
	if counter := mustHit(t, s, key, attemptBase.Add(window-time.Microsecond), window); counter.Count != 2 || !sameTime(counter.WindowStart, attemptBase) {
		t.Fatalf("a hit just before the window ends must join it: %+v", counter)
	}
	edge := attemptBase.Add(window)
	counter := mustHit(t, s, key, edge, window)
	if counter.Count != 1 || !sameTime(counter.WindowStart, edge) {
		t.Fatalf("a hit when the window ends must open a new one: %+v", counter)
	}
	if counter = mustHit(t, s, key, edge.Add(time.Second), window); counter.Count != 2 || !sameTime(counter.WindowStart, edge) {
		t.Fatalf("the new window must keep counting: %+v", counter)
	}
	if counter = mustHit(t, s, key, edge.Add(time.Hour), time.Minute); counter.Count != 1 || !sameTime(counter.WindowStart, edge.Add(time.Hour)) {
		t.Fatalf("a long pause must open a new window: %+v", counter)
	}
	if counter = mustHit(t, s, key, edge, 2*time.Hour); counter.Count != 2 {
		t.Fatalf("an earlier time with a long window joins the current one: %+v", counter)
	}
}

func testAttemptsKeepHoldsAcrossWindows(t *testing.T, s store.Store) {
	ctx := t.Context()
	key := attemptKey(1)
	window := 10 * time.Second
	mustHit(t, s, key, attemptBase, window)
	blocked, next := attemptBase.Add(time.Hour), attemptBase.Add(30*time.Minute)
	if err := s.Attempts().Hold(ctx, key, store.Hold{BlockedUntil: blocked, NextAllowedAt: next}); err != nil {
		t.Fatal(err)
	}
	counter := mustHit(t, s, key, attemptBase.Add(time.Minute), window)
	if counter.Count != 1 || !sameTime(counter.BlockedUntil, blocked) || !sameTime(counter.NextAllowedAt, next) {
		t.Fatalf("a new window must keep the holds: %+v", counter)
	}
	counter = mustHit(t, s, key, attemptBase.Add(time.Minute+time.Second), window)
	if counter.Count != 2 || !sameTime(counter.BlockedUntil, blocked) || !sameTime(counter.NextAllowedAt, next) {
		t.Fatalf("counting must keep the holds: %+v", counter)
	}
}

func testAttemptsHold(t *testing.T, s store.Store) {
	ctx := t.Context()
	key := attemptKey(1)
	if err := s.Attempts().Hold(ctx, key, store.Hold{BlockedUntil: attemptBase}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Hold of a missing counter = %v, want ErrNotFound", err)
	}
	if err := s.Attempts().Hold(ctx, key, store.Hold{}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an empty Hold of a missing counter = %v, want ErrNotFound", err)
	}
	mustHit(t, s, key, attemptBase, attemptWindow)
	if err := s.Attempts().Hold(ctx, key, store.Hold{}); err != nil {
		t.Fatalf("an empty Hold of an existing counter = %v, want nil", err)
	}
	if got := mustGetOne(t, s, key); !got.BlockedUntil.IsZero() || !got.NextAllowedAt.IsZero() {
		t.Fatalf("an empty Hold must change nothing: %+v", got)
	}

	blocked := attemptBase.Add(time.Hour).Add(789 * time.Nanosecond)
	if err := s.Attempts().Hold(ctx, key, store.Hold{BlockedUntil: blocked}); err != nil {
		t.Fatal(err)
	}
	got := mustGetOne(t, s, key)
	if !sameTime(got.BlockedUntil, blocked) || !got.NextAllowedAt.IsZero() {
		t.Fatalf("Hold of the block only = %+v, want BlockedUntil %v and no delay", got, blocked)
	}
	next := attemptBase.Add(time.Minute)
	if err := s.Attempts().Hold(ctx, key, store.Hold{NextAllowedAt: next}); err != nil {
		t.Fatal(err)
	}
	got = mustGetOne(t, s, key)
	if !sameTime(got.BlockedUntil, blocked) || !sameTime(got.NextAllowedAt, next) {
		t.Fatalf("Hold of the delay only = %+v, want both holds", got)
	}

	earlier := store.Hold{BlockedUntil: blocked.Add(-time.Minute), NextAllowedAt: next.Add(-time.Second)}
	if err := s.Attempts().Hold(ctx, key, earlier); err != nil {
		t.Fatalf("a Hold that moves backwards must be harmless: %v", err)
	}
	got = mustGetOne(t, s, key)
	if !sameTime(got.BlockedUntil, blocked) || !sameTime(got.NextAllowedAt, next) {
		t.Fatalf("Hold moved a time backwards: %+v", got)
	}
	later := store.Hold{BlockedUntil: blocked.Add(time.Minute), NextAllowedAt: next.Add(time.Second)}
	if err := s.Attempts().Hold(ctx, key, later); err != nil {
		t.Fatal(err)
	}
	got = mustGetOne(t, s, key)
	if !sameTime(got.BlockedUntil, later.BlockedUntil) || !sameTime(got.NextAllowedAt, later.NextAllowedAt) {
		t.Fatalf("Hold must move a time forward: %+v, want %+v", got, later)
	}
	if err := s.Attempts().Hold(ctx, "a\x00", store.Hold{BlockedUntil: blocked}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Hold with a NUL byte = %v, want ErrNotFound", err)
	}
	if err := s.Attempts().Hold(ctx, attemptKey(2), store.Hold{BlockedUntil: blocked, NextAllowedAt: next}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Hold of another missing counter = %v, want ErrNotFound", err)
	}
}

func testAttemptsGet(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustHit(t, s, attemptKey(1), attemptBase, attemptWindow)
	mustHit(t, s, attemptKey(1), attemptBase, attemptWindow)
	mustHit(t, s, attemptKey(2), attemptBase, attemptWindow)
	mustHit(t, s, attemptKey(3), attemptBase, attemptWindow)

	keysOf := func(list []store.Attempt) []string {
		var keys []string
		for _, a := range list {
			keys = append(keys, a.Key)
		}
		slices.Sort(keys)
		return keys
	}
	list, err := s.Attempts().Get(ctx, attemptKey(1), attemptKey(2), attemptKey(9))
	if err != nil || !slices.Equal(keysOf(list), []string{attemptKey(1), attemptKey(2)}) {
		t.Fatalf("Get = %v, %v; want the counters that exist", list, err)
	}
	for _, a := range list {
		if a.Key == attemptKey(1) && a.Count != 2 {
			t.Fatalf("counter 1 = %+v, want 2 hits", a)
		}
	}
	list, err = s.Attempts().Get(ctx, attemptKey(3), attemptKey(3))
	if err != nil || len(list) != 1 {
		t.Fatalf("Get with a repeated key = %v, %v; want one counter", list, err)
	}
	for name, keys := range map[string][]string{
		"no keys": nil, "missing keys": {attemptKey(8), attemptKey(9)}, "an empty key": {""},
		"a NUL byte": {"a\x00"}, "invalid UTF-8": {"\xff"}, "a long key": {strings.Repeat("k", 300)},
	} {
		if list, err = s.Attempts().Get(ctx, keys...); err != nil || len(list) != 0 {
			t.Errorf("Get with %s = %v, %v; want an empty list", name, list, err)
		}
	}
	list, err = s.Attempts().Get(ctx, "", attemptKey(2), "a\x00")
	if err != nil || !slices.Equal(keysOf(list), []string{attemptKey(2)}) {
		t.Fatalf("Get must skip keys that cannot exist: %v, %v", list, err)
	}
}

func testAttemptsReset(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustHit(t, s, attemptKey(1), attemptBase, attemptWindow)
	mustHit(t, s, attemptKey(1), attemptBase, attemptWindow)
	mustHit(t, s, attemptKey(2), attemptBase, attemptWindow)
	if err := s.Attempts().Reset(ctx, attemptKey(1)); err != nil {
		t.Fatal(err)
	}
	if list, err := s.Attempts().Get(ctx, attemptKey(1)); err != nil || len(list) != 0 {
		t.Fatalf("a reset counter must be gone: %v, %v", list, err)
	}
	if got := mustGetOne(t, s, attemptKey(2)); got.Count != 1 {
		t.Fatalf("Reset touched another counter: %+v", got)
	}
	if counter := mustHit(t, s, attemptKey(1), attemptBase.Add(time.Second), attemptWindow); counter.Count != 1 || !sameTime(counter.WindowStart, attemptBase.Add(time.Second)) {
		t.Fatalf("counting after a reset must start over: %+v", counter)
	}
	for _, key := range []string{attemptKey(9), "", "a\x00"} {
		if err := s.Attempts().Reset(ctx, key); err != nil {
			t.Errorf("Reset(%q) of nothing = %v, want nil", key, err)
		}
	}
}

func testAttemptsDeleteStale(t *testing.T, s store.Store) {
	ctx := t.Context()
	now := attemptBase.Add(24 * time.Hour)
	window := time.Minute
	mustHit(t, s, attemptKey(1), now.Add(-time.Hour), window)
	mustHit(t, s, attemptKey(2), now.Add(-time.Hour), window)
	mustHit(t, s, attemptKey(3), now.Add(-time.Hour), window)
	mustHit(t, s, attemptKey(4), now.Add(-time.Second), window)
	mustHit(t, s, attemptKey(5), now.Add(-time.Hour), window)
	mustHit(t, s, attemptKey(6), now, window)
	mustHit(t, s, attemptKey(7), now.Add(-time.Hour), window)
	hold := func(n int, h store.Hold) {
		t.Helper()
		if err := s.Attempts().Hold(ctx, attemptKey(n), h); err != nil {
			t.Fatal(err)
		}
	}
	hold(2, store.Hold{BlockedUntil: now.Add(time.Minute)})
	hold(3, store.Hold{NextAllowedAt: now.Add(time.Minute)})
	hold(5, store.Hold{BlockedUntil: now.Add(-time.Minute), NextAllowedAt: now.Add(-2 * time.Minute)})
	hold(7, store.Hold{BlockedUntil: now})

	removed, err := s.Attempts().DeleteStale(ctx, now)
	if err != nil || removed != 3 {
		t.Fatalf("DeleteStale = %d, %v; want 3: counters whose window began and whose holds ended before the given time", removed, err)
	}
	gone, kept := []int{1, 4, 5}, []int{2, 3, 6, 7}
	for _, n := range gone {
		if list, getErr := s.Attempts().Get(ctx, attemptKey(n)); getErr != nil || len(list) != 0 {
			t.Fatalf("counter %d must be removed: %v, %v", n, list, getErr)
		}
	}
	for _, n := range kept {
		mustGetOne(t, s, attemptKey(n))
	}
	if removed, err = s.Attempts().DeleteStale(ctx, now); err != nil || removed != 0 {
		t.Fatalf("a second DeleteStale = %d, %v; want 0", removed, err)
	}
}

func testAttemptsInvalidInput(t *testing.T, s store.Store) {
	ctx := t.Context()
	key := attemptKey(1)
	for name, call := range map[string]func() error{
		"an empty key":  func() error { _, err := s.Attempts().Hit(ctx, "", attemptBase, attemptWindow); return err },
		"a NUL byte":    func() error { _, err := s.Attempts().Hit(ctx, "a\x00", attemptBase, attemptWindow); return err },
		"invalid UTF-8": func() error { _, err := s.Attempts().Hit(ctx, "\xff", attemptBase, attemptWindow); return err },
		"a long key": func() error {
			_, err := s.Attempts().Hit(ctx, strings.Repeat("k", store.MaxAttemptKeyLength+1), attemptBase, attemptWindow)
			return err
		},
		"no time":        func() error { _, err := s.Attempts().Hit(ctx, key, time.Time{}, attemptWindow); return err },
		"a zero window":  func() error { _, err := s.Attempts().Hit(ctx, key, attemptBase, 0); return err },
		"a negative one": func() error { _, err := s.Attempts().Hit(ctx, key, attemptBase, -time.Second); return err },
	} {
		if err := call(); err == nil || isDomainError(err) {
			t.Errorf("Hit with %s = %v, want a validation error", name, err)
		}
	}
	if list, err := s.Attempts().Get(ctx, key); err != nil || len(list) != 0 {
		t.Fatalf("a rejected Hit must not store a counter: %v, %v", list, err)
	}
	longest := strings.Repeat("k", store.MaxAttemptKeyLength)
	if counter := mustHit(t, s, longest, attemptBase, attemptWindow); counter.Key != longest || counter.Count != 1 {
		t.Fatalf("the longest allowed key = %+v", counter)
	}
}

func testConcurrentAttemptHits(t *testing.T, s store.Store) {
	ctx := t.Context()
	const racers, hits = 16, 4
	key := attemptKey(1)
	var mu sync.Mutex
	highest := 0
	parallel(racers, func(i int) {
		for range hits {
			counter, err := s.Attempts().Hit(ctx, key, attemptBase, attemptWindow)
			if err != nil {
				t.Errorf("racer %d: Hit failed: %v", i, err)
				return
			}
			mu.Lock()
			highest = max(highest, counter.Count)
			mu.Unlock()
		}
	})
	got := mustGetOne(t, s, key)
	if got.Count != racers*hits || highest != racers*hits {
		t.Fatalf("after %d concurrent hits the count is %d and the highest one returned is %d; want %d for both",
			racers*hits, got.Count, highest, racers*hits)
	}
	if !sameTime(got.WindowStart, attemptBase) {
		t.Fatalf("the window must begin at the first hit: %+v", got)
	}
}

func testConcurrentAttemptWindowRestart(t *testing.T, s store.Store) {
	ctx := t.Context()
	const racers = 16
	key := attemptKey(1)
	window := 10 * time.Second
	mustHit(t, s, key, attemptBase, window)
	mustHit(t, s, key, attemptBase, window)
	later := attemptBase.Add(time.Hour)
	parallel(racers, func(i int) {
		if _, err := s.Attempts().Hit(ctx, key, later, window); err != nil {
			t.Errorf("racer %d: Hit failed: %v", i, err)
		}
	})
	got := mustGetOne(t, s, key)
	if got.Count != racers || !sameTime(got.WindowStart, later) {
		t.Fatalf("after %d concurrent hits that open a window the counter is %+v; want %d hits in the window that began at %v",
			racers, got, racers, later)
	}
}

func testConcurrentFirstAttemptHits(t *testing.T, s store.Store) {
	ctx := t.Context()
	const racers = 16
	key := attemptKey(1)
	parallel(racers, func(i int) {
		if _, err := s.Attempts().Hit(ctx, key, attemptBase, attemptWindow); err != nil {
			t.Errorf("racer %d: Hit failed: %v", i, err)
		}
	})
	if got := mustGetOne(t, s, key); got.Count != racers {
		t.Fatalf("after %d concurrent first hits the count is %d", racers, got.Count)
	}
}

func testConcurrentFirstAttemptHitsInTransactions(t *testing.T, s store.Store) {
	ctx := t.Context()
	const racers = 8
	key := attemptKey(1)
	parallel(racers, func(i int) {
		err := s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
			_, hitErr := tx.Attempts().Hit(ctx, key, attemptBase, attemptWindow)
			return hitErr
		})
		if err != nil {
			t.Errorf("racer %d: Hit in a transaction failed: %v", i, err)
		}
	})
	if got := mustGetOne(t, s, key); got.Count != racers {
		t.Fatalf("after %d concurrent first hits in transactions the count is %d", racers, got.Count)
	}
}

func testAttemptsRollback(t *testing.T, s store.Store) {
	ctx := t.Context()
	key := attemptKey(1)
	mustHit(t, s, key, attemptBase, attemptWindow)
	boom := errors.New("boom")
	err := s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if _, hitErr := tx.Attempts().Hit(ctx, key, attemptBase, attemptWindow); hitErr != nil {
			return hitErr
		}
		if _, hitErr := tx.Attempts().Hit(ctx, attemptKey(2), attemptBase, attemptWindow); hitErr != nil {
			return hitErr
		}
		if holdErr := tx.Attempts().Hold(ctx, key, store.Hold{BlockedUntil: attemptBase.Add(time.Hour)}); holdErr != nil {
			return holdErr
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("InTx = %v, want %v", err, boom)
	}
	if got := mustGetOne(t, s, key); got.Count != 1 || !got.BlockedUntil.IsZero() {
		t.Fatalf("a rolled back transaction changed the counter: %+v", got)
	}
	if list, getErr := s.Attempts().Get(ctx, attemptKey(2)); getErr != nil || len(list) != 0 {
		t.Fatalf("a rolled back transaction left a counter: %v, %v", list, getErr)
	}
	err = s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		_, hitErr := tx.Attempts().Hit(ctx, key, attemptBase, attemptWindow)
		return hitErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := mustGetOne(t, s, key); got.Count != 2 {
		t.Fatalf("a committed hit must count: %+v", got)
	}
}

func testAttemptHitsAndResets(t *testing.T, s store.Store) {
	ctx := t.Context()
	const hitters, hits, resetters, resets = 8, 60, 3, 150
	key := attemptKey(1)
	var wg sync.WaitGroup
	for range resetters {
		wg.Go(func() {
			for range resets {
				if err := s.Attempts().Reset(ctx, key); err != nil {
					t.Errorf("Reset failed: %v", err)
					return
				}
				time.Sleep(200 * time.Microsecond)
			}
		})
	}
	parallel(hitters, func(i int) {
		for range hits {
			counter, err := s.Attempts().Hit(ctx, key, attemptBase, attemptWindow)
			if err != nil {
				t.Errorf("hitter %d: Hit failed next to a Reset: %v", i, err)
				return
			}
			if counter.Count < 1 {
				t.Errorf("hitter %d: Hit returned the count %d", i, counter.Count)
				return
			}
		}
	})
	wg.Wait()
}
