package sqlstore

import (
	"context"
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func newRacingStore(t *testing.T, insertErr error) (*stub, *Store) {
	t.Helper()
	probe, s := newStubStore(t, nil)
	probe.script = func(query string, n int) error {
		if query == s.q.insertAttempt && n == 1 {
			return insertErr
		}
		return nil
	}
	probe.affect = func(query string, n int) int64 {
		switch {
		case query == s.q.bumpAttempt && n == 1, query == s.q.restartAttempt:
			return 0
		}
		return 1
	}
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	probe.rows = func(query string, _ int) ([]string, [][]driver.Value) {
		if query == s.q.selectAttempt {
			return []string{"key", "start", "count", "blocked", "next"}, [][]driver.Value{{"k", at, int64(2), nil, nil}}
		}
		return nil, nil
	}
	return probe, s
}

func TestAnInsertThatLosesTheRaceIsCountedAgain(t *testing.T) {
	probe, s := newRacingStore(t, errOther)
	got, err := s.Attempts().Hit(t.Context(), "k", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), time.Minute)
	if err != nil || got.Count != 2 {
		t.Fatalf("Hit = %+v, %v; want the counter after the second try", got, err)
	}
	if probe.counts[s.q.insertAttempt] != 1 || probe.counts[s.q.bumpAttempt] != 2 {
		t.Fatalf("the insert ran %d times and the increment %d times, want once and twice",
			probe.counts[s.q.insertAttempt], probe.counts[s.q.bumpAttempt])
	}
}

func TestAnInsertThatFailsOtherwiseFailsTheHit(t *testing.T) {
	_, s := newRacingStore(t, stubError{state: "42501"})
	if _, err := s.Attempts().Hit(t.Context(), "k", time.Now(), time.Minute); err == nil {
		t.Fatal("Hit hid an error of the insert")
	}
}

func TestAHitThatTheDatabaseKeepsAbortingIsCountedAgain(t *testing.T) {
	probe, s := newStubStore(t, nil)
	probe.script = func(query string, n int) error {
		if (query == s.q.bumpAttempt || query == s.q.insertAttempt) && n <= 2*maxAttempts {
			return errDeadlock
		}
		return nil
	}
	probe.affect = func(query string, _ int) int64 {
		if query == s.q.bumpAttempt {
			return 0
		}
		return 1
	}
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	probe.rows = func(query string, _ int) ([]string, [][]driver.Value) {
		if query == s.q.selectAttempt {
			return []string{"key", "start", "count", "blocked", "next"}, [][]driver.Value{{"k", at, int64(1), nil, nil}}
		}
		return nil, nil
	}
	got, err := s.Attempts().Hit(t.Context(), "k", at, time.Minute)
	if err != nil || got.Count != 1 {
		t.Fatalf("Hit = %+v, %v; want the counter after the statements stopped being aborted", got, err)
	}
	if probe.counts[s.q.bumpAttempt] <= maxAttempts {
		t.Fatalf("the increment ran %d times, want more than the %d that one statement is tried", probe.counts[s.q.bumpAttempt], maxAttempts)
	}
}

func TestAHitInATransactionGetsTheDeadlockAtOnceForTheTransactionToBeRunAgain(t *testing.T) {
	probe, s := newStubStore(t, nil)
	probe.script = func(query string, _ int) error {
		if query == s.q.bumpAttempt {
			return errDeadlock
		}
		return nil
	}
	err := s.InTx(t.Context(), func(ctx context.Context, tx store.Repositories) error {
		_, hitErr := tx.Attempts().Hit(ctx, "k", time.Now(), time.Minute)
		return hitErr
	})
	var got stubError
	if !errors.As(err, &got) || got != errDeadlock {
		t.Fatalf("the transaction = %v, want the deadlock that the database gave", err)
	}
	if probe.begins != maxAttempts || probe.counts[s.q.bumpAttempt] != maxAttempts {
		t.Fatalf("the transaction was begun %d times and the increment ran %d times, want %d of each: a hit in a transaction is not tried again, the transaction is",
			probe.begins, probe.counts[s.q.bumpAttempt], maxAttempts)
	}
}

func TestAHitThatTheDatabaseNeverStopsAbortingGivesUpWithTheErrorOfTheDatabase(t *testing.T) {
	probe, s := newStubStore(t, func(string, int) error { return errDeadlock })
	_, err := s.Attempts().Hit(t.Context(), "k", time.Now(), time.Minute)
	var got stubError
	if !errors.As(err, &got) || got != errDeadlock {
		t.Fatalf("Hit = %v, want the error of the database", err)
	}
	if probe.counts[s.q.bumpAttempt] < hitRetries {
		t.Fatalf("the increment ran %d times, want at least the %d tries of a hit", probe.counts[s.q.bumpAttempt], hitRetries)
	}
}
