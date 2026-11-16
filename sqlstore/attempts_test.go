package sqlstore

import (
	"database/sql/driver"
	"testing"
	"time"
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
