package sqlstore

import (
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

var sessionTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

type changedRows struct {
	probe *stub
	s     *Store
}

func newChangedRows(t *testing.T, matched bool) *changedRows {
	t.Helper()
	probe, s := newStubStore(t, nil)
	probe.affect = func(string, int) int64 { return 0 }
	probe.rows = func(query string, _ int) ([]string, [][]driver.Value) {
		if matched && (query == s.q.identifierExists || query == s.q.lockHeld) {
			return []string{"1"}, [][]driver.Value{{int64(1)}}
		}
		return nil, nil
	}
	return &changedRows{probe: probe, s: s}
}

func TestMarkVerifiedChecksTheRowWhenNoRowChanged(t *testing.T) {
	existing := newChangedRows(t, true)
	if err := existing.s.Identifiers().MarkVerified(t.Context(), store.DefaultTenant, "email", "a@example.com", sessionTime); err != nil {
		t.Fatalf("MarkVerified of an identifier that has the time = %v, want nil", err)
	}
	if existing.probe.counts[existing.s.q.identifierExists] != 1 {
		t.Fatalf("the identifier was looked up %d times, want once", existing.probe.counts[existing.s.q.identifierExists])
	}
	missing := newChangedRows(t, false)
	if err := missing.s.Identifiers().MarkVerified(t.Context(), store.DefaultTenant, "email", "a@example.com", sessionTime); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("MarkVerified of a missing identifier = %v, want ErrNotFound", err)
	}
}

func TestMarkVerifiedTrustsARowThatChanged(t *testing.T) {
	probe, s := newStubStore(t, nil)
	if err := s.Identifiers().MarkVerified(t.Context(), store.DefaultTenant, "email", "a@example.com", sessionTime); err != nil {
		t.Fatalf("MarkVerified = %v, want nil", err)
	}
	if probe.counts[s.q.identifierExists] != 0 {
		t.Fatal("the identifier was looked up although a row had changed")
	}
}

func TestTheLeaseIsRenewedWhenNoRowChanged(t *testing.T) {
	held := newChangedRows(t, true)
	if err := held.s.extendLease(t.Context(), "holder"); err != nil {
		t.Fatalf("extendLease of a lease that is ours = %v, want nil", err)
	}
	if held.probe.counts[held.s.q.lockHeld] != 1 {
		t.Fatalf("the lease was looked up %d times, want once", held.probe.counts[held.s.q.lockHeld])
	}
	lost := newChangedRows(t, false)
	if err := lost.s.extendLease(t.Context(), "holder"); err == nil {
		t.Fatal("extendLease of a lease that is not ours = nil, want an error")
	}
}

func TestTheLeaseIsRenewedByAChangedRow(t *testing.T) {
	probe, s := newStubStore(t, nil)
	if err := s.extendLease(t.Context(), "holder"); err != nil {
		t.Fatalf("extendLease = %v, want nil", err)
	}
	if probe.counts[s.q.lockHeld] != 0 {
		t.Fatal("the lease was looked up although a row had changed")
	}
}
