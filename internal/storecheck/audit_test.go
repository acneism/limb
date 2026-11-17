package storecheck

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func validAudit() store.AuditRecord {
	return store.AuditRecord{
		TenantID: "default", ID: "a1", At: time.Now(), ActorKind: store.ActorAdmin, ActorID: "admin-1",
		Action: "user.blocked", TargetUserID: "user-1", IP: "192.0.2.1", Details: `{"reason":"abuse"}`,
	}
}

func TestAuditRecordRules(t *testing.T) {
	if err := NewAuditRecord(validAudit()); err != nil {
		t.Fatalf("a valid record was rejected: %v", err)
	}
	bare := store.AuditRecord{TenantID: "default", ID: "a1", At: time.Now(), ActorKind: store.ActorSystem, Action: "maintenance.cleanup"}
	if err := NewAuditRecord(bare); err != nil {
		t.Fatalf("a record without an actor, a target, an address and details was rejected: %v", err)
	}
	cases := map[string]func(*store.AuditRecord){
		"no tenant":         func(r *store.AuditRecord) { r.TenantID = "" },
		"no ID":             func(r *store.AuditRecord) { r.ID = "" },
		"no kind":           func(r *store.AuditRecord) { r.ActorKind = "" },
		"an unknown kind":   func(r *store.AuditRecord) { r.ActorKind = "robot" },
		"no action":         func(r *store.AuditRecord) { r.Action = "" },
		"no time":           func(r *store.AuditRecord) { r.At = time.Time{} },
		"a long tenant":     func(r *store.AuditRecord) { r.TenantID = strings.Repeat("a", store.MaxTenantIDLength+1) },
		"a long ID":         func(r *store.AuditRecord) { r.ID = strings.Repeat("a", store.MaxIDLength+1) },
		"a long action":     func(r *store.AuditRecord) { r.Action = strings.Repeat("a", store.MaxAuditActionLength+1) },
		"a long actor":      func(r *store.AuditRecord) { r.ActorID = strings.Repeat("a", store.MaxIDLength+1) },
		"a long target":     func(r *store.AuditRecord) { r.TargetUserID = strings.Repeat("a", store.MaxIDLength+1) },
		"a long address":    func(r *store.AuditRecord) { r.IP = strings.Repeat("a", store.MaxIPLength+1) },
		"long details":      func(r *store.AuditRecord) { r.Details = strings.Repeat("a", store.MaxAuditDetailsLength+1) },
		"a NUL in details":  func(r *store.AuditRecord) { r.Details = "a\x00" },
		"bad UTF-8 details": func(r *store.AuditRecord) { r.Details = "\xff" },
		"a bad address":     func(r *store.AuditRecord) { r.IP = "\xff" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			r := validAudit()
			edit(&r)
			if err := NewAuditRecord(r); !errors.Is(err, ErrInvalid) {
				t.Fatalf("NewAuditRecord = %v, want ErrInvalid", err)
			}
		})
	}
	longest := validAudit()
	longest.Details = strings.Repeat("a", store.MaxAuditDetailsLength)
	if err := NewAuditRecord(longest); err != nil {
		t.Fatalf("details of the longest length were rejected: %v", err)
	}
}

func TestAuditQueryRules(t *testing.T) {
	good := store.AuditQuery{TenantID: "default", Limit: 10}
	if err := AuditQuery(good); err != nil {
		t.Fatalf("a valid query was rejected: %v", err)
	}
	for _, limit := range []int{1, store.MaxAuditPage} {
		if err := AuditQuery(store.AuditQuery{Limit: limit}); err != nil {
			t.Fatalf("a limit of %d was rejected: %v", limit, err)
		}
	}
	cases := map[string]store.AuditQuery{
		"no limit":            {},
		"a negative limit":    {Limit: -1},
		"a limit too large":   {Limit: store.MaxAuditPage + 1},
		"too many actions":    {Limit: 1, Actions: make([]string, store.MaxAuditActions+1)},
		"an unknown kind":     {Limit: 1, ActorKind: "robot"},
		"a cursor of no time": {Limit: 1, After: &store.AuditRecord{ID: "a"}},
	}
	for name, q := range cases {
		if err := AuditQuery(q); !errors.Is(err, ErrInvalid) {
			t.Errorf("AuditQuery with %s = %v, want ErrInvalid", name, err)
		}
	}
	if err := AuditQuery(store.AuditQuery{Limit: 1, Actions: make([]string, store.MaxAuditActions)}); err != nil {
		t.Fatalf("the most actions that a query takes were rejected: %v", err)
	}
	if err := AuditQuery(store.AuditQuery{Limit: 1, ActorKind: store.ActorUser, After: &store.AuditRecord{At: time.Now()}}); err != nil {
		t.Fatalf("a query with a kind and a cursor was rejected: %v", err)
	}
}

func TestAuditQueryValuesThatCannotBeStoredMatchNothing(t *testing.T) {
	if !ValidAuditQuery(store.AuditQuery{TenantID: "default", TargetUserID: "u", ActorID: "a", Actions: []string{"x"}, After: &store.AuditRecord{ID: "i"}}) {
		t.Fatal("a query of valid values was refused")
	}
	for name, q := range map[string]store.AuditQuery{
		"a tenant":      {TenantID: "a\x00"},
		"a target":      {TargetUserID: "\xff"},
		"an actor":      {ActorID: "a\x00"},
		"an action":     {Actions: []string{"ok", "\xff"}},
		"a cursor":      {After: &store.AuditRecord{ID: "a\x00"}},
		"a long target": {TargetUserID: strings.Repeat("a", store.MaxIdentifierValueLength+1)},
	} {
		if ValidAuditQuery(q) {
			t.Errorf("a query with %s that cannot be stored was accepted", name)
		}
	}
}

func TestAuditRecordsAreOrderedNewestFirstAndThenByID(t *testing.T) {
	now := time.Now()
	older := store.AuditRecord{ID: "z", At: now}
	newer := store.AuditRecord{ID: "a", At: now.Add(time.Second)}
	low, high := store.AuditRecord{ID: "a", At: now}, store.AuditRecord{ID: "b", At: now}
	if CompareAudit(newer, older) >= 0 || CompareAudit(older, newer) <= 0 {
		t.Fatal("a newer record must come first")
	}
	if CompareAudit(high, low) >= 0 || CompareAudit(low, high) <= 0 || CompareAudit(low, low) != 0 {
		t.Fatal("of two records of one moment the one with the greater ID must come first")
	}
}

func TestAuditBatchRules(t *testing.T) {
	for _, n := range []int{1, store.MaxAuditPage} {
		if err := AuditBatch(n); err != nil {
			t.Fatalf("a batch of %d was rejected: %v", n, err)
		}
	}
	for _, n := range []int{0, -1, store.MaxAuditPage + 1} {
		if err := AuditBatch(n); !errors.Is(err, ErrInvalid) {
			t.Fatalf("a batch of %d = %v, want ErrInvalid", n, err)
		}
	}
}
