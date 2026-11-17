package storetest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

var auditBase = time.Date(2026, 10, 11, 12, 13, 14, 123456789, time.UTC)

func newAudit(n int) store.AuditRecord {
	return store.AuditRecord{
		TenantID:     tenantA,
		ID:           id(n),
		At:           auditBase.Add(time.Duration(n) * time.Second),
		ActorKind:    store.ActorAdmin,
		ActorID:      id(1000),
		Action:       "user.blocked",
		TargetUserID: id(2000),
		IP:           "192.0.2.10",
		Details:      `{"reason":"abuse"}`,
	}
}

func mustAddAudit(t *testing.T, s store.Store, r store.AuditRecord) {
	t.Helper()
	if err := s.Audit().Add(t.Context(), r); err != nil {
		t.Fatalf("Add(%s) failed: %v", r.ID, err)
	}
}

func listAudit(t *testing.T, s store.Store, q store.AuditQuery) []store.AuditRecord {
	t.Helper()
	if q.TenantID == "" {
		q.TenantID = tenantA
	}
	if q.Limit == 0 {
		q.Limit = store.MaxAuditPage
	}
	list, err := s.Audit().List(t.Context(), q)
	if err != nil {
		t.Fatalf("List(%+v) failed: %v", q, err)
	}
	return list
}

func auditIDs(list []store.AuditRecord) []string {
	ids := make([]string, 0, len(list))
	for _, r := range list {
		ids = append(ids, r.ID)
	}
	return ids
}

func wantAuditIDs(t *testing.T, got []store.AuditRecord, want ...int) {
	t.Helper()
	expected := make([]string, 0, len(want))
	for _, n := range want {
		expected = append(expected, id(n))
	}
	if !slices.Equal(auditIDs(got), expected) {
		t.Fatalf("the records are %v, want %v", auditIDs(got), expected)
	}
}

func checkAudit(t *testing.T, got, want store.AuditRecord) {
	t.Helper()
	if got.TenantID != want.TenantID || got.ID != want.ID || got.ActorKind != want.ActorKind || got.ActorID != want.ActorID ||
		got.Action != want.Action || got.TargetUserID != want.TargetUserID || got.IP != want.IP || got.Details != want.Details {
		t.Fatalf("audit record differs:\n got %+v\nwant %+v", got, want)
	}
	if !sameTime(got.At, want.At) {
		t.Fatalf("audit record time differs, it must be UTC with microsecond precision:\n got %+v\nwant %+v", got, want)
	}
}

func testAuditLifecycle(t *testing.T, s store.Store) {
	if list := listAudit(t, s, store.AuditQuery{}); len(list) != 0 {
		t.Fatalf("a new store has audit records: %v", list)
	}
	local := time.FixedZone("UTC+3", 3*3600)
	full := newAudit(1)
	full.At = full.At.In(local)
	bare := store.AuditRecord{TenantID: tenantA, ID: id(2), At: auditBase.Add(time.Hour), ActorKind: store.ActorSystem, Action: "maintenance.cleanup"}
	user := newAudit(3)
	user.ActorKind, user.ActorID, user.Action = store.ActorUser, id(2000), "user.login"
	for _, r := range []store.AuditRecord{full, bare, user} {
		mustAddAudit(t, s, r)
	}
	list := listAudit(t, s, store.AuditQuery{})
	if len(list) != 3 {
		t.Fatalf("List = %d records, want 3", len(list))
	}
	checkAudit(t, list[0], bare)
	checkAudit(t, list[1], user)
	checkAudit(t, list[2], full)
	if bare := list[0]; bare.ActorID != "" || bare.TargetUserID != "" || bare.IP != "" || bare.Details != "" {
		t.Fatalf("fields that are not set must come back empty: %+v", bare)
	}
}

func testAuditConflicts(t *testing.T, s store.Store) {
	ctx := t.Context()
	first := newAudit(1)
	mustAddAudit(t, s, first)
	if err := s.Audit().Add(ctx, first); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Add of the same record = %v, want ErrConflict", err)
	}
	other := newAudit(2)
	other.ID = first.ID
	if err := s.Audit().Add(ctx, other); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Add of another record with a taken ID = %v, want ErrConflict", err)
	}
	if list := listAudit(t, s, store.AuditQuery{}); len(list) != 1 {
		t.Fatalf("a rejected record was stored: %v", list)
	}
	elsewhere := first
	elsewhere.TenantID = tenantB
	mustAddAudit(t, s, elsewhere)
}

func testAuditInvalidRecords(t *testing.T, s store.Store) {
	ctx := t.Context()
	edits := map[string]func(*store.AuditRecord){
		"no tenant":          func(r *store.AuditRecord) { r.TenantID = "" },
		"no id":              func(r *store.AuditRecord) { r.ID = "" },
		"no actor kind":      func(r *store.AuditRecord) { r.ActorKind = "" },
		"an unknown kind":    func(r *store.AuditRecord) { r.ActorKind = "robot" },
		"no action":          func(r *store.AuditRecord) { r.Action = "" },
		"no time":            func(r *store.AuditRecord) { r.At = time.Time{} },
		"NUL in the action":  func(r *store.AuditRecord) { r.Action = "a\x00b" },
		"NUL in the details": func(r *store.AuditRecord) { r.Details = "a\x00b" },
		"a bad UTF-8 actor":  func(r *store.AuditRecord) { r.ActorID = "a\xffb" },
		"a bad UTF-8 target": func(r *store.AuditRecord) { r.TargetUserID = "a\xffb" },
		"a bad UTF-8 ip":     func(r *store.AuditRecord) { r.IP = "a\xffb" },
	}
	fields := map[string]struct {
		limit int
		set   func(*store.AuditRecord, string)
	}{
		"tenant":  {store.MaxTenantIDLength, func(r *store.AuditRecord, v string) { r.TenantID = v }},
		"id":      {store.MaxIDLength, func(r *store.AuditRecord, v string) { r.ID = v }},
		"actor":   {store.MaxIDLength, func(r *store.AuditRecord, v string) { r.ActorID = v }},
		"action":  {store.MaxAuditActionLength, func(r *store.AuditRecord, v string) { r.Action = v }},
		"target":  {store.MaxIDLength, func(r *store.AuditRecord, v string) { r.TargetUserID = v }},
		"ip":      {store.MaxIPLength, func(r *store.AuditRecord, v string) { r.IP = v }},
		"details": {store.MaxAuditDetailsLength, func(r *store.AuditRecord, v string) { r.Details = v }},
	}
	for field, f := range fields {
		for label, text := range overTheLimit(f.limit) {
			edits[fmt.Sprintf("a %s %s", field, label)] = func(r *store.AuditRecord) { f.set(r, text) }
		}
	}
	for name, edit := range edits {
		r := newAudit(1)
		edit(&r)
		if err := s.Audit().Add(ctx, r); err == nil || isDomainError(err) {
			t.Errorf("Add with %s = %v, want a validation error", name, err)
		}
	}
	if list := listAudit(t, s, store.AuditQuery{}); len(list) != 0 {
		t.Fatalf("a rejected record must not be stored: %v", list)
	}
}

func testAuditLongestValues(t *testing.T, s store.Store) {
	for n, c := range characters {
		t.Run(c.name, func(t *testing.T) {
			r := store.AuditRecord{
				TenantID:     fill(c.unit, store.MaxTenantIDLength),
				ID:           fill(c.unit, store.MaxIDLength),
				At:           auditBase.Add(time.Duration(n) * time.Second),
				ActorKind:    store.ActorUser,
				ActorID:      fill(c.unit, store.MaxIDLength),
				Action:       fill(c.unit, store.MaxAuditActionLength),
				TargetUserID: fill(c.unit, store.MaxIDLength),
				IP:           fill(c.unit, store.MaxIPLength),
				Details:      fill(c.unit, store.MaxAuditDetailsLength),
			}
			mustAddAudit(t, s, r)
			list := listAudit(t, s, store.AuditQuery{TenantID: r.TenantID})
			if len(list) != 1 {
				t.Fatalf("List = %d records, want the longest one", len(list))
			}
			checkAudit(t, list[0], r)
			byTarget := listAudit(t, s, store.AuditQuery{TenantID: r.TenantID, TargetUserID: r.TargetUserID, ActorID: r.ActorID, Actions: []string{r.Action}})
			if len(byTarget) != 1 {
				t.Fatalf("a query by the longest values found %d records, want 1", len(byTarget))
			}
		})
	}
}

func testAuditFilters(t *testing.T, s store.Store) {
	records := []store.AuditRecord{newAudit(1), newAudit(2), newAudit(3), newAudit(4), newAudit(5), newAudit(6)}
	records[1].TargetUserID = id(2001)
	records[2].ActorKind, records[2].ActorID = store.ActorUser, id(2000)
	records[2].Action = "user.login"
	records[3].ActorKind, records[3].ActorID = store.ActorSystem, ""
	records[3].Action = "maintenance.purge"
	records[4].ActorID = id(1001)
	records[4].Action = "user.deleted"
	records[5].TargetUserID = ""
	records[5].Action = "admin.created"
	for _, r := range records {
		mustAddAudit(t, s, r)
	}
	other := newAudit(7)
	other.TenantID = tenantB
	mustAddAudit(t, s, other)

	cases := []struct {
		name  string
		query store.AuditQuery
		want  []int
	}{
		{"everything of the tenant", store.AuditQuery{}, []int{6, 5, 4, 3, 2, 1}},
		{"the other tenant", store.AuditQuery{TenantID: tenantB}, []int{7}},
		{"a tenant without records", store.AuditQuery{TenantID: "third"}, nil},
		{"a target user", store.AuditQuery{TargetUserID: id(2000)}, []int{5, 4, 3, 1}},
		{"another target user", store.AuditQuery{TargetUserID: id(2001)}, []int{2}},
		{"an actor kind", store.AuditQuery{ActorKind: store.ActorUser}, []int{3}},
		{"the system", store.AuditQuery{ActorKind: store.ActorSystem}, []int{4}},
		{"an actor", store.AuditQuery{ActorID: id(1001)}, []int{5}},
		{"an actor of a kind that does not fit", store.AuditQuery{ActorKind: store.ActorUser, ActorID: id(1001)}, nil},
		{"one action", store.AuditQuery{Actions: []string{"user.login"}}, []int{3}},
		{"two actions", store.AuditQuery{Actions: []string{"user.login", "admin.created"}}, []int{6, 3}},
		{"an action that is not there", store.AuditQuery{Actions: []string{"user.restored"}}, nil},
		{"an action and a user", store.AuditQuery{Actions: []string{"user.blocked"}, TargetUserID: id(2000)}, []int{1}},
		{"from a moment on, inclusive", store.AuditQuery{From: records[2].At}, []int{6, 5, 4, 3}},
		{"before a moment, exclusive", store.AuditQuery{To: records[2].At}, []int{2, 1}},
		{"a period", store.AuditQuery{From: records[1].At, To: records[4].At}, []int{4, 3, 2}},
		{"an empty period", store.AuditQuery{From: records[3].At, To: records[3].At}, nil},
		{"an upside down period", store.AuditQuery{From: records[4].At, To: records[1].At}, nil},
		{"every condition", store.AuditQuery{ActorKind: store.ActorAdmin, ActorID: id(1000), Actions: []string{"user.blocked"}, TargetUserID: id(2000), From: records[0].At, To: records[1].At}, []int{1}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantAuditIDs(t, listAudit(t, s, c.query), c.want...)
		})
	}
}

func testAuditOrder(t *testing.T, s store.Store) {
	same := auditBase.Truncate(time.Microsecond).Add(time.Hour)
	for _, n := range []int{5, 2, 9, 1} {
		r := newAudit(n)
		r.At = same
		mustAddAudit(t, s, r)
	}
	older := newAudit(20)
	older.At = auditBase
	mustAddAudit(t, s, older)
	newer := newAudit(3)
	newer.At = same.Add(time.Microsecond)
	mustAddAudit(t, s, newer)
	subMicrosecond := newAudit(4)
	subMicrosecond.At = same.Add(500 * time.Nanosecond)
	mustAddAudit(t, s, subMicrosecond)
	wantAuditIDs(t, listAudit(t, s, store.AuditQuery{}), 3, 9, 5, 4, 2, 1, 20)
}

func testAuditPages(t *testing.T, s store.Store) {
	const total = 23
	for n := 1; n <= total; n++ {
		r := newAudit(n)
		r.At = auditBase.Add(time.Duration(n/3) * time.Second)
		if n%5 == 0 {
			r.TargetUserID = id(2001)
		}
		mustAddAudit(t, s, r)
	}
	full := listAudit(t, s, store.AuditQuery{})
	if len(full) != total {
		t.Fatalf("List = %d records, want %d", len(full), total)
	}
	for _, size := range []int{1, 2, 3, 7, 22, 23, 24, store.MaxAuditPage} {
		var got []string
		var after *store.AuditRecord
		pages := 0
		for {
			page := listAudit(t, s, store.AuditQuery{Limit: size, After: after})
			if len(page) > size {
				t.Fatalf("a page of %d records has %d", size, len(page))
			}
			got = append(got, auditIDs(page)...)
			pages++
			if len(page) < size || pages > total+1 {
				break
			}
			last := page[len(page)-1]
			after = &last
		}
		if !slices.Equal(got, auditIDs(full)) {
			t.Fatalf("pages of %d records give %v, want %v: none may be missed or repeated, ties of time included", size, got, auditIDs(full))
		}
	}
	filtered := listAudit(t, s, store.AuditQuery{TargetUserID: id(2001), Limit: 2})
	wantAuditIDs(t, filtered, 20, 15)
	rest := listAudit(t, s, store.AuditQuery{TargetUserID: id(2001), Limit: 2, After: &filtered[1]})
	wantAuditIDs(t, rest, 10, 5)
	cursor := store.AuditRecord{ID: id(500), At: full[4].At.In(time.FixedZone("UTC+5", 5*3600)).Add(300 * time.Nanosecond)}
	at := cursor.At.UTC().Truncate(time.Microsecond)
	var want []string
	for _, r := range full {
		if r.At.Before(at) || (r.At.Equal(at) && r.ID < cursor.ID) {
			want = append(want, r.ID)
		}
	}
	if got := listAudit(t, s, store.AuditQuery{After: &cursor}); len(want) == 0 || len(want) == len(full) || !slices.Equal(auditIDs(got), want) {
		t.Fatalf("a cursor that is none of the records must continue with the records after it: got %v, want %v", auditIDs(got), want)
	}
}

func testAuditQueryLimits(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustAddAudit(t, s, newAudit(1))
	bad := map[string]store.AuditQuery{
		"no limit":                {TenantID: tenantA},
		"a negative limit":        {TenantID: tenantA, Limit: -1},
		"a limit over the page":   {TenantID: tenantA, Limit: store.MaxAuditPage + 1},
		"too many actions":        {TenantID: tenantA, Limit: 10, Actions: make([]string, store.MaxAuditActions+1)},
		"an unknown kind":         {TenantID: tenantA, Limit: 10, ActorKind: "robot"},
		"a cursor without a time": {TenantID: tenantA, Limit: 10, After: &store.AuditRecord{ID: id(1)}},
	}
	for name, q := range bad {
		if _, err := s.Audit().List(ctx, q); err == nil || isDomainError(err) {
			t.Errorf("List with %s = %v, want a validation error", name, err)
		}
	}
	for _, size := range []int{1, store.MaxAuditPage} {
		if list, err := s.Audit().List(ctx, store.AuditQuery{TenantID: tenantA, Limit: size}); err != nil || len(list) != 1 {
			t.Errorf("List with a limit of %d = %v, %v; want the record", size, list, err)
		}
	}
	many := make([]string, store.MaxAuditActions)
	for i := range many {
		many[i] = fmt.Sprintf("action.%d", i)
	}
	many[0] = "user.blocked"
	if list, err := s.Audit().List(ctx, store.AuditQuery{TenantID: tenantA, Limit: 10, Actions: many}); err != nil || len(list) != 1 {
		t.Errorf("List with %d actions = %v, %v; want the record", len(many), list, err)
	}
}

func testAuditLookupsThatFindNothing(t *testing.T, s store.Store) {
	mustAddAudit(t, s, newAudit(1))
	for _, bad := range []string{"a\x00b", "a\xffb", strings.Repeat("a", store.MaxIdentifierValueLength+1)} {
		queries := map[string]store.AuditQuery{
			"tenant":  {TenantID: bad},
			"target":  {TargetUserID: bad},
			"actor":   {ActorID: bad},
			"action":  {Actions: []string{bad}},
			"actions": {Actions: []string{"user.blocked", bad}},
			"cursor":  {After: &store.AuditRecord{ID: bad, At: auditBase}},
		}
		for name, q := range queries {
			if q.TenantID == "" {
				q.TenantID = tenantA
			}
			if list := listAudit(t, s, q); len(list) != 0 {
				t.Errorf("a query by a %s that cannot be stored (%q) found %v", name, bad, auditIDs(list))
			}
		}
	}
	for _, long := range []string{strings.Repeat("a", store.MaxIDLength+1), strings.Repeat("é", store.MaxIDLength)} {
		if list := listAudit(t, s, store.AuditQuery{TargetUserID: long}); len(list) != 0 {
			t.Errorf("a target user over the limit found %v", auditIDs(list))
		}
		if list := listAudit(t, s, store.AuditQuery{Actions: []string{long}}); len(list) != 0 {
			t.Errorf("an action over the limit found %v", auditIDs(list))
		}
	}
}

func testAuditDetailsAreStoredAsGiven(t *testing.T, s store.Store) {
	details := []string{
		`{"old":"a@example.com","new":"b@example.com"}`,
		"{\"text\":\"line\\nbreak and \u00e9 and \U0001F600 and \\u0000\"}",
		` {"padding":"around"} `,
		"plain text with 'quotes', \"double quotes\", %, _ and \\",
		fill("\U0001F600", store.MaxAuditDetailsLength),
	}
	for n, text := range details {
		r := newAudit(n + 1)
		r.Details = text
		mustAddAudit(t, s, r)
	}
	for n, text := range details {
		got := listAudit(t, s, store.AuditQuery{TargetUserID: id(2000), Actions: []string{"user.blocked"}, From: auditBase.Add(time.Duration(n+1) * time.Second), To: auditBase.Add(time.Duration(n+2) * time.Second)})
		if len(got) != 1 || got[0].Details != text {
			t.Fatalf("details %d came back as %q, want them as they were given", n, got)
		}
	}
}

func testAuditDeleteBefore(t *testing.T, s store.Store) {
	ctx := t.Context()
	for n := 1; n <= 10; n++ {
		r := newAudit(n)
		r.At = auditBase.Add(time.Duration(n) * time.Hour)
		mustAddAudit(t, s, r)
	}
	other := newAudit(11)
	other.TenantID = tenantB
	other.At = auditBase
	mustAddAudit(t, s, other)
	same := newAudit(12)
	same.At = auditBase.Add(3 * time.Hour)
	mustAddAudit(t, s, same)

	cutoff := auditBase.Add(6 * time.Hour)
	removed, err := s.Audit().DeleteBefore(ctx, tenantA, cutoff, 3)
	if err != nil || removed != 3 {
		t.Fatalf("DeleteBefore = %d, %v; want 3", removed, err)
	}
	wantAuditIDs(t, listAudit(t, s, store.AuditQuery{}), 10, 9, 8, 7, 6, 5, 4, 12)
	if removed, err = s.Audit().DeleteBefore(ctx, tenantA, cutoff, 3); err != nil || removed != 3 {
		t.Fatalf("second DeleteBefore = %d, %v; want 3", removed, err)
	}
	wantAuditIDs(t, listAudit(t, s, store.AuditQuery{}), 10, 9, 8, 7, 6)
	if removed, err = s.Audit().DeleteBefore(ctx, tenantA, cutoff, 3); err != nil || removed != 0 {
		t.Fatalf("DeleteBefore of nothing = %d, %v; want 0", removed, err)
	}
	if removed, err = s.Audit().DeleteBefore(ctx, tenantA, cutoff.Add(-time.Hour), 3); err != nil || removed != 0 {
		t.Fatalf("a record at the cutoff stays: DeleteBefore = %d, %v; want 0", removed, err)
	}
	wantAuditIDs(t, listAudit(t, s, store.AuditQuery{TenantID: tenantB}), 11)
	if removed, err = s.Audit().DeleteBefore(ctx, tenantA, auditBase.Add(100*time.Hour), store.MaxAuditPage); err != nil || removed != 5 {
		t.Fatalf("DeleteBefore of the rest = %d, %v; want 5", removed, err)
	}
	if list := listAudit(t, s, store.AuditQuery{}); len(list) != 0 {
		t.Fatalf("the records that are left: %v", auditIDs(list))
	}
	wantAuditIDs(t, listAudit(t, s, store.AuditQuery{TenantID: tenantB}), 11)
}

func testAuditDeleteBeforeInvalidInput(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustAddAudit(t, s, newAudit(1))
	for _, limit := range []int{0, -1, store.MaxAuditPage + 1} {
		if _, err := s.Audit().DeleteBefore(ctx, tenantA, auditBase.Add(time.Hour), limit); err == nil || isDomainError(err) {
			t.Errorf("DeleteBefore with a limit of %d = %v, want a validation error", limit, err)
		}
	}
	if _, err := s.Audit().DeleteBefore(ctx, tenantA, time.Time{}, 10); err == nil || isDomainError(err) {
		t.Errorf("DeleteBefore without a time = %v, want a validation error", err)
	}
	for _, bad := range []string{"a\x00b", "a\xffb", strings.Repeat("a", store.MaxIdentifierValueLength+1)} {
		if removed, err := s.Audit().DeleteBefore(ctx, bad, auditBase.Add(time.Hour), 10); err != nil || removed != 0 {
			t.Errorf("DeleteBefore in the tenant %q = %d, %v; want nothing", bad, removed, err)
		}
	}
	wantAuditIDs(t, listAudit(t, s, store.AuditQuery{}), 1)
}

func testConcurrentAuditAdds(t *testing.T, s store.Store) {
	ctx := t.Context()
	const racers = 8
	var wins, conflicts atomic.Int32
	parallel(racers, func(i int) {
		r := newAudit(1)
		r.Action = fmt.Sprintf("racer.%d", i)
		err := s.Audit().Add(ctx, r)
		switch {
		case err == nil:
			wins.Add(1)
		case errors.Is(err, store.ErrConflict):
			conflicts.Add(1)
		default:
			t.Errorf("racer %d: unexpected error %v", i, err)
		}
	})
	if wins.Load() != 1 || conflicts.Load() != racers-1 {
		t.Fatalf("%d adds succeeded and %d conflicted; want exactly 1 and %d", wins.Load(), conflicts.Load(), racers-1)
	}
}

func testConcurrentAuditDeletes(t *testing.T, s store.Store) {
	ctx := t.Context()
	const records = 40
	for n := 1; n <= records; n++ {
		mustAddAudit(t, s, newAudit(n))
	}
	var removed atomic.Int64
	parallel(4, func(int) {
		for {
			n, err := s.Audit().DeleteBefore(ctx, tenantA, auditBase.Add(time.Hour), 7)
			if err != nil {
				t.Errorf("DeleteBefore failed: %v", err)
				return
			}
			removed.Add(int64(n))
			if n == 0 {
				return
			}
		}
	})
	if list := listAudit(t, s, store.AuditQuery{}); len(list) != 0 {
		t.Fatalf("%d records are left after the deletes", len(list))
	}
	if removed.Load() > records {
		t.Fatalf("the deletes report %d removed records out of %d: a record is counted once", removed.Load(), records)
	}
}

func testAuditRollback(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustAddAudit(t, s, newAudit(1))
	err := s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if err := tx.Audit().Add(ctx, newAudit(2)); err != nil {
			return err
		}
		if _, err := tx.Audit().DeleteBefore(ctx, tenantA, auditBase.Add(1500*time.Millisecond), 10); err != nil {
			return err
		}
		list, err := tx.Audit().List(ctx, store.AuditQuery{TenantID: tenantA, Limit: 10})
		if err != nil || len(list) != 1 || list[0].ID != id(2) {
			return fmt.Errorf("the transaction must see its own writes: %v, %w", auditIDs(list), err)
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatalf("InTx = %v, want the error of the function", err)
	}
	wantAuditIDs(t, listAudit(t, s, store.AuditQuery{}), 1)
	err = s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		return tx.Audit().Add(ctx, newAudit(3))
	})
	if err != nil {
		t.Fatalf("InTx failed: %v", err)
	}
	wantAuditIDs(t, listAudit(t, s, store.AuditQuery{}), 3, 1)
}
