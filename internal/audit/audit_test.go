package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/internal/memstore"
	"github.com/acneism/limb/store"
)

var moment = time.Date(2026, 5, 6, 7, 8, 9, 123456789, time.UTC)

func writer(t *testing.T) (Writer, store.Store) {
	t.Helper()
	s := memstore.New()
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	n := 0
	return Writer{
		Tenant: store.DefaultTenant,
		Now:    func() time.Time { return moment },
		NewID: func() (string, error) {
			n++
			return fmt.Sprintf("00000000-0000-7000-8000-%012d", n), nil
		},
	}, s
}

func TestAnEntryBecomesARecord(t *testing.T) {
	w, s := writer(t)
	entry := Entry{
		Actor: Actor{Kind: store.ActorAdmin, ID: "admin-1"}, Action: AdminCreated, TargetUserID: "user-1", IP: "192.0.2.1",
		Details: map[string]any{"login": "root", "count": 3, "flags": []any{"a", true}},
	}
	if err := w.Add(t.Context(), s.Audit(), entry); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	list, err := s.Audit().List(t.Context(), store.AuditQuery{TenantID: store.DefaultTenant, Limit: 10})
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %v, %v", list, err)
	}
	got := list[0]
	if got.ID != "00000000-0000-7000-8000-000000000001" || !got.At.Equal(moment.Truncate(time.Microsecond)) || got.ActorKind != store.ActorAdmin ||
		got.ActorID != "admin-1" || got.Action != "admin.created" || got.TargetUserID != "user-1" || got.IP != "192.0.2.1" {
		t.Fatalf("the record is %+v", got)
	}
	var details map[string]any
	if err = json.Unmarshal([]byte(got.Details), &details); err != nil || details["login"] != "root" || details["count"] != float64(3) {
		t.Fatalf("the details are %q, %v", got.Details, err)
	}
}

func TestAnEntryWithoutDetailsHasNone(t *testing.T) {
	w, s := writer(t)
	for _, details := range []map[string]any{nil, {}} {
		if err := w.Add(t.Context(), s.Audit(), Entry{Actor: CLI, Action: AdminDeleted, Details: details}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.Audit().List(t.Context(), store.AuditQuery{TenantID: store.DefaultTenant, Limit: 10})
	if err != nil || len(list) != 2 || list[0].Details != "" || list[1].Details != "" {
		t.Fatalf("the records are %+v, %v", list, err)
	}
	if list[0].ActorKind != store.ActorSystem || list[0].ActorID != "cli" {
		t.Fatalf("the command line is the system actor cli: %+v", list[0])
	}
	if API.Kind != store.ActorSystem || API.ID != "api" {
		t.Fatalf("the code of the application is the system actor api: %+v", API)
	}
}

func TestARecordThatCannotBeWrittenIsReported(t *testing.T) {
	w, s := writer(t)
	if err := w.Add(t.Context(), s.Audit(), Entry{Actor: CLI, Action: ""}); err == nil {
		t.Fatal("an entry without an action must be refused")
	}
	broken := errors.New("no ids")
	w.NewID = func() (string, error) { return "", broken }
	if err := w.Add(t.Context(), s.Audit(), Entry{Actor: CLI, Action: AdminCreated}); !errors.Is(err, broken) {
		t.Fatalf("Add = %v, want the failure of the generator of IDs", err)
	}
	w, s = writer(t)
	if err := w.Add(t.Context(), s.Audit(), Entry{Actor: CLI, Action: AdminCreated, Details: map[string]any{"bad": make(chan int)}}); err == nil {
		t.Fatal("details that cannot be written must be reported")
	}
}

func TestARecordIsWrittenInTheTransactionOfTheChange(t *testing.T) {
	w, s := writer(t)
	errRollback := errors.New("roll back")
	err := s.InTx(t.Context(), func(ctx context.Context, tx store.Repositories) error {
		if err := w.Add(ctx, tx.Audit(), Entry{Actor: CLI, Action: AdminCreated}); err != nil {
			return err
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatal(err)
	}
	if list, listErr := s.Audit().List(t.Context(), store.AuditQuery{TenantID: store.DefaultTenant, Limit: 10}); listErr != nil || len(list) != 0 {
		t.Fatalf("a record of a change that was rolled back stayed: %v, %v", list, listErr)
	}
}

func TestDetailsThatFitAreKeptAsTheyAre(t *testing.T) {
	long := strings.Repeat("a", 500)
	text, err := Encode(map[string]any{"old": long, "new": long})
	if err != nil || len(text) > store.MaxAuditDetailsLength || strings.Contains(text, truncatedKey) {
		t.Fatalf("details of %d bytes were changed: %q, %v", len(text), text, err)
	}
}

func TestDetailsThatDoNotFitAreCutShort(t *testing.T) {
	huge := strings.Repeat("a", 3000)
	text, err := Encode(map[string]any{"old": huge, "new": huge, "login": "root"})
	if err != nil || len(text) > store.MaxAuditDetailsLength {
		t.Fatalf("Encode = %d bytes, %v", len(text), err)
	}
	var got map[string]any
	if err = json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("the details are not JSON: %v", err)
	}
	if got["login"] != "root" || got[truncatedKey] != true || got["old"] != strings.Repeat("a", longestValue)+ellipsis {
		t.Fatalf("the details are %v: the values must be cut and the cut must be said", got)
	}
}

func TestDetailsAreCutOnACharacterBoundary(t *testing.T) {
	huge := "a" + strings.Repeat("я", 3000)
	text, err := Encode(map[string]any{"old": huge, "new": huge, "extra": "ab" + strings.Repeat("\U0001F600", 3000)})
	if err != nil || len(text) > store.MaxAuditDetailsLength {
		t.Fatalf("Encode = %d bytes, %v", len(text), err)
	}
	var got map[string]any
	if err = json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("the details are not JSON: %v", err)
	}
	for key, value := range got {
		if s, ok := value.(string); ok && strings.ContainsRune(s, '�') {
			t.Fatalf("%s was cut in the middle of a character: %q", key, s)
		}
	}
	if got["old"] != "a"+strings.Repeat("я", 31)+ellipsis || got["extra"] != "ab"+strings.Repeat("\U0001F600", 15)+ellipsis {
		t.Fatalf("the values are cut at the last whole character before %d bytes: %q, %q", longestValue, got["old"], got["extra"])
	}
}

func TestDetailsOfManyKeysLoseTheLastOnesInTheAlphabet(t *testing.T) {
	details := map[string]any{}
	for i := range 300 {
		details[fmt.Sprintf("key%03d", i)] = strings.Repeat("v", 60)
	}
	text, err := Encode(details)
	if err != nil || len(text) > store.MaxAuditDetailsLength {
		t.Fatalf("Encode = %d bytes, %v", len(text), err)
	}
	var got map[string]any
	if err = json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatal(err)
	}
	if got[truncatedKey] != true || got["key000"] == nil || got["key299"] != nil {
		t.Fatalf("the first keys must stay and the last must go: %d keys", len(got))
	}
}

func TestNestedDetailsAreCutToo(t *testing.T) {
	huge := strings.Repeat("b", 4000)
	text, err := Encode(map[string]any{"old": map[string]any{"value": huge}, "list": []any{huge, 7}})
	if err != nil || len(text) > store.MaxAuditDetailsLength {
		t.Fatalf("Encode = %d bytes, %v", len(text), err)
	}
	var got map[string]any
	if err = json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatal(err)
	}
	if inner, ok := got["old"].(map[string]any); !ok || inner["value"] != strings.Repeat("b", longestValue)+ellipsis {
		t.Fatalf("a nested value was not cut: %v", got)
	}
	if list, ok := got["list"].([]any); !ok || len(list) != 2 || list[1] != float64(7) {
		t.Fatalf("a list was not kept: %v", got)
	}
}

func TestDetailsThatCannotBeWrittenAreReportedWhenTheyAreCut(t *testing.T) {
	if _, err := Encode(map[string]any{"a": strings.Repeat("x", 5000), "bad": make(chan int)}); err == nil {
		t.Fatal("details that cannot be written must be reported")
	}
}

func TestDetailsThatCannotBeShortenedKeepOnlyTheMarkThatTheyWereCut(t *testing.T) {
	deep := any("x")
	for range 3000 {
		deep = []any{deep}
	}
	text, err := Encode(map[string]any{"a": deep})
	if err != nil || len(text) > store.MaxAuditDetailsLength {
		t.Fatalf("Encode = %d bytes, %v", len(text), err)
	}
	if text != `{"`+truncatedKey+`":true}` {
		t.Fatalf("the details are %q, want only the mark", text)
	}
}
