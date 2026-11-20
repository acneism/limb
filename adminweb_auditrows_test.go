package limb

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/acneism/limb/internal/adminui"
	"github.com/acneism/limb/store"
)

func actionsOfTheAuditPackage(t *testing.T) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "internal/audit/audit.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, decl := range file.Decls {
		group, isGroup := decl.(*ast.GenDecl)
		if !isGroup || group.Tok != token.CONST {
			continue
		}
		for _, spec := range group.Specs {
			value, isValue := spec.(*ast.ValueSpec)
			if !isValue || len(value.Values) != 1 || value.Names[0].Name == "AuthPrefix" {
				continue
			}
			literal, isLiteral := value.Values[0].(*ast.BasicLit)
			if !isLiteral || literal.Kind != token.STRING {
				continue
			}
			text, unquoteErr := strconv.Unquote(literal.Value)
			if unquoteErr != nil {
				t.Fatal(unquoteErr)
			}
			if strings.Contains(text, ".") {
				actions = append(actions, text)
			}
		}
	}
	return actions
}

func TestEveryActionOfTheAuditLogIsKnownAndHasATextInEveryLanguage(t *testing.T) {
	declared := actionsOfTheAuditPackage(t)
	if len(declared) < 30 {
		t.Fatalf("only %d actions were found in the audit package: %v", len(declared), declared)
	}
	for _, event := range []EventType{EventUserCreated, EventLogin, EventLoginFailed, EventLogout, EventPasswordChanged, EventPasswordReset, EventSessionEnded, EventRefreshTokenReused, EventChannelVerified} {
		if !auditedEvents[event] {
			t.Errorf("the event %q is not audited any more: the list of the actions is out of date", event)
		}
		declared = append(declared, authAction(event))
	}
	for event, audited := range auditedEvents {
		if audited && !slices.Contains(declared, authAction(event)) {
			t.Errorf("the event %q is audited and has no text", event)
		}
	}
	slices.Sort(declared)
	known := slices.Clone(auditActions)
	slices.Sort(known)
	if !slices.Equal(known, declared) {
		t.Errorf("the actions that the pages know are %v, the audit package and the audited events make %v", known, declared)
	}
	catalog, err := adminui.NewCatalog(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, language := range catalog.Languages() {
		page := adminui.NewPage(catalog, language)
		for _, action := range auditActions {
			if text := page.T("audit.action." + action); text == "audit.action."+action || text == "" {
				t.Errorf("the action %q has no text in %s", action, language)
			}
		}
	}
	if len(journalActions) > store.MaxAuditActions || len(signInActions) > store.MaxAuditActions {
		t.Errorf("a query for the history of a user holds %d and %d actions, at most %d are allowed", len(journalActions), len(signInActions), store.MaxAuditActions)
	}
	for _, action := range slices.Concat(journalActions, signInActions) {
		if strings.HasPrefix(action, "admin.") || action == "setting.changed" {
			t.Errorf("the history of a user holds %q, an action of an administrator on their own account", action)
		}
	}
	for _, shared := range signInActions {
		if slices.Contains(journalActions, shared) {
			t.Errorf("%q is in the sign-ins and in the changes", shared)
		}
	}
}

func TestTheDetailsOfARecordAreShownAsPlainText(t *testing.T) {
	deep := map[string]any{"a": map[string]any{"b": map[string]any{"c": map[string]any{"d": map[string]any{"e": map[string]any{"f": map[string]any{"g": "end"}}}}}}}
	for _, c := range []struct {
		name  string
		value any
		want  string
	}{
		{"nothing", nil, ""},
		{"a text", "soft", "soft"},
		{"a text with markup is left to the template to escape", "<b>", "<b>"},
		{"true", true, "true"},
		{"false", false, "false"},
		{"a whole number", float64(3), "3"},
		{"a number that has a fraction", 2.5, "2.5"},
		{"a large number without an exponent", float64(12345678901234), "12345678901234"},
		{"a negative number", float64(-7), "-7"},
		{"a number of another type", 42, "42"},
		{"a list", []any{"a", float64(1), true, nil}, "a, 1, true, "},
		{"a list that is empty", []any{}, ""},
		{"a map is sorted by its keys", map[string]any{"b": "2", "a": "1"}, "a: 1, b: 2"},
		{"a map within a list", []any{map[string]any{"x": "1"}, "y"}, "x: 1, y"},
		{"a map that is too deep", deep, "a: b: c: d: e: f: …"},
	} {
		if got := detailText(c.value, 0); got != c.want {
			t.Errorf("%s: detailText(%v) = %q, want %q", c.name, c.value, got, c.want)
		}
	}
	pairs := detailPairs(map[string]any{"z": "last", "a": float64(1), "m": []any{"x", "y"}})
	want := []adminui.DetailPair{{Key: "a", Value: "1"}, {Key: "m", Value: "x, y"}, {Key: "z", Value: "last"}}
	if !slices.Equal(pairs, want) {
		t.Errorf("detailPairs = %v, want %v", pairs, want)
	}
	if got := detailPairs(nil); len(got) != 0 {
		t.Errorf("detailPairs(nil) = %v", got)
	}
}

func TestAnIdentifierOfAnAdministratorIsShortenedForTheListsOfRecords(t *testing.T) {
	for id, want := range map[string]string{"": "", "abc": "abc", "12345678": "12345678", "123456789": "12345678", "0198f2a4-7c11-7d44-9b0e-aaaaaaaaaaaa": "0198f2a4"} {
		if got := shorten(id); got != want {
			t.Errorf("shorten(%q) = %q, want %q", id, got, want)
		}
	}
}
