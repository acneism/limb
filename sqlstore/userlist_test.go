package sqlstore

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func TestTheListOfUsersEscapesWhatLikeWouldTakeForAPattern(t *testing.T) {
	for in, want := range map[string]string{"plain": "plain", "a_b": "a!_b", "50%": "50!%", "a!b": "a!!b", "!_%": "!!!_!%", `a\b`: `a\b`, "": ""} {
		if got := likeEscaper.Replace(in); got != want {
			t.Errorf("%q is escaped as %q, want %q", in, got, want)
		}
	}
}

func TestTheListOfUsersNumbersItsParametersInTheOrderOfTheConditions(t *testing.T) {
	probe, db := newStub(t, nil)
	s, err := New(db, Oracle)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	confirmed := true
	_, err = s.Users().List(t.Context(), store.UserQuery{
		TenantID: "t", Statuses: []store.Status{store.StatusActive, store.StatusBlocked}, CreatedVia: store.CreatedViaSignup,
		CreatedFrom: at, CreatedBefore: at.Add(time.Hour), LastLoginFrom: at, LastLoginBefore: at.Add(time.Hour), NeverLoggedIn: true,
		PurgeBefore: at, BlockedBefore: at, Confirmed: &confirmed, Identifiers: []store.IdentifierRef{{Type: "email", Value: "a@example.com"}, {Type: "nick", Value: "a"}},
		ValuePrefix: "a_", After: &store.User{ID: "u", CreatedAt: at}, Descending: true, Limit: 11,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(probe.queries) != 1 {
		t.Fatalf("the listing ran %d statements", len(probe.queries))
	}
	query := probe.queries[0]
	found := regexp.MustCompile(`:\d+`).FindAllString(query, -1)
	if len(found) != 18 || strings.Contains(query, "?") {
		t.Fatalf("the query has %d parameters, want 18, or a mark that was not replaced:\n%s", len(found), query)
	}
	for n, mark := range found {
		if mark != fmt.Sprintf(":%d", n+1) {
			t.Fatalf("the parameter %d is written %s:\n%s", n+1, mark, query)
		}
	}
	if !strings.HasSuffix(query, " ORDER BY u.created_at DESC, u.id DESC FETCH FIRST 11 ROWS ONLY") {
		t.Fatalf("the query does not end with the order and the limit of the dialect:\n%s", query)
	}
	if !strings.Contains(query, "ESCAPE '!'") {
		t.Fatalf("the prefix is not matched with the escape character:\n%s", query)
	}
}

func TestTheListOfUsersReportsFailures(t *testing.T) {
	broken := errors.New("the database is gone")
	probe, s := stubbedSettings(t, func(string, int) error { return broken })
	if _, err := s.Users().List(t.Context(), store.UserQuery{TenantID: store.DefaultTenant, Limit: 5}); !errors.Is(err, broken) {
		t.Fatalf("List = %v, want the failure of the database", err)
	}
	probe.script = nil
	probe.rows = func(string, int) ([]string, [][]driver.Value) {
		return []string{"tenant_id"}, [][]driver.Value{{"default"}}
	}
	if _, err := s.Users().List(t.Context(), store.UserQuery{TenantID: store.DefaultTenant, Limit: 5}); err == nil {
		t.Fatal("List must report a row that does not have the columns of a user")
	}
}

func TestTheOrderOfALastSignInKeepsTheUsersWhoNeverSignedInAtTheEnd(t *testing.T) {
	for _, descending := range []bool{false, true} {
		order := userOrdering(store.UserQuery{Order: store.OrderUsersByLastLogin, Descending: descending})
		if !strings.HasPrefix(order.by, "CASE WHEN u.last_login_at IS NULL THEN 1 ELSE 0 END, ") {
			t.Fatalf("the users who never signed in must come last in both directions: %s", order.by)
		}
	}
	signedIn := userOrdering(store.UserQuery{Order: store.OrderUsersByLastLogin, After: &store.User{ID: "u", LastLoginAt: time.Now()}})
	never := userOrdering(store.UserQuery{Order: store.OrderUsersByLastLogin, After: &store.User{ID: "u"}})
	if len(signedIn.args) != 3 || len(never.args) != 1 || !strings.Contains(signedIn.after, "OR u.last_login_at IS NULL") || strings.Contains(never.after, "IS NOT NULL") {
		t.Fatalf("the cursors differ in what they continue with:\n%+v\n%+v", signedIn, never)
	}
}
