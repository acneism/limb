package limb

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

var (
	ghostAdmin          = "0198f2a4-7c11-7d44-9b0e-aaaaaaaaaaaa"
	auditLabelPattern   = regexp.MustCompile(`</time></td>\n<td>([^<]+)</td>\n<td class="break">`)
	detailNumberPattern = regexp.MustCompile(`<span class="muted">n</span> (\d+)`)
)

func seedAudit(t *testing.T) *peopleFixture {
	t.Helper()
	f := newPeopleFixture(t)
	f.add("ann")
	f.add("bob")
	ann, bob, admin := string(f.ids["ann"]), string(f.ids["bob"]), f.adminID()
	f.record(audit.Entry{Actor: adminActor(admin), Action: audit.UserBlocked, TargetUserID: ann, IP: "198.51.100.1", Details: map[string]any{"reason": "first <b>"}})
	f.clock.advance(24 * time.Hour)
	f.record(audit.Entry{Actor: adminActor(ghost()), Action: audit.UserUnblocked, TargetUserID: ann, IP: "198.51.100.2"})
	f.clock.advance(24 * time.Hour)
	f.record(audit.Entry{Actor: audit.CLI, Action: audit.UserDeleted, TargetUserID: bob, Details: map[string]any{"mode": "soft"}})
	f.clock.advance(24 * time.Hour)
	f.record(audit.Entry{Actor: adminActor(admin), Action: audit.SettingChanged, IP: "198.51.100.3", Details: map[string]any{"name": "password_to_end_sessions", "new": "true"}})
	f.clock.advance(24 * time.Hour)
	f.record(audit.Entry{Actor: audit.Actor{Kind: store.ActorUser, ID: bob}, Action: audit.AuthPrefix + string(EventLogin), TargetUserID: bob, IP: "203.0.113.9", Details: map[string]any{"kind": "cookie"}})
	old := store.AuditRecord{
		TenantID: f.a.tenant, ID: "00000000-0000-7000-8000-000000000555", At: f.clock.now(), ActorKind: store.ActorSystem, Action: "old.action", Details: "plain words",
	}
	if err := f.a.store.Audit().Add(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	f.enroll()
	return f
}

func ghost() string {
	return ghostAdmin
}

func (f *peopleFixture) auditLabels(query string) []string {
	f.t.Helper()
	r := f.get("/audit" + query)
	if r.StatusCode != http.StatusOK {
		f.t.Fatalf("GET /audit%s = %d: %.300s", query, r.StatusCode, r.body)
	}
	var labels []string
	for _, m := range auditLabelPattern.FindAllStringSubmatch(r.body, -1) {
		labels = append(labels, m[1])
	}
	return labels
}

func TestTheAuditLogIsAPageForASessionThatOnlyReads(t *testing.T) {
	f := newPeopleFixture(t)
	if r := f.get("/audit"); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/login" {
		t.Fatalf("the log for a visitor is %d %q", r.StatusCode, r.location())
	}
	f.enroll()
	page := f.get("/audit")
	for _, want := range []string{
		`<h1 class="h1">Audit log</h1>`, `<a href="/admin/audit">Audit log</a>`, `<form method="get" action="/admin/audit"`, `name="user"`, `name="admin"`, `name="action"`,
		`name="from"`, `name="to"`, `name="limit"`, `<option value="" selected>Any administrator</option>`, `<option value="" selected>Any action</option>`, `>root</option>`,
		`<option value="user.blocked">User blocked</option>`, `<option value="50" selected>50</option>`, "<td>Administrator signed in</td>", "<td>Authenticator bound</td>",
	} {
		if page.StatusCode != http.StatusOK || !page.has(want) {
			t.Errorf("the log is %d and lacks %q", page.StatusCode, want)
		}
	}
	if home := f.get("/"); !home.has(`<a href="/admin/audit">Audit log</a>`) {
		t.Errorf("the start page does not lead to the log")
	}
	if r := f.request(http.MethodHead, "/audit"); r.StatusCode != http.StatusOK || r.body != "" {
		t.Errorf("HEAD of the log = %d with %d bytes", r.StatusCode, len(r.body))
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if r := f.request(method, "/audit"); r.StatusCode != http.StatusMethodNotAllowed || r.Header.Get("Allow") != "GET, HEAD" {
			t.Errorf("%s /audit = %d with Allow %q: the log cannot be changed", method, r.StatusCode, r.Header.Get("Allow"))
		}
	}
	for _, path := range []string{"/audit/", "/audit/1", "/audit/delete", "/audit/export"} {
		if r := f.get(path); r.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d", path, r.StatusCode)
		}
	}
}

func TestTheAuditLogShowsWhoDidWhatToWhomWhenAndFromWhereNewestFirst(t *testing.T) {
	f := seedAudit(t)
	ann, bob := string(f.ids["ann"]), string(f.ids["bob"])
	page := f.get("/audit?limit=200")
	for _, want := range []string{
		"<td>User blocked</td>\n<td class=\"break\">root</td>", `<a href="/admin/users/` + ann + `">` + ann + `</a>`, `<td>198.51.100.1</td>`,
		`<span class="muted">reason</span> first &lt;b&gt;`, "<td>User unblocked</td>\n<td class=\"break\">deleted administrator 0198f2a4</td>", "<td>User deleted</td>\n<td class=\"break\">command line</td>",
		`<span class="muted">mode</span> soft`, "<td>Setting changed</td>\n<td class=\"break\">root</td>", `<span class="muted">name</span> password_to_end_sessions`,
		"<td>Signed in</td>\n<td class=\"break\">the user</td>", `<a href="/admin/users/` + bob + `">` + bob + `</a>`, `<td>203.0.113.9</td>`,
		"<td>old.action</td>\n<td class=\"break\">unknown</td>", `<span class="muted">text</span> plain words`, "<td>Administrator signed in</td>", "<td>Authenticator bound</td>",
	} {
		if !page.has(want) {
			t.Errorf("the log lacks %q", want)
		}
	}
	if strings.Contains(page.body, "<b>") {
		t.Errorf("a text of a record is not escaped")
	}
	order := []string{"Signed in", "Setting changed", "User deleted", "User unblocked", "User blocked"}
	last := -1
	for _, label := range order {
		at := strings.Index(page.body, "<td>"+label+"</td>")
		if at < 0 || at < last {
			t.Errorf("%q is at %d, after %d: the newest record is the first", label, at, last)
		}
		last = max(last, at)
	}
}

func TestTheAuditLogIsFilteredByUserAdministratorActionAndPeriod(t *testing.T) {
	f := seedAudit(t)
	ann, bob, admin := string(f.ids["ann"]), string(f.ids["bob"]), f.adminID()
	for _, c := range []struct {
		name, query string
		want        []string
	}{
		{"a user", "?user=" + ann, []string{"User unblocked", "User blocked", "Account created"}},
		{"another user", "?user=" + bob, []string{"Signed in", "User deleted", "Account created"}},
		{"a user that has nothing", "?user=no-such-user", nil},
		{"an administrator", "?admin=" + admin + "&action=user.blocked", []string{"User blocked"}},
		{"an administrator that was deleted", "?admin=" + ghost(), []string{"User unblocked"}},
		{"an action", "?action=user.deleted", []string{"User deleted"}},
		{"an action of the sign-ins", "?action=auth.login", []string{"Signed in"}},
		{"a user and an action", "?user=" + ann + "&action=user.blocked", []string{"User blocked"}},
		{"a user and an action that is not theirs", "?user=" + bob + "&action=user.blocked", nil},
		{"an administrator and a user", "?admin=" + admin + "&user=" + ann, []string{"User blocked"}},
		{"a day, both of its ends", "?from=2026-09-13&to=2026-09-13&action=user.unblocked", []string{"User unblocked"}},
		{"before a day", "?to=2026-09-11&user=" + ann, []string{"Account created"}},
		{"from a day on", "?from=2026-09-14&action=user.deleted", []string{"User deleted"}},
		{"after the day of the record", "?from=2026-09-15&action=user.deleted", nil},
		{"until the day before the record", "?to=2026-09-13&action=user.deleted", nil},
		{"a period that has no record of the action", "?from=2026-09-13&to=2026-09-16&action=user.blocked", nil},
		{"the largest page", "?limit=200&action=user.blocked", []string{"User blocked"}},
	} {
		if got := f.auditLabels(c.query); !slices.Equal(got, c.want) {
			t.Errorf("%s: GET /audit%s lists %v, want %v", c.name, c.query, got, c.want)
		}
	}
	if r := f.get("/audit?user=" + ann + "&action=user.blocked&admin=" + admin + "&from=2026-09-10&to=2026-09-10&limit=25"); !r.has(`value="`+ann+`"`) ||
		!r.has(`<option value="user.blocked" selected>User blocked</option>`) || !r.has(`<option value="`+admin+`" selected>root</option>`) || !r.has(`name="from" type="date" class="input" value="2026-09-10"`) ||
		!r.has(`name="to" type="date" class="input" value="2026-09-10"`) || !r.has(`<option value="25" selected>25</option>`) {
		t.Errorf("the form does not keep what was asked for: %.2500s", r.body)
	}
	if r := f.get("/audit?user=no-such-user"); !r.has("No record matches.") || r.has("The audit log is empty.") {
		t.Errorf("a search that finds nothing does not say so")
	}
	if r := f.get("/audit?admin=" + ghost()); !r.has(`<option value="` + ghost() + `" selected>deleted administrator 0198f2a4</option>`) {
		t.Errorf("an administrator that was deleted is not in the list of those that can be asked for")
	}
}

func TestTheAuditLogIsReadPageByPageWithTheCursor(t *testing.T) {
	f := newPeopleFixture(t)
	f.add("ann")
	ann := string(f.ids["ann"])
	for i := range 25 {
		f.record(audit.Entry{Actor: audit.API, Action: audit.UserBlocked, TargetUserID: ann, Details: map[string]any{"n": i}})
		f.clock.advance(time.Second - time.Minute)
	}
	f.enroll()
	path := "/audit?limit=10&action=user.blocked"
	var seen []string
	sizes := []int{}
	for page := 1; path != ""; page++ {
		r := f.get(path)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d: %.300s", path, r.StatusCode, r.body)
		}
		var numbers []string
		for _, m := range detailNumberPattern.FindAllStringSubmatch(r.body, -1) {
			numbers = append(numbers, m[1])
		}
		seen, sizes = append(seen, numbers...), append(sizes, len(numbers))
		if first := hrefTo(t, r, "First page"); (page == 1) != (first == "") || strings.Contains(first, "cursor=") {
			t.Errorf("page %d: the link to the first page is %q", page, first)
		}
		path = hrefTo(t, r, "Next page")
		if page > 3 {
			t.Fatal("more than three pages")
		}
	}
	want := make([]string, 0, 25)
	for i := 24; i >= 0; i-- {
		want = append(want, strconv.Itoa(i))
	}
	if !slices.Equal(seen, want) || !slices.Equal(sizes, []int{10, 10, 5}) {
		t.Errorf("the pages hold %v records, the records are %v, want every one once, the newest first: %v", sizes, seen, want)
	}
}

func TestWrongValuesInTheQueryOfTheAuditLogAreRefusedAndTheFormKeepsTheRest(t *testing.T) {
	f := seedAudit(t)
	for query, labels := range map[string]string{
		"?user=a%20b":                          "User (ID)",
		"?user=" + url.QueryEscape("<b>x</b>"): "User (ID)",
		"?user=" + strings.Repeat("a", 65):     "User (ID)",
		"?admin=a/b":                           "Administrator",
		"?action=user.invented":                "Action",
		"?from=2026-13-40":                     "From (a day, UTC)",
		"?to=yesterday":                        "Until (a day, UTC)",
		"?to=10000-01-01":                      "Until (a day, UTC)",
		"?limit=7":                             "On a page",
		"?limit=abc":                           "On a page",
		"?cursor=" + strings.Repeat("a", 513):  "the page",
		"?cursor=junk":                         "the page",
		"?cursor=" + url.QueryEscape("e30"):    "the page",
		"?user=a%20b&action=nope&from=x":       "User (ID), Action, From (a day, UTC)",
	} {
		r := f.get("/audit" + query)
		if r.StatusCode != http.StatusBadRequest || !r.has("A value in the search is not valid: "+labels+".") || len(auditLabelPattern.FindAllString(r.body, -1)) != 0 {
			t.Errorf("GET /audit%.60s = %d, want 400 that names %q and lists nothing", query, r.StatusCode, labels)
		}
		if !r.has(`name="user"`) || !r.has(`name="limit"`) {
			t.Errorf("GET /audit%.60s does not show the form again", query)
		}
	}
	if r := f.get("/audit?user=a%20b&action=user.blocked"); !r.has(`<option value="user.blocked" selected>`) {
		t.Errorf("the form of a refused query lost what was valid")
	}
	for _, query := range []string{"?user=", "?admin=", "?action=", "?from=&to=", "?limit=", "?cursor=", "?unknown=1", "?user=%20"} {
		if got := f.auditLabels(query); len(got) == 0 {
			t.Errorf("GET /audit%s lists nothing: an empty value asks for nothing", query)
		}
	}
}

func TestTheAuditLogIsInTheLanguageOfTheAdministratorAndTheCardLeadsToItsRecords(t *testing.T) {
	f := seedAudit(t)
	ann := string(f.ids["ann"])
	card := f.card("ann")
	if !card.has(`<a href="/admin/audit?user=` + ann + `">All the records of this user</a>`) {
		t.Fatalf("the card has no link to the records of the user")
	}
	if r := f.get("/audit?user=" + ann + "&lang=ru"); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/audit?user="+ann {
		t.Fatalf("the switch of the language on the log is %d %q", r.StatusCode, r.location())
	}
	ru := f.get("/audit?user=" + ann)
	for _, want := range []string{`<html lang="ru">`, "Журнал аудита", "Пользователь заблокирован", "удалённый администратор 0198f2a4", "Любое действие", "Применить", "Любой администратор"} {
		if !ru.has(want) {
			t.Errorf("the Russian log lacks %q", want)
		}
	}
	if r := f.get("/audit?user=nobody"); !r.has("Ни одна запись не подошла.") {
		t.Errorf("the Russian log does not say that nothing matches")
	}
	f.get("/audit?lang=en")
	if r := f.get("/audit?admin=" + ghost() + "&limit=10"); !r.has(`href="?admin=` + ghost() + `&amp;lang=ru&amp;limit=10"`) {
		t.Errorf("the link to another language loses the query")
	}
}

func TestWhatAnAdministratorDoesThroughTheBrowserIsInTheLogUnderTheirNameAndAddress(t *testing.T) {
	f := seedPeople(t)
	id := string(f.ids["ann"])
	if r := f.act("ann", "block", url.Values{"reason": {"seen in the log"}}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("the block gave %d", r.StatusCode)
	}
	f.clock.advance(time.Second)
	if r := f.act("ann", "unblock", url.Values{}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("lifting the block gave %d", r.StatusCode)
	}
	page := f.get("/audit?admin=" + f.adminID() + "&user=" + id)
	for _, want := range []string{"<td>User unblocked</td>\n<td class=\"break\">root</td>", "<td>User blocked</td>\n<td class=\"break\">root</td>", "<td>127.0.0.1</td>", `<span class="muted">reason</span> seen in the log`} {
		if !page.has(want) {
			t.Errorf("the log of what the administrator did lacks %q", want)
		}
	}
	if got := f.auditLabels("?admin=" + f.adminID() + "&limit=200"); !slices.Contains(got, "Administrator signed in") || !slices.Contains(got, "User blocked") || !slices.Contains(got, "Authenticator bound") {
		t.Errorf("the log of the administrator is %v: the sign-in is among their actions too", got)
	}
}

func TestAFailureOfTheStoreOnTheAuditLogIsAnErrorPage(t *testing.T) {
	f, faults, logs := newFaultyWebFixture(t)
	f.enroll()
	ghostID := ghost()
	if err := f.a.auditWriter().Add(t.Context(), f.a.store.Audit(), audit.Entry{Actor: adminActor(ghostID), Action: audit.SettingChanged}); err != nil {
		t.Fatal(err)
	}
	if r := f.get("/audit"); r.StatusCode != http.StatusOK || !r.has("deleted administrator 0198f2a4") {
		t.Fatalf("the log without a failure is %d", r.StatusCode)
	}
	for _, name := range []string{"audit.list", "admins.list", "admins.get:" + ghostID} {
		faults.clear()
		faults.set(name, errors.New("down: "+name))
		r := f.get("/audit")
		if r.StatusCode != http.StatusInternalServerError || !r.has("Something went wrong") || r.has("down: "+name) || !strings.Contains(logs.String(), "down: "+name) {
			t.Errorf("a failure of %s gave %d", name, r.StatusCode)
		}
	}
}

func TestTheDaysOfTheAuditLogAreTurnedIntoTheMomentsOfTheFilter(t *testing.T) {
	q := parseAuditQuery(url.Values{"from": {"2026-09-12"}, "to": {"2026-09-14"}, "user": {" ann "}, "action": {"user.blocked"}, "limit": {"25"}})
	if len(q.invalid) != 0 {
		t.Fatalf("the query is refused: %v", q.invalid)
	}
	f := q.filter()
	if !f.From.Equal(time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)) || !f.To.Equal(time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)) || f.UserID != "ann" || f.Limit != 25 || !slices.Equal(f.Actions, []string{"user.blocked"}) {
		t.Errorf("the filter is %+v", f)
	}
	if got := parseAuditQuery(url.Values{}).filter(); got.Limit != defaultAuditPage || got.Actions != nil || !got.From.IsZero() || !got.To.IsZero() {
		t.Errorf("the filter of an empty query is %+v", got)
	}
}
