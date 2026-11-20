package limb

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

func (f *peopleFixture) card(name string) webResponse {
	f.t.Helper()
	return f.get("/users/" + string(f.ids[name]))
}

func (f *peopleFixture) adminID() string {
	f.t.Helper()
	found, err := f.a.store.Admins().FindByLogin(f.t.Context(), f.a.tenant, adminLoginName)
	if err != nil {
		f.t.Fatal(err)
	}
	return found.ID
}

func (f *peopleFixture) record(entry audit.Entry) {
	f.t.Helper()
	if err := f.a.auditWriter().Add(f.t.Context(), f.a.store.Audit(), entry); err != nil {
		f.t.Fatalf("writing the record %+v failed: %v", entry, err)
	}
	f.clock.advance(time.Minute)
}

func indexOf(t *testing.T, page webResponse, text string) int {
	t.Helper()
	at := strings.Index(page.body, text)
	if at < 0 {
		t.Fatalf("the page lacks %q: %.600s", text, page.body)
	}
	return at
}

func TestTheCardOfAUserIsAPageForASessionThatFindsOnlyTheUsersThatThereAre(t *testing.T) {
	f := seedPeople(t)
	signedOut := f.newBrowser()
	if r := signedOut.get("/users/" + string(f.ids["ann"])); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/login" {
		t.Fatalf("the card for a visitor is %d %q", r.StatusCode, r.location())
	}
	if r := f.request(http.MethodHead, "/users/"+string(f.ids["ann"])); r.StatusCode != http.StatusOK || r.body != "" {
		t.Errorf("HEAD of a card = %d with %d bytes", r.StatusCode, len(r.body))
	}
	for _, path := range []string{
		"/users/no-such-user", "/users/" + strings.Repeat("a", 36), "/users/" + strings.Repeat("a", store.MaxIDLength+1), "/users/a/b", "/users/a%20b", "/users/a.b",
		"/users/%00", "/users/" + string(f.ids["ann"]) + "/", "/users/" + string(f.ids["ann"]) + "/other",
	} {
		if r := f.get(path); r.StatusCode != http.StatusNotFound || !r.has("Page not found") || r.has(string(f.ids["ann"])) {
			t.Errorf("GET %s = %d, want the page that is not there", path, r.StatusCode)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if r := f.request(method, "/users/"+string(f.ids["ann"])); r.StatusCode != http.StatusMethodNotAllowed || r.Header.Get("Allow") != "GET, HEAD" {
			t.Errorf("%s of a card = %d with Allow %q", method, r.StatusCode, r.Header.Get("Allow"))
		}
	}
}

func TestTheCardOfAUserShowsTheAccountTheValuesTheyCameWithAndTheDates(t *testing.T) {
	f := seedPeople(t)
	id := string(f.ids["eve"])
	page := f.card("eve")
	if page.StatusCode != http.StatusOK {
		t.Fatalf("the card is %d: %.300s", page.StatusCode, page.body)
	}
	for _, want := range []string{
		`<title>eve@example.com · limb</title>`, `<h1 class="h1 break">eve@example.com</h1>`, `<a href="/admin/users">← All users</a>`, `<code class="break">` + id + `</code>`,
		`<span class="badge badge-active">Active</span>`, `<dt>Created</dt>`, `<time datetime="2026-09-14T11:12:13Z">2026-09-14 11:12 UTC</time>`,
		`<dt>Origin</dt>`, `<dd>Application code</dd>`, `<dt>Last sign-in</dt>`, `<time datetime="2026-09-15T08:00:00Z">`,
		`<td>email</td>`, `<td class="break">eve@example.com</td>`, `<td>username</td>`, `<td class="break">eve</td>`,
		`<time datetime="2026-09-10T11:12:13Z">2026-09-10 11:12 UTC</time>`, `<span class="muted">not confirmed</span>`,
		"The user has no session in use.", "Nobody signed in as this user yet.", `<a href="/admin/users">Users</a>`,
	} {
		if !page.has(want) {
			t.Errorf("the card lacks %q", want)
		}
	}
	for _, unwanted := range []string{"Reason of the block", "Removed for good after", "has to be changed", "<script"} {
		if page.has(unwanted) {
			t.Errorf("the card of an active user has %q", unwanted)
		}
	}
	if got := strings.Count(page.body, "<time datetime="); got != 4 {
		t.Errorf("%d moments are shown, want the creation, the last sign-in, the confirmation of the address and the creation in the journal", got)
	}
}

func TestTheCardOfAUserSaysWhyAndUntilWhenAccountIsBlockedAndWhenItWillBeRemoved(t *testing.T) {
	f := seedPeople(t)
	gus := f.card("gus")
	for _, want := range []string{
		`<span class="badge badge-blocked">Blocked</span>`, "Reason of the block", `<span class="muted">none given</span>`, "The block ends",
		`<time datetime="2026-10-01T00:00:00Z">2026-10-01 00:00 UTC</time>`,
	} {
		if !gus.has(want) {
			t.Errorf("the card of a user blocked until a day lacks %q", want)
		}
	}
	cara := f.card("cara")
	for _, want := range []string{`<dd class="break">spam</dd>`, "never, until an administrator lifts it"} {
		if !cara.has(want) {
			t.Errorf("the card of a user blocked without an end lacks %q", want)
		}
	}
	dan := f.card("dan")
	for _, want := range []string{
		`<span class="badge badge-deleted">Deleted</span>`, "<dt>Deleted</dt>", `<time datetime="2026-09-10T11:12:13Z">`, "Removed for good after",
		`<time datetime="2026-10-10T11:12:13Z">`,
	} {
		if !dan.has(want) {
			t.Errorf("the card of a deleted user lacks %q", want)
		}
	}
	if dan.has("Reason of the block") {
		t.Errorf("a deleted user has a block")
	}
	created, err := f.a.Admin().CreateUser(t.Context(), NewUser{Identifiers: map[string]string{"email": "temp@example.com", "username": "temp"}, Password: goodPassword})
	if err != nil {
		t.Fatal(err)
	}
	if r := f.get("/users/" + string(created.ID)); !r.has("has to be changed at the next sign-in") || !r.has("<dd>Administrator</dd>") {
		t.Errorf("the card of a user whom an administrator made with a password does not say that: %.500s", r.body)
	}
	if bob := f.card("bob"); bob.has("has to be changed") || !bob.has("<dd>Administrator</dd>") {
		t.Errorf("the card of a user who keeps the password says that it has to be changed")
	}
}

func TestWhatAUserAdministratorAndSystemDidIsShownOnTheCardWithWhoDidIt(t *testing.T) {
	f := seedPeople(t)
	ann := string(f.ids["ann"])
	admin := f.adminID()
	ghost := "0198f2a4-7c11-7d44-9b0e-aaaaaaaaaaaa"
	f.record(audit.Entry{Actor: adminActor(admin), Action: audit.UserBlocked, TargetUserID: ann, IP: "198.51.100.1", Details: map[string]any{"reason": "first <b>", "until": "2026-10-01T00:00:00Z"}})
	f.record(audit.Entry{Actor: adminActor(ghost), Action: audit.UserUnblocked, TargetUserID: ann, IP: "198.51.100.2"})
	f.record(audit.Entry{Actor: audit.CLI, Action: audit.UserDeleted, TargetUserID: ann, Details: map[string]any{"mode": "soft", "count": 3, "ok": true}})
	f.record(audit.Entry{Actor: audit.API, Action: audit.UserRestored, TargetUserID: ann, Details: map[string]any{"list": []any{"a", "b"}, "nested": map[string]any{"x": "1", "y": 2.5}}})
	f.record(audit.Entry{Actor: audit.Maintenance, Action: audit.UserIdentifierChanged, TargetUserID: ann})
	f.record(audit.Entry{Actor: audit.Actor{Kind: store.ActorSystem, ID: "worker-7"}, Action: audit.UserIdentifierAdded, TargetUserID: ann})
	f.record(audit.Entry{Actor: audit.Actor{Kind: store.ActorSystem}, Action: audit.UserInvited, TargetUserID: ann})
	f.record(audit.Entry{Actor: audit.Actor{Kind: store.ActorUser, ID: ann}, Action: audit.AuthPrefix + string(EventPasswordChanged), TargetUserID: ann})
	f.record(audit.Entry{Actor: adminActor(admin), Action: audit.AdminLogin, TargetUserID: ann})
	f.record(audit.Entry{Actor: adminActor(admin), Action: audit.UserBlocked, TargetUserID: string(f.ids["bob"])})
	page := f.card("ann")
	if page.StatusCode != http.StatusOK {
		t.Fatalf("the card is %d: %.300s", page.StatusCode, page.body)
	}
	for _, want := range []string{
		"<td>User blocked</td>\n<td class=\"break\">root</td>", `<td>198.51.100.1</td>`,
		`<span class="ident"><span class="muted">reason</span> first &lt;b&gt;</span>`, `<span class="ident"><span class="muted">until</span> 2026-10-01T00:00:00Z</span>`,
		"<td>User unblocked</td>", "deleted administrator 0198f2a4", "<td>User deleted</td>", "command line",
		`<span class="muted">count</span> 3`, `<span class="muted">mode</span> soft`, `<span class="muted">ok</span> true`, "<td>User restored</td>", "code of the application",
		`<span class="muted">list</span> a, b`, `<span class="muted">nested</span> x: 1, y: 2.5`, "<td>Value to sign in with changed</td>", "maintenance",
		"<td>Value to sign in with added</td>", "worker-7", "<td>User invited</td>", "unknown", "<td>Password changed</td>", "the user",
	} {
		if !page.has(want) {
			t.Errorf("the journal lacks %q", want)
		}
	}
	if page.has("Administrator signed in") || strings.Count(page.body, "<td>User blocked</td>") != 1 {
		t.Errorf("the journal shows what is not about changes of the user, or what was done to another user")
	}
	if strings.Contains(page.body, "<b>") || !strings.Contains(page.body, "&lt;b&gt;") {
		t.Errorf("a text of a record is not escaped")
	}
	order := []string{"Password changed", "User invited", "Value to sign in with added", "Value to sign in with changed", "User restored", "User deleted", "User unblocked", "User blocked"}
	for i := 1; i < len(order); i++ {
		if indexOf(t, page, "<td>"+order[i-1]+"</td>") > indexOf(t, page, "<td>"+order[i]+"</td>") {
			t.Errorf("%q comes after %q: the newest record is the first", order[i-1], order[i])
		}
	}
}

func TestTheCardOfAUserShowsTheSessionsInUseAndTheSignInsNewestFirst(t *testing.T) {
	f := seedPeople(t)
	login := func(password string, kind SessionKind, agent string) {
		_, err := f.a.Login(t.Context(), Credentials{Login: "eve", Password: password, IP: testIP, UserAgent: agent, Kind: kind})
		if password == goodPassword && err != nil {
			t.Fatal(err)
		}
		f.clock.advance(time.Minute)
	}
	login(goodPassword, SessionCookie, `Browser <b>1</b>`)
	login(goodPassword, SessionToken, "App 2")
	login("wrong password", SessionCookie, "App 3")
	eventually(t, "the record of the failed sign-in", func() bool { return len(recordsOf(t, f.a, "auth.login_failed")) == 1 })
	page := f.card("eve")
	for _, want := range []string{
		"<td>cookie</td>", "<td>tokens</td>", "<td>203.0.113.7</td>", `<td class="break">Browser &lt;b&gt;1&lt;/b&gt;</td>`, `<td class="break">App 2</td>`,
		"<td>Signed in</td>", "<td>Failed sign-in</td>", `<span class="muted">kind</span> cookie`, `<span class="muted">kind</span> token`, "<td>Account created</td>",
	} {
		if !page.has(want) {
			t.Errorf("the card lacks %q", want)
		}
	}
	if page.has("The user has no session in use.") || page.has("Nobody signed in as this user yet.") {
		t.Errorf("the card says that there is no session or no sign-in")
	}
	if strings.Count(page.body, "<td>Signed in</td>") != 2 || strings.Count(page.body, "<td>Failed sign-in</td>") != 1 {
		t.Errorf("the sign-ins are not the two and the failed one")
	}
	if indexOf(t, page, "<td>Failed sign-in</td>") > indexOf(t, page, "<td>Signed in</td>") {
		t.Errorf("a sign-in that came before is shown before the failed one")
	}
	if indexOf(t, page, "<td>Account created</td>") < indexOf(t, page, "Changes") {
		t.Errorf("the creation of the account is not among the changes")
	}
	if other := f.card("ann"); other.has("<td>Signed in</td>") || other.has("Failed sign-in") {
		t.Errorf("the sign-ins of Eve are on the card of Ann")
	}
	if err := f.a.Admin().BlockUser(t.Context(), f.ids["eve"], `spam <script>alert(1)</script>`, time.Time{}); err != nil {
		t.Fatal(err)
	}
	blocked := f.card("eve")
	if !blocked.has("User blocked") || !blocked.has("code of the application") || blocked.has("<script") || !blocked.has("spam &lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Errorf("the block by the code of the application is not shown or not escaped: %.800s", blocked.body)
	}
	if !blocked.has("The user has no session in use.") {
		t.Errorf("a block leaves the sessions in use on the card")
	}
}

func TestTheCardIsInTheLanguageOfTheAdministrator(t *testing.T) {
	f := seedPeople(t)
	id := string(f.ids["gus"])
	if r := f.get("/users/" + id + "?lang=ru"); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/users/"+id {
		t.Fatalf("the switch of the language on a card is %d %q", r.StatusCode, r.location())
	}
	ru := f.card("gus")
	for _, want := range []string{
		`<html lang="ru">`, "← Все пользователи", "Учётная запись", "Заблокирован", "Причина блокировки", "не указана", "Блокировка закончится", "Чем пользователь входит",
		"Сессии в работе", "У пользователя нет сессий в работе.", "Изменения", "Происхождение", "Код приложения", `<span class="muted">не подтверждено</span>`,
	} {
		if !ru.has(want) {
			t.Errorf("the Russian card lacks %q", want)
		}
	}
	f.record(audit.Entry{Actor: audit.CLI, Action: audit.UserBlocked, TargetUserID: id})
	if r := f.card("gus"); !r.has("Пользователь заблокирован") || !r.has("командная строка") {
		t.Errorf("a record is not in Russian: %.600s", r.body)
	}
}

func TestAFailureOfTheStoreOnTheCardIsAnErrorPageThatHidesWhyAndTheLogSaysIt(t *testing.T) {
	f, faults, logs := newFaultyWebFixture(t)
	user := mustRegister(t, f.a, map[string]string{"email": "ann@example.com"}, goodPassword)
	ghost := "0198f2a4-7c11-7d44-9b0e-aaaaaaaaaaaa"
	if err := f.a.auditWriter().Add(t.Context(), f.a.store.Audit(), audit.Entry{Actor: adminActor(ghost), Action: audit.UserBlocked, TargetUserID: string(user.ID)}); err != nil {
		t.Fatal(err)
	}
	f.enroll()
	if r := f.get("/users/" + string(user.ID)); r.StatusCode != http.StatusOK || !r.has("deleted administrator 0198f2a4") {
		t.Fatalf("the card without a failure is %d", r.StatusCode)
	}
	for _, name := range []string{"users.get", "identifiers.list", "sessions.list", "audit.list", "admins.get:" + ghost} {
		faults.clear()
		faults.set(name, errors.New("down: "+name))
		r := f.get("/users/" + string(user.ID))
		if r.StatusCode != http.StatusInternalServerError || !r.has("Something went wrong") || r.has("down: "+name) || r.has("ann@example.com") {
			t.Errorf("a failure of %s gave %d with %.200s", name, r.StatusCode, r.body)
		}
		if !strings.Contains(logs.String(), "down: "+name) {
			t.Errorf("the log does not say that %s failed", name)
		}
	}
	faults.clear()
	faults.set("users.get", errors.New("gone"))
	if r := f.get("/users"); r.StatusCode != http.StatusOK {
		t.Errorf("the list of users depends on the card: %d", r.StatusCode)
	}
}
func TestRoutesWithAnIdentifierMatchOnlyAValidIdentifier(t *testing.T) {
	longest := strings.Repeat("a", store.MaxIDLength)
	for _, c := range []struct {
		pattern, path, id string
		ok                bool
	}{
		{"/users", "/users", "", true},
		{"/users", "/users/", "", false},
		{"/users/{id}", "/users/abc", "abc", true},
		{"/users/{id}", "/users/AbC-1_2", "AbC-1_2", true},
		{"/users/{id}", "/users/" + longest, longest, true},
		{"/users/{id}", "/users/" + longest + "a", "", false},
		{"/users/{id}", "/users/", "", false},
		{"/users/{id}", "/users", "", false},
		{"/users/{id}", "/user/abc", "", false},
		{"/users/{id}", "/users/a/b", "", false},
		{"/users/{id}", "/users/a b", "", false},
		{"/users/{id}", "/users/a.b", "", false},
		{"/users/{id}", "/users/%41", "", false},
		{"/users/{id}", "/users/é", "", false},
		{"/users/{id}", "/users/abc/block", "", false},
		{"/users/{id}/block", "/users/abc/block", "abc", true},
		{"/users/{id}/block", "/users//block", "", false},
		{"/users/{id}/block", "/users/block", "", false},
		{"/users/{id}/block", "/users/abc/unblock", "", false},
		{"/users/{id}/block", "/users/abc/block/x", "", false},
		{"/users/{id}/block", "/users/a/b/block", "", false},
	} {
		if id, ok := matchRoute(c.pattern, c.path); id != c.id || ok != c.ok {
			t.Errorf("matchRoute(%q, %q) = %q, %v, want %q, %v", c.pattern, c.path, id, ok, c.id, c.ok)
		}
	}
	f := seedPeople(t)
	for name, id := range f.ids {
		if !validPathID(string(id)) {
			t.Errorf("the identifier of %s, %q, would not be taken in a path", name, id)
		}
	}
}
