package limb

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/internal/adminui"
	"github.com/acneism/limb/store"
)

var (
	userLinkPattern = regexp.MustCompile(`href="/admin/users/([A-Za-z0-9_-]+)"`)
	headPattern     = regexp.MustCompile(`<th scope="col" aria-sort="([a-z]+)"><a href="([^"]+)">([^<]+)</a></th>`)
)

type peopleFixture struct {
	*webFixture
	start time.Time
	ids   map[string]UserID
	names map[UserID]string
}

func newPeopleFixture(t *testing.T, opts ...Option) *peopleFixture {
	t.Helper()
	web := newWebFixture(t, append([]Option{emailAndUsername()}, opts...)...)
	return &peopleFixture{webFixture: web, start: web.clock.now(), ids: map[string]UserID{}, names: map[UserID]string{}}
}

func (f *peopleFixture) add(name string) {
	f.t.Helper()
	user := mustRegister(f.t, f.a, map[string]string{"email": name + "@example.com", "username": name}, goodPassword)
	f.ids[name], f.names[user.ID] = user.ID, name
	f.clock.advance(24 * time.Hour)
}

func (f *peopleFixture) addByAdministrator(name string) {
	f.t.Helper()
	user, err := f.a.Admin().CreateUser(f.t.Context(), NewUser{
		Identifiers: map[string]string{"email": name + "@example.com", "username": name}, Password: goodPassword, KeepPassword: true,
	})
	if err != nil {
		f.t.Fatalf("CreateUser(%s) failed: %v", name, err)
	}
	f.ids[name], f.names[user.ID] = user.ID, name
	f.clock.advance(24 * time.Hour)
}

func (f *peopleFixture) change(name string, edit func(*store.User)) {
	f.t.Helper()
	u, err := f.a.store.Users().Get(f.t.Context(), f.a.tenant, string(f.ids[name]))
	if err != nil {
		f.t.Fatal(err)
	}
	edit(&u)
	if _, err = f.a.store.Users().Update(f.t.Context(), u); err != nil {
		f.t.Fatal(err)
	}
}

func (f *peopleFixture) namesIn(r webResponse) []string {
	f.t.Helper()
	var names []string
	for _, m := range userLinkPattern.FindAllStringSubmatch(r.body, -1) {
		if m[1] == "new" {
			continue
		}
		name, known := f.names[UserID(m[1])]
		if !known {
			f.t.Fatalf("the page links the user %q that nobody made", m[1])
		}
		names = append(names, name)
	}
	return names
}

func (f *peopleFixture) listed(query string) []string {
	f.t.Helper()
	r := f.get("/users" + query)
	if r.StatusCode != http.StatusOK {
		f.t.Fatalf("GET /users%s = %d: %.300s", query, r.StatusCode, r.body)
	}
	return f.namesIn(r)
}

func seedPeople(t *testing.T) *peopleFixture {
	t.Helper()
	f := newPeopleFixture(t)
	f.add("ann")
	f.addByAdministrator("bob")
	for _, name := range []string{"cara", "dan", "eve", "fifty", "gus"} {
		f.add(name)
	}
	f.change("bob", func(u *store.User) { u.LastLoginAt = time.Date(2026, 9, 12, 20, 0, 0, 0, time.UTC) })
	f.change("cara", func(u *store.User) { u.Status, u.BlockedReason = store.StatusBlocked, "spam" })
	f.change("dan", func(u *store.User) {
		u.Status, u.DeletedAt, u.PurgeAfter = store.StatusDeleted, f.start, f.start.Add(30*24*time.Hour)
	})
	f.change("eve", func(u *store.User) { u.LastLoginAt = time.Date(2026, 9, 15, 8, 0, 0, 0, time.UTC) })
	f.change("gus", func(u *store.User) {
		u.Status, u.BlockedUntil = store.StatusBlocked, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	})
	if err := f.a.store.Identifiers().MarkVerified(t.Context(), f.a.tenant, "email", "eve@example.com", f.start); err != nil {
		t.Fatal(err)
	}
	f.enroll()
	return f
}

func reversed(names []string) []string {
	out := slices.Clone(names)
	slices.Reverse(out)
	return out
}

func TestTheListOfUsersIsAPageForASession(t *testing.T) {
	f := newPeopleFixture(t)
	if r := f.get("/users"); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/login" {
		t.Fatalf("the list for a visitor is %d %q", r.StatusCode, r.location())
	}
	f.enroll()
	page := f.get("/users")
	for _, want := range []string{
		`<h1 class="h1">Users</h1>`, `<a href="/admin/users">Users</a>`, `<form method="get" action="/admin/users"`, `name="q"`,
		`name="status" value="active"`, `name="status" value="blocked"`, `name="status" value="deleted"`, `name="confirmed"`, `name="via"`,
		`name="created_from"`, `name="created_to"`, `name="login_from"`, `name="login_to"`, `name="never"`, `name="order"`, `name="dir"`,
		`name="limit"`, "There are no users yet.",
	} {
		if page.StatusCode != http.StatusOK || !page.has(want) {
			t.Errorf("the list is %d and lacks %q", page.StatusCode, want)
		}
	}
	if page.has("<script") || page.has("Nobody matches.") {
		t.Errorf("the empty list has a script or says that nobody matches: %.300s", page.body)
	}
	if r := f.request(http.MethodHead, "/users"); r.StatusCode != http.StatusOK || r.body != "" {
		t.Errorf("HEAD of the list = %d with %d bytes", r.StatusCode, len(r.body))
	}
	if r := f.get("/users?status=active"); !r.has("There are no users yet.") && !r.has("Nobody matches.") {
		t.Errorf("a list without users says nothing about it")
	}
	if r := f.get("/users?q=nobody@example.com"); !r.has("Nobody matches.") || r.has("There are no users yet.") {
		t.Errorf("a search that finds nobody does not say so: %.300s", r.body)
	}
}

func TestTheListShowsWhatEveryUserSignsInWithTheirStatusAndDates(t *testing.T) {
	f := seedPeople(t)
	page := f.get("/users")
	want := []string{"gus", "fifty", "eve", "dan", "cara", "bob", "ann"}
	if got := f.namesIn(page); page.StatusCode != http.StatusOK || !slices.Equal(got, want) {
		t.Fatalf("the list is %d with %v, want the newest first: %v", page.StatusCode, got, want)
	}
	for _, text := range []string{
		"ann@example.com", `<span class="muted">email</span>`, `<span class="muted">username</span>`, `badge badge-active">Active`,
		`badge badge-blocked">Blocked`, `badge badge-deleted">Deleted`, `<time datetime="2026-10-01T00:00:00Z">2026-10-01 00:00 UTC</time>`,
		`<span class="muted">until <time datetime="2026-10-01T00:00:00Z">`, `<time datetime="2026-09-12T20:00:00Z">`, `<span class="muted">never</span>`, "Application code", "Administrator",
		`<time datetime="2026-09-10T11:12:13Z">`, `<span class="sr-only">confirmed</span>`, `aria-label="Open the user ann@example.com"`,
	} {
		if !page.has(text) {
			t.Errorf("the list lacks %q", text)
		}
	}
	if got := strings.Count(page.body, "confirmed</span>"); got != 1 {
		t.Errorf("%d values are marked as confirmed, want the one address of Eve", got)
	}
	if page.has("has to change the password") {
		t.Errorf("a user who has no need to change the password is told to")
	}
	if _, err := f.a.Admin().CreateUser(t.Context(), NewUser{Identifiers: map[string]string{"email": "temp@example.com", "username": "temp"}, Password: goodPassword}); err != nil {
		t.Fatal(err)
	}
	if r := f.get("/users"); !r.has("has to change the password") {
		t.Errorf("a user whom an administrator made with a password is not told to change it")
	}
}

func TestTheListIsFilteredAndSearchedByTheQuery(t *testing.T) {
	f := seedPeople(t)
	newestFirst := []string{"gus", "fifty", "eve", "dan", "cara", "bob", "ann"}
	for _, c := range []struct {
		name, query string
		want        []string
	}{
		{"everybody", "", newestFirst},
		{"oldest first", "?order=created&dir=asc", reversed(newestFirst)},
		{"oldest first without a direction", "?order=created&dir=asc&limit=25", reversed(newestFirst)},
		{"blocked", "?status=blocked", []string{"gus", "cara"}},
		{"blocked or deleted", "?status=blocked&status=deleted", []string{"gus", "dan", "cara"}},
		{"the same status twice", "?status=deleted&status=deleted", []string{"dan"}},
		{"active", "?status=active", []string{"fifty", "eve", "bob", "ann"}},
		{"with a confirmed value", "?confirmed=yes", []string{"eve"}},
		{"without a confirmed value", "?confirmed=no", []string{"gus", "fifty", "dan", "cara", "bob", "ann"}},
		{"any confirmation", "?confirmed=", newestFirst},
		{"made by an administrator", "?via=admin", []string{"bob"}},
		{"made by the code", "?via=api", []string{"gus", "fifty", "eve", "dan", "cara", "ann"}},
		{"invited", "?via=invite", nil},
		{"signed up", "?via=signup", nil},
		{"created within days, both of them included", "?created_from=2026-09-12&created_to=2026-09-14", []string{"eve", "dan", "cara"}},
		{"created from a day on", "?created_from=2026-09-15", []string{"gus", "fifty"}},
		{"created until a day", "?created_to=2026-09-11", []string{"bob", "ann"}},
		{"created on one day", "?created_from=2026-09-13&created_to=2026-09-13", []string{"dan"}},
		{"signed in on a day", "?login_from=2026-09-12&login_to=2026-09-12", []string{"bob"}},
		{"signed in from a day on", "?login_from=2026-09-13", []string{"eve"}},
		{"signed in until a day", "?login_to=2026-09-14", []string{"bob"}},
		{"never signed in", "?never=1", []string{"gus", "fifty", "dan", "cara", "ann"}},
		{"never signed in, as any value of the box", "?never=on", []string{"gus", "fifty", "dan", "cara", "ann"}},
		{"a prefix of an address", "?q=eve@example", []string{"eve"}},
		{"a prefix of a username", "?q=fif", []string{"fifty"}},
		{"a text in capitals with spaces round it", "?q=%20EVE%20", []string{"eve"}},
		{"a text that nobody has", "?q=zzz", nil},
		{"a short text that nobody has", "?q=ab", nil},
		{"conditions that all have to hold", "?status=active&created_from=2026-09-11&never=1", []string{"fifty"}},
		{"conditions that exclude each other", "?status=deleted&confirmed=yes", nil},
		{"the largest page", "?limit=200", newestFirst},
		{"the smallest page", "?limit=10", newestFirst},
	} {
		if got := f.listed(c.query); !slices.Equal(got, c.want) {
			t.Errorf("%s: GET /users%s lists %v, want %v", c.name, c.query, got, c.want)
		}
	}
}

func TestTheListIsOrderedByTheColumnThatWasAskedFor(t *testing.T) {
	f := seedPeople(t)
	if got := f.listed("?order=last_login&dir=desc"); len(got) != 7 || !slices.Equal(got[:2], []string{"eve", "bob"}) {
		t.Errorf("by the last sign-in, the latest first: %v", got)
	}
	if got := f.listed("?order=last_login&dir=asc"); len(got) != 7 || !slices.Equal(got[:2], []string{"bob", "eve"}) {
		t.Errorf("by the last sign-in, the earliest first, with those who never signed in last: %v", got)
	}
	if got := f.listed("?order=last_login"); len(got) != 7 || !slices.Equal(got[:2], []string{"eve", "bob"}) {
		t.Errorf("by the last sign-in without a direction: %v", got)
	}
	statuses := map[string]string{"ann": "active", "bob": "active", "eve": "active", "fifty": "active", "cara": "blocked", "gus": "blocked", "dan": "deleted"}
	order := func(query string) []string {
		var got []string
		for _, name := range f.listed(query) {
			got = append(got, statuses[name])
		}
		return got
	}
	if got, want := order("?order=status&dir=asc"), []string{"active", "active", "active", "active", "blocked", "blocked", "deleted"}; !slices.Equal(got, want) {
		t.Errorf("by the status, ascending: %v", got)
	}
	if got, want := order("?order=status&dir=desc"), []string{"deleted", "blocked", "blocked", "active", "active", "active", "active"}; !slices.Equal(got, want) {
		t.Errorf("by the status, descending: %v", got)
	}
	if got, want := order("?order=status"), []string{"active", "active", "active", "active", "blocked", "blocked", "deleted"}; !slices.Equal(got, want) {
		t.Errorf("by the status without a direction: %v", got)
	}
}

func headsOf(t *testing.T, page webResponse) map[string]struct {
	state string
	query url.Values
} {
	t.Helper()
	heads := map[string]struct {
		state string
		query url.Values
	}{}
	for _, m := range headPattern.FindAllStringSubmatch(page.body, -1) {
		link, err := url.Parse(html.UnescapeString(m[2]))
		if err != nil || link.Path != adminMount+"/users" {
			t.Fatalf("the head %q links to %q", m[3], m[2])
		}
		heads[m[3]] = struct {
			state string
			query url.Values
		}{m[1], link.Query()}
	}
	return heads
}

func TestTheHeadsOfTheColumnsOrderTheListAndSayHowItIsOrdered(t *testing.T) {
	f := seedPeople(t)
	heads := headsOf(t, f.get("/users"))
	if len(heads) != 3 {
		t.Fatalf("%d heads can order the list, want 3: %v", len(heads), heads)
	}
	for label, want := range map[string]struct{ state, order, dir string }{
		"Status": {"none", "status", "asc"}, "Created": {"descending", "created", "asc"}, "Last sign-in": {"none", "last_login", "desc"},
	} {
		got := heads[label]
		if got.state != want.state || got.query.Get("order") != want.order || got.query.Get("dir") != want.dir || got.query.Get("limit") != "50" || got.query.Has("cursor") {
			t.Errorf("the head %q is %+v, want %+v with the default page size", label, got, want)
		}
	}
	heads = headsOf(t, f.get("/users?order=last_login&dir=asc&status=active&status=blocked&status=blocked&q=gus&confirmed=no&via=api&created_from=2026-09-01&never=1&limit=25"))
	if len(heads) != 3 {
		t.Fatalf("a list with a filter has %d heads that can order it, want 3", len(heads))
	}
	for label, want := range map[string]struct{ state, order, dir string }{
		"Status": {"none", "status", "asc"}, "Created": {"none", "created", "desc"}, "Last sign-in": {"ascending", "last_login", "desc"},
	} {
		got := heads[label]
		if got.state != want.state || got.query.Get("order") != want.order || got.query.Get("dir") != want.dir {
			t.Errorf("the head %q is %+v, want %+v", label, got, want)
		}
		if !slices.Equal(got.query["status"], []string{"active", "blocked"}) || got.query.Get("q") != "gus" || got.query.Get("confirmed") != "no" ||
			got.query.Get("via") != "api" || got.query.Get("created_from") != "2026-09-01" || got.query.Get("never") != "1" || got.query.Get("limit") != "25" {
			t.Errorf("the head %q forgets what was asked for: %v", label, got.query)
		}
	}
}

func hrefTo(t *testing.T, page webResponse, text string) string {
	t.Helper()
	m := regexp.MustCompile(`<a href="([^"]+)">` + regexp.QuoteMeta(text) + `</a>`).FindStringSubmatch(page.body)
	if m == nil {
		return ""
	}
	return strings.TrimPrefix(html.UnescapeString(m[1]), adminMount)
}

func TestTheListIsReadPageByPageWithTheCursor(t *testing.T) {
	f := newPeopleFixture(t)
	var oldestFirst []string
	for i := range 25 {
		name := fmt.Sprintf("user%02d", i)
		f.add(name)
		oldestFirst = append(oldestFirst, name)
	}
	f.enroll()
	for _, c := range []struct {
		query string
		want  []string
	}{
		{"?limit=10&order=created&dir=asc", oldestFirst},
		{"?limit=10", reversed(oldestFirst)},
		{"?limit=10&status=active&q=user", reversed(oldestFirst)},
		{"?limit=10&status=active&confirmed=no&via=api&created_from=2026-01-01&created_to=2030-01-01&q=user&order=created&dir=desc", reversed(oldestFirst)},
	} {
		var got []string
		var sizes []int
		path := "/users" + c.query
		for page := 1; path != ""; page++ {
			r := f.get(path)
			if r.StatusCode != http.StatusOK {
				t.Fatalf("GET %s = %d: %.300s", path, r.StatusCode, r.body)
			}
			names := f.namesIn(r)
			got, sizes = append(got, names...), append(sizes, len(names))
			if first := hrefTo(t, r, "First page"); (page == 1) != (first == "") || (first != "" && strings.Contains(first, "cursor=")) {
				t.Errorf("%s page %d: the link to the first page is %q", c.query, page, first)
			}
			if page == 2 {
				for label, head := range headsOf(t, r) {
					if head.query.Has("cursor") || head.query.Get("limit") != "10" {
						t.Errorf("%s: the head %q of the second page is %v, want the first page of another order with the same size", c.query, label, head.query)
					}
				}
			}
			original, parseErr := url.ParseQuery(strings.TrimPrefix(c.query, "?"))
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			keys := make([]string, 0, len(original))
			for key := range original {
				keys = append(keys, key)
			}
			path = hrefTo(t, r, "Next page")
			if path != "" {
				if q := sameFilter(t, original, path, keys...); !q.Has("cursor") {
					t.Errorf("%s page %d: the link to the next page has no cursor: %q", c.query, page, path)
				}
			}
			if first := hrefTo(t, r, "First page"); first != "" {
				if q := sameFilter(t, original, first, keys...); q.Has("cursor") {
					t.Errorf("%s page %d: the link to the first page keeps the cursor: %q", c.query, page, first)
				}
			}
			if page > 3 {
				t.Fatalf("%s: more than three pages", c.query)
			}
		}
		if !slices.Equal(got, c.want) || !slices.Equal(sizes, []int{10, 10, 5}) {
			t.Errorf("%s: the pages hold %v users, the users are %v, want every one once in order %v", c.query, sizes, got, c.want)
		}
	}
	other := hrefTo(t, f.get("/users?limit=10"), "Next page")
	if r := f.get(strings.Replace(other, "order=created", "order=status", 1)); r.StatusCode != http.StatusBadRequest || !r.has("the page") {
		t.Errorf("a cursor of another order is %d, want it refused", r.StatusCode)
	}
}

func TestWrongValuesInTheQueryAreRefusedAndTheFormKeepsTheRest(t *testing.T) {
	f := seedPeople(t)
	for query, labels := range map[string]string{
		"?status=nope":                           "Status",
		"?status=active&status=nope":             "Status",
		"?confirmed=maybe":                       "Confirmed address or phone number",
		"?via=pigeon":                            "Origin",
		"?created_from=2026-13-40":               "Created from",
		"?created_from=0000-01-01":               "Created from",
		"?created_from=10000-01-01":              "Created from",
		"?created_to=yesterday":                  "Created until",
		"?login_from=1":                          "Signed in from",
		"?login_to=2026-9-1":                     "Signed in until",
		"?order=name":                            "Order by",
		"?dir=sideways":                          "Direction",
		"?limit=7":                               "On a page",
		"?limit=abc":                             "On a page",
		"?limit=0":                               "On a page",
		"?limit=-10":                             "On a page",
		"?limit=201":                             "On a page",
		"?cursor=" + strings.Repeat("a", 513):    "the page",
		"?cursor=junk":                           "the page",
		"?q=" + strings.Repeat("x", 129):         "the text to search for",
		"?status=nope&limit=7&dir=up":            "Status, Direction, On a page",
		"?q=eve&via=pigeon&created_from=nothing": "Origin, Created from",
	} {
		r := f.get("/users" + query)
		if r.StatusCode != http.StatusBadRequest || !r.has("A value in the search is not valid: "+labels+".") || len(f.namesIn(r)) != 0 {
			t.Errorf("GET /users%.60s = %d, want 400 that names %q and lists nobody", query, r.StatusCode, labels)
		}
		if !r.has(`name="q"`) || !r.has(`name="limit"`) || !r.has("Search and filters") {
			t.Errorf("GET /users%.60s does not show the form again", query)
		}
		values, parseErr := url.ParseQuery(strings.TrimPrefix(query, "?"))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		for _, name := range []string{"created_from", "created_to", "login_from", "login_to"} {
			if bad := values.Get(name); bad != "" && r.has(`name="`+name+`" type="date" class="input" value="`+bad+`"`) {
				t.Errorf("GET /users%.60s shows the day %q that was refused in the form", query, bad)
			}
		}
		if values.Get("via") == "pigeon" && !r.has(`<option value="" selected>Any origin</option>`) {
			t.Errorf("GET /users%.60s keeps the way that was refused in the form", query)
		}
		if values.Get("confirmed") == "maybe" && !r.has(`<option value="" selected>Does not matter</option>`) {
			t.Errorf("GET /users%.60s keeps the confirmation that was refused in the form", query)
		}
	}
	r := f.get("/users?q=eve&status=active&limit=7")
	if !r.has(`value="eve"`) || !r.has(`name="status" value="active" checked`) {
		t.Errorf("the form of a refused query lost what was valid: %.600s", r.body)
	}
	for _, query := range []string{"?limit=", "?order=&dir=", "?status=", "?status=&status=", "?via=&confirmed=&never=", "?unknown=1", "?cursor=", "?q=", "?q=%20%20"} {
		if got := f.listed(query); len(got) != 7 {
			t.Errorf("GET /users%s lists %v, want every user: an empty value asks for nothing", query, got)
		}
	}
}

func TestTheFormKeepsWhatWasAskedFor(t *testing.T) {
	f := seedPeople(t)
	page := f.get("/users?q=bob&status=blocked&status=deleted&confirmed=no&via=invite&created_from=2026-09-10&created_to=2026-09-20&login_from=2026-09-11&login_to=2026-09-21&never=1&order=last_login&dir=asc&limit=25")
	if page.StatusCode != http.StatusOK {
		t.Fatalf("the list is %d", page.StatusCode)
	}
	for _, want := range []string{
		`value="bob"`, `name="status" value="blocked" checked`, `name="status" value="deleted" checked`, `<option value="no" selected>`,
		`<option value="invite" selected>`, `name="created_from" type="date" class="input" value="2026-09-10"`,
		`name="created_to" type="date" class="input" value="2026-09-20"`, `name="login_from" type="date" class="input" value="2026-09-11"`,
		`name="login_to" type="date" class="input" value="2026-09-21"`, `name="never" value="1" checked`, `<option value="last_login" selected>`,
		`<option value="asc" selected>`, `<option value="25" selected>`,
	} {
		if !page.has(want) {
			t.Errorf("the form lacks %q", want)
		}
	}
	if page.has(`name="status" value="active" checked`) {
		t.Errorf("the status that was not asked for is ticked")
	}
	for _, query := range []string{"?created_from=2030-01-01", "?created_to=2000-01-01", "?login_from=2030-01-01", "?login_to=2000-01-01"} {
		if r := f.get("/users" + query); r.StatusCode != http.StatusOK || !r.has("Nobody matches.") || r.has("There are no users yet.") {
			t.Errorf("GET /users%s does not say that nobody matches", query)
		}
	}
	if r := f.get("/users?q=%20EVE%20"); !r.has(`value="EVE"`) || r.has(`value=" EVE "`) {
		t.Errorf("the search is not shown trimmed: %.800s", r.body)
	}
	plain := f.get("/users")
	for _, want := range []string{`<option value="" selected>`, `<option value="created" selected>`, `<option value="desc" selected>`, `<option value="50" selected>`} {
		if !plain.has(want) {
			t.Errorf("the form without a query lacks %q", want)
		}
	}
	if strings.Contains(plain.body, " checked") {
		t.Errorf("a box is ticked in a form that asked for nothing")
	}
}

func TestWhatWasSearchedForIsEscapedWhereThePageRepeatsIt(t *testing.T) {
	f := seedPeople(t)
	hostile := `"><script>alert(1)</script>'`
	r := f.get("/users?q=" + url.QueryEscape(hostile))
	if r.StatusCode != http.StatusOK || strings.Contains(r.body, "<script") || !r.has(`value="&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;&#39;"`) {
		t.Errorf("a hostile search is %d and is not escaped: %.800s", r.StatusCode, r.body)
	}
	for _, query := range []string{"?created_from=" + url.QueryEscape(hostile), "?cursor=" + url.QueryEscape(hostile), "?order=" + url.QueryEscape(hostile)} {
		if r = f.get("/users" + query); r.StatusCode != http.StatusBadRequest || strings.Contains(r.body, "<script") || strings.Contains(r.body, hostile) {
			t.Errorf("GET /users%s = %d and repeats what it was given", query, r.StatusCode)
		}
	}
}

func TestTheListSpeaksTheLanguageOfTheAdministratorAndKeepsTheQueryWhenItIsSwitched(t *testing.T) {
	f := seedPeople(t)
	switched := f.get("/users?status=blocked&lang=ru&limit=25")
	if switched.StatusCode != http.StatusSeeOther || switched.location() != adminMount+"/users?limit=25&status=blocked" {
		t.Fatalf("a switch of the language on the list is %d %q", switched.StatusCode, switched.location())
	}
	ru := f.get("/users?status=blocked&limit=10")
	for _, want := range []string{
		`<html lang="ru">`, "Пользователи", "Заблокирован", "Применить", "Происхождение", "Последний вход", `href="?lang=en&amp;limit=10&amp;status=blocked"`,
		`aria-label="Открыть пользователя gus@example.com"`, "до <time",
	} {
		if !ru.has(want) {
			t.Errorf("the Russian list lacks %q", want)
		}
	}
	if twice := f.get("/users?lang=en&lang=xx"); twice.StatusCode != http.StatusOK || !twice.has(`<html lang="ru">`) {
		t.Errorf("two languages asked at once are %d and change the language", twice.StatusCode)
	}
	if back := f.get("/users?lang=en"); back.location() != adminMount+"/users" {
		t.Fatalf("a switch back is %q", back.location())
	}
	en := f.get("/users?status=blocked&limit=10")
	if !en.has(`<html lang="en">`) || !en.has(`href="?lang=ru&amp;limit=10&amp;status=blocked"`) {
		t.Errorf("the link to another language loses the query: %.800s", en.body)
	}
}

func TestEveryWayToCreateAnAccountHasAWordOfItsOwn(t *testing.T) {
	catalog, err := adminui.NewCatalog(nil)
	if err != nil {
		t.Fatal(err)
	}
	page := adminui.NewPage(catalog, "en")
	for via, want := range map[string]string{"api": "Application code", "signup": "Sign-up", "admin": "Administrator", "invite": "Invitation", "other": "other", "": ""} {
		if got := viaText(page, via); got != want {
			t.Errorf("viaText(%q) = %q, want %q", via, got, want)
		}
	}
}

func TestTheDaysOfAPeriodAreTurnedIntoTheMomentsOfTheFilter(t *testing.T) {
	q := parseUsersQuery(url.Values{"created_from": {"2026-09-12"}, "created_to": {"2026-09-14"}, "login_from": {"0001-01-01"}, "login_to": {"9999-12-31"}})
	if len(q.invalid) != 0 {
		t.Fatalf("the days are refused: %v", q.invalid)
	}
	f := q.filter()
	if !f.CreatedFrom.Equal(time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)) || !f.CreatedBefore.Equal(time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("the period of creation is from %v before %v", f.CreatedFrom, f.CreatedBefore)
	}
	if !f.LastLoginFrom.IsZero() || !f.LastLoginBefore.IsZero() {
		t.Errorf("the first and the last day that a database keeps set bounds %v and %v, want none", f.LastLoginFrom, f.LastLoginBefore)
	}
	if err := checkMoment("created_before", time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Errorf("the year 10000 is a moment that a database keeps")
	}
}

func TestTheNameOfAFieldThatTheStoreRefusedIsItsTextOrItself(t *testing.T) {
	catalog, err := adminui.NewCatalog(nil)
	if err != nil {
		t.Fatal(err)
	}
	page := adminui.NewPage(catalog, "en")
	for field, want := range map[string]string{"limit": "On a page", "search": "the text to search for", "cursor": "the page", "something": "something", "": ""} {
		if got := fieldLabel(page, usersFieldTexts, field); got != want {
			t.Errorf("fieldLabel(%q) = %q, want %q", field, got, want)
		}
	}
}
