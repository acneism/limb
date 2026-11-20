package limb

import (
	"context"
	"encoding/base64"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/identifier/phone"
	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

func auditEntryOf(kind store.ActorKind, actor, action, target, ip string, details map[string]any) audit.Entry {
	return audit.Entry{Actor: audit.Actor{Kind: kind, ID: actor}, Action: action, TargetUserID: target, IP: ip, Details: details}
}

type usersFixture struct {
	a     *Auth
	clock *fakeClock
	start time.Time
	ids   map[string]UserID
}

func newUsersFixture(t *testing.T, opts ...Option) *usersFixture {
	t.Helper()
	a := newTestAuth(t, append([]Option{emailAndUsername()}, opts...)...)
	clock := newFakeClock()
	a.now = clock.now
	return &usersFixture{a: a, clock: clock, start: clock.now(), ids: map[string]UserID{}}
}

func (f *usersFixture) add(t *testing.T, name string, fields map[string]string) {
	t.Helper()
	user := mustRegister(t, f.a, fields, goodPassword)
	f.ids[name] = user.ID
	f.clock.advance(time.Hour)
}

func (f *usersFixture) change(t *testing.T, name string, edit func(*store.User)) {
	t.Helper()
	u, err := f.a.store.Users().Get(t.Context(), f.a.tenant, string(f.ids[name]))
	if err != nil {
		t.Fatal(err)
	}
	edit(&u)
	if _, err = f.a.store.Users().Update(t.Context(), u); err != nil {
		t.Fatal(err)
	}
}

func (f *usersFixture) names(page UserPage) []string {
	var names []string
	for _, u := range page.Users {
		for name, id := range f.ids {
			if id == u.ID {
				names = append(names, name)
			}
		}
	}
	return names
}

func (f *usersFixture) list(t *testing.T, filter UserFilter) []string {
	t.Helper()
	page, err := f.a.Admin().ListUsers(t.Context(), filter)
	if err != nil {
		t.Fatalf("ListUsers(%+v) failed: %v", filter, err)
	}
	return f.names(page)
}

func seedUsers(t *testing.T) *usersFixture {
	t.Helper()
	f := newUsersFixture(t)
	f.add(t, "ann", map[string]string{"email": "ann@example.com", "username": "ann_a"})
	f.add(t, "bob", map[string]string{"email": "bob@example.com", "username": "bob_b"})
	f.add(t, "cara", map[string]string{"email": "cara@example.org", "username": "cara_c"})
	f.add(t, "dan", map[string]string{"email": "dan@example.com", "username": "dan_d"})
	f.add(t, "eve", map[string]string{"email": "Eve@Example.com", "username": "eve_e"})
	f.add(t, "fifty", map[string]string{"email": "fifty@example.com", "username": "50_off"})
	f.add(t, "fiftyx", map[string]string{"email": "fiftyx@example.com", "username": "50xoff"})
	f.change(t, "bob", func(u *store.User) { u.LastLoginAt = f.start.Add(30 * time.Hour) })
	f.change(t, "eve", func(u *store.User) { u.LastLoginAt = f.start.Add(20 * time.Hour) })
	f.change(t, "cara", func(u *store.User) {
		u.Status, u.BlockedReason = store.StatusBlocked, "spam"
	})
	f.change(t, "dan", func(u *store.User) {
		u.Status, u.DeletedAt, u.PurgeAfter = store.StatusDeleted, f.start.Add(10*time.Hour), f.start.Add(40*24*time.Hour)
	})
	if err := f.a.store.Identifiers().MarkVerified(t.Context(), f.a.tenant, "email", "eve@example.com", f.start); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestUsersAreListedOldestFirstWithWhatTheySignInWith(t *testing.T) {
	f := seedUsers(t)
	page, err := f.a.Admin().ListUsers(t.Context(), UserFilter{})
	if err != nil || page.Next != "" {
		t.Fatalf("ListUsers = %+v, %v", page, err)
	}
	want := []string{"ann", "bob", "cara", "dan", "eve", "fifty", "fiftyx"}
	if got := f.names(page); !slices.Equal(got, want) {
		t.Fatalf("the users are %v, want %v: the oldest first unless the order is turned around", got, want)
	}
	eve := page.Users[4]
	if len(eve.Identifiers) != 2 || eve.Identifiers[0].Type != "email" || eve.Identifiers[0].Value != "eve@example.com" ||
		eve.Identifiers[0].DisplayValue != "Eve@Example.com" || eve.Identifiers[0].VerifiedAt.IsZero() || !eve.Identifiers[1].VerifiedAt.IsZero() {
		t.Fatalf("the identifiers of Eve are %+v", eve.Identifiers)
	}
	if !eve.HasPassword || eve.CreatedVia != "api" || eve.Status != StatusActive || !eve.CreatedAt.Equal(f.start.Add(4*time.Hour)) || !eve.LastLoginAt.Equal(f.start.Add(20*time.Hour)) {
		t.Fatalf("Eve is %+v", eve)
	}
	cara, dan := page.Users[2], page.Users[3]
	if cara.Status != StatusBlocked || cara.BlockedReason != "spam" || !cara.BlockedUntil.IsZero() {
		t.Fatalf("Cara is %+v", cara)
	}
	if dan.Status != StatusDeleted || !dan.DeletedAt.Equal(f.start.Add(10*time.Hour)) || !dan.PurgeAfter.Equal(f.start.Add(40*24*time.Hour)) {
		t.Fatalf("Dan is %+v", dan)
	}
}

func TestTheListIsFilteredByTheStatusTheConfirmationAndThePeriods(t *testing.T) {
	f := seedUsers(t)
	yes, no := true, false
	cases := map[string]struct {
		filter UserFilter
		want   []string
	}{
		"blocked":               {UserFilter{Statuses: []Status{StatusBlocked}}, []string{"cara"}},
		"deleted":               {UserFilter{Statuses: []Status{StatusDeleted}}, []string{"dan"}},
		"active and blocked":    {UserFilter{Statuses: []Status{StatusActive, StatusBlocked}}, []string{"ann", "bob", "cara", "eve", "fifty", "fiftyx"}},
		"confirmed":             {UserFilter{Confirmed: &yes}, []string{"eve"}},
		"not confirmed":         {UserFilter{Confirmed: &no}, []string{"ann", "bob", "cara", "dan", "fifty", "fiftyx"}},
		"made from":             {UserFilter{CreatedFrom: f.start.Add(4 * time.Hour)}, []string{"eve", "fifty", "fiftyx"}},
		"made before":           {UserFilter{CreatedBefore: f.start.Add(2 * time.Hour)}, []string{"ann", "bob"}},
		"made in a period":      {UserFilter{CreatedFrom: f.start.Add(time.Hour), CreatedBefore: f.start.Add(3 * time.Hour)}, []string{"bob", "cara"}},
		"signed in from":        {UserFilter{LastLoginFrom: f.start.Add(25 * time.Hour)}, []string{"bob"}},
		"signed in before":      {UserFilter{LastLoginBefore: f.start.Add(25 * time.Hour)}, []string{"eve"}},
		"signed in in a period": {UserFilter{LastLoginFrom: f.start.Add(10 * time.Hour), LastLoginBefore: f.start.Add(40 * time.Hour), Order: UserOrderLastLogin}, []string{"eve", "bob"}},
		"never signed in":       {UserFilter{NeverLoggedIn: true}, []string{"ann", "cara", "dan", "fifty", "fiftyx"}},
		"made by the code":      {UserFilter{CreatedVia: "api", CreatedBefore: f.start.Add(2 * time.Hour)}, []string{"ann", "bob"}},
		"made by a visitor":     {UserFilter{CreatedVia: "signup"}, nil},
		"every condition":       {UserFilter{Statuses: []Status{StatusActive}, Confirmed: &no, NeverLoggedIn: true, CreatedFrom: f.start.Add(5 * time.Hour)}, []string{"fifty", "fiftyx"}},
	}
	for name, c := range cases {
		if got := f.list(t, c.filter); !slices.Equal(got, c.want) {
			t.Errorf("%s: the users are %v, want %v", name, got, c.want)
		}
	}
}

func TestAnAccountWhoseBlockHasRunOutIsShownAsActive(t *testing.T) {
	f := seedUsers(t)
	f.change(t, "cara", func(u *store.User) { u.BlockedUntil = f.clock.now().Add(time.Hour) })
	card, err := f.a.Admin().User(t.Context(), f.ids["cara"])
	if err != nil || card.Status != StatusBlocked || !card.BlockedUntil.Equal(f.clock.now().Add(time.Hour)) {
		t.Fatalf("a block that holds is shown as %+v, %v", card, err)
	}
	f.clock.advance(time.Hour)
	card, err = f.a.Admin().User(t.Context(), f.ids["cara"])
	if err != nil || card.Status != StatusActive || card.BlockedReason != "spam" {
		t.Fatalf("a block that ran out is shown as %+v, %v: the status is active and the reason is kept", card, err)
	}
	page, err := f.a.Admin().ListUsers(t.Context(), UserFilter{Statuses: []Status{StatusBlocked}})
	if err != nil || len(page.Users) != 1 || page.Users[0].Status != StatusActive {
		t.Fatalf("the list shows %+v, %v: the filter works on the stored status and the user on the effective one", page, err)
	}
}

func TestTheListIsOrderedByCreationLastLoginOrStatus(t *testing.T) {
	f := seedUsers(t)
	cases := map[string]struct {
		filter UserFilter
		want   []string
	}{
		"created":                {UserFilter{Order: UserOrderCreated, Descending: true}, []string{"fiftyx", "fifty", "eve", "dan", "cara", "bob", "ann"}},
		"created upwards":        {UserFilter{Order: UserOrderCreated}, []string{"ann", "bob", "cara", "dan", "eve", "fifty", "fiftyx"}},
		"last sign-in":           {UserFilter{Order: UserOrderLastLogin}, []string{"eve", "bob", "ann", "cara", "dan", "fifty", "fiftyx"}},
		"last sign-in downwards": {UserFilter{Order: UserOrderLastLogin, Descending: true}, []string{"bob", "eve", "fiftyx", "fifty", "dan", "cara", "ann"}},
		"status":                 {UserFilter{Order: UserOrderStatus}, []string{"ann", "bob", "eve", "fifty", "fiftyx", "cara", "dan"}},
		"status downwards":       {UserFilter{Order: UserOrderStatus, Descending: true}, []string{"dan", "cara", "fiftyx", "fifty", "eve", "bob", "ann"}},
	}
	for name, c := range cases {
		if got := f.list(t, c.filter); !slices.Equal(got, c.want) {
			t.Errorf("%s: the users are %v, want %v", name, got, c.want)
		}
	}
}

func TestAListIsReadPageByPage(t *testing.T) {
	f := seedUsers(t)
	for _, order := range []UserOrder{UserOrderCreated, UserOrderLastLogin, UserOrderStatus} {
		for _, descending := range []bool{false, true} {
			all := f.list(t, UserFilter{Order: order, Descending: descending})
			var paged []string
			cursor := ""
			for pages := 0; ; pages++ {
				if pages > len(all) {
					t.Fatalf("%s/%v: the pages never end", order, descending)
				}
				page, err := f.a.Admin().ListUsers(t.Context(), UserFilter{Order: order, Descending: descending, Limit: 2, Cursor: cursor})
				if err != nil {
					t.Fatalf("%s/%v: ListUsers failed: %v", order, descending, err)
				}
				paged = append(paged, f.names(page)...)
				if page.Next == "" {
					break
				}
				if len(page.Users) != 2 {
					t.Fatalf("%s/%v: a page that is not the last holds %d users, want 2", order, descending, len(page.Users))
				}
				cursor = page.Next
			}
			if !slices.Equal(paged, all) {
				t.Errorf("%s/%v: the pages hold %v, the whole list is %v", order, descending, paged, all)
			}
		}
	}
	if page, err := f.a.Admin().ListUsers(t.Context(), UserFilter{Limit: 7}); err != nil || page.Next != "" || len(page.Users) != 7 {
		t.Fatalf("a page that holds every user = %d users, next %q, %v", len(page.Users), page.Next, err)
	}
}

func TestACursorThatDoesNotFitTheListIsRefused(t *testing.T) {
	f := seedUsers(t)
	page, err := f.a.Admin().ListUsers(t.Context(), UserFilter{Limit: 2})
	if err != nil || page.Next == "" {
		t.Fatalf("ListUsers = %+v, %v", page, err)
	}
	encode := func(text string) string { return base64.RawURLEncoding.EncodeToString([]byte(text)) }
	var validation *ValidationError
	for name, filter := range map[string]UserFilter{
		"another order":     {Order: UserOrderStatus, Cursor: page.Next},
		"another direction": {Descending: true, Cursor: page.Next},
		"text":              {Cursor: "not a cursor"},
		"not JSON":          {Cursor: encode("nothing")},
		"no ID":             {Cursor: encode(`{"o":"created","c":5}`)},
		"another list":      {Cursor: encode(`{"o":"status","i":"x"}`)},
		"standard encoding": {Cursor: base64.StdEncoding.EncodeToString([]byte(`{"o":"created","i":"x"}`)) + "+"},
		"no time":           {Cursor: encode(`{"o":"created","i":"x"}`)},
		"a time that no database keeps": {
			Cursor: encode(`{"o":"created","i":"x","c":9223372036854775807}`),
		},
		"the zero time":      {Cursor: encode(`{"o":"created","i":"x","c":-62135596800000000}`)},
		"an ID that is long": {Cursor: encode(`{"o":"created","i":"` + strings.Repeat("a", store.MaxIDLength+1) + `","c":5}`)},
		"a cursor that is long": {
			Cursor: encode(`{"o":"created","i":"x","c":5,"s":"` + strings.Repeat("a", longestCursor) + `"}`),
		},
		"no status":                  {Order: UserOrderStatus, Cursor: encode(`{"o":"status","i":"x"}`)},
		"a status that is unknown":   {Order: UserOrderStatus, Cursor: encode(`{"o":"status","i":"x","s":"gone"}`)},
		"a last sign-in that is far": {Order: UserOrderLastLogin, Cursor: encode(`{"o":"last_login","i":"x","l":-9223372036854775808}`)},
	} {
		if _, err := f.a.Admin().ListUsers(t.Context(), filter); !errors.As(err, &validation) || validation.Field != "cursor" {
			t.Errorf("%s: ListUsers = %v, want a *ValidationError for the cursor", name, err)
		}
	}
	padded := func(size int) string {
		prefix, suffix := `{"o":"created","i":"x","c":5,"p":"`, `"}`
		return prefix + strings.Repeat("a", size-len(prefix)-len(suffix)) + suffix
	}
	if got := len(encode(padded(longestCursor / 4 * 3))); got != longestCursor {
		t.Fatalf("the cursor that is meant to have the longest length has %d characters, want %d", got, longestCursor)
	}
	if _, err := f.a.Admin().ListUsers(t.Context(), UserFilter{Cursor: encode(padded(longestCursor/4*3 + 1))}); !errors.As(err, &validation) || validation.Field != "cursor" {
		t.Errorf("a cursor of %d characters: ListUsers = %v, want a *ValidationError for the cursor", len(encode(padded(longestCursor/4*3+1))), err)
	}
	for name, filter := range map[string]UserFilter{
		"a user who never signed in":   {Order: UserOrderLastLogin, Cursor: encode(`{"o":"last_login","i":"x"}`)},
		"a status":                     {Order: UserOrderStatus, Descending: true, Cursor: encode(`{"o":"status","d":true,"i":"x","s":"blocked"}`)},
		"the longest cursor":           {Cursor: encode(padded(longestCursor / 4 * 3))},
		"the first year":               {Cursor: encode(`{"o":"created","i":"x","c":-62135596799000000}`)},
		"the last moment":              {Cursor: encode(`{"o":"created","i":"x","c":253402300799999999}`)},
		"the last moment of a sign-in": {Order: UserOrderLastLogin, Cursor: encode(`{"o":"last_login","i":"x","l":253402300799999999}`)},
		"an ID of the longest length":  {Cursor: encode(`{"o":"created","i":"` + strings.Repeat("a", store.MaxIDLength) + `","c":5}`)},
	} {
		if _, err := f.a.Admin().ListUsers(t.Context(), filter); err != nil {
			t.Errorf("%s: ListUsers failed: %v", name, err)
		}
	}
	if _, err := f.a.Admin().ListUsers(t.Context(), UserFilter{Cursor: encode(`{"o":"created","i":"00000000-0000-7000-8000-000000000999","c":1}`)}); err != nil {
		t.Fatalf("a cursor of a user that does not exist is only a place in the list: %v", err)
	}
}

func TestAFilterThatCannotBeAppliedIsRefused(t *testing.T) {
	f := seedUsers(t)
	var validation *ValidationError
	for field, filter := range map[string]UserFilter{
		"limit":       {Limit: -1},
		"statuses":    {Statuses: []Status{"gone"}},
		"order":       {Order: "name"},
		"created_via": {CreatedVia: "magic"},
		"search":      {Search: strings.Repeat("a", longestSearch+1)},
	} {
		if _, err := f.a.Admin().ListUsers(t.Context(), filter); !errors.As(err, &validation) || validation.Field != field {
			t.Errorf("%s: ListUsers = %v, want a *ValidationError for that field", field, err)
		}
	}
	if _, err := f.a.Admin().ListUsers(t.Context(), UserFilter{Limit: largestUsersPage + 1}); !errors.As(err, &validation) || validation.Field != "limit" {
		t.Errorf("a limit over the largest = %v, want a *ValidationError", err)
	}
	beyond := []time.Time{
		time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC), time.Date(0, time.December, 31, 0, 0, 0, 0, time.UTC),
		time.UnixMicro(math.MaxInt64), time.UnixMicro(math.MinInt64),
	}
	for _, at := range beyond {
		for field, filter := range map[string]UserFilter{
			"created_from": {CreatedFrom: at}, "created_before": {CreatedBefore: at},
			"last_login_from": {LastLoginFrom: at}, "last_login_before": {LastLoginBefore: at},
		} {
			if _, err := f.a.Admin().ListUsers(t.Context(), filter); !errors.As(err, &validation) || validation.Field != field {
				t.Errorf("%s of %v: ListUsers = %v, want a *ValidationError for that field", field, at, err)
			}
		}
	}
	edges := UserFilter{
		CreatedFrom: time.Date(1, time.January, 1, 0, 0, 1, 0, time.UTC), CreatedBefore: time.Date(9999, time.December, 31, 23, 59, 59, 999999000, time.UTC),
		LastLoginFrom: time.Date(1, time.January, 1, 0, 0, 1, 0, time.UTC), LastLoginBefore: time.Date(9999, time.December, 31, 23, 59, 59, 999999000, time.UTC),
	}
	if page, err := f.a.Admin().ListUsers(t.Context(), edges); err != nil || len(page.Users) != 2 {
		t.Errorf("the edges of the years that are kept = %d users, %v; want the two who signed in", len(page.Users), err)
	}
	if page, err := f.a.Admin().ListUsers(t.Context(), UserFilter{Limit: largestUsersPage}); err != nil || len(page.Users) != 7 {
		t.Errorf("the largest limit = %d users, %v", len(page.Users), err)
	}
}

func TestUsersAreFoundByWhatTheySignInWith(t *testing.T) {
	f := seedUsers(t)
	cases := map[string]struct {
		search string
		want   []string
	}{
		"the start of an address":            {"bob@", []string{"bob"}},
		"in capitals":                        {"BOB@EXAM", []string{"bob"}},
		"with spaces around":                 {"  cara@example.o ", []string{"cara"}},
		"the start of a name":                {"ann_", []string{"ann"}},
		"a domain is no start":               {"example.com", nil},
		"the start of many":                  {"fifty", []string{"fifty", "fiftyx"}},
		"an underscore is no wildcard":       {"50_", []string{"fifty"}},
		"a percent sign is no wildcard":      {"a%c", nil},
		"only percent signs":                 {"%%%", nil},
		"an escape character is no wildcard": {"ann!", nil},
		"too short to be a start":            {"an", nil},
		"too short and exact":                {"bo", nil},
		"nothing but blanks":                 {"   ", []string{"ann", "bob", "cara", "dan", "eve", "fifty", "fiftyx"}},
		"a compatible form of a letter":      {"ｂｏｂ@", []string{"bob"}},
		"a value that does not exist":        {"nobody@", nil},
	}
	for name, c := range cases {
		if got := f.list(t, UserFilter{Search: c.search}); !slices.Equal(got, c.want) {
			t.Errorf("%s: searching %q finds %v, want %v", name, c.search, got, c.want)
		}
	}
	if got := f.list(t, UserFilter{Search: "fifty", Statuses: []Status{StatusBlocked}}); got != nil {
		t.Errorf("a search together with a filter finds %v, want nothing: both have to hold", got)
	}
}

func TestANumberIsFoundTheWayItIsTyped(t *testing.T) {
	a := newTestAuth(t, WithIdentifiers(identifier.Email(identifier.Required()), phone.Number("RU")))
	a.now = newFakeClock().now
	user := mustRegister(t, a, map[string]string{"email": "dora@example.com", "phone": "+7 916 123-45-67"}, goodPassword)
	mustRegister(t, a, map[string]string{"email": "eli@example.com", "phone": "+7 903 123-45-67"}, goodPassword)
	for _, search := range []string{"+79161234567", "+7 916 123-45-67", "8 (916) 123-45-67", "+7 (916", "+7916", "7916"} {
		page, err := a.Admin().ListUsers(t.Context(), UserFilter{Search: search})
		if search == "7916" {
			if err != nil || len(page.Users) != 0 {
				t.Errorf("searching %q finds %d users, want none: a number starts with the plus sign", search, len(page.Users))
			}
			continue
		}
		if err != nil || len(page.Users) != 1 || page.Users[0].ID != user.ID {
			t.Errorf("searching %q finds %+v, %v, want Dora", search, page.Users, err)
		}
	}
}

func TestAUserIsReadWhateverTheStatusIs(t *testing.T) {
	f := seedUsers(t)
	for _, name := range []string{"ann", "cara", "dan"} {
		card, err := f.a.Admin().User(t.Context(), f.ids[name])
		if err != nil || card.ID != f.ids[name] || len(card.Identifiers) != 2 {
			t.Errorf("User(%s) = %+v, %v", name, card, err)
		}
	}
	for _, id := range []UserID{"00000000-0000-7000-8000-000000000999", "", "not an id", "x\x00y"} {
		if _, err := f.a.Admin().User(t.Context(), id); !errors.Is(err, ErrUserNotFound) {
			t.Errorf("User(%q) = %v, want ErrUserNotFound", id, err)
		}
	}
	faults := newFaults()
	f.a.store = faultStore{Store: f.a.store, faults: faults}
	broken := errors.New("the store is gone")
	for _, op := range []string{"users.get", "identifiers.list"} {
		faults.set(op, broken)
		if _, err := f.a.Admin().User(t.Context(), f.ids["ann"]); !errors.Is(err, broken) || errors.Is(err, ErrUserNotFound) {
			t.Errorf("with %s failing User = %v", op, err)
		}
		if _, err := f.a.Admin().UserSessions(t.Context(), f.ids["ann"]); !errors.Is(err, broken) {
			t.Errorf("with %s failing UserSessions = %v", op, err)
		}
		faults.clear()
	}
	faults.set("identifiers.list", broken)
	if _, err := f.a.Admin().ListUsers(t.Context(), UserFilter{}); !errors.Is(err, broken) {
		t.Errorf("with the identifiers failing ListUsers = %v", err)
	}
}

func TestTheSessionsOfAUserAreListedForTheAdministration(t *testing.T) {
	f := newSessionFixture(t)
	first := f.login(t)
	f.clock.advance(time.Minute)
	second := f.login(t)
	f.clock.advance(time.Minute)
	third := f.login(t)
	if err := f.a.Logout(t.Context(), third.Principal); err != nil {
		t.Fatal(err)
	}
	sessions, err := f.a.Admin().UserSessions(t.Context(), f.user.ID)
	if err != nil || len(sessions) != 2 {
		t.Fatalf("UserSessions = %+v, %v, want the two sessions that are in use", sessions, err)
	}
	if sessions[0].ID != first.Principal.SessionID || sessions[1].ID != second.Principal.SessionID {
		t.Fatalf("the sessions are %+v, want the oldest first", sessions)
	}
	for _, s := range sessions {
		if s.Current || s.IP != testIP.String() || s.UserAgent != testAgent || s.Kind != SessionCookie {
			t.Errorf("the session is %+v: none is the current one for the administration", s)
		}
	}
	f.clock.advance(f.a.idle)
	if sessions, err = f.a.Admin().UserSessions(t.Context(), f.user.ID); err != nil || len(sessions) != 0 {
		t.Fatalf("the sessions after they went idle = %+v, %v", sessions, err)
	}
	if _, err = f.a.Admin().UserSessions(t.Context(), "00000000-0000-7000-8000-000000000999"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("UserSessions of a user that does not exist = %v", err)
	}
}

func TestTheAuditLogIsListedNewestFirstAndFiltered(t *testing.T) {
	f := newSessionFixture(t)
	admin := f.a.Admin()
	adminID := "00000000-0000-7000-8000-0000000000a1"
	other := "00000000-0000-7000-8000-0000000000a2"
	write := func(actor string, kind store.ActorKind, action string, target string, details map[string]any) {
		t.Helper()
		f.clock.advance(time.Minute)
		entry := auditEntryOf(kind, actor, action, target, "198.51.100.4", details)
		if err := f.a.auditWriter().Add(t.Context(), f.a.store.Audit(), entry); err != nil {
			t.Fatal(err)
		}
	}
	user := string(f.user.ID)
	write(user, store.ActorUser, "auth.login", user, nil)
	write(adminID, store.ActorAdmin, "user.blocked", user, map[string]any{"reason": "spam"})
	write(other, store.ActorAdmin, "user.unblocked", user, nil)
	write(adminID, store.ActorAdmin, "user.deleted", "00000000-0000-7000-8000-000000000777", nil)
	write("", store.ActorSystem, "user.purged", user, map[string]any{"reason": "unconfirmed"})
	ours := []string{"user.blocked", "user.unblocked", "user.deleted", "user.purged"}
	all, err := admin.ListAudit(t.Context(), AuditFilter{Actions: ours})
	if err != nil || all.Next != "" || len(all.Entries) != 4 {
		t.Fatalf("ListAudit = %+v, %v", all, err)
	}
	newest := all.Entries[0]
	if newest.Action != "user.purged" || newest.ActorKind != "system" || newest.UserID != f.user.ID || newest.Details["reason"] != "unconfirmed" || !newest.At.Equal(f.clock.now().Truncate(time.Microsecond)) {
		t.Fatalf("the newest entry is %+v", newest)
	}
	for i := 1; i < len(all.Entries); i++ {
		if all.Entries[i].At.After(all.Entries[i-1].At) {
			t.Fatalf("the entries are not ordered by time: %+v", all.Entries)
		}
	}
	actions := func(filter AuditFilter) []string {
		t.Helper()
		page, listErr := admin.ListAudit(t.Context(), filter)
		if listErr != nil {
			t.Fatalf("ListAudit(%+v) failed: %v", filter, listErr)
		}
		var got []string
		for _, e := range page.Entries {
			got = append(got, e.Action)
		}
		return got
	}
	cases := map[string]struct {
		filter AuditFilter
		want   []string
	}{
		"of an administrator":                  {AuditFilter{AdminID: adminID}, []string{"user.deleted", "user.blocked"}},
		"of another":                           {AuditFilter{AdminID: other}, []string{"user.unblocked"}},
		"about a user":                         {AuditFilter{UserID: f.user.ID, Actions: ours}, []string{"user.purged", "user.unblocked", "user.blocked"}},
		"of a user taken for an administrator": {AuditFilter{AdminID: user}, nil},
		"of an action":                         {AuditFilter{Actions: []string{"user.deleted"}}, []string{"user.deleted"}},
		"of two actions":                       {AuditFilter{Actions: []string{"user.deleted", "user.blocked"}}, []string{"user.deleted", "user.blocked"}},
		"in a period":                          {AuditFilter{AdminID: adminID, From: f.clock.now().Add(-2 * time.Minute), To: f.clock.now()}, []string{"user.deleted"}},
		"of nobody":                            {AuditFilter{AdminID: "00000000-0000-7000-8000-0000000000ff"}, nil},
	}
	for name, c := range cases {
		if got := actions(c.filter); !slices.Equal(got, c.want) {
			t.Errorf("%s: the actions are %v, want %v", name, got, c.want)
		}
	}
	if page, listErr := admin.ListAudit(t.Context(), AuditFilter{Actions: ours, Limit: 4}); listErr != nil || len(page.Entries) != 4 || page.Next != "" {
		t.Fatalf("a page that holds all the records = %d entries, next %q, %v; want 4 and no next page", len(page.Entries), page.Next, listErr)
	}
	if page, listErr := admin.ListAudit(t.Context(), AuditFilter{Actions: ours, Limit: 3}); listErr != nil || len(page.Entries) != 3 || page.Next == "" {
		t.Fatalf("a page that holds all but one = %d entries, next %q, %v; want 3 and a next page", len(page.Entries), page.Next, listErr)
	}
	if _, listErr := admin.ListAudit(t.Context(), AuditFilter{Limit: largestAuditPage}); listErr != nil {
		t.Fatalf("the largest page failed: %v", listErr)
	}
	var paged []string
	cursor := ""
	for range 20 {
		page, listErr := admin.ListAudit(t.Context(), AuditFilter{Actions: ours, Limit: 2, Cursor: cursor})
		if listErr != nil {
			t.Fatal(listErr)
		}
		for _, e := range page.Entries {
			paged = append(paged, e.ID)
		}
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}
	var whole []string
	for _, e := range all.Entries {
		whole = append(whole, e.ID)
	}
	if !slices.Equal(paged, whole) {
		t.Fatalf("the pages hold %v, the whole log is %v", paged, whole)
	}
}

func TestAnAuditFilterThatCannotBeAppliedIsRefused(t *testing.T) {
	f := newSessionFixture(t)
	var validation *ValidationError
	for field, filter := range map[string]AuditFilter{
		"limit":   {Limit: -3},
		"actions": {Actions: make([]string, store.MaxAuditActions+1)},
		"cursor":  {Cursor: "not a cursor"},
		"from":    {From: time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)},
		"to":      {To: time.UnixMicro(math.MinInt64)},
	} {
		if _, err := f.a.Admin().ListAudit(t.Context(), filter); !errors.As(err, &validation) || validation.Field != field {
			t.Errorf("%s: ListAudit = %v, want a *ValidationError for that field", field, err)
		}
	}
	encode := func(text string) string { return base64.RawURLEncoding.EncodeToString([]byte(text)) }
	for name, cursor := range map[string]string{
		"a time that no database keeps": `{"t":9223372036854775807,"i":"x"}`,
		"the zero time":                 `{"t":-62135596800000000,"i":"x"}`,
		"an ID that is long":            `{"t":5,"i":"` + strings.Repeat("a", store.MaxIDLength+1) + `"}`,
		"a cursor that is long":         `{"t":5,"i":"x","x":"` + strings.Repeat("a", longestCursor) + `"}`,
	} {
		if _, err := f.a.Admin().ListAudit(t.Context(), AuditFilter{Cursor: encode(cursor)}); !errors.As(err, &validation) || validation.Field != "cursor" {
			t.Errorf("%s: ListAudit = %v, want a *ValidationError for the cursor", name, err)
		}
	}
	if _, err := f.a.Admin().ListAudit(t.Context(), AuditFilter{Cursor: encode(`{"t":0,"i":"x"}`), From: time.Date(9999, time.December, 31, 23, 59, 59, 999999000, time.UTC)}); err != nil {
		t.Errorf("a cursor at the first moment of the epoch and a filter at the last moment of the years that are kept failed: %v", err)
	}
	padded := func(size int) string {
		prefix, suffix := `{"t":5,"i":"x","p":"`, `"}`
		return prefix + strings.Repeat("a", size-len(prefix)-len(suffix)) + suffix
	}
	for name, cursor := range map[string]string{
		"the longest cursor":          padded(longestCursor / 4 * 3),
		"the first year":              `{"t":-62135596799000000,"i":"x"}`,
		"the last moment":             `{"t":253402300799999999,"i":"x"}`,
		"an ID of the longest length": `{"t":5,"i":"` + strings.Repeat("a", store.MaxIDLength) + `"}`,
	} {
		if _, err := f.a.Admin().ListAudit(t.Context(), AuditFilter{Cursor: encode(cursor)}); err != nil {
			t.Errorf("%s: ListAudit failed: %v", name, err)
		}
	}
	if _, err := f.a.Admin().ListAudit(t.Context(), AuditFilter{Cursor: encode(padded(longestCursor/4*3 + 1))}); !errors.As(err, &validation) || validation.Field != "cursor" {
		t.Errorf("a cursor over the longest length: ListAudit = %v, want a *ValidationError for the cursor", err)
	}
	if _, err := f.a.Admin().ListAudit(t.Context(), AuditFilter{Actions: make([]string, store.MaxAuditActions)}); err != nil {
		t.Errorf("the most actions that a filter takes: ListAudit failed: %v", err)
	}
	if _, err := f.a.Admin().ListAudit(t.Context(), AuditFilter{Limit: largestAuditPage + 1}); !errors.As(err, &validation) {
		t.Errorf("a limit over the largest = %v, want a *ValidationError", err)
	}
	if _, err := f.a.Admin().ListAudit(t.Context(), AuditFilter{Cursor: base64.RawURLEncoding.EncodeToString([]byte(`{"t":5}`))}); !errors.As(err, &validation) {
		t.Errorf("a cursor without an ID = %v, want a *ValidationError", err)
	}
	faults := newFaults()
	f.a.store = faultStore{Store: f.a.store, faults: faults}
	broken := errors.New("the audit log is gone")
	faults.set("audit.list", broken)
	if _, err := f.a.Admin().ListAudit(t.Context(), AuditFilter{}); !errors.Is(err, broken) {
		t.Errorf("ListAudit = %v, want the failure of the store", err)
	}
}

func TestDetailsThatAreNotJSONAreShownAsText(t *testing.T) {
	f := newSessionFixture(t)
	record := store.AuditRecord{
		TenantID: f.a.tenant, ID: "00000000-0000-7000-8000-000000000555", At: f.clock.now(), ActorKind: store.ActorSystem, Action: "old.action", Details: "plain words",
	}
	if err := f.a.store.Audit().Add(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	page, err := f.a.Admin().ListAudit(t.Context(), AuditFilter{Actions: []string{"old.action"}})
	if err != nil || len(page.Entries) != 1 || page.Entries[0].Details["text"] != "plain words" {
		t.Fatalf("ListAudit = %+v, %v", page, err)
	}
}

func TestATypedNumberIsRecognizedOnlyWhenItLooksLikeOne(t *testing.T) {
	cases := map[string]string{
		"+7 (916) 12":  "+791612",
		"+7-916":       "+7916",
		"+7916":        "+7916",
		"8 916 123":    "8916123",
		"(916) 123-45": "91612345",
		"7916":         "",
		"916-123":      "",
		"50_":          "",
		"12.34":        "",
		"ann smith":    "",
		"+7 916 abc":   "",
		"a+7 916":      "",
		"+ 7 916":      "+7916",
		"7 (9+1":       "",
		"+7 +9 (1":     "",
		"":             "",
	}
	for text, want := range cases {
		if got := typedNumber(text); got != want {
			t.Errorf("typedNumber(%q) = %q, want %q", text, got, want)
		}
	}
}
