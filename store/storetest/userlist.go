package storetest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

var listBase = time.Date(2026, 3, 1, 10, 0, 0, 123456789, time.UTC)

func minutes(n int) time.Time {
	return listBase.Add(time.Duration(n) * time.Minute)
}

type listedIdentifier struct {
	typ, value string
	verified   bool
}

type listedUser struct {
	n          int
	created    int
	status     store.Status
	via        store.CreatedVia
	login      int
	purgeDays  int
	blocked    int
	identifier []listedIdentifier
}

var listedUsers = []listedUser{
	{n: 1, created: 1, status: store.StatusActive, via: store.CreatedViaAPI, login: 10,
		identifier: []listedIdentifier{{"email", "ann@example.com", true}, {"nick", "ann", false}}},
	{n: 2, created: 2, status: store.StatusBlocked, via: store.CreatedViaSignup,
		identifier: []listedIdentifier{{"email", "bob@example.com", false}}},
	{n: 3, created: 3, status: store.StatusDeleted, via: store.CreatedViaAdmin, login: 5, purgeDays: 30,
		identifier: []listedIdentifier{{"email", "cat@example.com", true}, {"phone", "+79260000003", false}}},
	{n: 4, created: 3, status: store.StatusActive, via: store.CreatedViaInvite,
		identifier: []listedIdentifier{{"nick", "a_b", false}}},
	{n: 5, created: 5, status: store.StatusActive, via: "", login: 10,
		identifier: []listedIdentifier{{"nick", "axb", false}, {"email", "axb@example.com", true}}},
	{n: 6, created: 6, status: store.StatusDeleted, via: store.CreatedViaSignup, purgeDays: 10,
		identifier: []listedIdentifier{{"nick", "50%", false}}},
	{n: 7, created: 7, status: store.StatusBlocked, via: store.CreatedViaAPI, login: 20, blocked: 60,
		identifier: []listedIdentifier{{"nick", "500", false}}},
	{n: 8, created: 8, status: store.StatusActive, via: store.CreatedViaSignup,
		identifier: []listedIdentifier{{"nick", "a!b", false}}},
	{n: 9, created: 9, status: store.StatusActive, via: store.CreatedViaAdmin, login: 1,
		identifier: []listedIdentifier{{"nick", `a\b`, false}}},
	{n: 10, created: 10, status: store.StatusActive, via: store.CreatedViaAPI},
}

func seedListedUsers(t *testing.T, s store.Store) {
	t.Helper()
	for _, l := range listedUsers {
		u := newUser(tenantA, id(l.n))
		u.Status, u.CreatedVia, u.CreatedAt = l.status, l.via, minutes(l.created)
		if l.login != 0 {
			u.LastLoginAt = minutes(l.login)
		}
		if l.blocked != 0 {
			u.BlockedReason, u.BlockedUntil = "reason", minutes(l.blocked)
		}
		if l.status == store.StatusDeleted {
			u.DeletedAt = minutes(l.created)
			u.PurgeAfter = listBase.Add(time.Duration(l.purgeDays) * 24 * time.Hour)
		}
		mustCreate(t, s, u)
		for _, i := range l.identifier {
			ident := newIdentifier(tenantA, i.typ, i.value, id(l.n))
			if i.verified {
				ident.VerifiedAt = minutes(l.created + 1)
			}
			mustAdd(t, s, ident)
		}
	}
	other := newUser(tenantB, id(11))
	other.CreatedAt = minutes(11)
	mustCreate(t, s, other)
	mustAdd(t, s, newIdentifier(tenantB, "email", "ann@example.com", id(11)))
}

func listUsers(t *testing.T, s store.Store, q store.UserQuery) []store.User {
	t.Helper()
	if q.TenantID == "" {
		q.TenantID = tenantA
	}
	if q.Limit == 0 {
		q.Limit = store.MaxUsersPage
	}
	list, err := s.Users().List(t.Context(), q)
	if err != nil {
		t.Fatalf("List(%+v) failed: %v", q, err)
	}
	return list
}

func userNumbers(list []store.User) []int {
	numbers := make([]int, 0, len(list))
	for _, u := range list {
		for n := 1; n <= 11; n++ {
			if u.ID == id(n) {
				numbers = append(numbers, n)
			}
		}
	}
	return numbers
}

func wantUsers(t *testing.T, got []store.User, want ...int) {
	t.Helper()
	if !slices.Equal(userNumbers(got), want) || len(got) != len(want) {
		t.Fatalf("the users are %v, want %v", userNumbers(got), want)
	}
}

func yes() *bool { v := true; return &v }
func no() *bool  { v := false; return &v }

func testUserListFilters(t *testing.T, s store.Store) {
	seedListedUsers(t, s)
	cases := []struct {
		name  string
		query store.UserQuery
		want  []int
	}{
		{"every user of the tenant", store.UserQuery{}, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
		{"the other tenant", store.UserQuery{TenantID: tenantB}, []int{11}},
		{"a tenant without users", store.UserQuery{TenantID: "third"}, nil},
		{"one status", store.UserQuery{Statuses: []store.Status{store.StatusBlocked}}, []int{2, 7}},
		{"two statuses", store.UserQuery{Statuses: []store.Status{store.StatusActive, store.StatusDeleted}}, []int{1, 3, 4, 5, 6, 8, 9, 10}},
		{"confirmed", store.UserQuery{Confirmed: yes()}, []int{1, 3, 5}},
		{"not confirmed", store.UserQuery{Confirmed: no()}, []int{2, 4, 6, 7, 8, 9, 10}},
		{"made by a visitor", store.UserQuery{CreatedVia: store.CreatedViaSignup}, []int{2, 6, 8}},
		{"made by an administrator", store.UserQuery{CreatedVia: store.CreatedViaAdmin}, []int{3, 9}},
		{"made by an invitation", store.UserQuery{CreatedVia: store.CreatedViaInvite}, []int{4}},
		{"made by the code, with the default of an empty value", store.UserQuery{CreatedVia: store.CreatedViaAPI}, []int{1, 5, 7, 10}},
		{"created from a moment, inclusive", store.UserQuery{CreatedFrom: minutes(5)}, []int{5, 6, 7, 8, 9, 10}},
		{"created before a moment, exclusive", store.UserQuery{CreatedBefore: minutes(5)}, []int{1, 2, 3, 4}},
		{"created in a period", store.UserQuery{CreatedFrom: minutes(3), CreatedBefore: minutes(7)}, []int{3, 4, 5, 6}},
		{"created in an empty period", store.UserQuery{CreatedFrom: minutes(3), CreatedBefore: minutes(3)}, nil},
		{"last signed in from a moment", store.UserQuery{LastLoginFrom: minutes(10)}, []int{1, 5, 7}},
		{"last signed in before a moment", store.UserQuery{LastLoginBefore: minutes(10)}, []int{3, 9}},
		{"last signed in in a period", store.UserQuery{LastLoginFrom: minutes(5), LastLoginBefore: minutes(20)}, []int{1, 3, 5}},
		{"never signed in", store.UserQuery{NeverLoggedIn: true}, []int{2, 4, 6, 8, 10}},
		{"never signed in and signed in after a moment", store.UserQuery{NeverLoggedIn: true, LastLoginFrom: minutes(1)}, nil},
		{"never signed in and not confirmed", store.UserQuery{NeverLoggedIn: true, Confirmed: no()}, []int{2, 4, 6, 8, 10}},
		{"to be removed before a moment", store.UserQuery{PurgeBefore: listBase.Add(20 * 24 * time.Hour)}, []int{6}},
		{"to be removed before a later moment", store.UserQuery{PurgeBefore: listBase.Add(40 * 24 * time.Hour)}, []int{3, 6}},
		{"to be removed at the moment itself", store.UserQuery{PurgeBefore: listBase.Add(10 * 24 * time.Hour)}, nil},
		{"deleted and to be removed", store.UserQuery{Statuses: []store.Status{store.StatusDeleted}, PurgeBefore: listBase.Add(20 * 24 * time.Hour)}, []int{6}},
		{"a block that ends before a moment", store.UserQuery{BlockedBefore: minutes(61)}, []int{7}},
		{"a block that ends at the moment itself", store.UserQuery{BlockedBefore: minutes(60)}, nil},
		{"blocked users whose block ends", store.UserQuery{Statuses: []store.Status{store.StatusBlocked}, BlockedBefore: minutes(1000)}, []int{7}},
		{"every condition at once", store.UserQuery{
			Statuses: []store.Status{store.StatusActive}, CreatedVia: store.CreatedViaAPI, Confirmed: yes(),
			CreatedFrom: minutes(1), CreatedBefore: minutes(10), LastLoginFrom: minutes(10), ValuePrefix: "a",
		}, []int{1, 5}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantUsers(t, listUsers(t, s, c.query), c.want...)
		})
	}
	for _, u := range listUsers(t, s, store.UserQuery{}) {
		want := listedUsers[userNumbers([]store.User{u})[0]-1]
		wantVia := cmpOr(want.via, store.CreatedViaAPI)
		if u.CreatedVia != wantVia || u.Status != want.status || !sameTime(u.CreatedAt, minutes(want.created)) {
			t.Fatalf("List returned %+v for the user %d, want the record as it is stored", u, want.n)
		}
	}
}

func cmpOr(v, fallback store.CreatedVia) store.CreatedVia {
	if v == "" {
		return fallback
	}
	return v
}

func testUserListSearch(t *testing.T, s store.Store) {
	seedListedUsers(t, s)
	long := strings.Repeat("a", store.MaxIdentifierValueLength+1)
	cases := []struct {
		name  string
		query store.UserQuery
		want  []int
	}{
		{"an exact value", store.UserQuery{Identifiers: []store.IdentifierRef{{Type: "email", Value: "ann@example.com"}}}, []int{1}},
		{"an exact value of another user", store.UserQuery{Identifiers: []store.IdentifierRef{{Type: "nick", Value: "a_b"}}}, []int{4}},
		{"several exact values", store.UserQuery{Identifiers: []store.IdentifierRef{{Type: "email", Value: "ann@example.com"}, {Type: "nick", Value: "a_b"}, {Type: "phone", Value: "+79260000003"}}}, []int{1, 3, 4}},
		{"two values of one user", store.UserQuery{Identifiers: []store.IdentifierRef{{Type: "email", Value: "ann@example.com"}, {Type: "nick", Value: "ann"}}}, []int{1}},
		{"a value of another type", store.UserQuery{Identifiers: []store.IdentifierRef{{Type: "nick", Value: "ann@example.com"}}}, nil},
		{"a value that differs in the case", store.UserQuery{Identifiers: []store.IdentifierRef{{Type: "email", Value: "Ann@example.com"}}}, nil},
		{"a value that is not there", store.UserQuery{Identifiers: []store.IdentifierRef{{Type: "email", Value: "nobody@example.com"}}}, nil},
		{"an exact value in the other tenant", store.UserQuery{TenantID: tenantB, Identifiers: []store.IdentifierRef{{Type: "email", Value: "ann@example.com"}}}, []int{11}},
		{"values that cannot be stored are ignored", store.UserQuery{Identifiers: []store.IdentifierRef{{Type: "email", Value: "a\x00b"}, {Type: "email", Value: "ann@example.com"}, {Type: "", Value: "x"}, {Type: "email", Value: ""}, {Type: "email", Value: long}}}, []int{1}},
		{"only values that cannot be stored", store.UserQuery{Identifiers: []store.IdentifierRef{{Type: "email", Value: "a\xffb"}}}, nil},
		{"a prefix", store.UserQuery{ValuePrefix: "a"}, []int{1, 4, 5, 8, 9}},
		{"a longer prefix", store.UserQuery{ValuePrefix: "ann"}, []int{1}},
		{"a whole value as a prefix", store.UserQuery{ValuePrefix: "ann@example.com"}, []int{1}},
		{"a prefix of an e-mail address", store.UserQuery{ValuePrefix: "axb@"}, []int{5}},
		{"an underscore is an underscore", store.UserQuery{ValuePrefix: "a_"}, []int{4}},
		{"an underscore does not stand for a letter", store.UserQuery{ValuePrefix: "a_b"}, []int{4}},
		{"a percent sign is a percent sign", store.UserQuery{ValuePrefix: "50%"}, []int{6}},
		{"a prefix that the percent sign would match", store.UserQuery{ValuePrefix: "50"}, []int{6, 7}},
		{"a percent sign does not stand for anything", store.UserQuery{ValuePrefix: "%"}, nil},
		{"a percent sign after a letter", store.UserQuery{ValuePrefix: "a%"}, nil},
		{"an exclamation mark is an exclamation mark", store.UserQuery{ValuePrefix: "a!"}, []int{8}},
		{"the escape character twice", store.UserQuery{ValuePrefix: "a!!"}, nil},
		{"a backslash is a backslash", store.UserQuery{ValuePrefix: `a\`}, []int{9}},
		{"an underscore alone", store.UserQuery{ValuePrefix: "_"}, nil},
		{"a prefix is compared byte by byte", store.UserQuery{ValuePrefix: "A"}, nil},
		{"a prefix of a value in the other tenant", store.UserQuery{ValuePrefix: "ann@"}, []int{1}},
		{"a prefix in the other tenant", store.UserQuery{TenantID: tenantB, ValuePrefix: "ann@"}, []int{11}},
		{"a prefix that is too long", store.UserQuery{ValuePrefix: long}, nil},
		{"a prefix that cannot be stored", store.UserQuery{ValuePrefix: "a\x00"}, nil},
		{"a prefix that is not text", store.UserQuery{ValuePrefix: "a\xff"}, nil},
		{"a prefix and a status", store.UserQuery{ValuePrefix: "a", Statuses: []store.Status{store.StatusActive}}, []int{1, 4, 5, 8, 9}},
		{"a prefix and a status that does not fit", store.UserQuery{ValuePrefix: "a", Statuses: []store.Status{store.StatusBlocked}}, nil},
		{"a prefix and an exact value", store.UserQuery{ValuePrefix: "b", Identifiers: []store.IdentifierRef{{Type: "email", Value: "bob@example.com"}}}, []int{2}},
		{"a prefix and an exact value that do not fit together", store.UserQuery{ValuePrefix: "a", Identifiers: []store.IdentifierRef{{Type: "email", Value: "bob@example.com"}}}, nil},
		{"a prefix and a confirmation", store.UserQuery{ValuePrefix: "a", Confirmed: yes()}, []int{1, 5}},
		{"a tenant that cannot be stored", store.UserQuery{TenantID: "a\x00b"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantUsers(t, listUsers(t, s, c.query), c.want...)
		})
	}
}

func testUserListOrder(t *testing.T, s store.Store) {
	seedListedUsers(t, s)
	cases := []struct {
		name  string
		query store.UserQuery
		want  []int
	}{
		{"by creation, the oldest first", store.UserQuery{}, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
		{"by creation, the newest first", store.UserQuery{Descending: true}, []int{10, 9, 8, 7, 6, 5, 4, 3, 2, 1}},
		{"by creation, named", store.UserQuery{Order: store.OrderUsersByCreation}, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
		{"by status", store.UserQuery{Order: store.OrderUsersByStatus}, []int{1, 4, 5, 8, 9, 10, 2, 7, 3, 6}},
		{"by status, turned around", store.UserQuery{Order: store.OrderUsersByStatus, Descending: true}, []int{6, 3, 7, 2, 10, 9, 8, 5, 4, 1}},
		{"by the last sign-in, the oldest first", store.UserQuery{Order: store.OrderUsersByLastLogin}, []int{9, 3, 1, 5, 7, 2, 4, 6, 8, 10}},
		{"by the last sign-in, the newest first", store.UserQuery{Order: store.OrderUsersByLastLogin, Descending: true}, []int{7, 5, 1, 3, 9, 10, 8, 6, 4, 2}},
		{"by the last sign-in of the active", store.UserQuery{Order: store.OrderUsersByLastLogin, Statuses: []store.Status{store.StatusActive}}, []int{9, 1, 5, 4, 8, 10}},
		{"with a limit", store.UserQuery{Descending: true, Limit: 3}, []int{10, 9, 8}},
		{"with the limit of one", store.UserQuery{Order: store.OrderUsersByLastLogin, Limit: 1}, []int{9}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantUsers(t, listUsers(t, s, c.query), c.want...)
		})
	}
	t.Run("after a user that is not in the list, in a created order", func(t *testing.T) {
		after := &store.User{ID: id(500), CreatedAt: minutes(4)}
		wantUsers(t, listUsers(t, s, store.UserQuery{After: after}), 5, 6, 7, 8, 9, 10)
		wantUsers(t, listUsers(t, s, store.UserQuery{After: after, Descending: true}), 4, 3, 2, 1)
		tie := &store.User{ID: id(3), CreatedAt: minutes(3)}
		wantUsers(t, listUsers(t, s, store.UserQuery{After: tie}), 4, 5, 6, 7, 8, 9, 10)
		wantUsers(t, listUsers(t, s, store.UserQuery{After: tie, Descending: true}), 2, 1)
	})
	t.Run("after a user that is not in the list, in a last sign-in order", func(t *testing.T) {
		signedIn := &store.User{ID: id(500), LastLoginAt: minutes(10)}
		wantUsers(t, listUsers(t, s, store.UserQuery{Order: store.OrderUsersByLastLogin, After: signedIn}), 7, 2, 4, 6, 8, 10)
		wantUsers(t, listUsers(t, s, store.UserQuery{Order: store.OrderUsersByLastLogin, After: signedIn, Descending: true}), 5, 1, 3, 9, 10, 8, 6, 4, 2)
		never := &store.User{ID: id(5)}
		wantUsers(t, listUsers(t, s, store.UserQuery{Order: store.OrderUsersByLastLogin, After: never}), 6, 8, 10)
		wantUsers(t, listUsers(t, s, store.UserQuery{Order: store.OrderUsersByLastLogin, After: never, Descending: true}), 4, 2)
	})
	t.Run("after a user that is not in the list, in a status order", func(t *testing.T) {
		after := &store.User{ID: id(500), Status: store.StatusBlocked}
		wantUsers(t, listUsers(t, s, store.UserQuery{Order: store.OrderUsersByStatus, After: after}), 3, 6)
		wantUsers(t, listUsers(t, s, store.UserQuery{Order: store.OrderUsersByStatus, After: after, Descending: true}), 7, 2, 10, 9, 8, 5, 4, 1)
	})
}

func testUserListPages(t *testing.T, s store.Store) {
	seedListedUsers(t, s)
	for _, order := range []store.UserOrder{"", store.OrderUsersByCreation, store.OrderUsersByLastLogin, store.OrderUsersByStatus} {
		for _, descending := range []bool{false, true} {
			base := store.UserQuery{Order: order, Descending: descending}
			full := listUsers(t, s, base)
			if len(full) != 10 {
				t.Fatalf("List = %d users, want 10", len(full))
			}
			for _, size := range []int{1, 2, 3, 4, 9, 10, 11} {
				var got []store.User
				query := base
				query.Limit = size
				for pages := 0; ; pages++ {
					page := listUsers(t, s, query)
					if len(page) > size || pages > 12 {
						t.Fatalf("order %q descending %v: a page of %d users has %d", order, descending, size, len(page))
					}
					got = append(got, page...)
					if len(page) < size {
						break
					}
					last := page[len(page)-1]
					query.After = &last
				}
				if !slices.Equal(userNumbers(got), userNumbers(full)) {
					t.Fatalf("order %q descending %v: pages of %d users give %v, want %v: none may be missed or repeated", order, descending, size, userNumbers(got), userNumbers(full))
				}
			}
			active := base
			active.Statuses = []store.Status{store.StatusActive}
			active.Limit = 2
			var got []store.User
			for range 10 {
				page := listUsers(t, s, active)
				got = append(got, page...)
				if len(page) < 2 {
					break
				}
				last := page[len(page)-1]
				active.After = &last
			}
			want := listUsers(t, s, store.UserQuery{Order: order, Descending: descending, Statuses: []store.Status{store.StatusActive}})
			if !slices.Equal(userNumbers(got), userNumbers(want)) {
				t.Fatalf("order %q descending %v: pages of a filtered listing give %v, want %v", order, descending, userNumbers(got), userNumbers(want))
			}
		}
	}
}

func testUserListInvalidQueries(t *testing.T, s store.Store) {
	ctx := t.Context()
	seedListedUsers(t, s)
	bad := map[string]store.UserQuery{
		"no limit":                                       {TenantID: tenantA},
		"a negative limit":                               {TenantID: tenantA, Limit: -1},
		"a limit over the page":                          {TenantID: tenantA, Limit: store.MaxUsersPage + 1},
		"an unknown status":                              {TenantID: tenantA, Limit: 5, Statuses: []store.Status{"frozen"}},
		"an unknown way of creation":                     {TenantID: tenantA, Limit: 5, CreatedVia: "import"},
		"an unknown order":                               {TenantID: tenantA, Limit: 5, Order: "login"},
		"too many identifiers":                           {TenantID: tenantA, Limit: 5, Identifiers: make([]store.IdentifierRef, store.MaxUserIdentifierRefs+1)},
		"a cursor without an ID":                         {TenantID: tenantA, Limit: 5, After: &store.User{CreatedAt: minutes(1)}},
		"a cursor without a time":                        {TenantID: tenantA, Limit: 5, After: &store.User{ID: id(1)}},
		"a cursor without a status":                      {TenantID: tenantA, Limit: 5, Order: store.OrderUsersByStatus, After: &store.User{ID: id(1)}},
		"a cursor of a user without a time of a sign-in": {TenantID: tenantA, Limit: 5, Order: "login", After: &store.User{ID: id(1)}},
	}
	for name, q := range bad {
		if name == "a cursor of a user without a time of a sign-in" {
			continue
		}
		if _, err := s.Users().List(ctx, q); err == nil || isDomainError(err) {
			t.Errorf("List with %s = %v, want a validation error", name, err)
		}
	}
	for _, size := range []int{1, store.MaxUsersPage} {
		if list, err := s.Users().List(ctx, store.UserQuery{TenantID: tenantA, Limit: size}); err != nil || len(list) == 0 {
			t.Errorf("List with a limit of %d = %d users, %v; want users", size, len(list), err)
		}
	}
	many := make([]store.IdentifierRef, store.MaxUserIdentifierRefs)
	many[0] = store.IdentifierRef{Type: "email", Value: "ann@example.com"}
	if list, err := s.Users().List(ctx, store.UserQuery{TenantID: tenantA, Limit: 5, Identifiers: many}); err != nil || len(list) != 1 {
		t.Errorf("List with %d identifiers = %d users, %v; want 1", len(many), len(list), err)
	}
	if list, err := s.Users().List(ctx, store.UserQuery{TenantID: tenantA, Limit: 5, After: &store.User{ID: "a\x00b", CreatedAt: minutes(1)}}); err != nil || len(list) != 0 {
		t.Errorf("List after a user that cannot be stored = %d users, %v; want nothing", len(list), err)
	}
	if list, err := s.Users().List(ctx, store.UserQuery{TenantID: tenantA, Limit: 5, Order: store.OrderUsersByLastLogin, After: &store.User{ID: id(1)}}); err != nil || len(list) == 0 {
		t.Errorf("List in the order of the last sign-in after a user who never signed in = %d users, %v; want the rest of those", len(list), err)
	}
}

func testUserListSeesTransactions(t *testing.T, s store.Store) {
	ctx := t.Context()
	seedListedUsers(t, s)
	err := s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		u := newUser(tenantA, id(20))
		u.CreatedAt = minutes(20)
		u.CreatedVia = store.CreatedViaInvite
		if err := tx.Users().Create(ctx, u); err != nil {
			return err
		}
		list, err := tx.Users().List(ctx, store.UserQuery{TenantID: tenantA, CreatedVia: store.CreatedViaInvite, Limit: 10})
		if err != nil || len(list) != 2 {
			return fmt.Errorf("the transaction must see its own user: %v, %w", len(list), err)
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatalf("InTx = %v, want the error of the function", err)
	}
	wantUsers(t, listUsers(t, s, store.UserQuery{CreatedVia: store.CreatedViaInvite}), 4)
}

func testUserCreatedVia(t *testing.T, s store.Store) {
	ctx := t.Context()
	for n, via := range []store.CreatedVia{"", store.CreatedViaAPI, store.CreatedViaSignup, store.CreatedViaAdmin, store.CreatedViaInvite} {
		u := newUser(tenantA, id(n+1))
		u.CreatedVia = via
		got := mustCreate(t, s, u)
		if want := cmpOr(via, store.CreatedViaAPI); got.CreatedVia != want {
			t.Fatalf("a user created with %q has %q, want %q", via, got.CreatedVia, want)
		}
	}
	signup, err := s.Users().Get(ctx, tenantA, id(3))
	if err != nil {
		t.Fatal(err)
	}
	changed := signup
	changed.CreatedVia = store.CreatedViaAdmin
	changed.BlockedReason = "spam"
	updated, err := s.Users().Update(ctx, changed)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if updated.CreatedVia != store.CreatedViaAdmin && updated.CreatedVia != store.CreatedViaSignup {
		t.Fatalf("Update returned %q", updated.CreatedVia)
	}
	reread, err := s.Users().Get(ctx, tenantA, id(3))
	if err != nil || reread.CreatedVia != store.CreatedViaSignup || reread.BlockedReason != "spam" {
		t.Fatalf("Update must not change how the user was made: %+v, %v", reread, err)
	}
	bad := newUser(tenantA, id(9))
	bad.CreatedVia = "import"
	if err = s.Users().Create(ctx, bad); err == nil || isDomainError(err) {
		t.Fatalf("Create with an unknown way = %v, want a validation error", err)
	}
	reread.CreatedVia = "import"
	if _, err = s.Users().Update(ctx, reread); err == nil || isDomainError(err) {
		t.Fatalf("Update with an unknown way = %v, want a validation error", err)
	}
}
