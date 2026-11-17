package storecheck

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func TestCreatedViaRules(t *testing.T) {
	for _, via := range []store.CreatedVia{"", store.CreatedViaAPI, store.CreatedViaSignup, store.CreatedViaAdmin, store.CreatedViaInvite} {
		if err := CreatedVia(via); err != nil {
			t.Errorf("%q was rejected: %v", via, err)
		}
		u := store.User{TenantID: "default", ID: "u1", Status: store.StatusActive, CreatedAt: time.Now(), CreatedVia: via}
		if err := NewUser(u); err != nil {
			t.Errorf("a user made %q was rejected: %v", via, err)
		}
	}
	if err := CreatedVia("import"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("CreatedVia(import) = %v, want ErrInvalid", err)
	}
	u := store.User{TenantID: "default", ID: "u1", Status: store.StatusActive, CreatedAt: time.Now(), CreatedVia: "import"}
	if err := User(u); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a user made in an unknown way = %v, want ErrInvalid", err)
	}
}

func TestUserQueryRules(t *testing.T) {
	good := store.UserQuery{TenantID: "default", Limit: 10}
	if err := UserQuery(good); err != nil {
		t.Fatalf("a valid query was rejected: %v", err)
	}
	for _, limit := range []int{1, store.MaxUsersPage} {
		if err := UserQuery(store.UserQuery{Limit: limit}); err != nil {
			t.Errorf("a limit of %d was rejected: %v", limit, err)
		}
	}
	cases := map[string]store.UserQuery{
		"no limit":                {},
		"a negative limit":        {Limit: -1},
		"a limit too large":       {Limit: store.MaxUsersPage + 1},
		"an unknown status":       {Limit: 1, Statuses: []store.Status{store.StatusActive, "frozen"}},
		"an unknown way":          {Limit: 1, CreatedVia: "import"},
		"an unknown order":        {Limit: 1, Order: "login"},
		"too many identifiers":    {Limit: 1, Identifiers: make([]store.IdentifierRef, store.MaxUserIdentifierRefs+1)},
		"a cursor without an ID":  {Limit: 1, After: &store.User{CreatedAt: time.Now()}},
		"a cursor without a time": {Limit: 1, After: &store.User{ID: "u"}},
		"a cursor without a time for the created order":  {Limit: 1, Order: store.OrderUsersByCreation, After: &store.User{ID: "u"}},
		"a cursor without a status for the status order": {Limit: 1, Order: store.OrderUsersByStatus, After: &store.User{ID: "u"}},
	}
	for name, q := range cases {
		if err := UserQuery(q); !errors.Is(err, ErrInvalid) {
			t.Errorf("UserQuery with %s = %v, want ErrInvalid", name, err)
		}
	}
	valid := []store.UserQuery{
		{Limit: 1, Order: store.OrderUsersByLastLogin, After: &store.User{ID: "u"}},
		{Limit: 1, Order: store.OrderUsersByStatus, After: &store.User{ID: "u", Status: store.StatusBlocked}},
		{Limit: 1, After: &store.User{ID: "u", CreatedAt: time.Now()}},
		{Limit: 1, Identifiers: make([]store.IdentifierRef, store.MaxUserIdentifierRefs)},
	}
	for i, q := range valid {
		if err := UserQuery(q); err != nil {
			t.Errorf("valid query %d was rejected: %v", i, err)
		}
	}
}

func TestIdentifierRefsThatCannotBeStoredAreLeftOut(t *testing.T) {
	long := strings.Repeat("a", store.MaxIdentifierValueLength+1)
	refs := []store.IdentifierRef{
		{Type: "email", Value: "a@example.com"}, {Type: "", Value: "x"}, {Type: "email", Value: ""}, {Type: "email", Value: "a\x00"},
		{Type: "email", Value: long}, {Type: strings.Repeat("t", store.MaxIdentifierTypeLength+1), Value: "x"}, {Type: "nick", Value: "\xff"}, {Type: "nick", Value: "ok"},
	}
	valid := IdentifierRefs(refs)
	if len(valid) != 2 || valid[0].Value != "a@example.com" || valid[1].Value != "ok" {
		t.Fatalf("the references that can be stored are %v", valid)
	}
	if IdentifierRefs(nil) != nil {
		t.Fatal("no references give no references")
	}
}

func TestUserQueryValuesThatCannotBeStoredMatchNothing(t *testing.T) {
	if !ValidUserQuery(store.UserQuery{TenantID: "default", ValuePrefix: "ab", After: &store.User{ID: "u", Status: store.StatusActive}, Identifiers: []store.IdentifierRef{{Type: "e", Value: "v"}}}) {
		t.Fatal("a query of valid values was refused")
	}
	for name, q := range map[string]store.UserQuery{
		"a tenant":                              {TenantID: "a\x00"},
		"a prefix":                              {ValuePrefix: "\xff"},
		"a long prefix":                         {ValuePrefix: strings.Repeat("a", store.MaxIdentifierValueLength+1)},
		"a cursor":                              {After: &store.User{ID: "a\x00"}},
		"a cursor status":                       {After: &store.User{ID: "u", Status: "a\xff"}},
		"only references that cannot be stored": {Identifiers: []store.IdentifierRef{{Type: "e", Value: "\xff"}}},
	} {
		if ValidUserQuery(q) {
			t.Errorf("a query with %s was accepted", name)
		}
	}
}
