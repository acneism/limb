package limb

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/store"
)

func TestAUserIsCreatedWithAPasswordThatMustBeChanged(t *testing.T) {
	f, log := newManageFixture(t)
	log.take()
	created, err := f.a.Admin().CreateUser(t.Context(), NewUser{
		Identifiers: map[string]string{"email": "  Olga@Example.com ", "username": "olga_o"}, Password: goodPassword,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if created.CreatedVia != "admin" || !created.MustChangePassword || created.Status != StatusActive || !created.CreatedAt.Equal(f.clock.now().Truncate(time.Microsecond)) {
		t.Fatalf("the user is %+v", created)
	}
	if len(created.Identifiers) != 2 || created.Identifiers[0].Value != "olga@example.com" || created.Identifiers[0].DisplayValue != "Olga@Example.com" || !created.Identifiers[0].VerifiedAt.IsZero() {
		t.Fatalf("the identifiers are %+v", created.Identifiers)
	}
	stored := f.storedUser(t, created.ID)
	if stored.CreatedVia != store.CreatedViaAdmin || !stored.MustChangePassword || stored.PasswordHash == "" || stored.Version != 1 {
		t.Fatalf("the stored user is %+v", stored)
	}
	login, err := f.a.Login(t.Context(), Credentials{Login: "olga_o", Password: goodPassword, IP: testIP, UserAgent: testAgent, Kind: SessionCookie})
	if err != nil || !login.Principal.MustChangePassword {
		t.Fatalf("Login = %+v, %v, want a session that has to change the password", login, err)
	}
	records := recordsOf(t, f.a, "user.created")
	if len(records) != 1 || records[0].ActorKind != store.ActorSystem || records[0].ActorID != "api" || records[0].TargetUserID != string(created.ID) {
		t.Fatalf("the creation is recorded as %+v", records)
	}
	details := detailsOf(t, records[0])
	values, _ := details["identifiers"].(map[string]any)
	if values["email"] != "olga@example.com" || values["username"] != "olga_o" || details["must_change_password"] != true {
		t.Fatalf("the details are %v", details)
	}
	if got := len(recordsOf(t, f.a, "auth.user_created")); got != 1 {
		t.Fatalf("the audit log holds %d records of registrations made from events, want only the one of the fixture", got)
	}
	events := log.take()
	if len(events) < 1 || events[0].Type != EventUserCreated || events[0].UserID != string(created.ID) || events[0].Details["via"] != "admin" {
		t.Fatalf("the events are %+v", events)
	}
	if strings.Contains(records[0].Details, goodPassword) {
		t.Fatal("the password is in the audit log")
	}
}

func TestAUserWhoMayKeepThePasswordIsNotMadeToChangeIt(t *testing.T) {
	f, _ := newManageFixture(t)
	created, err := f.a.Admin().CreateUser(t.Context(), NewUser{
		Identifiers: map[string]string{"email": "pavel@example.com"}, Password: goodPassword, KeepPassword: true, Verified: []string{"email"},
	})
	if err != nil || created.MustChangePassword || created.Identifiers[0].VerifiedAt.IsZero() {
		t.Fatalf("CreateUser = %+v, %v", created, err)
	}
	records := recordsOf(t, f.a, "user.created")
	details := detailsOf(t, records[0])
	verified, _ := details["verified"].([]any)
	if details["must_change_password"] != false || len(verified) != 1 || verified[0] != "email" {
		t.Fatalf("the details are %v: what the administrator vouches for is recorded", details)
	}
}

func TestAUserThatBreaksTheRulesIsNotCreated(t *testing.T) {
	f, log := newManageFixture(t)
	log.take()
	var validation *ValidationError
	var policy *PolicyError
	for name, c := range map[string]struct {
		user  NewUser
		field string
	}{
		"an unknown type":      {NewUser{Identifiers: map[string]string{"email": "a1@example.com", "shoe": "42"}, Password: goodPassword}, "shoe"},
		"no required value":    {NewUser{Identifiers: map[string]string{"username": "someone"}, Password: goodPassword}, "email"},
		"a value that is bad":  {NewUser{Identifiers: map[string]string{"email": "not an address"}, Password: goodPassword}, "email"},
		"a type to vouch for":  {NewUser{Identifiers: map[string]string{"email": "a2@example.com"}, Password: goodPassword, Verified: []string{"username"}}, "verified"},
		"a type without value": {NewUser{Identifiers: map[string]string{"email": "a3@example.com"}, Password: goodPassword, Verified: []string{"phone"}}, "verified"},
	} {
		if _, err := f.a.Admin().CreateUser(t.Context(), c.user); !errors.As(err, &validation) || validation.Field != c.field {
			t.Errorf("%s: CreateUser = %v, want a *ValidationError for %s", name, err, c.field)
		}
	}
	if _, err := f.a.Admin().CreateUser(t.Context(), NewUser{Identifiers: map[string]string{"email": "a4@example.com"}, Password: "short"}); !errors.As(err, &policy) {
		t.Errorf("CreateUser with a short password = %v, want a *PolicyError", err)
	}
	if _, err := f.a.Admin().CreateUser(t.Context(), NewUser{Identifiers: map[string]string{"email": "NINA@example.com"}, Password: goodPassword}); !errors.Is(err, ErrIdentifierTaken) {
		t.Errorf("CreateUser with a taken address = %v, want ErrIdentifierTaken", err)
	}
	if got := len(recordsOf(t, f.a, "user.created")); got != 0 {
		t.Fatalf("%d creations that failed were recorded", got)
	}
	if events := log.take(); len(events) != 0 {
		t.Fatalf("creations that failed were reported: %+v", events)
	}
	page, err := f.a.Admin().ListUsers(t.Context(), UserFilter{})
	if err != nil || len(page.Users) != 1 {
		t.Fatalf("the service holds %d users, want only the one of the fixture: %v", len(page.Users), err)
	}
}

func TestAUserThatCannotBeRecordedIsNotCreated(t *testing.T) {
	f, log := newManageFixture(t)
	log.take()
	faults := newFaults()
	f.a.store = faultStore{Store: f.a.store, faults: faults}
	broken := errors.New("the audit log is gone")
	faults.set("audit.add", broken)
	if _, err := f.a.Admin().CreateUser(t.Context(), NewUser{Identifiers: map[string]string{"email": "quentin@example.com"}, Password: goodPassword}); !errors.Is(err, broken) {
		t.Fatalf("CreateUser = %v, want the failure of the audit log", err)
	}
	faults.clear()
	if _, err := f.a.store.Identifiers().Find(t.Context(), f.a.tenant, "email", "quentin@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the user was created although the creation could not be recorded: %v", err)
	}
	if events := log.take(); len(events) != 0 {
		t.Fatalf("a creation that failed was reported: %+v", events)
	}
}

func TestAValueOfAUserIsAddedChangedAndRemoved(t *testing.T) {
	f, log, _ := newMailFixture(t)
	f.confirm(t, "nina@example.com")
	log.take()
	admin := f.a.Admin()
	if err := admin.RemoveUserIdentifier(t.Context(), f.user.ID, "username"); err != nil {
		t.Fatalf("RemoveUserIdentifier failed: %v", err)
	}
	if _, found := f.identifiers(t, f.user.ID)["username"]; found {
		t.Fatal("the username was not removed")
	}
	if err := admin.SetUserIdentifier(t.Context(), f.user.ID, "username", "  Nina_New "); err != nil {
		t.Fatalf("SetUserIdentifier failed: %v", err)
	}
	added := f.identifiers(t, f.user.ID)["username"]
	if added.Value != "nina_new" || added.DisplayValue != "Nina_New" || !added.VerifiedAt.IsZero() {
		t.Fatalf("the username is %+v", added)
	}
	if err := admin.SetUserIdentifier(t.Context(), f.user.ID, "email", "nina.new@example.com"); err != nil {
		t.Fatalf("SetUserIdentifier failed: %v", err)
	}
	email := f.identifiers(t, f.user.ID)["email"]
	if email.Value != "nina.new@example.com" || !email.VerifiedAt.IsZero() {
		t.Fatalf("the address is %+v, want the new one, not confirmed", email)
	}
	if _, err := f.a.Login(t.Context(), Credentials{Login: "nina.new@example.com", Password: goodPassword, IP: testIP, Kind: SessionCookie}); err != nil {
		t.Fatalf("Login with the new address failed: %v", err)
	}
	if _, err := f.a.Login(t.Context(), Credentials{Login: "nina@example.com", Password: goodPassword, IP: testIP, Kind: SessionCookie}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login with the old address = %v, want ErrInvalidCredentials", err)
	}
	for action, want := range map[string]int{"user.identifier_removed": 1, "user.identifier_added": 1, "user.identifier_changed": 1} {
		if got := len(recordsOf(t, f.a, action)); got != want {
			t.Errorf("the audit log holds %d records of %s, want %d", got, action, want)
		}
	}
	changed := recordsOf(t, f.a, "user.identifier_changed")[0]
	details := detailsOf(t, changed)
	if details["type"] != "email" || details["old"] != "nina@example.com" || details["new"] != "nina.new@example.com" || details["old_verified"] != true || changed.ActorID != "api" {
		t.Fatalf("the change is recorded as %v", details)
	}
	events := log.take()
	var changes []string
	for _, e := range events {
		if e.Type == EventUserChanged {
			changes = append(changes, e.Details["change"]+":"+e.Channel)
		}
	}
	if strings.Join(changes, ",") != "identifier_removed:username,identifier_added:username,identifier_changed:email" {
		t.Fatalf("the changes reported are %v", changes)
	}
	for _, e := range events {
		if e.Type == EventUserChanged && (strings.Contains(e.Address, "nina") || e.Address == "") {
			t.Fatalf("the address of the event %+v is not masked", e)
		}
	}
}

func TestAChangedValueIsToldToTheChannelsThatWereConfirmedBefore(t *testing.T) {
	f, _, sender := newMailFixture(t)
	f.confirm(t, "nina@example.com")
	if err := f.a.Admin().SetUserIdentifier(t.Context(), f.user.ID, "email", "nina.new@example.com"); err != nil {
		t.Fatal(err)
	}
	m := f.messages(t, sender, 1)[0]
	if m.Kind != MessageIdentifierChanged || m.To != "nina@example.com" || m.Link != "" || m.Code != "" {
		t.Fatalf("the notice is %+v: it goes to the address that was confirmed before the change", m)
	}
	f.confirm(t, "nina.new@example.com")
	if err := f.a.Admin().SetUserIdentifier(t.Context(), f.user.ID, "username", "nina_other"); err != nil {
		t.Fatal(err)
	}
	if got := f.messages(t, sender, 2); got[1].Kind != MessageIdentifierChanged || got[1].To != "nina.new@example.com" {
		t.Fatalf("the second notice is %+v: it goes to the address that is confirmed now", got[1])
	}
}

func TestAValueThatIsTheSameOrTakenOrBadChangesNothing(t *testing.T) {
	f, log, sender := newMailFixture(t)
	f.confirm(t, "nina@example.com")
	other := mustRegister(t, f.a, map[string]string{"email": "olga@example.com", "username": "olga_o"}, goodPassword)
	log.take()
	admin := f.a.Admin()
	if err := admin.SetUserIdentifier(t.Context(), f.user.ID, "email", "NINA@example.com"); err != nil {
		t.Fatalf("SetUserIdentifier with the value the user has failed: %v", err)
	}
	if got := len(recordsOf(t, f.a, "user.identifier_changed")); got != 0 || len(log.take()) != 0 {
		t.Fatal("a value that did not change was recorded or reported")
	}
	if err := admin.SetUserIdentifier(t.Context(), f.user.ID, "email", "Olga@Example.com"); !errors.Is(err, ErrIdentifierTaken) {
		t.Fatalf("SetUserIdentifier with a taken value = %v, want ErrIdentifierTaken", err)
	}
	email := f.identifiers(t, f.user.ID)["email"]
	if email.Value != "nina@example.com" || email.VerifiedAt.IsZero() {
		t.Fatalf("a refused change left the address as %+v: it has to stay as it was, confirmed", email)
	}
	if f.identifiers(t, other.ID)["email"].Value != "olga@example.com" {
		t.Fatal("the address of the other user changed")
	}
	var validation *ValidationError
	for name, c := range map[string]struct{ typ, value string }{
		"a bad value": {"email", "not an address"}, "no value": {"email", "   "}, "an unknown type": {"shoe", "42"}, "a short name": {"username", "ab"},
	} {
		if err := admin.SetUserIdentifier(t.Context(), f.user.ID, c.typ, c.value); !errors.As(err, &validation) || validation.Field != c.typ {
			t.Errorf("%s: SetUserIdentifier = %v, want a *ValidationError for %s", name, err, c.typ)
		}
	}
	eventually(t, "the queue of messages to empty", func() bool { return f.a.dispatcher.pending.Load() == 0 })
	if got := sender.sent(); len(got) != 0 {
		t.Fatalf("messages were sent for changes that were not made: %+v", got)
	}
}

func TestTheValuesThatAUserNeedsCannotBeRemoved(t *testing.T) {
	f, _, _ := newMailFixture(t)
	var validation *ValidationError
	if err := f.a.Admin().RemoveUserIdentifier(t.Context(), f.user.ID, "email"); !errors.As(err, &validation) || validation.Field != "email" {
		t.Fatalf("RemoveUserIdentifier of a required type = %v, want a *ValidationError", err)
	}
	if err := f.a.Admin().RemoveUserIdentifier(t.Context(), f.user.ID, "shoe"); !errors.As(err, &validation) || validation.Field != "shoe" {
		t.Fatalf("RemoveUserIdentifier of an unknown type = %v, want a *ValidationError", err)
	}
	if err := f.a.Admin().RemoveUserIdentifier(t.Context(), f.user.ID, "username"); err != nil {
		t.Fatal(err)
	}
	if err := f.a.Admin().RemoveUserIdentifier(t.Context(), f.user.ID, "username"); !errors.As(err, &validation) || validation.Field != "username" {
		t.Fatalf("RemoveUserIdentifier of a value the user does not have = %v, want a *ValidationError", err)
	}
	if got := len(f.identifiers(t, f.user.ID)); got != 1 {
		t.Fatalf("the user has %d values, want the address", got)
	}
}

func TestTheLastWayToSignInCannotBeRemoved(t *testing.T) {
	f, _ := newManageFixture(t, WithIdentifiers(identifier.Email(), identifier.Username()))
	user, err := f.a.Admin().CreateUser(t.Context(), NewUser{Identifiers: map[string]string{"email": "last@example.com"}, Password: goodPassword})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.a.Admin().SetUserIdentifier(t.Context(), user.ID, "username", "last_l"); err != nil {
		t.Fatal(err)
	}
	if err = f.a.Admin().RemoveUserIdentifier(t.Context(), user.ID, "email"); err != nil {
		t.Fatalf("RemoveUserIdentifier failed: %v", err)
	}
	var validation *ValidationError
	if err = f.a.Admin().RemoveUserIdentifier(t.Context(), user.ID, "username"); !errors.As(err, &validation) || validation.Field != "identifiers" {
		t.Fatalf("RemoveUserIdentifier of the last way to sign in = %v, want a *ValidationError for the identifiers", err)
	}
	if got := f.identifiers(t, user.ID); len(got) != 1 || got["username"].Value != "last_l" {
		t.Fatalf("the values are %+v", got)
	}
}

func TestAnAddressIsConfirmedOnTheWordOfTheAdministrator(t *testing.T) {
	f, log, _ := newMailFixture(t)
	log.take()
	admin := f.a.Admin()
	if err := admin.VerifyUserIdentifier(t.Context(), f.user.ID, "email"); err != nil {
		t.Fatalf("VerifyUserIdentifier failed: %v", err)
	}
	if f.identifiers(t, f.user.ID)["email"].VerifiedAt.IsZero() {
		t.Fatal("the address is not confirmed")
	}
	records := recordsOf(t, f.a, "user.identifier_verified")
	details := detailsOf(t, records[0])
	if len(records) != 1 || details["type"] != "email" || details["value"] != "nina@example.com" || records[0].ActorID != "api" {
		t.Fatalf("the confirmation is recorded as %+v", records)
	}
	events := log.take()
	if len(events) != 1 || events[0].Type != EventUserChanged || events[0].Details["change"] != "identifier_verified" || events[0].Address != "n***@example.com" {
		t.Fatalf("the events are %+v", events)
	}
	if err := admin.VerifyUserIdentifier(t.Context(), f.user.ID, "email"); err != nil {
		t.Fatalf("a second confirmation failed: %v", err)
	}
	if got := len(recordsOf(t, f.a, "user.identifier_verified")); got != 1 {
		t.Fatalf("a confirmation that was not needed was recorded: %d records", got)
	}
	var validation *ValidationError
	if err := admin.VerifyUserIdentifier(t.Context(), f.user.ID, "username"); !errors.As(err, &validation) || validation.Field != "username" {
		t.Fatalf("VerifyUserIdentifier of a name = %v, want a *ValidationError", err)
	}
	if err := admin.VerifyUserIdentifier(t.Context(), f.user.ID, "shoe"); !errors.As(err, &validation) || validation.Field != "shoe" {
		t.Fatalf("VerifyUserIdentifier of an unknown type = %v, want a *ValidationError", err)
	}
}

func TestTheOperationsOnValuesRefuseAUserThatCannotTakeThem(t *testing.T) {
	f, _, _ := newMailFixture(t)
	admin := f.a.Admin()
	missing := UserID("00000000-0000-7000-8000-000000000999")
	ops := map[string]func(UserID) error{
		"SetUserIdentifier":    func(id UserID) error { return admin.SetUserIdentifier(t.Context(), id, "username", "someone_s") },
		"RemoveUserIdentifier": func(id UserID) error { return admin.RemoveUserIdentifier(t.Context(), id, "username") },
		"VerifyUserIdentifier": func(id UserID) error { return admin.VerifyUserIdentifier(t.Context(), id, "email") },
		"ResendInvitation":     func(id UserID) error { return admin.ResendInvitation(t.Context(), id, "") },
	}
	for name, op := range ops {
		if err := op(missing); !errors.Is(err, ErrUserNotFound) {
			t.Errorf("%s of a user that does not exist = %v, want ErrUserNotFound", name, err)
		}
	}
	f.change(t, func(u *store.User) {
		u.Status, u.DeletedAt, u.PurgeAfter = store.StatusDeleted, f.clock.now(), f.clock.now().Add(time.Hour)
	})
	for name, op := range ops {
		if err := op(f.user.ID); !errors.Is(err, ErrUserDeleted) {
			t.Errorf("%s of a deleted user = %v, want ErrUserDeleted", name, err)
		}
	}
}
