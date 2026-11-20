package limb

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

func (f *peopleFixture) values(name string) map[string]UserIdentifier {
	f.t.Helper()
	user, err := f.a.Admin().User(f.t.Context(), f.ids[name])
	if err != nil {
		f.t.Fatal(err)
	}
	byType := map[string]UserIdentifier{}
	for _, i := range user.Identifiers {
		byType[i.Type] = i
	}
	return byType
}

func TestTheCardOffersToChangeConfirmAndRemoveTheValuesThatCanBe(t *testing.T) {
	f := seedPeople(t)
	id := string(f.ids["ann"])
	card := f.card("ann")
	for _, want := range []string{
		`action="/admin/users/` + id + `/identifiers/set"`, `name="type" value="email"`, `name="type" value="username"`, `id="value-email"`, `id="value-username"`,
		`<label for="value-email" class="sr-only">New value of the type email</label>`, `action="/admin/users/` + id + `/identifiers/verify"`, "Mark as confirmed",
		`action="/admin/users/` + id + `/identifiers/remove"`,
	} {
		if !card.has(want) {
			t.Errorf("the card lacks %q", want)
		}
	}
	if got := strings.Count(card.body, `/identifiers/verify"`); got != 1 {
		t.Errorf("%d values can be confirmed, want the address that is not confirmed", got)
	}
	if got := strings.Count(card.body, `/identifiers/remove"`); got != 1 || !strings.Contains(card.body, `/identifiers/remove">`+"\n"+`<input type="hidden" name="csrf" value="`+f.csrfOf(card)+`">`+"\n"+`<input type="hidden" name="type" value="username">`) {
		t.Errorf("%d values can be removed, want only the username: the address is required", got)
	}
	if card.has("Add a value") || card.has(`id="add-type"`) {
		t.Errorf("a user who has a value of every type is offered to add one")
	}
	eve := f.card("eve")
	if got := strings.Count(eve.body, `/identifiers/verify"`); got != 0 || eve.has("Mark as confirmed") {
		t.Errorf("the card of a user whose address is confirmed offers to confirm %d values: a username cannot be confirmed", got)
	}
	dan := f.card("dan")
	for _, unwanted := range []string{"/identifiers/", "Add a value", `id="value-email"`} {
		if dan.has(unwanted) {
			t.Errorf("the card of a deleted user has %q", unwanted)
		}
	}
	if !dan.has("<td>email</td>") {
		t.Errorf("the card of a deleted user does not show the values")
	}
}

func TestAnAdministratorChangesAndAddsAndRemovesTheValuesOfAUserThroughTheBrowser(t *testing.T) {
	f, sender := newMailPeople(t)
	f.add("ann")
	f.add("bob")
	f.confirm("ann")
	f.confirm("bob")
	f.enroll()
	id := string(f.ids["ann"])
	r := f.act("ann", "identifiers/set", url.Values{"type": {"email"}, "value": {"  New.Ann@Example.com "}})
	if r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/users/"+id+"?done=value" {
		t.Fatalf("a change of the address gave %d %q: %.300s", r.StatusCode, r.location(), r.body)
	}
	changed := f.values("ann")["email"]
	if changed.Value != "new.ann@example.com" || changed.DisplayValue != "New.Ann@Example.com" || !changed.VerifiedAt.IsZero() {
		t.Fatalf("the address is %+v, want the new one, unconfirmed", changed)
	}
	page := f.get("/users/" + id + "?done=value")
	for _, want := range []string{"The value is saved.", `<td class="break">New.Ann@Example.com</td>`, "<td>Value to sign in with changed</td>", `<span class="muted">old</span> ann@example.com`, `<span class="muted">new</span> new.ann@example.com`} {
		if !page.has(want) {
			t.Errorf("the card after a change lacks %q", want)
		}
	}
	record := f.only(audit.UserIdentifierChanged)
	if record.ActorKind != store.ActorAdmin || record.ActorID != f.adminID() || record.IP != "127.0.0.1" || record.TargetUserID != id {
		t.Errorf("the record of the change is %+v", record)
	}
	if notice := f.sentMessages(sender, 1)[0]; notice.Kind != MessageIdentifierChanged || notice.To != "ann@example.com" {
		t.Errorf("the old address was not told of the change: %+v", notice)
	}
	if r = f.act("ann", "identifiers/set", url.Values{"type": {"email"}, "value": {"new.ann@example.com"}}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("setting the same value gave %d", r.StatusCode)
	}
	if got := recordsOf(t, f.a, audit.UserIdentifierChanged); len(got) != 1 {
		t.Errorf("setting the value that the user has is recorded: %d records", len(got))
	}

	for _, c := range []struct {
		name   string
		fields url.Values
		status int
		text   string
	}{
		{"a value that is not an address", url.Values{"type": {"email"}, "value": {"not an address"}}, http.StatusUnprocessableEntity, "The value of email is not accepted:"},
		{"no value", url.Values{"type": {"email"}, "value": {"   "}}, http.StatusUnprocessableEntity, "The value of email is not accepted: required."},
		{"a value that another user has", url.Values{"type": {"email"}, "value": {"BOB@example.com"}}, http.StatusConflict, "Another user has this value."},
		{"a username that another user has", url.Values{"type": {"username"}, "value": {"bob"}}, http.StatusConflict, "Another user has this value."},
		{"a type that is not declared", url.Values{"type": {"phone"}, "value": {"+12025550100"}}, http.StatusUnprocessableEntity, "The value of type is not accepted: unknown identifier type."},
		{"no type", url.Values{"value": {"x@example.com"}}, http.StatusUnprocessableEntity, "The value of type is not accepted: unknown identifier type."},
		{"a type that is far too long", url.Values{"type": {strings.Repeat("t", 5000)}, "value": {"x"}}, http.StatusUnprocessableEntity, "The value of type is not accepted: unknown identifier type."},
	} {
		r = f.act("ann", "identifiers/set", c.fields)
		if r.StatusCode != c.status || !r.has(c.text) || r.has(strings.Repeat("t", 100)) {
			t.Errorf("%s: the answer is %d: %.300s", c.name, r.StatusCode, r.body)
		}
	}
	if f.values("ann")["email"].Value != "new.ann@example.com" || f.values("bob")["email"].Value != "bob@example.com" {
		t.Fatal("a change that was refused changed an address")
	}

	if r = f.act("ann", "identifiers/remove", url.Values{"type": {"username"}}); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/users/"+id+"?done=removed" {
		t.Fatalf("removing the username gave %d %q: %.300s", r.StatusCode, r.location(), r.body)
	}
	if _, has := f.values("ann")["username"]; has {
		t.Fatal("the username is still there")
	}
	if record = f.only(audit.UserIdentifierRemoved); record.ActorID != f.adminID() || detailsOf(t, record)["type"] != "username" || detailsOf(t, record)["old"] != "ann" {
		t.Errorf("the record of the removal is %+v", record)
	}
	card := f.get("/users/" + id)
	for _, want := range []string{"Add a value", `<option value="username">username</option>`, `id="add-value"`} {
		if !card.has(want) {
			t.Errorf("the card of a user who lacks a value does not offer to add it: lacks %q", want)
		}
	}
	if card.has(`/identifiers/remove"`) {
		t.Errorf("the card offers to remove the last value to sign in with or a required one")
	}
	if r = f.act("ann", "identifiers/remove", url.Values{"type": {"email"}}); r.StatusCode != http.StatusUnprocessableEntity || !r.has("The value of email is not accepted: required.") {
		t.Errorf("removing a required value gave %d", r.StatusCode)
	}
	if r = f.act("ann", "identifiers/remove", url.Values{"type": {"username"}}); r.StatusCode != http.StatusUnprocessableEntity || !r.has("not accepted: the user has no value of this type.") {
		t.Errorf("removing a value that the user has not gave %d", r.StatusCode)
	}

	f.clock.advance(1)
	if r = f.act("ann", "identifiers/set", url.Values{"type": {"username"}, "value": {"Ann_Again"}}); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/users/"+id+"?done=value" {
		t.Fatalf("adding a username gave %d %q", r.StatusCode, r.location())
	}
	if added := f.values("ann")["username"]; added.Value != "ann_again" || added.DisplayValue != "Ann_Again" {
		t.Errorf("the username is %+v", added)
	}
	if record = f.only(audit.UserIdentifierAdded); detailsOf(t, record)["new"] != "ann_again" || record.ActorID != f.adminID() {
		t.Errorf("the record of the addition is %+v", record)
	}
}

func TestAnAdministratorMarksAnAddressAsConfirmedAndTheLogSaysSo(t *testing.T) {
	f := seedPeople(t)
	id := string(f.ids["ann"])
	if f.values("ann")["email"].VerifiedAt.IsZero() != true {
		t.Fatal("the address is confirmed before it is asked for")
	}
	r := f.act("ann", "identifiers/verify", url.Values{"type": {"email"}})
	if r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/users/"+id+"?done=confirmed" {
		t.Fatalf("confirming gave %d %q: %.300s", r.StatusCode, r.location(), r.body)
	}
	if f.values("ann")["email"].VerifiedAt.IsZero() {
		t.Fatal("the address is not confirmed")
	}
	page := f.get("/users/" + id + "?done=confirmed")
	if !page.has("The value is marked as confirmed.") || !page.has("<td>Value marked as confirmed</td>") || strings.Contains(page.body, `/identifiers/verify"`) {
		t.Errorf("the card after confirming is wrong: %.800s", page.body)
	}
	record := f.only(audit.UserIdentifierVerified)
	if record.ActorKind != store.ActorAdmin || record.ActorID != f.adminID() || record.IP != "127.0.0.1" || detailsOf(t, record)["type"] != "email" || detailsOf(t, record)["value"] != "ann@example.com" {
		t.Errorf("the record of confirming is %+v", record)
	}
	if r = f.act("ann", "identifiers/verify", url.Values{"type": {"email"}}); r.StatusCode != http.StatusSeeOther {
		t.Errorf("confirming a confirmed address gave %d", r.StatusCode)
	}
	if got := recordsOf(t, f.a, audit.UserIdentifierVerified); len(got) != 1 {
		t.Errorf("confirming a confirmed address is recorded: %d records", len(got))
	}
	if r = f.act("ann", "identifiers/verify", url.Values{"type": {"username"}}); r.StatusCode != http.StatusUnprocessableEntity || !r.has("only an address or a phone number can be confirmed") {
		t.Errorf("confirming a username gave %d: %.300s", r.StatusCode, r.body)
	}
	if r = f.act("ann", "identifiers/verify", url.Values{"type": {"nothing"}}); r.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("confirming a type that is not declared gave %d", r.StatusCode)
	}
}

func TestTheLastValueToSignInWithOfAUserCannotBeRemovedAndADeletedUserIsNotEdited(t *testing.T) {
	f := newPeopleFixture(t, WithIdentifiers(identifier.Email(), identifier.Username()))
	user := mustRegister(t, f.a, map[string]string{"username": "solo"}, goodPassword)
	f.ids["solo"], f.names[user.ID] = user.ID, "solo"
	f.enroll()
	card := f.card("solo")
	if card.has(`/identifiers/remove"`) || !card.has(`<option value="email">email</option>`) {
		t.Errorf("the card of a user who has one value offers to remove it: %.1500s", card.body)
	}
	if r := f.act("solo", "identifiers/remove", url.Values{"type": {"username"}}); r.StatusCode != http.StatusUnprocessableEntity || !r.has("A user has to keep at least one value to sign in with.") {
		t.Errorf("removing the last value gave %d: %.300s", r.StatusCode, r.body)
	}
	if _, has := f.values("solo")["username"]; !has {
		t.Fatal("the last value was removed")
	}
	if err := f.a.Admin().DeleteUser(t.Context(), user.ID); err != nil {
		t.Fatal(err)
	}
	token := f.csrfOf(f.get("/users"))
	for action, fields := range map[string]url.Values{
		"set": {"type": {"email"}, "value": {"solo@example.com"}}, "remove": {"type": {"username"}}, "verify": {"type": {"email"}},
	} {
		fields.Set("csrf", token)
		if r := f.post("/users/"+string(user.ID)+"/identifiers/"+action, fields); r.StatusCode != http.StatusConflict || !r.has("The user is deleted.") {
			t.Errorf("%s for a deleted user gave %d", action, r.StatusCode)
		}
	}
}

func TestAFailureOfTheStoreWhileAValueIsChangedLeavesTheOldValue(t *testing.T) {
	f, faults, logs := newFaultyWebFixture(t)
	user := mustRegister(t, f.a, map[string]string{"email": "ann@example.com"}, goodPassword)
	f.enroll()
	id := string(user.ID)
	token := f.csrfOf(f.get("/users/" + id))
	faults.set("identifiers.add", errors.New("down: identifiers.add"))
	r := f.post("/users/"+id+"/identifiers/set", url.Values{"csrf": {token}, "type": {"email"}, "value": {"other@example.com"}})
	if r.StatusCode != http.StatusInternalServerError || r.has("down: identifiers.add") || !strings.Contains(logs.String(), "down: identifiers.add") {
		t.Errorf("a failure of the store gave %d", r.StatusCode)
	}
	if got, err := f.a.Admin().User(t.Context(), user.ID); err != nil || len(got.Identifiers) != 1 || got.Identifiers[0].Value != "ann@example.com" {
		t.Errorf("a change that failed left the values as %+v, %v", got.Identifiers, err)
	}
	if got := recordsOf(t, f.a, audit.UserIdentifierChanged); len(got) != 0 {
		t.Errorf("a change that failed is recorded: %+v", got)
	}
}
