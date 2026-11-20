package limb

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

func createdID(t *testing.T, r webResponse, notice string) UserID {
	t.Helper()
	prefix, suffix := adminMount+"/users/", "?done="+notice
	location := r.location()
	if r.StatusCode != http.StatusSeeOther || !strings.HasPrefix(location, prefix) || !strings.HasSuffix(location, suffix) {
		t.Fatalf("the answer is %d %q: %.400s, want a redirect to the card with the notice %q", r.StatusCode, location, r.body, notice)
	}
	return UserID(strings.TrimSuffix(strings.TrimPrefix(location, prefix), suffix))
}

func (f *peopleFixture) users() int {
	f.t.Helper()
	page, err := f.a.Admin().ListUsers(f.t.Context(), UserFilter{Limit: 200})
	if err != nil {
		f.t.Fatal(err)
	}
	return len(page.Users)
}

func (f *peopleFixture) create(fields url.Values) webResponse {
	f.t.Helper()
	fields.Set("csrf", f.csrfOf(f.get("/users/new")))
	return f.post("/users/new", fields)
}

func TestTheFormOfANewUserAsksForEveryValueAndOffersInvitationsOnlyToAServiceThatCanSendThem(t *testing.T) {
	f := seedPeople(t)
	form := f.get("/users/new")
	if form.StatusCode != http.StatusOK {
		t.Fatalf("the form is %d: %.300s", form.StatusCode, form.body)
	}
	for _, want := range []string{
		`<h1 class="h1">New user</h1>`, `action="/admin/users/new"`, `name="value.email"`, `name="value.username"`, `name="verified.email"`, `name="mode" value="password" checked`,
		`name="password"`, `autocomplete="new-password"`, `name="keep"`, "Invitations need a sender of messages", `<a href="/admin/users">← All users</a>`,
	} {
		if !form.has(want) {
			t.Errorf("the form lacks %q", want)
		}
	}
	if got := strings.Count(form.body, `<span class="muted">(required)</span>`); got != 1 {
		t.Errorf("%d values are marked as required, want the address only", got)
	}
	for _, unwanted := range []string{`name="verified.username"`, `value="invite"`, `name="language"`} {
		if form.has(unwanted) {
			t.Errorf("the form of a service that cannot send has %q", unwanted)
		}
	}
	if !strings.Contains(form.body, `id="new-email" name="value.email" type="text" class="input" value="" maxlength="1024" autocomplete="off" required>`) ||
		strings.Contains(form.body, `id="new-username" name="value.username" type="text" class="input" value="" maxlength="1024" autocomplete="off" required>`) {
		t.Errorf("the address is not the only value that is required: %.1500s", form.body)
	}
	if list := f.get("/users"); !list.has(`<a class="btn btn-primary" href="/admin/users/new">New user</a>`) {
		t.Errorf("the list has no way to the form")
	}
	if r := f.request(http.MethodHead, "/users/new"); r.StatusCode != http.StatusOK || r.body != "" {
		t.Errorf("HEAD of the form = %d with %d bytes", r.StatusCode, len(r.body))
	}
	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		if r := f.request(method, "/users/new"); r.StatusCode != http.StatusMethodNotAllowed || r.Header.Get("Allow") != "GET, HEAD, POST" {
			t.Errorf("%s of the form = %d with Allow %q", method, r.StatusCode, r.Header.Get("Allow"))
		}
	}
	signedOut := f.newBrowser()
	if r := signedOut.get("/users/new"); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/login" {
		t.Errorf("the form for a visitor is %d %q", r.StatusCode, r.location())
	}
	token := f.csrfOf(form)
	fields := url.Values{"csrf": {token}, "value.email": {"x@example.com"}, "password": {goodPassword}}
	if r := signedOut.post("/users/new", fields); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/login" {
		t.Errorf("a new user from a visitor is %d %q", r.StatusCode, r.location())
	}
	other := f.newBrowser()
	other.signInAgain()
	for name, headers := range map[string][]string{
		"another origin": {"Origin", "https://evil.example"}, "another site": {"Sec-Fetch-Site", "cross-site"}, "JSON": {"Content-Type", "application/json"},
	} {
		want := http.StatusForbidden
		if name == "JSON" {
			want = http.StatusUnsupportedMediaType
		}
		if r := f.post("/users/new", fields, headers...); r.StatusCode != want {
			t.Errorf("a new user from %s is %d, want %d", name, r.StatusCode, want)
		}
	}
	for name, bad := range map[string]string{"a wrong token": "wrong", "no token": "", "the token of another session": other.csrfOf(other.get("/account"))} {
		fields.Set("csrf", bad)
		if r := f.post("/users/new", fields); r.StatusCode != http.StatusForbidden {
			t.Errorf("a new user with %s is %d", name, r.StatusCode)
		}
	}
	if f.users() != 7 {
		t.Errorf("a request that was refused made a user")
	}
	mail, _ := newMailPeople(t)
	mail.enroll()
	invite := mail.get("/users/new")
	for _, want := range []string{`name="mode" value="invite"`, `name="language"`, `<option value="en" selected>English</option>`, `<option value="ru">Русский</option>`} {
		if !invite.has(want) {
			t.Errorf("the form of a service that can send lacks %q", want)
		}
	}
	if invite.has("Invitations need a sender of messages") {
		t.Errorf("the form of a service that can send says that it cannot")
	}
}

func TestAnAdministratorCreatesAUserWithAPasswordThroughTheBrowser(t *testing.T) {
	f := seedPeople(t)
	before := f.users()
	r := f.create(url.Values{"mode": {"password"}, "value.email": {"  New.User@Example.com "}, "value.username": {"new_user"}, "password": {goodPassword}, "verified.email": {"1"}})
	id := createdID(t, r, "created")
	user, err := f.a.Admin().User(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if user.CreatedVia != "admin" || !user.MustChangePassword || !user.HasPassword || len(user.Identifiers) != 2 || user.Identifiers[0].DisplayValue != "New.User@Example.com" || user.Identifiers[0].VerifiedAt.IsZero() || !user.Identifiers[1].VerifiedAt.IsZero() {
		t.Fatalf("the user is %+v", user)
	}
	login, err := f.a.Login(t.Context(), Credentials{Login: "new_user", Password: goodPassword, IP: testIP, Kind: SessionCookie})
	if err != nil || !login.Principal.MustChangePassword {
		t.Fatalf("the new user cannot sign in with the password they were given: %+v, %v", login, err)
	}
	card := f.get("/users/" + string(id) + "?done=created")
	for _, want := range []string{"The user is created.", "<dd>Administrator</dd>", "has to be changed at the next sign-in", `<h1 class="h1 break">New.User@Example.com</h1>`, "<td>User created by an administrator</td>"} {
		if !card.has(want) {
			t.Errorf("the card of the new user lacks %q", want)
		}
	}
	var record store.AuditRecord
	for _, candidate := range recordsOf(t, f.a, audit.UserCreated) {
		if candidate.TargetUserID == string(id) {
			record = candidate
		}
	}
	details := detailsOf(t, record)
	verified, _ := details["verified"].([]any)
	if record.ActorKind != store.ActorAdmin || record.ActorID != f.adminID() || record.IP != "127.0.0.1" || record.TargetUserID != string(id) || details["must_change_password"] != true ||
		len(verified) != 1 || strings.Contains(record.Details, goodPassword) {
		t.Errorf("the record of the creation is %+v %v", record, details)
	}

	kept := createdID(t, f.create(url.Values{"value.email": {"kept@example.com"}, "password": {goodPassword}, "keep": {"1"}, "mode": {"nonsense"}}), "created")
	if user, err = f.a.Admin().User(t.Context(), kept); err != nil || user.MustChangePassword || user.CreatedVia != "admin" || !user.Identifiers[0].VerifiedAt.IsZero() {
		t.Errorf("a user who keeps the password is %+v, %v", user, err)
	}
	if f.users() != before+2 {
		t.Errorf("%d users, want %d", f.users(), before+2)
	}
}

func TestAUserWhoCannotBeCreatedIsAnsweredWithTheFormAgainAndWhatWasTyped(t *testing.T) {
	f := seedPeople(t)
	before, recorded := f.users(), len(recordsOf(t, f.a, audit.UserCreated))
	for _, c := range []struct {
		name   string
		fields url.Values
		status int
		text   string
	}{
		{"a password that is too short", url.Values{"value.email": {"new@example.com"}, "password": {"short"}}, http.StatusUnprocessableEntity, "The new password is not allowed: it is too short."},
		{"no password", url.Values{"value.email": {"new@example.com"}}, http.StatusUnprocessableEntity, "it is too short"},
		{"a password that is too long", url.Values{"value.email": {"new@example.com"}, "password": {strings.Repeat("p", 1025)}}, http.StatusUnprocessableEntity, "it is too long"},
		{"a password that many use", url.Values{"value.email": {"new@example.com"}, "password": {"password1234"}}, http.StatusUnprocessableEntity, "many people use it"},
		{"no address", url.Values{"value.username": {"only_name"}, "password": {goodPassword}}, http.StatusUnprocessableEntity, "The value of email is not accepted: required."},
		{"an address that is not one", url.Values{"value.email": {"not an address"}, "password": {goodPassword}}, http.StatusUnprocessableEntity, "The value of email is not accepted:"},
		{"an address that another user has", url.Values{"value.email": {"ANN@example.com"}, "password": {goodPassword}}, http.StatusConflict, "Another user has this value."},
		{"a username that another user has", url.Values{"value.email": {"new@example.com"}, "value.username": {"ann"}, "password": {goodPassword}}, http.StatusConflict, "Another user has this value."},
		{"a username that is vouched for", url.Values{"value.email": {"new@example.com"}, "value.username": {"nuser"}, "verified.username": {"1"}, "password": {goodPassword}}, http.StatusUnprocessableEntity, "only an address or a phone number can be confirmed"},
	} {
		r := f.create(c.fields)
		if r.StatusCode != c.status || !r.has(c.text) || !r.has(`role="alert" class="alert alert-error"`) || !r.has(`name="password"`) {
			t.Errorf("%s: the answer is %d: %.300s", c.name, r.StatusCode, r.body)
		}
		if r.has(goodPassword) || r.has(`value="short"`) || r.has(strings.Repeat("p", 100)) {
			t.Errorf("%s: the form shows the password again", c.name)
		}
	}
	r := f.create(url.Values{"value.email": {"typed<b>@example.com"}, "value.username": {"kept_name"}, "verified.email": {"1"}, "keep": {"1"}, "password": {"short"}})
	if !r.has(`value="typed&lt;b&gt;@example.com"`) || !r.has(`value="kept_name"`) || !r.has(`name="verified.email" value="1" checked`) || !r.has(`name="keep" value="1" checked`) || r.has("<b>@") {
		t.Errorf("the form does not keep, and escape, what was typed: %.2500s", r.body)
	}
	if f.users() != before || len(recordsOf(t, f.a, audit.UserCreated)) != recorded {
		t.Errorf("a user that could not be created was created or recorded")
	}
}

func TestAnAdministratorInvitesAUserAndSendsTheInvitationAgainUntilTheyChooseAPassword(t *testing.T) {
	f, sender := newMailPeople(t)
	f.add("ann")
	f.enroll()
	r := f.create(url.Values{"mode": {"invite"}, "value.email": {"Ivan@Example.com"}, "language": {"ru"}})
	id := createdID(t, r, "invited")
	user, err := f.a.Admin().User(t.Context(), id)
	if err != nil || user.CreatedVia != "invite" || user.HasPassword || user.MustChangePassword {
		t.Fatalf("the invited user is %+v, %v", user, err)
	}
	first := f.sentMessages(sender, 1)[0]
	if first.Kind != MessageInvitation || first.To != "ivan@example.com" || first.Language != "ru" || !strings.HasPrefix(first.Link, "https://app.example.com/reset#token=") {
		t.Fatalf("the invitation is %+v", first)
	}
	card := f.get("/users/" + string(id) + "?done=invited")
	for _, want := range []string{
		"The user is created and the invitation is being sent.", "<h2 class=\"h2\">Invitation</h2>", `action="/admin/users/` + string(id) + `/invitation"`, "Send the invitation again",
		"none yet, the user was invited and has not chosen one", "<dd>Invitation</dd>", "<td>User invited</td>", `id="invite-language"`,
	} {
		if !card.has(want) {
			t.Errorf("the card of the invited user lacks %q", want)
		}
	}
	if record := f.only(audit.UserInvited); record.ActorKind != store.ActorAdmin || record.ActorID != f.adminID() || record.TargetUserID != string(id) {
		t.Errorf("the record of the invitation is %+v", record)
	}

	f.clock.advance(1)
	again := f.post("/users/"+string(id)+"/invitation", url.Values{"csrf": {f.csrfOf(card)}, "language": {"en"}})
	if again.StatusCode != http.StatusSeeOther || again.location() != adminMount+"/users/"+string(id)+"?done=invitation" {
		t.Fatalf("sending the invitation again gave %d %q: %.300s", again.StatusCode, again.location(), again.body)
	}
	second := f.sentMessages(sender, 2)[1]
	if second.Kind != MessageInvitation || second.Language != "en" || second.Link == first.Link {
		t.Errorf("the second invitation is %+v", second)
	}
	if page := f.get("/users/" + string(id) + "?done=invitation"); !page.has("The invitation is being sent again.") || !page.has("<td>Invitation sent again</td>") {
		t.Errorf("the card after sending the invitation again is wrong")
	}
	if err = f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(second.Link), Password: chosen}); err != nil {
		t.Fatalf("the invitation does not work: %v", err)
	}
	done := f.get("/users/" + string(id))
	if done.has("Send the invitation again") || done.has("<h2 class=\"h2\">Invitation</h2>") || !done.has("<dd>set</dd>") {
		t.Errorf("the card of a user who chose a password still waits for them: %.1500s", done.body)
	}
	if record := f.only(audit.UserInvitationResent); record.ActorKind != store.ActorAdmin || record.ActorID != f.adminID() || record.IP != "127.0.0.1" || record.TargetUserID != string(id) {
		t.Errorf("the record of the invitation that was sent again is %+v", record)
	}
	if r = f.post("/users/"+string(id)+"/invitation", url.Values{"csrf": {f.csrfOf(done)}}); r.StatusCode != http.StatusConflict || !r.has("The user has a password already, there is nothing to invite them to.") {
		t.Errorf("an invitation for a user who has a password gave %d", r.StatusCode)
	}
	if r = f.act("ann", "invitation", url.Values{}); r.StatusCode != http.StatusConflict || !r.has("The user has a password already") {
		t.Errorf("an invitation for a user who registered gave %d", r.StatusCode)
	}
	for name, fields := range map[string]url.Values{
		"no address":                 {"mode": {"invite"}, "value.username": {"only_name"}},
		"an address that is not one": {"mode": {"invite"}, "value.email": {"nope"}},
		"an address that is taken":   {"mode": {"invite"}, "value.email": {"ANN@example.com"}},
	} {
		want := http.StatusUnprocessableEntity
		if strings.Contains(name, "taken") {
			want = http.StatusConflict
		}
		fields.Set("language", "ru")
		if r = f.create(fields); r.StatusCode != want || !r.has(`name="mode" value="invite" checked`) || !r.has(`<option value="ru" selected>Русский</option>`) || r.has(`<option value="en" selected>`) {
			t.Errorf("an invitation with %s gave %d", name, r.StatusCode)
		}
	}
}

func TestAServiceThatCannotSendInvitationsRefusesThemEvenWhenTheyAreAskedFor(t *testing.T) {
	f := seedPeople(t)
	before := f.users()
	r := f.create(url.Values{"mode": {"invite"}, "value.email": {"ivan@example.com"}})
	if r.StatusCode != http.StatusConflict || !r.has("The service cannot send invitations.") || !r.has(`name="mode" value="password" checked`) || f.users() != before {
		t.Errorf("an invitation from a service that cannot send gave %d", r.StatusCode)
	}
	card := f.get("/users/" + string(f.ids["ann"]))
	if card.has("/invitation") {
		t.Errorf("the card of a user who has a password offers an invitation")
	}
	if r = f.act("ann", "invitation", url.Values{}); r.StatusCode != http.StatusConflict || !r.has("The service cannot send invitations.") {
		t.Errorf("an invitation to a user, from a service that cannot send, gave %d", r.StatusCode)
	}
}

func TestAnInvitationThatCannotBeQueuedLeavesTheUserCreatedAndSaysSo(t *testing.T) {
	var mu sync.Mutex
	entered, release := make(chan struct{}, 8), make(chan struct{})
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		select {
		case <-release:
		default:
			close(release)
		}
	})
	sender := senderFunc(func(context.Context, Message) error {
		entered <- struct{}{}
		<-release
		return nil
	})
	f := newPeopleFixture(t, WithSender(sender), WithResetURL("https://app.example.com/reset"), WithSending(SendingOptions{Workers: 1, Queue: 1}))
	f.enroll()
	createdID(t, f.create(url.Values{"mode": {"invite"}, "value.email": {"one@example.com"}}), "invited")
	<-entered
	createdID(t, f.create(url.Values{"mode": {"invite"}, "value.email": {"two@example.com"}}), "invited")
	id := createdID(t, f.create(url.Values{"mode": {"invite"}, "value.email": {"three@example.com"}}), "invitebusy")
	if user, err := f.a.Admin().User(t.Context(), id); err != nil || user.CreatedVia != "invite" {
		t.Fatalf("the user whose invitation was not queued is %+v, %v", user, err)
	}
	if page := f.get("/users/" + string(id) + "?done=invitebusy"); !page.has("The user is created, but the invitation could not be queued now.") || !page.has("Send the invitation again") {
		t.Errorf("the card does not say that the invitation has to be sent again: %.800s", page.body)
	}
}

func TestAVouchForAValueThatWasNotGivenIsIgnored(t *testing.T) {
	f := newPeopleFixture(t, WithIdentifiers(identifier.Email(), identifier.Username()))
	f.enroll()
	id := createdID(t, f.create(url.Values{"value.email": {"   "}, "value.username": {"only_name"}, "verified.email": {"1"}, "password": {goodPassword}}), "created")
	user, err := f.a.Admin().User(t.Context(), id)
	if err != nil || len(user.Identifiers) != 1 || user.Identifiers[0].Type != "username" {
		t.Fatalf("the user is %+v, %v", user, err)
	}
	if r := f.create(url.Values{"value.email": {"other@example.com"}, "value.username": {"other_name"}, "verified.username": {"1"}, "password": {goodPassword}}); r.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("a username that is vouched for, which cannot be confirmed, gave %d", r.StatusCode)
	}
}

func TestAFailureOfTheStoreWhileAUserIsMadeIsAnErrorPageThatHidesWhyAndMakesNoUser(t *testing.T) {
	f, faults, logs := newFaultyWebFixture(t)
	f.enroll()
	token := f.csrfOf(f.get("/users/new"))
	faults.set("users.create", errors.New("down: users.create"))
	r := f.post("/users/new", url.Values{"csrf": {token}, "value.email": {"new@example.com"}, "password": {goodPassword}})
	if r.StatusCode != http.StatusInternalServerError || !r.has("Something went wrong") || r.has("down: users.create") || r.has("new@example.com") || !strings.Contains(logs.String(), "down: users.create") {
		t.Errorf("a failure of the store gave %d: %.300s", r.StatusCode, r.body)
	}
	if page, err := f.a.Admin().ListUsers(t.Context(), UserFilter{}); err != nil || len(page.Users) != 0 {
		t.Errorf("a user that could not be made is there: %+v, %v", page.Users, err)
	}
	faults.clear()
	if r = f.post("/users/new", url.Values{"csrf": {token}, "value.email": {"new@example.com"}, "password": {goodPassword}}); r.StatusCode != http.StatusSeeOther {
		t.Errorf("the user after the failure gave %d", r.StatusCode)
	}
}
