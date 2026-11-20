package limb

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

var temporaryPattern = regexp.MustCompile(`<code class="secret">([^<]+)</code>`)

func newMailPeople(t *testing.T) (*peopleFixture, *recordingSender) {
	t.Helper()
	sender := &recordingSender{}
	return newPeopleFixture(t, WithSender(sender), WithResetURL("https://app.example.com/reset"), WithServiceName("Acme")), sender
}

func (f *peopleFixture) confirm(name string) {
	f.t.Helper()
	if err := f.a.store.Identifiers().MarkVerified(f.t.Context(), f.a.tenant, "email", name+"@example.com", f.clock.now().UTC()); err != nil {
		f.t.Fatal(err)
	}
}

func (f *peopleFixture) sentMessages(sender *recordingSender, n int) []Message {
	f.t.Helper()
	eventually(f.t, "the messages to be sent", func() bool { return len(sender.sent()) >= n })
	eventually(f.t, "the queue of messages to empty", func() bool { return f.a.dispatcher.pending.Load() == 0 })
	got := sender.sent()
	if len(got) != n {
		f.t.Fatalf("%d messages were sent, want %d: %+v", len(got), n, got)
	}
	return got
}

func TestAnAdministratorSendsALinkToChooseAPasswordInTheLanguageThatWasAskedFor(t *testing.T) {
	f, sender := newMailPeople(t)
	f.add("ann")
	f.add("eve")
	f.enroll()
	id := string(f.ids["ann"])
	card := f.card("ann")
	for _, want := range []string{
		`action="/admin/users/` + id + `/password/link"`, "Send the link", "Language of the message", `<option value="en" selected>English</option>`, `<option value="ru">Русский</option>`,
		`action="/admin/users/` + id + `/password/temporary"`, "Set a temporary password",
	} {
		if !card.has(want) {
			t.Errorf("the card lacks %q", want)
		}
	}
	r := f.act("ann", "password/link", url.Values{"language": {"ru"}})
	if r.StatusCode != http.StatusConflict || !r.has("The user has no confirmed address or phone number to send the link to.") || !r.has(`role="alert" class="alert alert-error"`) {
		t.Fatalf("a link for a user who has no confirmed value gave %d: %.400s", r.StatusCode, r.body)
	}
	f.noRecords(audit.UserPasswordResetSent)
	f.confirm("ann")
	r = f.act("ann", "password/link", url.Values{"language": {"ru"}})
	if r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/users/"+id+"?done=link" {
		t.Fatalf("the link gave %d %q: %.300s", r.StatusCode, r.location(), r.body)
	}
	message := f.sentMessages(sender, 1)[0]
	if message.Kind != MessagePasswordReset || message.To != "ann@example.com" || message.Language != "ru" || message.UserID != id || !strings.HasPrefix(message.Link, "https://app.example.com/reset#token=") {
		t.Fatalf("the message is %+v", message)
	}
	if page := f.get("/users/" + id + "?done=link"); !page.has("The link to choose a new password is being sent to the user.") || !page.has("<td>Link to reset the password sent</td>") {
		t.Errorf("the card after sending the link is wrong: %.800s", page.body)
	}
	record := f.only(audit.UserPasswordResetSent)
	if record.ActorKind != store.ActorAdmin || record.ActorID != f.adminID() || record.IP != "127.0.0.1" || record.TargetUserID != id || strings.Contains(record.Details, message.Link) || strings.Contains(record.Details, "ann@example.com") {
		t.Errorf("the record of the link is %+v", record)
	}
	f.clock.advance(1)
	if r = f.act("ann", "password/link", url.Values{"language": {"klingon"}}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("a language that there are no texts for gave %d", r.StatusCode)
	}
	if got := f.sentMessages(sender, 2)[1]; got.Language != "en" {
		t.Errorf("a language that there are no texts for gave the message in %q", got.Language)
	}
	chosen := "a password that the user chose 1"
	if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(sender.sent()[1].Link), Password: chosen}); err != nil {
		t.Fatalf("the link that the administration sent does not work: %v", err)
	}
	if _, err := f.a.Login(t.Context(), Credentials{Login: "ann", Password: chosen, IP: testIP, Kind: SessionCookie}); err != nil {
		t.Errorf("the user cannot sign in with the password that they chose: %v", err)
	}
}

func TestWithoutASenderTheCardOffersNoLinkAndAForgedRequestForOneIsRefused(t *testing.T) {
	f := seedPeople(t)
	id := string(f.ids["eve"])
	card := f.card("eve")
	if !card.has("The service has no way to send messages, so a link cannot be sent.") || card.has("/password/link") || card.has(`name="language"`) || !card.has("/password/temporary") {
		t.Errorf("the card of a service that cannot send does not tell so: %.1500s", card.body)
	}
	r := f.post("/users/"+id+"/password/link", url.Values{"csrf": {f.csrfOf(card)}, "language": {"en"}})
	if r.StatusCode != http.StatusConflict || !r.has("The service has no way to send messages.") {
		t.Errorf("a link that cannot be sent gave %d", r.StatusCode)
	}
	f.noRecords(audit.UserPasswordResetSent)
}

func TestAnAdministratorSetsATemporaryPasswordThatIsShownOnceAndThatTheUserHasToChange(t *testing.T) {
	f, sender := newMailPeople(t)
	f.add("ann")
	f.confirm("ann")
	f.enroll()
	id := string(f.ids["ann"])
	cookie, token := f.userLogin("ann", SessionCookie), f.userLogin("ann", SessionToken)
	r := f.act("ann", "password/temporary", url.Values{"language": {"ru"}})
	if r.StatusCode != http.StatusOK || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("the temporary password gave %d with Cache-Control %q: %.300s", r.StatusCode, r.Header.Get("Cache-Control"), r.body)
	}
	for _, want := range []string{"<h1 class=\"h1\">Temporary password</h1>", "The temporary password of ann@example.com:", "Give it to the user.", `href="/admin/users/` + id + `"`} {
		if !r.has(want) {
			t.Errorf("the page of the temporary password lacks %q", want)
		}
	}
	found := temporaryPattern.FindStringSubmatch(r.body)
	if found == nil || len(found[1]) < 25 {
		t.Fatalf("the page shows no password: %.600s", r.body)
	}
	password := found[1]
	if f.authenticated(cookie) || f.authenticated(token) {
		t.Error("the sessions of the user did not end")
	}
	if _, err := f.a.Login(t.Context(), Credentials{Login: "ann", Password: goodPassword, IP: testIP, Kind: SessionCookie}); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("the old password still works: %v", err)
	}
	login, err := f.a.Login(t.Context(), Credentials{Login: "ann@example.com", Password: password, IP: testIP, Kind: SessionCookie})
	if err != nil || !login.Principal.MustChangePassword {
		t.Fatalf("the temporary password gave %+v, %v, want a session that has to change it", login, err)
	}
	card := f.card("ann")
	if strings.Contains(card.body, password) || !card.has("has to be changed at the next sign-in") {
		t.Errorf("the card shows the temporary password again, or does not say that it has to be changed")
	}
	record := f.only(audit.UserPasswordTemporary)
	if record.ActorKind != store.ActorAdmin || record.ActorID != f.adminID() || record.IP != "127.0.0.1" || strings.Contains(record.Details, password) {
		t.Errorf("the record of the temporary password is %+v", record)
	}
	if notice := f.sentMessages(sender, 1)[0]; notice.Kind != MessagePasswordChanged || notice.Language != "ru" || notice.To != "ann@example.com" || strings.Contains(notice.Text, password) {
		t.Errorf("the notice to the user is %+v", notice)
	}
	if again := f.act("ann", "password/temporary", url.Values{}); again.StatusCode != http.StatusOK || temporaryPattern.FindStringSubmatch(again.body)[1] == password {
		t.Errorf("a second temporary password is the same as the first")
	}
}

func TestAPasswordOfADeletedUserIsNotResetAndAFailureShowsNoPassword(t *testing.T) {
	f, faults, logs := newFaultyWebFixture(t)
	user := mustRegister(t, f.a, map[string]string{"email": "ann@example.com"}, goodPassword)
	f.enroll()
	id := string(user.ID)
	token := f.csrfOf(f.get("/users/" + id))
	faults.set("users.update", errors.New("down: users.update"))
	r := f.post("/users/"+id+"/password/temporary", url.Values{"csrf": {token}})
	if r.StatusCode != http.StatusInternalServerError || r.has("secret") || r.has("down: users.update") || !strings.Contains(logs.String(), "down: users.update") {
		t.Errorf("a failure while the password was set gave %d: %.300s", r.StatusCode, r.body)
	}
	if _, err := f.a.Login(t.Context(), Credentials{Login: "ann@example.com", Password: goodPassword, IP: testIP, Kind: SessionCookie}); err != nil {
		t.Errorf("a password that failed to change stopped working: %v", err)
	}
	faults.clear()
	if err := f.a.Admin().DeleteUser(t.Context(), user.ID); err != nil {
		t.Fatal(err)
	}
	if r = f.post("/users/"+id+"/password/temporary", url.Values{"csrf": {token}}); r.StatusCode != http.StatusConflict || !r.has("The user is deleted.") || r.has(`class="secret"`) {
		t.Errorf("a temporary password for a deleted user gave %d", r.StatusCode)
	}
	if card := f.get("/users/" + id); card.has("/password/") || card.has("Reset the password") {
		t.Errorf("the card of a deleted user offers to reset the password")
	}
}

func TestALinkIsNotSentToADeletedUser(t *testing.T) {
	f, sender := newMailPeople(t)
	f.add("ann")
	f.confirm("ann")
	f.enroll()
	if err := f.a.Admin().DeleteUser(t.Context(), f.ids["ann"]); err != nil {
		t.Fatal(err)
	}
	if r := f.act("ann", "password/link", url.Values{"language": {"en"}}); r.StatusCode != http.StatusConflict || !r.has("The user is deleted.") {
		t.Errorf("a link for a deleted user gave %d", r.StatusCode)
	}
	eventually(t, "the queue of messages to empty", func() bool { return f.a.dispatcher.pending.Load() == 0 })
	if got := sender.sent(); len(got) != 0 {
		t.Errorf("a message was sent to a deleted user: %+v", got)
	}
}
