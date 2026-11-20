package limb

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/store"
)

const (
	invitedAddress = "ivan@example.com"
	chosen         = "a password that the invited user chose 1"
)

func (f *sessionFixture) storedUser(t *testing.T, id UserID) store.User {
	t.Helper()
	u, err := f.a.store.Users().Get(t.Context(), f.a.tenant, string(id))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (f *sessionFixture) identifiers(t *testing.T, id UserID) map[string]store.Identifier {
	t.Helper()
	list, err := f.a.store.Identifiers().ListByUser(t.Context(), f.a.tenant, string(id))
	if err != nil {
		t.Fatal(err)
	}
	byType := map[string]store.Identifier{}
	for _, i := range list {
		byType[i.Type] = i
	}
	return byType
}

func TestAnInvitedUserChoosesThePasswordWithTheLink(t *testing.T) {
	f, log, sender := newMailFixture(t)
	log.take()
	invited, err := f.a.Admin().InviteUser(t.Context(), Invitation{Identifiers: map[string]string{"email": invitedAddress}, Language: "en"})
	if err != nil {
		t.Fatalf("InviteUser failed: %v", err)
	}
	stored := f.storedUser(t, invited.ID)
	if invited.CreatedVia != "invite" || stored.CreatedVia != store.CreatedViaInvite || stored.PasswordHash != "" || stored.MustChangePassword || invited.Status != StatusActive {
		t.Fatalf("the invited user is %+v, stored %+v", invited, stored)
	}
	if listed, userErr := f.a.Admin().User(t.Context(), invited.ID); userErr != nil || listed.HasPassword || invited.HasPassword {
		t.Fatalf("an invited user who has no password has one: %+v, %v", listed, userErr)
	}
	m := f.messages(t, sender, 1)[0]
	if m.Kind != MessageInvitation || m.To != invitedAddress || m.UserID != string(invited.ID) || m.Code != "" ||
		!strings.HasPrefix(m.Link, "https://app.example.com/reset#token=") || !m.LinkExpiresAt.Equal(f.clock.now().Add(7*24*time.Hour).Truncate(time.Microsecond)) {
		t.Fatalf("the message is %+v", m)
	}
	if !strings.Contains(m.Text, "7 days") || !strings.Contains(m.Text, m.Link) {
		t.Fatalf("the text %q does not carry the link and its time", m.Text)
	}
	if _, err = f.a.Login(t.Context(), Credentials{Login: invitedAddress, Password: goodPassword, IP: testIP, Kind: SessionCookie}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login before the invitation was accepted = %v, want ErrInvalidCredentials: there is no password", err)
	}
	if !f.identifiers(t, invited.ID)["email"].VerifiedAt.IsZero() {
		t.Fatal("the address is confirmed before the link was used")
	}
	log.take()

	var policy *PolicyError
	if err = f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: "short"}); !errors.As(err, &policy) {
		t.Fatalf("ResetPassword with a short password = %v, want a *PolicyError", err)
	}
	f.clock.advance(6 * 24 * time.Hour)
	if err = f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: chosen}); err != nil {
		t.Fatalf("the link of the invitation did not work: %v", err)
	}
	identifier := f.identifiers(t, invited.ID)["email"]
	if identifier.VerifiedAt.IsZero() || f.storedUser(t, invited.ID).PasswordHash == "" {
		t.Fatalf("the invitation did not confirm the address and set the password: %+v", identifier)
	}
	if listed, userErr := f.a.Admin().User(t.Context(), invited.ID); userErr != nil || !listed.HasPassword {
		t.Fatalf("an invited user who chose a password has none: %+v, %v", listed, userErr)
	}
	login, err := f.a.Login(t.Context(), Credentials{Login: invitedAddress, Password: chosen, IP: testIP, UserAgent: testAgent, Kind: SessionCookie})
	if err != nil || login.Principal.MustChangePassword {
		t.Fatalf("Login = %+v, %v", login, err)
	}
	events := log.take()
	var types []EventType
	for _, e := range events {
		types = append(types, e.Type)
	}
	if len(events) < 2 || events[0].Type != EventChannelVerified || events[1].Type != EventPasswordReset || events[1].Details["kind"] != "invitation" || events[0].Address != "i***@example.com" {
		t.Fatalf("the events are %v: %+v", types, events)
	}
	if err = f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: chosen + "2"}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("the link used twice = %v, want ErrInvalidSecret", err)
	}
	eventually(t, "the queue of messages to empty", func() bool { return f.a.dispatcher.pending.Load() == 0 })
	if got := sender.sent(); len(got) != 1 {
		t.Fatalf("%d messages were sent, want only the invitation: no notice of a change that was none", len(got))
	}
}

func TestTheLinkOfAnInvitationEndsWithItsSeventhDay(t *testing.T) {
	f, _, sender := newMailFixture(t)
	if _, err := f.a.Admin().InviteUser(t.Context(), Invitation{Identifiers: map[string]string{"email": invitedAddress}}); err != nil {
		t.Fatal(err)
	}
	m := f.messages(t, sender, 1)[0]
	f.clock.advance(7 * 24 * time.Hour)
	if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: chosen}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("the link after seven days = %v, want ErrInvalidSecret", err)
	}
}

func TestAnInvitationIsSentAgainAndTheOldLinkEnds(t *testing.T) {
	f, log, sender := newMailFixture(t)
	invited, err := f.a.Admin().InviteUser(t.Context(), Invitation{Identifiers: map[string]string{"email": invitedAddress}})
	if err != nil {
		t.Fatal(err)
	}
	first := f.messages(t, sender, 1)[0]
	log.take()
	if err = f.a.Admin().ResendInvitation(t.Context(), invited.ID, "ru"); err != nil {
		t.Fatalf("ResendInvitation failed: %v", err)
	}
	second := f.messages(t, sender, 2)[1]
	if second.Kind != MessageInvitation || second.Language != "ru" || second.Link == first.Link {
		t.Fatalf("the second message is %+v", second)
	}
	if err = f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(first.Link), Password: chosen}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("the first link after a second invitation = %v, want ErrInvalidSecret", err)
	}
	records := recordsOf(t, f.a, "user.invitation_resent")
	channels, _ := detailsOf(t, records[0])["channels"].([]any)
	if len(records) != 1 || len(channels) != 1 || channels[0] != "email:i***@example.com" {
		t.Fatalf("the second sending is recorded as %+v", records)
	}
	if err = f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(second.Link), Password: chosen}); err != nil {
		t.Fatalf("the second link did not work: %v", err)
	}
	var validation *ValidationError
	if err = f.a.Admin().ResendInvitation(t.Context(), invited.ID, ""); !errors.As(err, &validation) || validation.Field != "user" {
		t.Fatalf("ResendInvitation to a user who has a password = %v, want a *ValidationError", err)
	}
}

func TestAnInvitationIsSentAgainToAChannelThatIsConfirmed(t *testing.T) {
	f, _, sender := newMailFixture(t)
	invited, err := f.a.Admin().InviteUser(t.Context(), Invitation{Identifiers: map[string]string{"email": invitedAddress}})
	if err != nil {
		t.Fatal(err)
	}
	f.messages(t, sender, 1)
	if err = f.a.Admin().VerifyUserIdentifier(t.Context(), invited.ID, "email"); err != nil {
		t.Fatal(err)
	}
	if err = f.a.Admin().ResendInvitation(t.Context(), invited.ID, ""); err != nil {
		t.Fatalf("ResendInvitation to an address that an administrator confirmed failed: %v", err)
	}
	f.messages(t, sender, 2)
	records := recordsOf(t, f.a, "user.invitation_resent")
	if channels, _ := detailsOf(t, records[0])["channels"].([]any); len(records) != 1 || len(channels) != 1 || channels[0] != "email:i***@example.com" {
		t.Fatalf("the second sending is recorded as %+v", records)
	}
}

func TestAnInvitationIsNotSentAgainWhenTheUserHasNoChannelLeft(t *testing.T) {
	sender := &recordingSender{}
	f, _ := newManageFixture(t, WithIdentifiers(identifier.Email(), identifier.Username()), WithSender(sender), WithResetURL("https://app.example.com/reset"))
	invited, err := f.a.Admin().InviteUser(t.Context(), Invitation{Identifiers: map[string]string{"email": invitedAddress}})
	if err != nil {
		t.Fatal(err)
	}
	f.messages(t, sender, 1)
	if err = f.a.Admin().SetUserIdentifier(t.Context(), invited.ID, "username", "ivan_i"); err != nil {
		t.Fatal(err)
	}
	if err = f.a.Admin().RemoveUserIdentifier(t.Context(), invited.ID, "email"); err != nil {
		t.Fatal(err)
	}
	var validation *ValidationError
	if err = f.a.Admin().ResendInvitation(t.Context(), invited.ID, ""); !errors.As(err, &validation) || validation.Field != "user" {
		t.Fatalf("ResendInvitation to a user with no address or phone number = %v, want a *ValidationError", err)
	}
	eventually(t, "the queue of messages to empty", func() bool { return f.a.dispatcher.pending.Load() == 0 })
	if got := len(sender.sent()); got != 1 {
		t.Fatalf("%d messages were sent, want only the first invitation", got)
	}
	if got := len(recordsOf(t, f.a, "user.invitation_resent")); got != 0 {
		t.Fatalf("%d sendings that did not happen were recorded", got)
	}
}

func TestAnInvitationDoesNotOutliveThePasswordOfTheAccount(t *testing.T) {
	f, _, sender := newMailFixture(t)
	invited, err := f.a.Admin().InviteUser(t.Context(), Invitation{Identifiers: map[string]string{"email": invitedAddress}})
	if err != nil {
		t.Fatal(err)
	}
	m := f.messages(t, sender, 1)[0]
	if _, err = f.a.Admin().SetTemporaryPassword(t.Context(), invited.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err = f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: chosen}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("the link of an invitation after the account got a password = %v, want ErrInvalidSecret", err)
	}
	if !f.identifiers(t, invited.ID)["email"].VerifiedAt.IsZero() {
		t.Fatal("a link that was refused confirmed the address")
	}
}

func TestAnInvitationNeedsWhatItIsSentWith(t *testing.T) {
	plain, _ := newManageFixture(t)
	if _, err := plain.a.Admin().InviteUser(t.Context(), Invitation{Identifiers: map[string]string{"email": invitedAddress}}); !errors.Is(err, ErrInvitationsDisabled) {
		t.Fatalf("InviteUser without a Sender = %v, want ErrInvitationsDisabled", err)
	}
	if err := plain.a.Admin().ResendInvitation(t.Context(), plain.user.ID, ""); !errors.Is(err, ErrInvitationsDisabled) {
		t.Fatalf("ResendInvitation without a Sender = %v, want ErrInvitationsDisabled", err)
	}
	noURL, _ := newManageFixture(t, WithSender(&recordingSender{}))
	if _, err := noURL.a.Admin().InviteUser(t.Context(), Invitation{Identifiers: map[string]string{"email": invitedAddress}}); !errors.Is(err, ErrInvitationsDisabled) {
		t.Fatalf("InviteUser without WithResetURL = %v, want ErrInvitationsDisabled", err)
	}
	f, _, _ := newMailFixture(t)
	var validation *ValidationError
	if _, err := f.a.Admin().InviteUser(t.Context(), Invitation{Identifiers: map[string]string{"email": "not an address"}}); !errors.As(err, &validation) {
		t.Fatalf("InviteUser with a bad address = %v, want a *ValidationError", err)
	}
	if _, err := f.a.Admin().InviteUser(t.Context(), Invitation{Identifiers: map[string]string{"email": "NINA@example.com"}}); !errors.Is(err, ErrIdentifierTaken) {
		t.Fatalf("InviteUser with a taken address = %v, want ErrIdentifierTaken", err)
	}
	if got := len(recordsOf(t, f.a, "user.invited")); got != 0 {
		t.Fatalf("%d invitations that failed were recorded", got)
	}
}

func TestAnInvitationNeedsAChannelToGoTo(t *testing.T) {
	sender := &recordingSender{}
	f, _ := newManageFixture(t, WithIdentifiers(identifier.Email(), identifier.Username()), WithSender(sender), WithResetURL("https://app.example.com/reset"))
	var validation *ValidationError
	if _, err := f.a.Admin().InviteUser(t.Context(), Invitation{Identifiers: map[string]string{"username": "nobody_n"}}); !errors.As(err, &validation) || validation.Field != "identifiers" {
		t.Fatalf("InviteUser with no address = %v, want a *ValidationError for the identifiers", err)
	}
	if page, err := f.a.Admin().ListUsers(t.Context(), UserFilter{Search: "nobody"}); err != nil || len(page.Users) != 0 {
		t.Fatalf("a user was created without a channel: %+v, %v", page.Users, err)
	}
}

func TestAnInvitationThatCannotBeQueuedLeavesTheUserAndSaysSo(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	sender := senderFunc(func(ctx context.Context, _ Message) error {
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	})
	f, _ := newManageFixture(t, WithSender(sender), WithResetURL("https://app.example.com/reset"), WithSending(SendingOptions{Workers: 1, Queue: 1, Timeout: 5 * time.Second}))
	t.Cleanup(func() { close(release) })
	admin := f.a.Admin()
	if _, err := admin.InviteUser(t.Context(), Invitation{Identifiers: map[string]string{"email": "first@example.com"}}); err != nil {
		t.Fatal(err)
	}
	<-started
	if _, err := admin.InviteUser(t.Context(), Invitation{Identifiers: map[string]string{"email": "second@example.com"}}); err != nil {
		t.Fatal(err)
	}
	created, err := admin.InviteUser(t.Context(), Invitation{Identifiers: map[string]string{"email": "third@example.com"}})
	if !errors.Is(err, ErrBusy) || created.ID == "" {
		t.Fatalf("InviteUser = %+v, %v, want the user and ErrBusy", created, err)
	}
	if _, found := f.identifiers(t, created.ID)["email"]; !found {
		t.Fatal("the user of an invitation that was not queued is not there")
	}
}
