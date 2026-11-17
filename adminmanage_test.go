package limb

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func newManageFixture(t *testing.T, opts ...Option) (*sessionFixture, *eventLog) {
	t.Helper()
	f, log := newEventFixture(t, opts...)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = f.a.Shutdown(ctx)
	})
	return f, log
}

func newMailFixture(t *testing.T) (*sessionFixture, *eventLog, *recordingSender) {
	t.Helper()
	sender := &recordingSender{}
	f, log := newManageFixture(t, WithSender(sender), WithResetURL("https://app.example.com/reset"), WithServiceName("Acme"))
	return f, log, sender
}

func (f *sessionFixture) confirm(t *testing.T, value string) {
	t.Helper()
	if err := f.a.store.Identifiers().MarkVerified(t.Context(), f.a.tenant, "email", value, f.clock.now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func (f *sessionFixture) messages(t *testing.T, sender *recordingSender, n int) []Message {
	t.Helper()
	eventually(t, "the messages to be sent", func() bool { return len(sender.sent()) >= n })
	eventually(t, "the queue of messages to empty", func() bool { return f.a.dispatcher.pending.Load() == 0 })
	got := sender.sent()
	if len(got) != n {
		t.Fatalf("%d messages were sent, want %d: %+v", len(got), n, got)
	}
	return got
}

func TestBlockingAUserEndsTheirAccessAtOnce(t *testing.T) {
	f, log := newManageFixture(t)
	cookie := f.login(t)
	token := f.tokenLogin(t)
	log.take()
	until := f.clock.now().Add(48 * time.Hour)
	if err := f.a.Admin().BlockUser(t.Context(), f.user.ID, "  spam wave  ", until); err != nil {
		t.Fatalf("BlockUser failed: %v", err)
	}
	events := log.take()
	if f.works(t, cookie) || f.works(t, token) {
		t.Fatal("a session of a blocked user still works")
	}
	f.refused(t, "the refresh token of a blocked user", token.Tokens.RefreshToken)
	if _, err := f.a.Login(t.Context(), f.credentials()); !errors.Is(err, ErrUserBlocked) {
		t.Fatalf("Login = %v, want ErrUserBlocked", err)
	}
	stored := f.stored(t)
	if stored.Status != store.StatusBlocked || stored.BlockedReason != "spam wave" || !stored.BlockedUntil.Equal(until.Truncate(time.Microsecond)) {
		t.Fatalf("the stored user is %+v", stored)
	}
	records := recordsOf(t, f.a, "user.blocked")
	if len(records) != 1 {
		t.Fatalf("the audit log holds %d blocks, want 1", len(records))
	}
	details := detailsOf(t, records[0])
	if records[0].ActorKind != store.ActorSystem || records[0].ActorID != "api" || records[0].TargetUserID != string(f.user.ID) ||
		details["reason"] != "spam wave" || details["until"] != until.UTC().Format(time.RFC3339) || details["sessions"] != float64(2) {
		t.Fatalf("the block is recorded as %+v %v", records[0], details)
	}
	wantTypes(t, events, EventUserBlocked, EventSessionEnded)
	if events[0].UserID != string(f.user.ID) || events[0].Details["reason"] != "spam wave" || events[0].Details["until"] != until.UTC().Format(time.RFC3339) ||
		events[1].Details["reason"] != "administrator" || events[1].Details["count"] != "2" {
		t.Fatalf("the events are %+v", events)
	}
	if got := len(recordsOf(t, f.a, "auth.session_ended")); got != 0 {
		t.Fatalf("the audit log holds %d records of ended sessions made from events: the block is recorded once", got)
	}
	f.clock.advance(48 * time.Hour)
	if _, err := f.a.Login(t.Context(), f.credentials()); err != nil {
		t.Fatalf("Login after the block ran out failed: %v", err)
	}
}

func TestABlockWithoutAnEndHoldsUntilItIsLifted(t *testing.T) {
	f, log := newManageFixture(t)
	if err := f.a.Admin().BlockUser(t.Context(), f.user.ID, "fraud", time.Time{}); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(5 * 365 * 24 * time.Hour)
	if _, err := f.a.Login(t.Context(), f.credentials()); !errors.Is(err, ErrUserBlocked) {
		t.Fatalf("Login = %v, want ErrUserBlocked: the block has no end", err)
	}
	log.take()
	if err := f.a.Admin().UnblockUser(t.Context(), f.user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.Login(t.Context(), f.credentials()); err != nil {
		t.Fatalf("Login after the block was lifted failed: %v", err)
	}
	wantTypes(t, log.take(), EventUserUnblocked, EventLogin)
	records := recordsOf(t, f.a, "user.unblocked")
	if len(records) != 1 || detailsOf(t, records[0])["previous_reason"] != "fraud" {
		t.Fatalf("the lifting is recorded as %+v", records)
	}
	stored := f.stored(t)
	if stored.Status != store.StatusActive || stored.BlockedReason != "" || !stored.BlockedUntil.IsZero() {
		t.Fatalf("the stored user is %+v", stored)
	}
	if err := f.a.Admin().UnblockUser(t.Context(), f.user.ID); err != nil {
		t.Fatalf("UnblockUser of a user who is not blocked failed: %v", err)
	}
	if got := len(recordsOf(t, f.a, "user.unblocked")); got != 1 {
		t.Fatalf("lifting a block that is not there was recorded: %d records", got)
	}
}

func TestBlockingABlockedUserChangesTheReasonAndTheEnd(t *testing.T) {
	f, _ := newManageFixture(t)
	first := f.clock.now().Add(time.Hour)
	if err := f.a.Admin().BlockUser(t.Context(), f.user.ID, "first", first); err != nil {
		t.Fatal(err)
	}
	if err := f.a.Admin().BlockUser(t.Context(), f.user.ID, "second", time.Time{}); err != nil {
		t.Fatal(err)
	}
	stored := f.stored(t)
	if stored.BlockedReason != "second" || !stored.BlockedUntil.IsZero() {
		t.Fatalf("the stored user is %+v", stored)
	}
	records := recordsOf(t, f.a, "user.blocked")
	if len(records) != 2 {
		t.Fatalf("the audit log holds %d blocks, want 2", len(records))
	}
	details := detailsOf(t, records[0])
	if details["previous_reason"] != "second" && details["previous_reason"] != "first" {
		t.Fatalf("the second block is recorded as %v", details)
	}
}

func TestABlockNeedsAReasonAndAnEndInTheFuture(t *testing.T) {
	f, _ := newManageFixture(t)
	var validation *ValidationError
	for field, c := range map[string]struct {
		reason string
		until  time.Time
	}{
		"reason": {"", time.Time{}},
	} {
		if err := f.a.Admin().BlockUser(t.Context(), f.user.ID, c.reason, c.until); !errors.As(err, &validation) || validation.Field != field {
			t.Errorf("BlockUser(%q) = %v, want a *ValidationError for %s", c.reason, err, field)
		}
	}
	for name, reason := range map[string]string{
		"blank": "  \t ", "too long": strings.Repeat("a", store.MaxBlockedReasonLength+1), "control": "line\nbreak", "bad UTF-8": "a\xffb",
	} {
		if err := f.a.Admin().BlockUser(t.Context(), f.user.ID, reason, time.Time{}); !errors.As(err, &validation) || validation.Field != "reason" {
			t.Errorf("%s: BlockUser = %v, want a *ValidationError for the reason", name, err)
		}
	}
	for name, until := range map[string]time.Time{"now": f.clock.now(), "past": f.clock.now().Add(-time.Hour)} {
		if err := f.a.Admin().BlockUser(t.Context(), f.user.ID, "reason", until); !errors.As(err, &validation) || validation.Field != "until" {
			t.Errorf("%s: BlockUser = %v, want a *ValidationError for the end", name, err)
		}
	}
	if err := f.a.Admin().BlockUser(t.Context(), f.user.ID, strings.Repeat("я", store.MaxBlockedReasonLength/2), time.Time{}); err != nil {
		t.Fatalf("a reason of the longest length failed: %v", err)
	}
	if stored := f.stored(t); stored.Status != store.StatusBlocked {
		t.Fatalf("the user is %+v", stored)
	}
}

func TestTheOperationsOnAUserRefuseAUserThatCannotTakeThem(t *testing.T) {
	f, _ := newManageFixture(t)
	missing := UserID("00000000-0000-7000-8000-000000000999")
	admin := f.a.Admin()
	for name, op := range map[string]func(UserID) error{
		"BlockUser":         func(id UserID) error { return admin.BlockUser(t.Context(), id, "reason", time.Time{}) },
		"UnblockUser":       func(id UserID) error { return admin.UnblockUser(t.Context(), id) },
		"EndUserSession":    func(id UserID) error { return admin.EndUserSession(t.Context(), id, "x") },
		"SendPasswordReset": func(id UserID) error { return admin.SendPasswordReset(t.Context(), id, "") },
		"SetTemporaryPassword": func(id UserID) error {
			_, err := admin.SetTemporaryPassword(t.Context(), id, "")
			return err
		},
		"EndUserSessions": func(id UserID) error { _, err := admin.EndUserSessions(t.Context(), id); return err },
	} {
		err := op(missing)
		if allowed := errors.Is(err, ErrUserNotFound) || (name == "SendPasswordReset" && errors.Is(err, ErrRecoveryDisabled)); !allowed {
			t.Errorf("%s of a user that does not exist = %v, want ErrUserNotFound", name, err)
		}
	}
	f.change(t, func(u *store.User) {
		u.Status, u.DeletedAt, u.PurgeAfter = store.StatusDeleted, f.clock.now(), f.clock.now().Add(24*time.Hour)
	})
	for name, op := range map[string]func(UserID) error{
		"BlockUser":   func(id UserID) error { return admin.BlockUser(t.Context(), id, "reason", time.Time{}) },
		"UnblockUser": func(id UserID) error { return admin.UnblockUser(t.Context(), id) },
		"SetTemporaryPassword": func(id UserID) error {
			_, err := admin.SetTemporaryPassword(t.Context(), id, "")
			return err
		},
	} {
		if err := op(f.user.ID); !errors.Is(err, ErrUserDeleted) {
			t.Errorf("%s of a deleted user = %v, want ErrUserDeleted", name, err)
		}
	}
	if stored := f.stored(t); stored.Status != store.StatusDeleted || stored.BlockedReason != "" {
		t.Fatalf("a refused operation changed the user: %+v", stored)
	}
}

type racedUsers struct {
	store.Users
	stale *atomic.Int64
}

func (s racedUsers) Update(ctx context.Context, u store.User) (store.User, error) {
	if s.stale.Add(-1) >= 0 {
		return store.User{}, store.ErrStale
	}
	return s.Users.Update(ctx, u)
}

type racedUsersRepositories struct {
	store.Repositories
	stale *atomic.Int64
}

func (r racedUsersRepositories) Users() store.Users {
	return racedUsers{Users: r.Repositories.Users(), stale: r.stale}
}

type racedUsersStore struct {
	store.Store
	stale *atomic.Int64
}

func (s racedUsersStore) InTx(ctx context.Context, fn func(ctx context.Context, tx store.Repositories) error) error {
	return s.Store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		return fn(ctx, racedUsersRepositories{Repositories: tx, stale: s.stale})
	})
}

func TestAChangeThatLosesTheRaceIsMadeAgain(t *testing.T) {
	f, log := newManageFixture(t)
	stale := &atomic.Int64{}
	f.a.store = racedUsersStore{Store: f.a.store, stale: stale}
	stale.Store(2)
	if err := f.a.Admin().BlockUser(t.Context(), f.user.ID, "reason", time.Time{}); err != nil {
		t.Fatalf("BlockUser = %v, want the change to be made again", err)
	}
	if f.stored(t).Status != store.StatusBlocked {
		t.Fatal("the user is not blocked")
	}
	if got := len(recordsOf(t, f.a, "user.blocked")); got != 1 {
		t.Fatalf("the block was recorded %d times, want once", got)
	}
	wantTypes(t, log.take(), EventUserBlocked)
	stale.Store(changeAttempts)
	if err := f.a.Admin().UnblockUser(t.Context(), f.user.ID); !errors.Is(err, store.ErrStale) {
		t.Fatalf("UnblockUser = %v, want the error of a race that was lost every time", err)
	}
	if f.stored(t).Status != store.StatusBlocked {
		t.Fatal("a change that lost every race was made")
	}
}

func TestABlockThatCannotBeRecordedIsNotMade(t *testing.T) {
	f, log := newManageFixture(t)
	login := f.login(t)
	log.take()
	faults := newFaults()
	f.a.store = faultStore{Store: f.a.store, faults: faults}
	broken := errors.New("the audit log is gone")
	faults.set("audit.add", broken)
	if err := f.a.Admin().BlockUser(t.Context(), f.user.ID, "reason", time.Time{}); !errors.Is(err, broken) {
		t.Fatalf("BlockUser = %v, want the failure of the audit log", err)
	}
	if f.stored(t).Status != store.StatusActive || !f.works(t, login) {
		t.Fatal("a block that was not recorded was made: the status or the sessions changed")
	}
	if events := log.take(); len(events) != 0 {
		t.Fatalf("a block that failed was reported: %+v", events)
	}
}

func TestSessionsAreEndedOneByOneOrAllAtOnce(t *testing.T) {
	f, log := newManageFixture(t)
	first := f.login(t)
	second := f.login(t)
	third := f.tokenLogin(t)
	log.take()
	admin := f.a.Admin()
	if err := admin.EndUserSession(t.Context(), f.user.ID, first.Principal.SessionID); err != nil {
		t.Fatalf("EndUserSession failed: %v", err)
	}
	if f.works(t, first) || !f.works(t, second) {
		t.Fatal("the session that was named is not the only one that ended")
	}
	if err := admin.EndUserSession(t.Context(), f.user.ID, first.Principal.SessionID); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("EndUserSession of a session that ended = %v, want ErrSessionNotFound", err)
	}
	events := log.take()
	wantTypes(t, events, EventSessionEnded)
	if events[0].SessionID != first.Principal.SessionID || events[0].Details["reason"] != "administrator" || events[0].Details["count"] != "1" {
		t.Fatalf("the event is %+v", events[0])
	}
	ended, err := admin.EndUserSessions(t.Context(), f.user.ID)
	if err != nil || ended != 2 {
		t.Fatalf("EndUserSessions = %d, %v, want 2", ended, err)
	}
	if f.works(t, second) || f.works(t, third) {
		t.Fatal("a session of the user is left")
	}
	f.refused(t, "the refresh token of an ended session", third.Tokens.RefreshToken)
	if events = log.take(); len(events) != 1 || events[0].Details["count"] != "2" {
		t.Fatalf("the events are %+v", events)
	}
	if ended, err = admin.EndUserSessions(t.Context(), f.user.ID); err != nil || ended != 0 {
		t.Fatalf("EndUserSessions with none left = %d, %v", ended, err)
	}
	if events = log.take(); len(events) != 0 {
		t.Fatalf("ending no session was reported: %+v", events)
	}
	if got := len(recordsOf(t, f.a, "user.session_ended")); got != 1 {
		t.Fatalf("the audit log holds %d records of one ended session, want 1", got)
	}
	all := recordsOf(t, f.a, "user.sessions_ended")
	if len(all) != 1 || detailsOf(t, all[0])["count"] != float64(2) || all[0].ActorID != "api" {
		t.Fatalf("the ended sessions are recorded as %+v", all)
	}
}

func TestASessionOfAnotherUserCannotBeEndedThroughThisOne(t *testing.T) {
	f, _ := newManageFixture(t)
	other := mustRegister(t, f.a, map[string]string{"email": "olga@example.com", "username": "olga_o"}, goodPassword)
	mine := f.login(t)
	if err := f.a.Admin().EndUserSession(t.Context(), other.ID, mine.Principal.SessionID); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("EndUserSession = %v, want ErrSessionNotFound: the session is not theirs", err)
	}
	if !f.works(t, mine) {
		t.Fatal("the session of another user ended")
	}
}

func TestSessionsThatCannotBeEndedAreReported(t *testing.T) {
	f, _ := newManageFixture(t)
	f.login(t)
	faults := newFaults()
	f.a.store = faultStore{Store: f.a.store, faults: faults}
	broken := errors.New("the sessions are gone")
	faults.set("sessions.revoke_one", broken)
	faults.set("sessions.revoke", broken)
	if err := f.a.Admin().EndUserSession(t.Context(), f.user.ID, "x"); !errors.Is(err, broken) {
		t.Errorf("EndUserSession = %v, want the failure of the store", err)
	}
	if _, err := f.a.Admin().EndUserSessions(t.Context(), f.user.ID); !errors.Is(err, broken) {
		t.Errorf("EndUserSessions = %v, want the failure of the store", err)
	}
	if err := f.a.Admin().BlockUser(t.Context(), f.user.ID, "reason", time.Time{}); !errors.Is(err, broken) {
		t.Errorf("BlockUser = %v, want the failure of the store", err)
	}
	if f.stored(t).Status != store.StatusActive {
		t.Fatal("a block whose sessions could not be ended was made")
	}
}

func TestALinkToResetThePasswordIsSentToTheConfirmedChannels(t *testing.T) {
	f, log, sender := newMailFixture(t)
	f.confirm(t, "nina@example.com")
	log.take()
	if err := f.a.Admin().SendPasswordReset(t.Context(), f.user.ID, "en"); err != nil {
		t.Fatalf("SendPasswordReset failed: %v", err)
	}
	messages := f.messages(t, sender, 1)
	m := messages[0]
	if m.Kind != MessagePasswordReset || m.To != "nina@example.com" || m.Language != "en" || !strings.HasPrefix(m.Link, "https://app.example.com/reset#token=") || m.Code == "" {
		t.Fatalf("the message is %+v", m)
	}
	records := recordsOf(t, f.a, "user.password_reset_sent")
	if len(records) != 1 || records[0].ActorID != "api" || records[0].TargetUserID != string(f.user.ID) {
		t.Fatalf("the sending is recorded as %+v", records)
	}
	channels, _ := detailsOf(t, records[0])["channels"].([]any)
	if len(channels) != 1 || channels[0] != "email:n***@example.com" || strings.Contains(records[0].Details, "nina@") {
		t.Fatalf("the channels are %v in %s: the address is masked", channels, records[0].Details)
	}
	events := log.take()
	wantTypes(t, events, EventUserChanged)
	if events[0].UserID != string(f.user.ID) || events[0].Details["change"] != "password_reset_sent" {
		t.Fatalf("the event is %+v", events[0])
	}
	if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: "a new password that is long enough 1"}); err != nil {
		t.Fatalf("the link did not reset the password: %v", err)
	}
	if !f.canSignInWith(t, "a new password that is long enough 1") {
		t.Fatal("the new password does not work")
	}
}

func TestALinkIsNotSentWhereNoChannelIsConfirmed(t *testing.T) {
	f, log, sender := newMailFixture(t)
	log.take()
	if err := f.a.Admin().SendPasswordReset(t.Context(), f.user.ID, ""); !errors.Is(err, ErrNoConfirmedChannel) {
		t.Fatalf("SendPasswordReset = %v, want ErrNoConfirmedChannel", err)
	}
	eventually(t, "the queue of messages to empty", func() bool { return f.a.dispatcher.pending.Load() == 0 })
	if got := sender.sent(); len(got) != 0 {
		t.Fatalf("messages were sent: %+v", got)
	}
	if got := len(recordsOf(t, f.a, "user.password_reset_sent")) + len(log.take()); got != 0 {
		t.Fatalf("a link that was not sent was recorded or reported: %d", got)
	}
}

func TestALinkNeedsASenderAndAChannelToSendTo(t *testing.T) {
	f, _ := newManageFixture(t)
	if err := f.a.Admin().SendPasswordReset(t.Context(), f.user.ID, ""); !errors.Is(err, ErrRecoveryDisabled) {
		t.Fatalf("SendPasswordReset without a Sender = %v, want ErrRecoveryDisabled", err)
	}
}

func TestABlockedUserStillGetsTheLinkAndADeletedOneDoesNot(t *testing.T) {
	f, _, sender := newMailFixture(t)
	f.confirm(t, "nina@example.com")
	if err := f.a.Admin().BlockUser(t.Context(), f.user.ID, "reason", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := f.a.Admin().SendPasswordReset(t.Context(), f.user.ID, ""); err != nil {
		t.Fatalf("SendPasswordReset to a blocked user failed: %v", err)
	}
	f.messages(t, sender, 1)
	f.change(t, func(u *store.User) {
		u.Status, u.DeletedAt, u.PurgeAfter = store.StatusDeleted, f.clock.now(), f.clock.now().Add(time.Hour)
	})
	if err := f.a.Admin().SendPasswordReset(t.Context(), f.user.ID, ""); !errors.Is(err, ErrUserDeleted) {
		t.Fatalf("SendPasswordReset to a deleted user = %v, want ErrUserDeleted", err)
	}
}

func TestATemporaryPasswordIsShownOnceAndMustBeChanged(t *testing.T) {
	f, log, sender := newMailFixture(t)
	f.confirm(t, "nina@example.com")
	cookie := f.login(t)
	log.take()
	temporary, err := f.a.Admin().SetTemporaryPassword(t.Context(), f.user.ID, "en")
	if err != nil {
		t.Fatalf("SetTemporaryPassword failed: %v", err)
	}
	if len(temporary) != 29 || strings.Count(temporary, "-") != 4 {
		t.Fatalf("the temporary password is %q, want five groups of five characters", temporary)
	}
	again, err := f.a.Admin().SetTemporaryPassword(t.Context(), f.user.ID, "")
	if err != nil || again == temporary {
		t.Fatalf("a second temporary password = %q, %v, want another one", again, err)
	}
	if f.works(t, cookie) || f.canSignInWith(t, goodPassword) || f.canSignInWith(t, temporary) {
		t.Fatal("the old password, the first temporary password or the old session still works")
	}
	login, err := f.a.Login(t.Context(), func() Credentials { c := f.credentials(); c.Password = again; return c }())
	if err != nil || !login.Principal.MustChangePassword {
		t.Fatalf("Login with the temporary password = %+v, %v, want a session that has to change the password", login, err)
	}
	if f.stored(t).MustChangePassword != true {
		t.Fatal("the user does not have to change the password")
	}
	if _, err = f.a.ChangePassword(t.Context(), login.Principal, again, "a new password that is long enough 1"); err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}
	if f.stored(t).MustChangePassword {
		t.Fatal("the user still has to change the password after they did")
	}
	notices := f.messages(t, sender, 3)
	kinds := map[MessageKind]int{}
	for _, m := range notices {
		kinds[m.Kind]++
	}
	if kinds[MessagePasswordChanged] != 3 {
		t.Fatalf("the messages are %v, want a notice of each change of the password", kinds)
	}
	records := recordsOf(t, f.a, "user.password_temporary")
	if len(records) != 2 || detailsOf(t, records[1])["sessions"] != float64(1) {
		t.Fatalf("the temporary passwords are recorded as %+v", records)
	}
	events := log.take()
	if len(events) == 0 || events[0].Type != EventUserChanged || events[0].Details["change"] != "password_temporary" {
		t.Fatalf("the events are %+v", events)
	}
	list, listErr := f.a.store.Audit().List(t.Context(), store.AuditQuery{TenantID: f.a.tenant, Limit: store.MaxAuditPage})
	if listErr != nil {
		t.Fatal(listErr)
	}
	raw, _ := json.Marshal(list)
	rawEvents, _ := json.Marshal(events)
	for _, secret := range []string{temporary, again, strings.ReplaceAll(temporary, "-", ""), strings.ReplaceAll(again, "-", "")} {
		if strings.Contains(string(raw), secret) || strings.Contains(string(rawEvents), secret) {
			t.Fatalf("the temporary password %q is in the audit log or in the events", secret)
		}
	}
}

func TestATemporaryPasswordFollowsThePolicyOfTheService(t *testing.T) {
	for name, c := range map[string]struct {
		policy PasswordPolicy
		length int
	}{
		"a long minimum":  {PasswordPolicy{MinLength: 40, MaxLength: 60}, 40},
		"a short maximum": {PasswordPolicy{MinLength: 8, MaxLength: 20}, 20},
		"a tight maximum": {PasswordPolicy{MinLength: 12, MaxLength: 26}, 25},
		"the defaults":    {PasswordPolicy{}, 29},
	} {
		f, _ := newManageFixture(t)
		f.a.policy.MinLength, f.a.policy.MaxLength = c.policy.MinLength, c.policy.MaxLength
		if c.policy.MinLength == 0 {
			f.a.policy.MinLength, f.a.policy.MaxLength = 12, 128
		}
		temporary, err := f.a.Admin().SetTemporaryPassword(t.Context(), f.user.ID, "")
		if err != nil || len(temporary) != c.length {
			t.Errorf("%s: the temporary password is %q (%d), %v, want %d characters", name, temporary, len(temporary), err, c.length)
			continue
		}
		if !f.canSignInWith(t, temporary) {
			t.Errorf("%s: the temporary password does not work", name)
		}
	}
}

func TestATemporaryPasswordThatCannotBeStoredIsNotGiven(t *testing.T) {
	f, _ := newManageFixture(t)
	faults := newFaults()
	f.a.store = faultStore{Store: f.a.store, faults: faults}
	broken := errors.New("the store is gone")
	for _, op := range []string{"users.update", "audit.add"} {
		faults.set(op, broken)
		if temporary, err := f.a.Admin().SetTemporaryPassword(t.Context(), f.user.ID, ""); !errors.Is(err, broken) || temporary != "" {
			t.Errorf("with %s failing SetTemporaryPassword = %q, %v", op, temporary, err)
		}
		faults.clear()
	}
	if !f.canSignInWith(t, goodPassword) {
		t.Fatal("a temporary password that was not given replaced the password")
	}
}
