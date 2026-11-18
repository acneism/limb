package limb

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func TestADeletedUserIsKeptCannotSignInAndKeepsTheirValues(t *testing.T) {
	f, log, sender := newMailFixture(t)
	f.confirm(t, "nina@example.com")
	cookie := f.login(t)
	token := f.tokenLogin(t)
	if err := f.a.Admin().SendPasswordReset(t.Context(), f.user.ID, ""); err != nil {
		t.Fatal(err)
	}
	reset := f.messages(t, sender, 1)[0]
	log.take()
	if err := f.a.Admin().DeleteUser(t.Context(), f.user.ID); err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}
	events := log.take()
	stored := f.stored(t)
	purge := f.clock.now().Add(30 * 24 * time.Hour).Truncate(time.Microsecond)
	if stored.Status != store.StatusDeleted || !stored.DeletedAt.Equal(f.clock.now().Truncate(time.Microsecond)) || !stored.PurgeAfter.Equal(purge) {
		t.Fatalf("the stored user is %+v", stored)
	}
	if f.works(t, cookie) || f.works(t, token) {
		t.Fatal("a session of a deleted user still works")
	}
	f.refused(t, "the refresh token of a deleted user", token.Tokens.RefreshToken)
	if _, err := f.a.Login(t.Context(), f.credentials()); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login = %v, want ErrInvalidCredentials", err)
	}
	if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(reset.Link), Password: "a new password that is long enough 1"}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("a link of a deleted user = %v, want ErrInvalidSecret", err)
	}
	if _, err := f.a.Register(t.Context(), Registration{Identifiers: map[string]string{"email": "nina@example.com"}, Password: goodPassword}); !errors.Is(err, ErrIdentifierTaken) {
		t.Fatalf("Register with the address of a deleted user = %v, want ErrIdentifierTaken", err)
	}
	if _, err := f.a.Admin().CreateUser(t.Context(), NewUser{Identifiers: map[string]string{"email": "other@example.com", "username": "nina_n"}, Password: goodPassword}); !errors.Is(err, ErrIdentifierTaken) {
		t.Fatalf("CreateUser with the name of a deleted user = %v, want ErrIdentifierTaken", err)
	}
	card, err := f.a.Admin().User(t.Context(), f.user.ID)
	if err != nil || card.Status != StatusDeleted || !card.PurgeAfter.Equal(purge) || len(card.Identifiers) != 2 {
		t.Fatalf("the card is %+v, %v", card, err)
	}
	records := recordsOf(t, f.a, "user.deleted")
	if len(records) != 1 || records[0].ActorID != "api" || records[0].TargetUserID != string(f.user.ID) {
		t.Fatalf("the deletion is recorded as %+v", records)
	}
	details := detailsOf(t, records[0])
	values, _ := details["identifiers"].(map[string]any)
	if details["mode"] != "soft" || details["purge_after"] != purge.UTC().Format(time.RFC3339) || values["email"] != "nina@example.com" || details["sessions"] != float64(2) {
		t.Fatalf("the details are %v", details)
	}
	wantTypes(t, events, EventUserDeleted, EventSessionEnded)
	if events[0].Details["mode"] != "soft" || events[0].Details["purge_after"] != purge.UTC().Format(time.RFC3339) || events[1].Details["reason"] != "administrator" {
		t.Fatalf("the events are %+v", events)
	}
	if err = f.a.Admin().DeleteUser(t.Context(), f.user.ID); !errors.Is(err, ErrUserDeleted) {
		t.Fatalf("DeleteUser of a deleted user = %v, want ErrUserDeleted", err)
	}
}

func TestALinkSentBeforeTheDeletionDoesNotWorkAfterTheRestoration(t *testing.T) {
	f, _, sender := newMailFixture(t)
	f.confirm(t, "nina@example.com")
	if err := f.a.Admin().SendPasswordReset(t.Context(), f.user.ID, ""); err != nil {
		t.Fatal(err)
	}
	link := f.messages(t, sender, 1)[0].Link
	if err := f.a.Admin().DeleteUser(t.Context(), f.user.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.a.Admin().RestoreUser(t.Context(), f.user.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(link), Password: "a new password that is long enough 1"}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("a link sent before the deletion = %v after the restoration, want ErrInvalidSecret", err)
	}
	if !f.canSignInWith(t, goodPassword) {
		t.Fatal("the password changed")
	}
}

func TestTheRetentionOfDeletedUsersCanBeSet(t *testing.T) {
	f, _ := newManageFixture(t, WithDeletedUserRetention(36*time.Hour))
	if err := f.a.Admin().DeleteUser(t.Context(), f.user.ID); err != nil {
		t.Fatal(err)
	}
	if got := f.stored(t).PurgeAfter; !got.Equal(f.clock.now().Add(36 * time.Hour).Truncate(time.Microsecond)) {
		t.Fatalf("the user is kept until %v, want 36 hours from now", got)
	}
	for name, d := range map[string]time.Duration{"zero": 0, "negative": -time.Hour, "short": time.Minute, "long": 11 * 365 * 24 * time.Hour} {
		if err := newFixtureErr(t, WithDeletedUserRetention(d)); err == nil {
			t.Errorf("%s: New accepted a retention of %v", name, d)
		}
	}
	if err := newFixtureErr(t, WithDeletedUserRetention(time.Hour)); err != nil {
		t.Errorf("New refused a retention of an hour: %v", err)
	}
	if err := newFixtureErr(t, WithDeletedUserRetention(10*365*24*time.Hour)); err != nil {
		t.Errorf("New refused a retention of ten years: %v", err)
	}
}

func TestAnImmediateDeletionErasesTheUserAndFreesTheirValues(t *testing.T) {
	f, log := newManageFixture(t, WithImmediateDeletion())
	cookie := f.login(t)
	token := f.tokenLogin(t)
	log.take()
	if err := f.a.Admin().DeleteUser(t.Context(), f.user.ID); err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}
	if _, err := f.a.store.Users().Get(t.Context(), f.a.tenant, string(f.user.ID)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the user is still there: %v", err)
	}
	if _, err := f.a.store.Identifiers().Find(t.Context(), f.a.tenant, "email", "nina@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the address is still taken: %v", err)
	}
	if f.works(t, cookie) || f.works(t, token) {
		t.Fatal("a session of an erased user still works")
	}
	if _, err := f.a.Admin().User(t.Context(), f.user.ID); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("User = %v, want ErrUserNotFound", err)
	}
	if err := f.a.Admin().DeleteUser(t.Context(), f.user.ID); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("DeleteUser of an erased user = %v, want ErrUserNotFound", err)
	}
	if _, err := f.a.Register(t.Context(), Registration{Identifiers: map[string]string{"email": "nina@example.com"}, Password: goodPassword}); err != nil {
		t.Fatalf("Register with the address of an erased user failed: %v", err)
	}
	records := recordsOf(t, f.a, "user.deleted")
	if len(records) != 1 || detailsOf(t, records[0])["mode"] != "immediate" || records[0].TargetUserID != string(f.user.ID) {
		t.Fatalf("the deletion is recorded as %+v: the audit log keeps what happened to a user who is gone", records)
	}
	if values, _ := detailsOf(t, records[0])["identifiers"].(map[string]any); values["email"] != "nina@example.com" || values["username"] != "nina_n" {
		t.Fatalf("the record holds the values %v, want the ones that the user signed in with, which nothing else will say", values)
	}
	if got := len(recordsOf(t, f.a, "auth.login")); got != 2 {
		t.Fatalf("the audit log holds %d sign-ins of the erased user, want 2: it outlives them", got)
	}
	events := log.take()
	if len(events) < 1 || events[0].Type != EventUserDeleted || events[0].UserID != string(f.user.ID) || events[0].Details["mode"] != "immediate" {
		t.Fatalf("the events are %+v", events)
	}
}

func TestAnImmediateDeletionErasesAUserWhoWasDeletedSoftly(t *testing.T) {
	f, _ := newManageFixture(t)
	if err := f.a.Admin().DeleteUser(t.Context(), f.user.ID); err != nil {
		t.Fatal(err)
	}
	f.a.immediate = true
	if err := f.a.Admin().DeleteUser(t.Context(), f.user.ID); err != nil {
		t.Fatalf("DeleteUser of a user who is deleted softly, in the immediate mode, failed: %v", err)
	}
	if _, err := f.a.store.Users().Get(t.Context(), f.a.tenant, string(f.user.ID)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the user is still there: %v", err)
	}
}

func TestADeletionThatCannotBeRecordedDoesNotHappen(t *testing.T) {
	for name, immediate := range map[string]bool{"soft": false, "immediate": true} {
		f, log := newManageFixture(t)
		f.a.immediate = immediate
		cookie := f.login(t)
		log.take()
		faults := newFaults()
		f.a.store = faultStore{Store: f.a.store, faults: faults}
		broken := errors.New("the audit log is gone")
		faults.set("audit.add", broken)
		if err := f.a.Admin().DeleteUser(t.Context(), f.user.ID); !errors.Is(err, broken) {
			t.Fatalf("%s: DeleteUser = %v, want the failure of the audit log", name, err)
		}
		if f.stored(t).Status != store.StatusActive || !f.works(t, cookie) {
			t.Fatalf("%s: a deletion that was not recorded was made", name)
		}
		if events := log.take(); len(events) != 0 {
			t.Fatalf("%s: a deletion that failed was reported: %+v", name, events)
		}
	}
}

func TestTheHookBeforeADeletionSeesTheUserAndCanRefuseIt(t *testing.T) {
	for name, immediate := range map[string]bool{"soft": false, "immediate": true} {
		f, log := newManageFixture(t)
		f.a.immediate = immediate
		var seen User
		var statusInHook Status
		calls := 0
		f.a.hooks.BeforeDelete = func(ctx context.Context, u User) error {
			calls++
			seen = u
			stored, err := f.a.store.Users().Get(ctx, f.a.tenant, string(u.ID))
			if err == nil {
				statusInHook = stored.Status
			}
			return nil
		}
		log.take()
		if err := f.a.Admin().DeleteUser(t.Context(), f.user.ID); err != nil {
			t.Fatalf("%s: DeleteUser failed: %v", name, err)
		}
		if calls != 1 || seen.ID != f.user.ID || len(seen.Identifiers) != 2 || seen.Identifiers[0].Value != "nina@example.com" || statusInHook != StatusActive {
			t.Fatalf("%s: the hook was called %d times with %+v while the user was %q: it runs once, before the change, with the user", name, calls, seen, statusInHook)
		}
	}
	f, log := newManageFixture(t)
	cookie := f.login(t)
	log.take()
	reason := errors.New("the user has an open order")
	f.a.hooks.BeforeDelete = func(context.Context, User) error { return reason }
	err := f.a.Admin().DeleteUser(t.Context(), f.user.ID)
	if !errors.Is(err, ErrDeletionRefused) || !errors.Is(err, reason) || !strings.Contains(err.Error(), "open order") {
		t.Fatalf("DeleteUser = %v, want ErrDeletionRefused wrapping the reason of the hook", err)
	}
	if f.stored(t).Status != store.StatusActive || !f.works(t, cookie) || len(recordsOf(t, f.a, "user.deleted")) != 0 || len(log.take()) != 0 {
		t.Fatal("a deletion that the hook refused changed something")
	}
}

func TestAHookThatPanicsRefusesTheDeletionAndLeaksNothing(t *testing.T) {
	logger, logs := capturingLogger()
	f, _ := newManageFixture(t, WithLogger(logger))
	f.a.hooks.BeforeDelete = func(context.Context, User) error { panic("secret value " + goodPassword) }
	err := f.a.Admin().DeleteUser(t.Context(), f.user.ID)
	if !errors.Is(err, ErrDeletionRefused) || strings.Contains(err.Error(), goodPassword) {
		t.Fatalf("DeleteUser = %v, want ErrDeletionRefused", err)
	}
	if strings.Contains(logs.String(), goodPassword) || !strings.Contains(logs.String(), "the hook before a deletion panicked") || !strings.Contains(logs.String(), "panic_type=string") {
		t.Fatalf("the log says %s: only the type of the value of the panic is logged", logs.String())
	}
	if f.stored(t).Status != store.StatusActive {
		t.Fatal("a deletion that the hook refused was made")
	}
}

func TestTheHookBeforeADeletionIsNotCalledForOtherChanges(t *testing.T) {
	f, _ := newManageFixture(t)
	calls := 0
	f.a.hooks.BeforeDelete = func(context.Context, User) error { calls++; return errors.New("no") }
	admin := f.a.Admin()
	if err := admin.BlockUser(t.Context(), f.user.ID, "reason", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := admin.UnblockUser(t.Context(), f.user.ID); err != nil {
		t.Fatal(err)
	}
	if err := admin.SetUserIdentifier(t.Context(), f.user.ID, "username", "nina_other"); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("the hook before a deletion was called %d times for changes that delete nothing", calls)
	}
	var validation *ValidationError
	if err := admin.RestoreUser(t.Context(), f.user.ID); !errors.As(err, &validation) {
		t.Fatalf("RestoreUser of a user who is not deleted = %v", err)
	}
}

func TestADeletedUserIsRestoredUntilTheRetentionEnds(t *testing.T) {
	f, log := newManageFixture(t)
	cookie := f.login(t)
	if err := f.a.Admin().DeleteUser(t.Context(), f.user.ID); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(29 * 24 * time.Hour)
	log.take()
	if err := f.a.Admin().RestoreUser(t.Context(), f.user.ID); err != nil {
		t.Fatalf("RestoreUser failed: %v", err)
	}
	stored := f.stored(t)
	if stored.Status != store.StatusActive || !stored.DeletedAt.IsZero() || !stored.PurgeAfter.IsZero() {
		t.Fatalf("the stored user is %+v", stored)
	}
	if f.works(t, cookie) {
		t.Fatal("a session that ended with the deletion works again")
	}
	if _, err := f.a.Login(t.Context(), f.credentials()); err != nil {
		t.Fatalf("Login after the restoring failed: %v", err)
	}
	records := recordsOf(t, f.a, "user.restored")
	if len(records) != 1 || detailsOf(t, records[0])["status"] != "active" || records[0].ActorID != "api" {
		t.Fatalf("the restoring is recorded as %+v", records)
	}
	events := log.take()
	if len(events) < 1 || events[0].Type != EventUserRestored || events[0].UserID != string(f.user.ID) {
		t.Fatalf("the events are %+v", events)
	}
	var validation *ValidationError
	if err := f.a.Admin().RestoreUser(t.Context(), f.user.ID); !errors.As(err, &validation) || validation.Field != "user" {
		t.Fatalf("RestoreUser of a user who is not deleted = %v, want a *ValidationError", err)
	}
}

func TestARestoredUserWhoWasBlockedIsBlockedAgain(t *testing.T) {
	f, _ := newManageFixture(t)
	admin := f.a.Admin()
	if err := admin.BlockUser(t.Context(), f.user.ID, "fraud", f.clock.now().Add(10*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := admin.DeleteUser(t.Context(), f.user.ID); err != nil {
		t.Fatal(err)
	}
	if err := admin.RestoreUser(t.Context(), f.user.ID); err != nil {
		t.Fatal(err)
	}
	if stored := f.stored(t); stored.Status != store.StatusBlocked || stored.BlockedReason != "fraud" {
		t.Fatalf("the restored user is %+v, want the block that was there", stored)
	}
	if got := detailsOf(t, recordsOf(t, f.a, "user.restored")[0])["status"]; got != "blocked" {
		t.Fatalf("the restoring is recorded with the status %v", got)
	}
	if err := admin.DeleteUser(t.Context(), f.user.ID); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(11 * 24 * time.Hour)
	if err := admin.RestoreUser(t.Context(), f.user.ID); err != nil {
		t.Fatal(err)
	}
	if stored := f.stored(t); stored.Status != store.StatusActive {
		t.Fatalf("the restored user is %+v, want an active one: the block ran out", stored)
	}
}

func TestADeletedUserIsNotRestoredAfterTheRetentionEnds(t *testing.T) {
	f, _ := newManageFixture(t)
	if err := f.a.Admin().DeleteUser(t.Context(), f.user.ID); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(30*24*time.Hour - time.Second)
	if err := f.a.Admin().RestoreUser(t.Context(), f.user.ID); err != nil {
		t.Fatalf("RestoreUser a second before the end failed: %v", err)
	}
	if err := f.a.Admin().DeleteUser(t.Context(), f.user.ID); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(30 * 24 * time.Hour)
	if err := f.a.Admin().RestoreUser(t.Context(), f.user.ID); !errors.Is(err, ErrRetentionOver) {
		t.Fatalf("RestoreUser when the retention is over = %v, want ErrRetentionOver", err)
	}
	if err := f.a.Admin().RestoreUser(t.Context(), "00000000-0000-7000-8000-000000000999"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("RestoreUser of a user that does not exist = %v, want ErrUserNotFound", err)
	}
	if f.stored(t).Status != store.StatusDeleted {
		t.Fatal("the user is not deleted")
	}
}

func TestTheOperationsOnADeletedUserThatNeedAnAccountAreRefused(t *testing.T) {
	f, _ := newManageFixture(t)
	if err := f.a.Admin().DeleteUser(t.Context(), f.user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.Admin().SetTemporaryPassword(t.Context(), f.user.ID, ""); !errors.Is(err, ErrUserDeleted) {
		t.Fatalf("SetTemporaryPassword of a deleted user = %v, want ErrUserDeleted", err)
	}
	if err := f.a.Admin().SetUserIdentifier(t.Context(), f.user.ID, "username", "nina_other"); !errors.Is(err, ErrUserDeleted) {
		t.Fatalf("SetUserIdentifier of a deleted user = %v, want ErrUserDeleted", err)
	}
	if _, err := f.a.Admin().EndUserSessions(t.Context(), f.user.ID); err != nil {
		t.Fatalf("EndUserSessions of a deleted user failed: %v", err)
	}
}
