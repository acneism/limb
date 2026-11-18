package limb

import (
	"slices"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

var eventsOfTheAdministration = []EventType{
	EventUserBlocked, EventUserUnblocked, EventSessionEnded, EventUserChanged, EventUserDeleted, EventUserRestored, EventUserCreated,
}

func TestEveryOperationOnAUserRecordsWhoDidItAndFromWhere(t *testing.T) {
	f, log, _ := newMailFixture(t)
	f.confirm(t, "nina@example.com")
	adminID := "00000000-0000-7000-8000-0000000000a1"
	by := actorRef{actor: adminActor(adminID), ip: "198.51.100.4"}
	nina := f.user.ID
	var olga, ivan ManagedUser
	steps := []struct {
		action string
		events bool
		run    func() (UserID, error)
	}{
		{"user.blocked", true, func() (UserID, error) { return nina, f.a.blockUser(t.Context(), by, nina, "spam", time.Time{}) }},
		{"user.unblocked", true, func() (UserID, error) { return nina, f.a.unblockUser(t.Context(), by, nina) }},
		{"user.session_ended", true, func() (UserID, error) {
			return nina, f.a.endUserSession(t.Context(), by, nina, f.login(t).Principal.SessionID)
		}},
		{"user.sessions_ended", true, func() (UserID, error) {
			f.login(t)
			_, err := f.a.endUserSessions(t.Context(), by, nina)
			return nina, err
		}},
		{"user.password_reset_sent", true, func() (UserID, error) { return nina, f.a.sendResetLink(t.Context(), by, nina, "en") }},
		{"user.password_temporary", true, func() (UserID, error) {
			_, err := f.a.setTemporaryPassword(t.Context(), by, nina, "en")
			return nina, err
		}},
		{"user.identifier_changed", true, func() (UserID, error) {
			return nina, f.a.changeIdentifier(t.Context(), by, nina, "username", "nina_new")
		}},
		{"user.identifier_removed", true, func() (UserID, error) { return nina, f.a.removeIdentifier(t.Context(), by, nina, "username") }},
		{"user.identifier_added", true, func() (UserID, error) {
			return nina, f.a.changeIdentifier(t.Context(), by, nina, "username", "nina_again")
		}},
		{"user.created", true, func() (UserID, error) {
			var err error
			olga, err = f.a.createUser(t.Context(), by, NewUser{Identifiers: map[string]string{"email": "olga@example.com"}, Password: goodPassword})
			return olga.ID, err
		}},
		{"user.identifier_verified", true, func() (UserID, error) { return olga.ID, f.a.verifyIdentifier(t.Context(), by, olga.ID, "email") }},
		{"user.invited", true, func() (UserID, error) {
			var err error
			ivan, err = f.a.inviteUser(t.Context(), by, Invitation{Identifiers: map[string]string{"email": "ivan@example.com"}, Language: "en"})
			return ivan.ID, err
		}},
		{"user.invitation_resent", false, func() (UserID, error) { return ivan.ID, f.a.resendInvitation(t.Context(), by, ivan.ID, "en") }},
		{"user.deleted", true, func() (UserID, error) { return nina, f.a.deleteUser(t.Context(), by, nina) }},
		{"user.restored", true, func() (UserID, error) { return nina, f.a.restoreUser(t.Context(), by, nina) }},
	}
	for _, step := range steps {
		log.take()
		target, err := step.run()
		if err != nil {
			t.Fatalf("%s: the operation failed: %v", step.action, err)
		}
		records := recordsOf(t, f.a, step.action)
		if len(records) != 1 {
			t.Fatalf("%s: the audit log holds %d records of it, want 1", step.action, len(records))
		}
		if got := records[0]; got.ActorKind != store.ActorAdmin || got.ActorID != adminID || got.IP != by.ip || got.TargetUserID != string(target) {
			t.Errorf("%s: the record says %s %q from %q about %q, want the administrator %q from %q about %q",
				step.action, got.ActorKind, got.ActorID, got.IP, got.TargetUserID, adminID, by.ip, target)
		}
		seen := 0
		for _, e := range log.take() {
			if !slices.Contains(eventsOfTheAdministration, e.Type) {
				continue
			}
			seen++
			if e.IP != by.ip || e.UserID != string(target) {
				t.Errorf("%s: the event %s is about %q from %q, want %q from %q", step.action, e.Type, e.UserID, e.IP, target, by.ip)
			}
		}
		if step.events && seen == 0 {
			t.Errorf("%s: no event was reported", step.action)
		}
		if !step.events && seen != 0 {
			t.Errorf("%s: %d events were reported, want none", step.action, seen)
		}
	}
}

func TestAnImmediateDeletionRecordsWhoDidItAndFromWhere(t *testing.T) {
	f, log := newManageFixture(t, WithImmediateDeletion())
	adminID := "00000000-0000-7000-8000-0000000000a2"
	by := actorRef{actor: adminActor(adminID), ip: "198.51.100.9"}
	log.take()
	if err := f.a.deleteUser(t.Context(), by, f.user.ID); err != nil {
		t.Fatalf("deleteUser failed: %v", err)
	}
	records := recordsOf(t, f.a, "user.deleted")
	if len(records) != 1 || records[0].ActorKind != store.ActorAdmin || records[0].ActorID != adminID || records[0].IP != by.ip || records[0].TargetUserID != string(f.user.ID) {
		t.Fatalf("the deletion is recorded as %+v", records)
	}
	events := log.take()
	wantTypes(t, events, EventUserDeleted)
	if events[0].IP != by.ip || events[0].UserID != string(f.user.ID) {
		t.Fatalf("the event is %+v", events[0])
	}
}
