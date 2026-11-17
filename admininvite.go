package limb

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

// Invitation is a user that an administrator invites to an address or a phone
// number.
type Invitation struct {
	// Identifiers maps the name of an identifier type to its value, as in
	// Registration, with at least one value of a type that is a delivery channel,
	// which the invitation goes to.
	Identifiers map[string]string

	// Language is the language of the invitation, "ru" or "en", or the one of
	// ContextWithLanguage when it is empty.
	Language string
}

func (a *Auth) invitationsReady() bool {
	return a.recoveryReady() && a.resetURL != ""
}

func (a *Auth) inviteUser(ctx context.Context, by actorRef, inv Invitation) (ManagedUser, error) {
	if !a.invitationsReady() {
		return ManagedUser{}, ErrInvitationsDisabled
	}
	pending, err := a.collectIdentifiers(inv.Identifiers)
	if err != nil {
		return ManagedUser{}, err
	}
	if !slices.ContainsFunc(pending, func(p pendingIdentifier) bool { return p.kind.IsDelivery() }) {
		return ManagedUser{}, &ValidationError{Field: "identifiers", Reason: "an address or a phone number to invite is required"}
	}
	id, err := a.newID()
	if err != nil {
		return ManagedUser{}, err
	}
	user, identifiers := a.newAccount(id, "", store.CreatedViaInvite, pending, nil)
	err = a.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if storeErr := storeNewUser(ctx, tx, user, identifiers); storeErr != nil {
			return storeErr
		}
		return a.auditWriter().Add(ctx, tx.Audit(), audit.Entry{
			Actor: by.actor, Action: audit.UserInvited, TargetUserID: id, IP: by.ip, Details: map[string]any{"identifiers": identifierValues(identifiers)},
		})
	})
	if err != nil {
		return ManagedUser{}, err
	}
	user.Version = 1
	a.emitHook(ctx, Event{Type: EventUserCreated, UserID: id, IP: by.ip, Details: map[string]string{"via": "invite"}})
	created := a.createdUser(user, identifiers)
	return created, a.queueInvitation(ctx, id, inv.Language)
}

func (a *Auth) queueInvitation(ctx context.Context, userID, language string) error {
	job := recoveryJob{purpose: store.PurposeInvite, kind: MessageInvitation, language: a.languageFor(ctx, language), linkOnly: true}
	return a.dispatcher.submit(task{kind: job.kind, run: func(ctx context.Context) error {
		return a.sendSecretsToUser(ctx, userID, job)
	}})
}

func (a *Auth) resendInvitation(ctx context.Context, by actorRef, id UserID, language string) error {
	if !a.invitationsReady() {
		return ErrInvitationsDisabled
	}
	return a.editUser(ctx, by, id, func(ctx context.Context, tx store.Repositories, u store.User, _ time.Time) (userEdit, error) {
		if u.PasswordHash != "" {
			return userEdit{}, &ValidationError{Field: "user", Reason: "has a password already, there is nothing to invite them to"}
		}
		identifiers, err := tx.Identifiers().ListByUser(ctx, a.tenant, u.ID)
		if err != nil {
			return userEdit{}, fmt.Errorf("limb: list the identifiers: %w", err)
		}
		channels := slices.Concat(a.deliveryChannels(identifiers, true), a.deliveryChannels(identifiers, false))
		if len(channels) == 0 {
			return userEdit{}, &ValidationError{Field: "user", Reason: "has no address or phone number to invite"}
		}
		masked := make([]any, 0, len(channels))
		for _, c := range channels {
			masked = append(masked, c.Type+":"+maskValue(c.Value))
		}
		if err = a.queueInvitation(ctx, u.ID, language); err != nil {
			return userEdit{}, err
		}
		return userEdit{entry: &audit.Entry{Action: audit.UserInvitationResent, Details: map[string]any{"channels": masked}}}, nil
	})
}

// InviteUser creates a user who has no password and sends a link to the address
// or the phone number of the invitation, in the background. The link opens the
// page of WithResetURL, where the holder chooses the password, which confirms
// the channel too, see ResetPassword. It works for seven days, and ResendInvitation
// sends another. The account stays without a password until then, so nobody can
// sign in to it.
//
// It returns ErrInvitationsDisabled when the service cannot send an invitation,
// the errors of CreateUser except those of the password and, together with the
// user who was created, ErrBusy when the queue of messages was full: send the
// invitation again then.
func (x *AdminAPI) InviteUser(ctx context.Context, inv Invitation) (ManagedUser, error) {
	return x.a.inviteUser(ctx, apiActor, inv)
}

// ResendInvitation sends the invitation of a user who has no password yet again,
// to every address and phone number of theirs, and ends the links it sent
// before. It returns ErrInvitationsDisabled, ErrUserNotFound, ErrUserDeleted, a
// *ValidationError when the user has a password or has no channel to send to and
// ErrBusy.
func (x *AdminAPI) ResendInvitation(ctx context.Context, id UserID, language string) error {
	return x.a.resendInvitation(ctx, apiActor, id, language)
}
