package limb

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

const userEditAttempts = 8

type userEdit struct {
	next   store.User
	update bool
	revoke bool
	entry  *audit.Entry
	events []Event
}

type userEditor func(ctx context.Context, tx store.Repositories, u store.User, now time.Time) (userEdit, error)

func (a *Auth) editUser(ctx context.Context, by actorRef, id UserID, edit userEditor) error {
	return a.editUserWith(ctx, by, id, false, edit)
}

func (a *Auth) editDeletedUser(ctx context.Context, by actorRef, id UserID, edit userEditor) error {
	return a.editUserWith(ctx, by, id, true, edit)
}

func (a *Auth) editUserWith(ctx context.Context, by actorRef, id UserID, allowDeleted bool, edit userEditor) error {
	var err error
	for range userEditAttempts {
		var applied userEdit
		var ended int
		now := a.now().UTC().Truncate(time.Microsecond)
		err = a.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
			applied, ended = userEdit{}, 0
			u, getErr := tx.Users().Get(ctx, a.tenant, string(id))
			switch {
			case errors.Is(getErr, store.ErrNotFound):
				return ErrUserNotFound
			case getErr != nil:
				return fmt.Errorf("limb: get the user: %w", getErr)
			case u.Status == store.StatusDeleted && !allowDeleted:
				return ErrUserDeleted
			}
			var editErr error
			if applied, editErr = edit(ctx, tx, u, now); editErr != nil {
				return editErr
			}
			if applied.update {
				if _, updateErr := tx.Users().Update(ctx, applied.next); updateErr != nil {
					if errors.Is(updateErr, store.ErrStale) {
						return updateErr
					}
					return fmt.Errorf("limb: update the user: %w", updateErr)
				}
			}
			if applied.revoke {
				var revokeErr error
				if ended, revokeErr = tx.Sessions().RevokeAllForUser(ctx, a.tenant, string(id), "", now); revokeErr != nil {
					return fmt.Errorf("limb: end the sessions: %w", revokeErr)
				}
			}
			if applied.entry == nil {
				return nil
			}
			entry := *applied.entry
			entry.Actor, entry.IP, entry.TargetUserID = by.actor, by.ip, string(id)
			if applied.revoke {
				entry.Details = withCount(entry.Details, "sessions", ended)
			}
			return a.auditWriter().Add(ctx, tx.Audit(), entry)
		})
		if !errors.Is(err, store.ErrStale) {
			if err == nil {
				a.reportEdit(ctx, id, applied, ended, by)
			}
			return err
		}
	}
	return fmt.Errorf("%w: %w", ErrConcurrentChange, err)
}

func withCount(details map[string]any, key string, count int) map[string]any {
	out := make(map[string]any, len(details)+1)
	for k, v := range details {
		out[k] = v
	}
	out[key] = count
	return out
}

func (a *Auth) reportEdit(ctx context.Context, id UserID, applied userEdit, ended int, by actorRef) {
	for _, e := range applied.events {
		e.UserID, e.IP = string(id), by.ip
		a.emitHook(ctx, e)
	}
	if applied.revoke && ended > 0 {
		a.emitHook(ctx, Event{
			Type: EventSessionEnded, UserID: string(id), IP: by.ip,
			Details: map[string]string{"reason": "administrator", "count": strconv.Itoa(ended)},
		})
	}
}

func validReason(reason string) (string, error) {
	reason = strings.TrimSpace(reason)
	switch {
	case reason == "":
		return "", &ValidationError{Field: "reason", Reason: "required"}
	case len(reason) > store.MaxBlockedReasonLength || !utf8.ValidString(reason) || hasControl(reason):
		return "", &ValidationError{Field: "reason", Reason: fmt.Sprintf("at most %d bytes of text without control characters", store.MaxBlockedReasonLength)}
	}
	return reason, nil
}

func (a *Auth) blockUser(ctx context.Context, by actorRef, id UserID, reason string, until time.Time) error {
	reason, err := validReason(reason)
	if err != nil {
		return err
	}
	if !until.IsZero() && !until.After(a.now()) {
		return &ValidationError{Field: "until", Reason: "must be in the future"}
	}
	if !until.IsZero() {
		until = until.UTC().Truncate(time.Microsecond)
	}
	return a.editUser(ctx, by, id, func(_ context.Context, _ store.Repositories, u store.User, _ time.Time) (userEdit, error) {
		details := map[string]any{"reason": reason}
		event := Event{Type: EventUserBlocked, Details: map[string]string{"reason": reason}}
		if !until.IsZero() {
			details["until"] = until.Format(time.RFC3339)
			event.Details["until"] = until.Format(time.RFC3339)
		}
		if u.Status == store.StatusBlocked {
			details["previous_reason"] = u.BlockedReason
			if !u.BlockedUntil.IsZero() {
				details["previous_until"] = u.BlockedUntil.UTC().Format(time.RFC3339)
			}
		}
		next := u
		next.Status, next.BlockedReason, next.BlockedUntil = store.StatusBlocked, reason, until
		return userEdit{
			next: next, update: true, revoke: true, events: []Event{event},
			entry: &audit.Entry{Action: audit.UserBlocked, Details: details},
		}, nil
	})
}

func (a *Auth) unblockUser(ctx context.Context, by actorRef, id UserID) error {
	return a.editUser(ctx, by, id, func(_ context.Context, _ store.Repositories, u store.User, _ time.Time) (userEdit, error) {
		if u.Status != store.StatusBlocked {
			return userEdit{}, nil
		}
		details := map[string]any{"previous_reason": u.BlockedReason}
		if !u.BlockedUntil.IsZero() {
			details["previous_until"] = u.BlockedUntil.UTC().Format(time.RFC3339)
		}
		next := u
		next.Status, next.BlockedReason, next.BlockedUntil = store.StatusActive, "", time.Time{}
		return userEdit{
			next: next, update: true, events: []Event{{Type: EventUserUnblocked}},
			entry: &audit.Entry{Action: audit.UserUnblocked, Details: details},
		}, nil
	})
}

func (a *Auth) endUserSession(ctx context.Context, by actorRef, id UserID, sessionID string) error {
	var err error
	if err = a.requireUser(ctx, id); err != nil {
		return err
	}
	now := a.now().UTC().Truncate(time.Microsecond)
	err = a.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if revokeErr := tx.Sessions().Revoke(ctx, a.tenant, string(id), sessionID, now); revokeErr != nil {
			if errors.Is(revokeErr, store.ErrNotFound) {
				return ErrSessionNotFound
			}
			return fmt.Errorf("limb: end the session: %w", revokeErr)
		}
		return a.auditWriter().Add(ctx, tx.Audit(), audit.Entry{
			Actor: by.actor, Action: audit.UserSessionEnded, TargetUserID: string(id), IP: by.ip, Details: map[string]any{"session": sessionID},
		})
	})
	if err == nil {
		a.emitHook(ctx, Event{
			Type: EventSessionEnded, UserID: string(id), SessionID: sessionID, IP: by.ip,
			Details: map[string]string{"reason": "administrator", "count": "1"},
		})
	}
	return err
}

func (a *Auth) endUserSessions(ctx context.Context, by actorRef, id UserID) (int, error) {
	if err := a.requireUser(ctx, id); err != nil {
		return 0, err
	}
	now := a.now().UTC().Truncate(time.Microsecond)
	var ended int
	err := a.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		var revokeErr error
		if ended, revokeErr = tx.Sessions().RevokeAllForUser(ctx, a.tenant, string(id), "", now); revokeErr != nil {
			return fmt.Errorf("limb: end the sessions: %w", revokeErr)
		}
		if ended == 0 {
			return nil
		}
		return a.auditWriter().Add(ctx, tx.Audit(), audit.Entry{
			Actor: by.actor, Action: audit.UserSessionsEnded, TargetUserID: string(id), IP: by.ip, Details: map[string]any{"count": ended},
		})
	})
	if err != nil {
		return 0, err
	}
	if ended > 0 {
		a.emitHook(ctx, Event{
			Type: EventSessionEnded, UserID: string(id), IP: by.ip,
			Details: map[string]string{"reason": "administrator", "count": strconv.Itoa(ended)},
		})
	}
	return ended, nil
}

func (a *Auth) requireUser(ctx context.Context, id UserID) error {
	_, err := a.store.Users().Get(ctx, a.tenant, string(id))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrUserNotFound
	case err != nil:
		return fmt.Errorf("limb: get the user: %w", err)
	}
	return nil
}

func (a *Auth) sendResetLink(ctx context.Context, by actorRef, id UserID, language string) error {
	if !a.recoveryReady() {
		return ErrRecoveryDisabled
	}
	return a.editUser(ctx, by, id, func(ctx context.Context, tx store.Repositories, u store.User, _ time.Time) (userEdit, error) {
		identifiers, err := tx.Identifiers().ListByUser(ctx, a.tenant, u.ID)
		if err != nil {
			return userEdit{}, fmt.Errorf("limb: list the identifiers: %w", err)
		}
		channels := a.deliveryChannels(identifiers, true)
		if len(channels) == 0 {
			return userEdit{}, ErrNoConfirmedChannel
		}
		masked := make([]any, 0, len(channels))
		for _, c := range channels {
			masked = append(masked, c.Type+":"+maskValue(c.Value))
		}
		language = a.languageFor(ctx, language)
		job := recoveryJob{purpose: store.PurposeReset, kind: MessagePasswordReset, language: language}
		if err = a.dispatcher.submit(task{kind: job.kind, run: func(ctx context.Context) error {
			return a.sendSecretsToUser(ctx, u.ID, job)
		}}); err != nil {
			return userEdit{}, err
		}
		return userEdit{
			entry:  &audit.Entry{Action: audit.UserPasswordResetSent, Details: map[string]any{"channels": masked}},
			events: []Event{{Type: EventUserChanged, Details: map[string]string{"change": "password_reset_sent"}}},
		}, nil
	})
}

func (a *Auth) temporaryPassword() string {
	length := min(max(25, a.policy.MinLength), a.policy.MaxLength)
	var text strings.Builder
	for text.Len() < length {
		text.WriteString(rand.Text())
	}
	plain := text.String()[:length]
	if length == 25 && a.policy.MaxLength >= 29 {
		return plain[0:5] + "-" + plain[5:10] + "-" + plain[10:15] + "-" + plain[15:20] + "-" + plain[20:25]
	}
	return plain
}

func (a *Auth) setTemporaryPassword(ctx context.Context, by actorRef, id UserID, language string) (string, error) {
	temporary := a.temporaryPassword()
	hash, err := a.hasher.Hash(ctx, temporary)
	if err != nil {
		return "", fmt.Errorf("limb: hash the password: %w", err)
	}
	err = a.editUser(ctx, by, id, func(ctx context.Context, tx store.Repositories, u store.User, _ time.Time) (userEdit, error) {
		identifiers, listErr := tx.Identifiers().ListByUser(ctx, a.tenant, u.ID)
		if listErr != nil {
			return userEdit{}, fmt.Errorf("limb: list the identifiers: %w", listErr)
		}
		if rules := a.policy.Check(ctx, temporary, loginsOf(identifiers)); len(rules) > 0 {
			return userEdit{}, &PolicyError{Rules: rules}
		}
		next := u
		next.PasswordHash, next.MustChangePassword = hash, true
		return userEdit{
			next: next, update: true, revoke: true,
			entry:  &audit.Entry{Action: audit.UserPasswordTemporary},
			events: []Event{{Type: EventUserChanged, Details: map[string]string{"change": "password_temporary"}}},
		}, nil
	})
	if err != nil {
		return "", err
	}
	a.notifyPasswordChanged(ctx, string(id), language)
	return temporary, nil
}

// BlockUser blocks the user with a reason, which an administrator has to give,
// until a time or, when until is the zero time, without an end. The block ends the
// sessions of the user and so their refresh tokens at once, and the user cannot
// sign in until it is lifted or has run out. A user who is blocked already gets
// the new reason and end. It returns a *ValidationError for a reason that is empty
// or too long and for a time that is not in the future, ErrUserNotFound and
// ErrUserDeleted.
func (x *AdminAPI) BlockUser(ctx context.Context, id UserID, reason string, until time.Time) error {
	return x.a.blockUser(ctx, apiActor, id, reason, until)
}

// UnblockUser lifts the block of the user. It does nothing for a user who is not
// blocked. It returns ErrUserNotFound and ErrUserDeleted.
func (x *AdminAPI) UnblockUser(ctx context.Context, id UserID) error {
	return x.a.unblockUser(ctx, apiActor, id)
}

// EndUserSession ends one session of the user, a session of a cookie or of
// tokens, with its refresh tokens. It returns ErrUserNotFound, and
// ErrSessionNotFound for a session that the user does not have or that has ended.
func (x *AdminAPI) EndUserSession(ctx context.Context, id UserID, sessionID string) error {
	return x.a.endUserSession(ctx, apiActor, id, sessionID)
}

// EndUserSessions ends every session of the user and returns how many it ended.
// It returns ErrUserNotFound.
func (x *AdminAPI) EndUserSessions(ctx context.Context, id UserID) (int, error) {
	return x.a.endUserSessions(ctx, apiActor, id)
}

// SendPasswordReset sends the user a link and a code that let them choose a new
// password, on every address and phone number of theirs that is confirmed, as
// RequestPasswordReset does, but for the user the administrator names. The
// message goes out in the background, in the language, "ru" or "en", or in the
// language of ContextWithLanguage when it is empty. It returns
// ErrRecoveryDisabled when the service has no Sender or no channel to send to,
// ErrNoConfirmedChannel when the user has no channel that is confirmed, and
// ErrUserNotFound and ErrUserDeleted.
func (x *AdminAPI) SendPasswordReset(ctx context.Context, id UserID, language string) error {
	return x.a.sendResetLink(ctx, apiActor, id, language)
}

// SetTemporaryPassword gives the user a password that was made at random and
// returns it. It is shown only here and never stored or logged. The user has to
// choose another one when they sign in, and all their sessions end. The user gets
// a notice that the password was changed, on every confirmed channel, in the
// background, in the language or in the one of ContextWithLanguage when it is
// empty. It returns ErrUserNotFound and ErrUserDeleted.
func (x *AdminAPI) SetTemporaryPassword(ctx context.Context, id UserID, language string) (string, error) {
	return x.a.setTemporaryPassword(ctx, apiActor, id, language)
}
