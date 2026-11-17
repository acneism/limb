package limb

import (
	"context"
	"errors"
	"fmt"

	"github.com/acneism/limb/store"
)

func (a *Auth) notifyPasswordChanged(ctx context.Context, userID, language string) {
	if !a.recoveryReady() {
		return
	}
	language = a.languageFor(ctx, language)
	err := a.dispatcher.submit(task{kind: MessagePasswordChanged, run: func(ctx context.Context) error {
		return a.sendNoticeToUser(ctx, userID, MessagePasswordChanged, language)
	}})
	if err != nil {
		a.logger.WarnContext(ctx, "limb: the notice that a password was changed is not sent", "error", err)
	}
}

func (a *Auth) sendNoticeToUser(ctx context.Context, userID string, kind MessageKind, language string) error {
	user, err := a.store.Users().Get(ctx, a.tenant, userID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("limb: get the user: %w", err)
	case user.Status == store.StatusDeleted:
		return nil
	}
	identifiers, err := a.store.Identifiers().ListByUser(ctx, a.tenant, user.ID)
	if err != nil {
		return fmt.Errorf("limb: list the identifiers: %w", err)
	}
	for _, channel := range a.deliveryChannels(identifiers, true) {
		if err = a.sendNoticeTo(ctx, user.ID, channel, kind, language); err != nil {
			a.failMessage(ctx, err)
		}
	}
	return nil
}

func (a *Auth) sendNoticeTo(ctx context.Context, userID string, channel store.Identifier, kind MessageKind, language string) error {
	if !a.allowMessage(ctx, kind, userID) {
		return nil
	}
	m := Message{Kind: kind, UserID: userID, Channel: channel.Type, To: channel.Value, Language: normalizeLanguage(language)}
	return a.sendMessage(ctx, m, MessageData{})
}
