package limb

import (
	"context"
	"errors"
	"fmt"

	"github.com/acneism/limb/store"
)

// Sessions lists the sessions of the user that are still in use: not ended, not
// expired and not idle for longer than the idle lifetime. The oldest comes
// first, and the one that made the request is marked as current.
func (a *Auth) Sessions(ctx context.Context, p Principal) ([]Session, error) {
	now := a.now()
	listed, err := a.store.Sessions().ListByUser(ctx, a.tenant, string(p.UserID), now)
	if err != nil {
		return nil, fmt.Errorf("limb: list the sessions: %w", err)
	}
	sessions := make([]Session, 0, len(listed))
	for _, s := range listed {
		if !a.sessionActive(s, now) {
			continue
		}
		sessions = append(sessions, Session{
			ID:         s.ID,
			Kind:       s.Kind,
			IP:         s.IP,
			UserAgent:  s.UserAgent,
			CreatedAt:  s.CreatedAt,
			LastSeenAt: s.LastSeenAt,
			ExpiresAt:  s.ExpiresAt,
			Current:    s.ID == p.SessionID,
		})
	}
	return sessions, nil
}

// Logout ends the session of the principal. Ending a session that has ended
// already is not an error.
func (a *Auth) Logout(ctx context.Context, p Principal) error {
	err := a.store.Sessions().Revoke(ctx, a.tenant, string(p.UserID), p.SessionID, a.now())
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("limb: end the session: %w", err)
	}
	return nil
}
