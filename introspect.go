package limb

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/acneism/limb/internal/secret"
)

type introspection struct {
	Active    bool
	Subject   string
	SessionID string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

func (a *Auth) serviceName(key string) (string, bool) {
	sum := sha256.Sum256([]byte(key))
	name, found := "", false
	for _, s := range a.services {
		same := secret.Equal(sum[:], s.hash[:])
		if same {
			name = s.name
		}
		found = found || same
	}
	return name, found
}

func (a *Auth) introspect(ctx context.Context, serviceKey, token string) (introspection, error) {
	service, known := a.serviceName(serviceKey)
	if !known {
		return introspection{}, ErrUnauthenticated
	}
	claims, err := a.verifyAccessToken(ctx, token)
	switch {
	case errors.Is(err, ErrUnauthenticated):
		return introspection{}, nil
	case err != nil:
		return introspection{}, err
	}
	principal, err := a.checkTokenSession(ctx, claims)
	switch {
	case errors.Is(err, ErrUnauthenticated):
		return introspection{}, nil
	case err != nil:
		return introspection{}, err
	}
	if principal.MustChangePassword || claims.ChangePassword {
		return introspection{}, nil
	}
	a.logger.DebugContext(ctx, "limb: a token was introspected", "service", service, "session_id", claims.SessionID)
	return introspection{
		Active:    true,
		Subject:   claims.Subject,
		SessionID: claims.SessionID,
		IssuedAt:  claims.IssuedAt.Time,
		ExpiresAt: claims.ExpiresAt.Time,
	}, nil
}
