package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/acneism/limb/internal/storecheck"
	"github.com/acneism/limb/store"
)

type sessions struct {
	s *Store
	x executor
}

func (r sessions) Create(ctx context.Context, s store.Session) error {
	if err := storecheck.NewSession(s); err != nil {
		return err
	}
	_, err := r.x.ExecContext(ctx, r.s.q.insertSession,
		s.TenantID, s.ID, string(s.Kind), optionalBytes(s.SecretHash), s.UserID, optionalText(s.IP),
		optionalText(s.UserAgent), storedTime(s.CreatedAt), storedTime(s.LastSeenAt), storedTime(s.ExpiresAt))
	switch {
	case err == nil:
		return nil
	case r.s.dialect.IsUniqueViolation(err):
		return store.ErrConflict
	case r.s.dialect.IsForeignKeyViolation(err):
		return store.ErrNotFound
	}
	return fmt.Errorf("sqlstore: create session: %w", err)
}

func (r sessions) ResolveByID(ctx context.Context, tenantID, id string) (store.ResolvedSession, error) {
	if !storecheck.ValidText(tenantID, id) {
		return store.ResolvedSession{}, store.ErrNotFound
	}
	return r.resolve(ctx, r.s.q.resolveByID, tenantID, id)
}

func (r sessions) ResolveBySecret(ctx context.Context, tenantID string, secretHash []byte) (store.ResolvedSession, error) {
	if !storecheck.ValidText(tenantID) || !storecheck.ValidHash(secretHash) {
		return store.ResolvedSession{}, store.ErrNotFound
	}
	return r.resolve(ctx, r.s.q.resolveBySecret, tenantID, secretHash)
}

func (r sessions) resolve(ctx context.Context, query string, args ...any) (store.ResolvedSession, error) {
	resolved, err := scanResolved(r.x.QueryRowContext(ctx, query, args...))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return store.ResolvedSession{}, store.ErrNotFound
	case err != nil:
		return store.ResolvedSession{}, fmt.Errorf("sqlstore: resolve session: %w", err)
	}
	return resolved, nil
}

func (r sessions) Touch(ctx context.Context, tenantID, id string, at time.Time) error {
	if err := storecheck.Time("touch time", at); err != nil {
		return err
	}
	if !storecheck.ValidText(tenantID, id) {
		return nil
	}
	moment := storedTime(at)
	if _, err := r.x.ExecContext(ctx, r.s.q.touchSession, moment, tenantID, id, moment); err != nil {
		return fmt.Errorf("sqlstore: touch session: %w", err)
	}
	return nil
}

func (r sessions) Revoke(ctx context.Context, tenantID, userID, id string, at time.Time) error {
	if err := storecheck.Time("revocation time", at); err != nil {
		return err
	}
	if !storecheck.ValidText(tenantID, userID, id) {
		return store.ErrNotFound
	}
	result, err := r.x.ExecContext(ctx, r.s.q.revokeSession, storedTime(at), tenantID, userID, id)
	if err != nil {
		return fmt.Errorf("sqlstore: revoke session: %w", err)
	}
	return requireRow(result, "revoke session")
}

func (r sessions) RevokeAllForUser(ctx context.Context, tenantID, userID, exceptID string, at time.Time) (int, error) {
	if err := storecheck.Time("revocation time", at); err != nil {
		return 0, err
	}
	if !storecheck.ValidText(tenantID, userID, exceptID) {
		return 0, nil
	}
	query, args := r.s.q.revokeAll, []any{storedTime(at), tenantID, userID}
	if exceptID != "" {
		query, args = r.s.q.revokeAllExcept, append(args, exceptID)
	}
	result, err := r.x.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("sqlstore: revoke sessions: %w", err)
	}
	return affected(result, "revoke sessions")
}

func (r sessions) ListByUser(ctx context.Context, tenantID, userID string, now time.Time) ([]store.Session, error) {
	if !storecheck.ValidText(tenantID, userID) {
		return nil, nil
	}
	rows, err := r.x.QueryContext(ctx, r.s.q.listSessions, tenantID, userID, storedTime(now))
	if err != nil {
		return nil, fmt.Errorf("sqlstore: list sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var list []store.Session
	for rows.Next() {
		var row sessionRow
		if err = rows.Scan(row.dest()...); err != nil {
			return nil, fmt.Errorf("sqlstore: list sessions: %w", err)
		}
		list = append(list, row.session())
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore: list sessions: %w", err)
	}
	slices.SortFunc(list, storecheck.CompareSessions)
	return list, nil
}

func (r sessions) DeleteInactive(ctx context.Context, tenantID string, expiredBefore, idleBefore, revokedBefore time.Time) (int, error) {
	if !storecheck.ValidText(tenantID) {
		return 0, nil
	}
	result, err := r.x.ExecContext(ctx, r.s.q.deleteSessions,
		tenantID, storedTime(expiredBefore), storedTime(idleBefore), storedTime(revokedBefore))
	if err != nil {
		return 0, fmt.Errorf("sqlstore: delete sessions: %w", err)
	}
	return affected(result, "delete sessions")
}

func affected(result sql.Result, action string) (int, error) {
	changed, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sqlstore: %s: %w", action, err)
	}
	return int(changed), nil
}

type sessionRow struct {
	rec                    store.Session
	kind                   string
	hash                   []byte
	ip, agent              sql.NullString
	created, seen, expires time.Time
	revoked                sql.NullTime
}

func (w *sessionRow) dest() []any {
	s := &w.rec
	return []any{&s.TenantID, &s.ID, &w.kind, &w.hash, &s.UserID, &w.ip, &w.agent, &w.created, &w.seen, &w.expires, &w.revoked}
}

func (w *sessionRow) session() store.Session {
	s := w.rec
	s.Kind = store.SessionKind(w.kind)
	if len(w.hash) > 0 {
		s.SecretHash = w.hash
	}
	s.IP = w.ip.String
	s.UserAgent = w.agent.String
	s.CreatedAt = w.created.UTC()
	s.LastSeenAt = w.seen.UTC()
	s.ExpiresAt = w.expires.UTC()
	s.RevokedAt = utcOrZero(w.revoked)
	return s
}

func scanResolved(row scanner) (store.ResolvedSession, error) {
	var (
		w            sessionRow
		status       string
		blockedUntil sql.NullTime
		mustChange   bool
	)
	if err := row.Scan(append(w.dest(), &status, &blockedUntil, &mustChange)...); err != nil {
		return store.ResolvedSession{}, err
	}
	return store.ResolvedSession{
		Session: w.session(),
		User:    store.UserState{Status: store.Status(status), BlockedUntil: utcOrZero(blockedUntil), MustChangePassword: mustChange},
	}, nil
}
