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

type adminSessions struct {
	s *Store
	x executor
}

func (r adminSessions) Create(ctx context.Context, s store.AdminSession) error {
	if err := storecheck.NewAdminSession(s); err != nil {
		return err
	}
	_, err := r.x.ExecContext(ctx, r.s.q.insertAdminSession,
		s.TenantID, s.ID, s.AdminID, string(s.Stage), s.SecretHash, s.AdminVersion, optionalText(s.IP), optionalText(s.UserAgent),
		storedTime(s.CreatedAt), storedTime(s.LastSeenAt), storedTime(s.ExpiresAt))
	switch {
	case err == nil:
		return nil
	case r.s.dialect.IsUniqueViolation(err):
		return store.ErrConflict
	case r.s.dialect.IsForeignKeyViolation(err):
		return store.ErrNotFound
	}
	return fmt.Errorf("sqlstore: create admin session: %w", err)
}

func (r adminSessions) ResolveBySecret(ctx context.Context, tenantID string, secretHash []byte) (store.ResolvedAdminSession, error) {
	if !storecheck.ValidText(tenantID) || !storecheck.ValidHash(secretHash) {
		return store.ResolvedAdminSession{}, store.ErrNotFound
	}
	var (
		w             adminSessionRow
		login, status string
		version       int64
		confirmed     sql.NullTime
	)
	err := r.x.QueryRowContext(ctx, r.s.q.resolveAdminSession, tenantID, secretHash).Scan(append(w.dest(), &login, &status, &version, &confirmed)...)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return store.ResolvedAdminSession{}, store.ErrNotFound
	case err != nil:
		return store.ResolvedAdminSession{}, fmt.Errorf("sqlstore: resolve admin session: %w", err)
	}
	return store.ResolvedAdminSession{
		Session: w.session(),
		Admin:   store.AdminState{Login: login, Status: store.AdminStatus(status), Version: version, TOTPConfirmed: confirmed.Valid},
	}, nil
}

func (r adminSessions) Touch(ctx context.Context, tenantID, id string, at time.Time) error {
	if err := storecheck.Time("touch time", at); err != nil {
		return err
	}
	if !storecheck.ValidText(tenantID, id) {
		return nil
	}
	moment := storedTime(at)
	if _, err := r.x.ExecContext(ctx, r.s.q.touchAdminSession, moment, tenantID, id, moment); err != nil {
		return fmt.Errorf("sqlstore: touch admin session: %w", err)
	}
	return nil
}

func (r adminSessions) TryAttempt(ctx context.Context, tenantID, id string, limit int) (bool, error) {
	if err := storecheck.Attempts(limit); err != nil {
		return false, err
	}
	if !storecheck.ValidText(tenantID, id) {
		return false, nil
	}
	result, err := r.x.ExecContext(ctx, r.s.q.tryAdminAttempt, tenantID, id, limit)
	if err != nil {
		return false, fmt.Errorf("sqlstore: count an attempt: %w", err)
	}
	counted, err := affected(result, "count an attempt")
	return counted > 0, err
}

func (r adminSessions) Rebind(ctx context.Context, tenantID, adminID, id string, version int64) error {
	if !storecheck.ValidText(tenantID, adminID, id) {
		return store.ErrNotFound
	}
	result, err := r.x.ExecContext(ctx, r.s.q.rebindAdminSession, version, tenantID, id, adminID)
	if err != nil {
		return fmt.Errorf("sqlstore: rebind admin session: %w", err)
	}
	return requireRow(result, "rebind admin session")
}

func (r adminSessions) Delete(ctx context.Context, tenantID, adminID, id string) error {
	if !storecheck.ValidText(tenantID, adminID, id) {
		return store.ErrNotFound
	}
	result, err := r.x.ExecContext(ctx, r.s.q.deleteAdminSession, tenantID, adminID, id)
	if err != nil {
		return fmt.Errorf("sqlstore: delete admin session: %w", err)
	}
	return requireRow(result, "delete admin session")
}

func (r adminSessions) DeleteForAdmin(ctx context.Context, tenantID, adminID, exceptID string) (int, error) {
	if !storecheck.ValidText(tenantID, adminID, exceptID) {
		return 0, nil
	}
	query, args := r.s.q.deleteAdminSessions, []any{tenantID, adminID}
	if exceptID != "" {
		query, args = r.s.q.deleteAdminSessionsExcept, append(args, exceptID)
	}
	result, err := r.x.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("sqlstore: delete admin sessions: %w", err)
	}
	return affected(result, "delete admin sessions")
}

func (r adminSessions) ListByAdmin(ctx context.Context, tenantID, adminID string, now time.Time) ([]store.AdminSession, error) {
	if !storecheck.ValidText(tenantID, adminID) {
		return nil, nil
	}
	rows, err := r.x.QueryContext(ctx, r.s.q.listAdminSessions, tenantID, adminID, storedTime(now))
	if err != nil {
		return nil, fmt.Errorf("sqlstore: list admin sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var list []store.AdminSession
	for rows.Next() {
		var w adminSessionRow
		if err = rows.Scan(w.dest()...); err != nil {
			return nil, fmt.Errorf("sqlstore: list admin sessions: %w", err)
		}
		list = append(list, w.session())
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore: list admin sessions: %w", err)
	}
	slices.SortFunc(list, storecheck.CompareAdminSessions)
	return list, nil
}

func (r adminSessions) DeleteStale(ctx context.Context, tenantID string, expiredBefore, idleBefore time.Time) (int, error) {
	if !storecheck.ValidText(tenantID) {
		return 0, nil
	}
	result, err := r.x.ExecContext(ctx, r.s.q.deleteStaleAdminSessions, tenantID, storedTime(expiredBefore), storedTime(idleBefore))
	if err != nil {
		return 0, fmt.Errorf("sqlstore: delete admin sessions: %w", err)
	}
	return affected(result, "delete admin sessions")
}

type adminSessionRow struct {
	rec                    store.AdminSession
	stage                  string
	ip, agent              sql.NullString
	created, seen, expires time.Time
}

func (w *adminSessionRow) dest() []any {
	s := &w.rec
	return []any{&s.TenantID, &s.ID, &s.AdminID, &w.stage, &s.SecretHash, &s.AdminVersion, &s.Attempts, &w.ip, &w.agent, &w.created, &w.seen, &w.expires}
}

func (w *adminSessionRow) session() store.AdminSession {
	s := w.rec
	s.Stage = store.AdminSessionStage(w.stage)
	s.IP = w.ip.String
	s.UserAgent = w.agent.String
	s.CreatedAt = w.created.UTC()
	s.LastSeenAt = w.seen.UTC()
	s.ExpiresAt = w.expires.UTC()
	return s
}
