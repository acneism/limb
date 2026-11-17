package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/acneism/limb/internal/storecheck"
	"github.com/acneism/limb/store"
)

type audit struct {
	s *Store
	x executor
}

func (r audit) Add(ctx context.Context, rec store.AuditRecord) error {
	if err := storecheck.NewAuditRecord(rec); err != nil {
		return err
	}
	_, err := r.x.ExecContext(ctx, r.s.q.insertAudit,
		rec.TenantID, rec.ID, storedTime(rec.At), string(rec.ActorKind), optionalText(rec.ActorID), rec.Action,
		optionalText(rec.TargetUserID), optionalText(rec.IP), optionalText(rec.Details))
	switch {
	case err == nil:
		return nil
	case r.s.dialect.IsUniqueViolation(err):
		return store.ErrConflict
	}
	return fmt.Errorf("sqlstore: add audit record: %w", err)
}

func (r audit) List(ctx context.Context, q store.AuditQuery) ([]store.AuditRecord, error) {
	if err := storecheck.AuditQuery(q); err != nil {
		return nil, err
	}
	if !storecheck.ValidAuditQuery(q) {
		return nil, nil
	}
	var c conditions
	c.add("tenant_id = ?", q.TenantID)
	if q.TargetUserID != "" {
		c.add("target_user_id = ?", q.TargetUserID)
	}
	if q.ActorKind != "" {
		c.add("actor_kind = ?", string(q.ActorKind))
	}
	if q.ActorID != "" {
		c.add("actor_id = ?", q.ActorID)
	}
	if len(q.Actions) > 0 {
		c.add("action IN ("+marks(len(q.Actions))+")", values(q.Actions)...)
	}
	if !q.From.IsZero() {
		c.add("occurred_at >= ?", storedTime(q.From))
	}
	if !q.To.IsZero() {
		c.add("occurred_at < ?", storedTime(q.To))
	}
	if q.After != nil {
		at := storedTime(q.After.At)
		c.add("(occurred_at < ? OR (occurred_at = ? AND id < ?))", at, at, q.After.ID)
	}
	query := r.s.q.bind("SELECT " + auditColumns + " FROM {audit_log} WHERE " + c.where() +
		" ORDER BY occurred_at DESC, id DESC" + r.s.dialect.Limit(q.Limit))
	rows, err := r.x.QueryContext(ctx, query, c.args...)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: list audit records: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var list []store.AuditRecord
	for rows.Next() {
		rec, scanErr := scanAudit(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("sqlstore: list audit records: %w", scanErr)
		}
		list = append(list, rec)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore: list audit records: %w", err)
	}
	return list, nil
}

func (r audit) DeleteBefore(ctx context.Context, tenantID string, before time.Time, limit int) (int, error) {
	if err := storecheck.AuditBatch(limit); err != nil {
		return 0, err
	}
	if err := storecheck.Time("cutoff time", before); err != nil {
		return 0, err
	}
	if !storecheck.ValidText(tenantID) {
		return 0, nil
	}
	ids, err := r.oldest(ctx, tenantID, storedTime(before), limit)
	if err != nil || len(ids) == 0 {
		return 0, err
	}
	query := r.s.q.bind("DELETE FROM {audit_log} WHERE tenant_id = ? AND id IN (" + marks(len(ids)) + ")")
	result, err := r.x.ExecContext(ctx, query, append([]any{tenantID}, values(ids)...)...)
	if err != nil {
		return 0, fmt.Errorf("sqlstore: delete audit records: %w", err)
	}
	return affected(result, "delete audit records")
}

func (r audit) oldest(ctx context.Context, tenantID string, before time.Time, limit int) ([]string, error) {
	query := r.s.q.bind("SELECT id FROM {audit_log} WHERE tenant_id = ? AND occurred_at < ? ORDER BY occurred_at, id" + r.s.dialect.Limit(limit))
	rows, err := r.x.QueryContext(ctx, query, tenantID, before)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: delete audit records: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("sqlstore: delete audit records: %w", err)
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore: delete audit records: %w", err)
	}
	return ids, nil
}

func scanAudit(row scanner) (store.AuditRecord, error) {
	var (
		rec                         store.AuditRecord
		at                          time.Time
		kind                        string
		actorID, target, ip, detail sql.NullString
	)
	if err := row.Scan(&rec.TenantID, &rec.ID, &at, &kind, &actorID, &rec.Action, &target, &ip, &detail); err != nil {
		return store.AuditRecord{}, err
	}
	rec.At = at.UTC()
	rec.ActorKind = store.ActorKind(kind)
	rec.ActorID = actorID.String
	rec.TargetUserID = target.String
	rec.IP = ip.String
	rec.Details = detail.String
	return rec, nil
}
