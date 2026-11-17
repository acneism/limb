package memstore

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/acneism/limb/internal/storecheck"
	"github.com/acneism/limb/store"
)

type auditKey struct{ tenant, id string }

type audit struct {
	d  func() *data
	mu *sync.Mutex
}

func (r audit) enter(ctx context.Context) (*data, func(), error) {
	return enter(ctx, r.d, r.mu)
}

func (r audit) Add(ctx context.Context, rec store.AuditRecord) error {
	if err := storecheck.NewAuditRecord(rec); err != nil {
		return err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	key := auditKey{rec.TenantID, rec.ID}
	if _, taken := d.audit[key]; taken {
		return store.ErrConflict
	}
	rec.At = normalizeTime(rec.At)
	d.audit[key] = rec
	return nil
}

func (r audit) List(ctx context.Context, q store.AuditQuery) ([]store.AuditRecord, error) {
	if err := storecheck.AuditQuery(q); err != nil {
		return nil, err
	}
	if !storecheck.ValidAuditQuery(q) {
		return nil, nil
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer leave()
	var list []store.AuditRecord
	for _, rec := range d.audit {
		if matchesAudit(rec, q) {
			list = append(list, rec)
		}
	}
	slices.SortFunc(list, storecheck.CompareAudit)
	if len(list) > q.Limit {
		list = list[:q.Limit]
	}
	return list, nil
}

func matchesAudit(rec store.AuditRecord, q store.AuditQuery) bool {
	switch {
	case rec.TenantID != q.TenantID,
		q.TargetUserID != "" && rec.TargetUserID != q.TargetUserID,
		q.ActorKind != "" && rec.ActorKind != q.ActorKind,
		q.ActorID != "" && rec.ActorID != q.ActorID,
		len(q.Actions) > 0 && !slices.Contains(q.Actions, rec.Action),
		!q.From.IsZero() && rec.At.Before(normalizeTime(q.From)),
		!q.To.IsZero() && !rec.At.Before(normalizeTime(q.To)):
		return false
	}
	if q.After == nil {
		return true
	}
	after := normalizeTime(q.After.At)
	return rec.At.Before(after) || (rec.At.Equal(after) && strings.Compare(rec.ID, q.After.ID) < 0)
}

func (r audit) DeleteBefore(ctx context.Context, tenantID string, before time.Time, limit int) (int, error) {
	if err := storecheck.AuditBatch(limit); err != nil {
		return 0, err
	}
	if err := storecheck.Time("cutoff time", before); err != nil {
		return 0, err
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return 0, err
	}
	defer leave()
	cutoff := normalizeTime(before)
	var old []store.AuditRecord
	for _, rec := range d.audit {
		if rec.TenantID == tenantID && rec.At.Before(cutoff) {
			old = append(old, rec)
		}
	}
	slices.SortFunc(old, func(a, b store.AuditRecord) int { return storecheck.CompareAudit(b, a) })
	if len(old) > limit {
		old = old[:limit]
	}
	for _, rec := range old {
		delete(d.audit, auditKey{rec.TenantID, rec.ID})
	}
	return len(old), nil
}
