package storecheck

import (
	"slices"
	"strings"

	"github.com/acneism/limb/store"
)

func NewAuditRecord(r store.AuditRecord) error {
	if err := required("audit tenant_id", r.TenantID, store.MaxTenantIDLength); err != nil {
		return err
	}
	if err := required("audit id", r.ID, store.MaxIDLength); err != nil {
		return err
	}
	if err := ActorKind(r.ActorKind); err != nil {
		return err
	}
	if err := required("audit action", r.Action, store.MaxAuditActionLength); err != nil {
		return err
	}
	for _, f := range []struct {
		name, value string
		limit       int
	}{
		{"audit actor_id", r.ActorID, store.MaxIDLength},
		{"audit target_user_id", r.TargetUserID, store.MaxIDLength},
		{"audit ip", r.IP, store.MaxIPLength},
		{"audit details", r.Details, store.MaxAuditDetailsLength},
	} {
		if err := optional(f.name, f.value, f.limit); err != nil {
			return err
		}
	}
	if r.At.IsZero() {
		return invalid("audit at is required")
	}
	return nil
}

func ActorKind(kind store.ActorKind) error {
	switch kind {
	case store.ActorAdmin, store.ActorUser, store.ActorSystem:
		return nil
	}
	return invalid("audit actor kind %q is unknown", string(kind))
}

func AuditQuery(q store.AuditQuery) error {
	if q.Limit < 1 || q.Limit > store.MaxAuditPage {
		return invalid("a page of the audit log has from 1 to %d records, not %d", store.MaxAuditPage, q.Limit)
	}
	if len(q.Actions) > store.MaxAuditActions {
		return invalid("a query of the audit log asks for at most %d actions", store.MaxAuditActions)
	}
	if q.After != nil && q.After.At.IsZero() {
		return invalid("the record that a listing of the audit log continues after has no time")
	}
	if q.ActorKind != "" {
		return ActorKind(q.ActorKind)
	}
	return nil
}

func ValidAuditQuery(q store.AuditQuery) bool {
	if !ValidText(q.TenantID, q.TargetUserID, q.ActorID) || slices.ContainsFunc(q.Actions, func(a string) bool { return !ValidText(a) }) {
		return false
	}
	return q.After == nil || ValidText(q.After.ID)
}

func CompareAudit(a, b store.AuditRecord) int {
	switch {
	case a.At.After(b.At):
		return -1
	case a.At.Before(b.At):
		return 1
	}
	return strings.Compare(b.ID, a.ID)
}

func AuditBatch(limit int) error {
	if limit < 1 || limit > store.MaxAuditPage {
		return invalid("a batch of audit records has from 1 to %d records, not %d", store.MaxAuditPage, limit)
	}
	return nil
}
