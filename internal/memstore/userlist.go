package memstore

import (
	"context"
	"slices"
	"strings"

	"github.com/acneism/limb/internal/storecheck"
	"github.com/acneism/limb/store"
)

func (r users) List(ctx context.Context, q store.UserQuery) ([]store.User, error) {
	if err := storecheck.UserQuery(q); err != nil {
		return nil, err
	}
	if !storecheck.ValidUserQuery(q) {
		return nil, nil
	}
	d, leave, err := r.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer leave()
	identifiers := map[userKey][]store.Identifier{}
	for _, i := range d.idents {
		key := userKey{i.TenantID, i.UserID}
		identifiers[key] = append(identifiers[key], i)
	}
	refs := storecheck.IdentifierRefs(q.Identifiers)
	var list []store.User
	for _, u := range d.users {
		if u.TenantID == q.TenantID && matchesUser(u, identifiers[userKey{u.TenantID, u.ID}], q, refs) {
			list = append(list, u)
		}
	}
	before := userOrder(q.Order, q.Descending)
	slices.SortFunc(list, before)
	if q.After != nil {
		cursor := normalizeUser(*q.After)
		start := slices.IndexFunc(list, func(u store.User) bool { return before(u, cursor) > 0 })
		if start < 0 {
			return nil, nil
		}
		list = list[start:]
	}
	if len(list) > q.Limit {
		list = list[:q.Limit]
	}
	return list, nil
}

func matchesUser(u store.User, identifiers []store.Identifier, q store.UserQuery, refs []store.IdentifierRef) bool {
	switch {
	case len(q.Statuses) > 0 && !slices.Contains(q.Statuses, u.Status),
		q.CreatedVia != "" && u.CreatedVia != q.CreatedVia,
		!q.CreatedFrom.IsZero() && u.CreatedAt.Before(normalizeTime(q.CreatedFrom)),
		!q.CreatedBefore.IsZero() && !u.CreatedAt.Before(normalizeTime(q.CreatedBefore)),
		!q.LastLoginFrom.IsZero() && (u.LastLoginAt.IsZero() || u.LastLoginAt.Before(normalizeTime(q.LastLoginFrom))),
		!q.LastLoginBefore.IsZero() && (u.LastLoginAt.IsZero() || !u.LastLoginAt.Before(normalizeTime(q.LastLoginBefore))),
		q.NeverLoggedIn && !u.LastLoginAt.IsZero(),
		!q.PurgeBefore.IsZero() && (u.PurgeAfter.IsZero() || !u.PurgeAfter.Before(normalizeTime(q.PurgeBefore))),
		!q.BlockedBefore.IsZero() && (u.BlockedUntil.IsZero() || !u.BlockedUntil.Before(normalizeTime(q.BlockedBefore))):
		return false
	case q.Confirmed != nil && slices.ContainsFunc(identifiers, func(i store.Identifier) bool { return !i.VerifiedAt.IsZero() }) != *q.Confirmed:
		return false
	case len(q.Identifiers) > 0 && !slices.ContainsFunc(identifiers, func(i store.Identifier) bool {
		return slices.Contains(refs, store.IdentifierRef{Type: i.Type, Value: i.Value})
	}):
		return false
	case q.ValuePrefix != "" && !slices.ContainsFunc(identifiers, func(i store.Identifier) bool { return strings.HasPrefix(i.Value, q.ValuePrefix) }):
		return false
	}
	return true
}

func userOrder(order store.UserOrder, descending bool) func(a, b store.User) int {
	return func(a, b store.User) int {
		c := 0
		switch order {
		case store.OrderUsersByLastLogin:
			aNever, bNever := a.LastLoginAt.IsZero(), b.LastLoginAt.IsZero()
			switch {
			case aNever && !bNever:
				return 1
			case !aNever && bNever:
				return -1
			case !aNever:
				c = a.LastLoginAt.Compare(b.LastLoginAt)
			}
		case store.OrderUsersByStatus:
			c = strings.Compare(string(a.Status), string(b.Status))
		case store.OrderUsersByCreation, "":
			c = a.CreatedAt.Compare(b.CreatedAt)
		}
		if c == 0 {
			c = strings.Compare(a.ID, b.ID)
		}
		if descending {
			return -c
		}
		return c
	}
}
