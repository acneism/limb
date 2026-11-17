package sqlstore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/acneism/limb/internal/storecheck"
	"github.com/acneism/limb/store"
)

const (
	likeEscape       = "!"
	identifierOfUser = "FROM {identifiers} i WHERE i.tenant_id = u.tenant_id AND i.user_id = u.id"
)

var likeEscaper = strings.NewReplacer("!", "!!", "%", "!%", "_", "!_")

func (r users) List(ctx context.Context, q store.UserQuery) ([]store.User, error) {
	if err := storecheck.UserQuery(q); err != nil {
		return nil, err
	}
	if !storecheck.ValidUserQuery(q) {
		return nil, nil
	}
	var c conditions
	c.add("u.tenant_id = ?", q.TenantID)
	if len(q.Statuses) > 0 {
		statuses := make([]any, len(q.Statuses))
		for i, status := range q.Statuses {
			statuses[i] = string(status)
		}
		c.add("u.status IN ("+marks(len(statuses))+")", statuses...)
	}
	if q.CreatedVia != "" {
		c.add("u.created_via = ?", string(q.CreatedVia))
	}
	addTimeBounds(&c, "u.created_at", q.CreatedFrom, q.CreatedBefore)
	addTimeBounds(&c, "u.last_login_at", q.LastLoginFrom, q.LastLoginBefore)
	if q.NeverLoggedIn {
		c.add("u.last_login_at IS NULL")
	}
	if !q.PurgeBefore.IsZero() {
		c.add("u.purge_after < ?", storedTime(q.PurgeBefore))
	}
	if q.Confirmed != nil {
		exists := "EXISTS (SELECT 1 " + identifierOfUser + " AND i.verified_at IS NOT NULL)"
		if !*q.Confirmed {
			exists = "NOT " + exists
		}
		c.add(exists)
	}
	if refs := storecheck.IdentifierRefs(q.Identifiers); len(refs) > 0 {
		var alternatives []string
		var args []any
		for _, ref := range refs {
			alternatives = append(alternatives, "(i.type = ? AND i.value = ?)")
			args = append(args, ref.Type, ref.Value)
		}
		c.add("EXISTS (SELECT 1 "+identifierOfUser+" AND ("+strings.Join(alternatives, " OR ")+"))", args...)
	}
	if q.ValuePrefix != "" {
		c.add("EXISTS (SELECT 1 "+identifierOfUser+" AND i.value LIKE ? ESCAPE '"+likeEscape+"')", likeEscaper.Replace(q.ValuePrefix)+"%")
	}
	order := userOrdering(q)
	if order.after != "" {
		c.add(order.after, order.args...)
	}
	query := r.s.q.bind("SELECT " + qualified("u.", userColumns) + " FROM {users} u WHERE " + c.where() +
		" ORDER BY " + order.by + r.s.dialect.Limit(q.Limit))
	rows, err := r.x.QueryContext(ctx, query, c.args...)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: list users: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var list []store.User
	for rows.Next() {
		u, scanErr := scanUser(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("sqlstore: list users: %w", scanErr)
		}
		list = append(list, u)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore: list users: %w", err)
	}
	return list, nil
}

func addTimeBounds(c *conditions, column string, from, before time.Time) {
	if !from.IsZero() {
		c.add(column+" >= ?", storedTime(from))
	}
	if !before.IsZero() {
		c.add(column+" < ?", storedTime(before))
	}
}

func qualified(prefix, columns string) string {
	return prefix + strings.ReplaceAll(columns, ", ", ", "+prefix)
}

type ordering struct {
	by    string
	after string
	args  []any
}

func userOrdering(q store.UserQuery) ordering {
	direction, beyond := "ASC", ">"
	if q.Descending {
		direction, beyond = "DESC", "<"
	}
	switch q.Order {
	case store.OrderUsersByLastLogin:
		return lastLoginOrdering(q.After, direction, beyond)
	case store.OrderUsersByStatus:
		return statusOrdering(q.After, direction, beyond)
	case store.OrderUsersByCreation:
		return creationOrdering(q.After, direction, beyond)
	}
	return creationOrdering(q.After, direction, beyond)
}

func statusOrdering(after *store.User, direction, beyond string) ordering {
	o := ordering{by: "u.status " + direction + ", u.id " + direction}
	if after != nil {
		status := string(after.Status)
		o.after = "(u.status " + beyond + " ? OR (u.status = ? AND u.id " + beyond + " ?))"
		o.args = []any{status, status, after.ID}
	}
	return o
}

func creationOrdering(after *store.User, direction, beyond string) ordering {
	o := ordering{by: "u.created_at " + direction + ", u.id " + direction}
	if after != nil {
		at := storedTime(after.CreatedAt)
		o.after = "(u.created_at " + beyond + " ? OR (u.created_at = ? AND u.id " + beyond + " ?))"
		o.args = []any{at, at, after.ID}
	}
	return o
}

func lastLoginOrdering(after *store.User, direction, beyond string) ordering {
	o := ordering{by: "CASE WHEN u.last_login_at IS NULL THEN 1 ELSE 0 END, u.last_login_at " + direction + ", u.id " + direction}
	switch {
	case after == nil:
	case after.LastLoginAt.IsZero():
		o.after = "(u.last_login_at IS NULL AND u.id " + beyond + " ?)"
		o.args = []any{after.ID}
	default:
		at := storedTime(after.LastLoginAt)
		o.after = "((u.last_login_at IS NOT NULL AND (u.last_login_at " + beyond + " ? OR (u.last_login_at = ? AND u.id " + beyond + " ?))) OR u.last_login_at IS NULL)"
		o.args = []any{at, at, after.ID}
	}
	return o
}
