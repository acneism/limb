package sqlstore

import "strings"

type conditions struct {
	parts []string
	args  []any
}

func (c *conditions) add(part string, args ...any) {
	c.parts = append(c.parts, part)
	c.args = append(c.args, args...)
}

func (c *conditions) where() string {
	return strings.Join(c.parts, " AND ")
}

func marks(n int) string {
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}

func values[T any](list []T) []any {
	out := make([]any, len(list))
	for i, v := range list {
		out[i] = v
	}
	return out
}
