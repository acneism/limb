package sqlstore

import (
	"strings"
	"time"
)

const (
	userColumns = "tenant_id, id, status, password_hash, must_change_password, blocked_reason, " +
		"blocked_until, deleted_at, purge_after, created_at, last_login_at, version"
	identifierColumns = "tenant_id, type, value, display_value, user_id, verified_at"
)

type queries struct {
	insertUser       string
	selectUser       string
	updateUser       string
	userExists       string
	deleteUser       string
	insertIdentifier string
	selectIdentifier string
	listIdentifiers  string
	deleteIdentifier string
	markVerified     string
	schemaVersion    string
	probeSchema      string
	insertSchemaRow  string
	acquireLock      string
	renewLock        string
	setVersion       string
	releaseLock      string
}

func newQueries(prefix string, d Dialect) queries {
	build := func(template string) string {
		text := strings.NewReplacer(
			"{users}", prefix+"users",
			"{identifiers}", prefix+"identifiers",
			"{schema}", prefix+"schema",
		).Replace(template)
		var out strings.Builder
		n := 0
		for _, r := range text {
			if r == '?' {
				n++
				out.WriteString(d.Placeholder(n))
				continue
			}
			out.WriteRune(r)
		}
		return out.String()
	}
	return queries{
		insertUser: build("INSERT INTO {users} (" + userColumns + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)"),
		selectUser: build("SELECT " + userColumns + " FROM {users} WHERE tenant_id = ? AND id = ?"),
		updateUser: build("UPDATE {users} SET status = ?, password_hash = ?, must_change_password = ?, " +
			"blocked_reason = ?, blocked_until = ?, deleted_at = ?, purge_after = ?, last_login_at = ?, " +
			"version = version + 1 WHERE tenant_id = ? AND id = ? AND version = ?"),
		userExists:       build("SELECT 1 FROM {users} WHERE tenant_id = ? AND id = ?"),
		deleteUser:       build("DELETE FROM {users} WHERE tenant_id = ? AND id = ?"),
		insertIdentifier: build("INSERT INTO {identifiers} (" + identifierColumns + ") VALUES (?, ?, ?, ?, ?, ?)"),
		selectIdentifier: build("SELECT " + identifierColumns + " FROM {identifiers} WHERE tenant_id = ? AND type = ? AND value = ?"),
		listIdentifiers:  build("SELECT " + identifierColumns + " FROM {identifiers} WHERE tenant_id = ? AND user_id = ?"),
		deleteIdentifier: build("DELETE FROM {identifiers} WHERE tenant_id = ? AND type = ? AND value = ?"),
		markVerified:     build("UPDATE {identifiers} SET verified_at = ? WHERE tenant_id = ? AND type = ? AND value = ?"),
		schemaVersion:    build("SELECT version FROM {schema} WHERE id = 1"),
		probeSchema:      build("SELECT 1 FROM {schema} WHERE id = 1"),
		insertSchemaRow:  build("INSERT INTO {schema} (id, version, applied_at) VALUES (1, 0, ?)"),
		acquireLock: build("UPDATE {schema} SET lock_holder = ?, lock_expires_at = ? " +
			"WHERE id = 1 AND (lock_holder IS NULL OR lock_expires_at < ?)"),
		renewLock: build("UPDATE {schema} SET lock_expires_at = ? WHERE id = 1 AND lock_holder = ?"),
		setVersion: build("UPDATE {schema} SET version = ?, applied_at = ?, lock_expires_at = ? " +
			"WHERE id = 1 AND lock_holder = ?"),
		releaseLock: build("UPDATE {schema} SET lock_holder = NULL, lock_expires_at = NULL " +
			"WHERE id = 1 AND lock_holder = ?"),
	}
}

func storedTime(t time.Time) time.Time {
	return t.UTC().Truncate(time.Microsecond)
}

func optionalTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return storedTime(t)
}

func optionalText(s string) any {
	if s == "" {
		return nil
	}
	return s
}
