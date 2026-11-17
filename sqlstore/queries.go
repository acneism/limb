package sqlstore

import (
	"strings"
	"time"
)

const (
	userColumns = "tenant_id, id, status, password_hash, must_change_password, blocked_reason, " +
		"blocked_until, deleted_at, purge_after, created_at, last_login_at, version"
	identifierColumns = "tenant_id, type, value, display_value, user_id, verified_at"
	sessionColumns    = "tenant_id, id, kind, secret_hash, user_id, ip, user_agent, created_at, last_seen_at, expires_at, revoked_at"
	resolveColumns    = "s.tenant_id, s.id, s.kind, s.secret_hash, s.user_id, s.ip, s.user_agent, s.created_at, s.last_seen_at, " +
		"s.expires_at, s.revoked_at, u.status, u.blocked_until, u.must_change_password"
	resolveFrom  = " FROM {sessions} s JOIN {users} u ON u.tenant_id = s.tenant_id AND u.id = s.user_id"
	tokenColumns = "tenant_id, token_hash, session_id, expires_at, used_at"

	onetimeColumns = "tenant_id, id, kind, secret_hash, user_id, purpose, channel_type, channel_value, attempts, created_at, expires_at, used_at"

	attemptColumns = "attempt_key, window_start, hit_count, blocked_until, next_allowed_at"
	keyColumns     = "kid, algorithm, generation, private_key, public_key, created_at, retire_after"

	settingColumns = "tenant_id, name, value, updated_at, updated_by"
	auditColumns   = "tenant_id, id, occurred_at, actor_kind, actor_id, action, target_user_id, ip, details"
	adminColumns   = "tenant_id, id, login, password_hash, totp_secret, totp_confirmed_at, totp_last_step, status, created_at, last_login_at, version"
)

type queries struct {
	insertUser          string
	selectUser          string
	updateUser          string
	userExists          string
	identifierExists    string
	deleteUser          string
	insertIdentifier    string
	selectIdentifier    string
	listIdentifiers     string
	deleteIdentifier    string
	markVerified        string
	insertSession       string
	resolveByID         string
	resolveBySecret     string
	touchSession        string
	revokeSession       string
	revokeAll           string
	revokeAllExcept     string
	listSessions        string
	deleteSessions      string
	insertToken         string
	useToken            string
	selectToken         string
	deleteTokens        string
	insertSecret        string
	endSecrets          string
	endChannel          string
	useLink             string
	selectLink          string
	selectCodes         string
	selectChannel       string
	countAttempt        string
	useCode             string
	deleteSecrets       string
	insertAttempt       string
	bumpAttempt         string
	restartAttempt      string
	selectAttempt       string
	holdBlock           string
	holdDelay           string
	resetAttempt        string
	deleteAttempts      string
	insertKey           string
	listKeys            string
	retireKey           string
	keyExists           string
	deleteKeys          string
	selectSetting       string
	listSettings        string
	updateSetting       string
	insertSetting       string
	settingExists       string
	deleteSetting       string
	insertAudit         string
	insertAdmin         string
	selectAdmin         string
	selectAdminByLogin  string
	listAdmins          string
	updateAdmin         string
	deleteAdmin         string
	adminMark           string
	adminExists         string
	acceptStep          string
	recordLogin         string
	deleteRecoveryCodes string
	insertRecoveryCode  string
	useRecoveryCode     string
	countRecoveryCodes  string
	bind                func(template string) string
	schemaVersion       string
	probeSchema         string
	touchSchema         string
	insertSchemaRow     string
	acquireLock         string
	renewLock           string
	lockHeld            string
	setVersion          string
	releaseLock         string
}

func newQueries(prefix string, d Dialect) queries {
	build := func(template string) string {
		text := strings.NewReplacer(
			"{users}", prefix+"users",
			"{identifiers}", prefix+"identifiers",
			"{sessions}", prefix+"sessions",
			"{refresh_tokens}", prefix+"refresh_tokens",
			"{secrets}", prefix+"secrets",
			"{attempts}", prefix+"attempts",
			"{signing_keys}", prefix+"signing_keys",
			"{settings}", prefix+"settings",
			"{audit_log}", prefix+"audit_log",
			"{admins}", prefix+"admins",
			"{admin_sessions}", prefix+"admin_sessions",
			"{admin_recovery_codes}", prefix+"admin_recovery_codes",
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
		identifierExists: build("SELECT 1 FROM {identifiers} WHERE tenant_id = ? AND type = ? AND value = ?"),
		deleteIdentifier: build("DELETE FROM {identifiers} WHERE tenant_id = ? AND type = ? AND value = ?"),
		markVerified:     build("UPDATE {identifiers} SET verified_at = ? WHERE tenant_id = ? AND type = ? AND value = ?"),
		insertSession:    build("INSERT INTO {sessions} (" + sessionColumns + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)"),
		resolveByID:      build("SELECT " + resolveColumns + resolveFrom + " WHERE s.tenant_id = ? AND s.id = ?"),
		resolveBySecret:  build("SELECT " + resolveColumns + resolveFrom + " WHERE s.tenant_id = ? AND s.secret_hash = ?"),
		touchSession:     build("UPDATE {sessions} SET last_seen_at = ? WHERE tenant_id = ? AND id = ? AND last_seen_at < ?"),
		revokeSession: build("UPDATE {sessions} SET revoked_at = ? " +
			"WHERE tenant_id = ? AND user_id = ? AND id = ? AND revoked_at IS NULL"),
		revokeAll: build("UPDATE {sessions} SET revoked_at = ? " +
			"WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL"),
		revokeAllExcept: build("UPDATE {sessions} SET revoked_at = ? " +
			"WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL AND id <> ?"),
		listSessions: build("SELECT " + sessionColumns + " FROM {sessions} " +
			"WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ?"),
		deleteSessions: build("DELETE FROM {sessions} " +
			"WHERE tenant_id = ? AND (expires_at < ? OR last_seen_at < ? OR revoked_at < ?)"),
		insertToken: build("INSERT INTO {refresh_tokens} (token_hash, tenant_id, session_id, expires_at) VALUES (?, ?, ?, ?)"),
		useToken: build("UPDATE {refresh_tokens} SET used_at = ? " +
			"WHERE tenant_id = ? AND token_hash = ? AND used_at IS NULL"),
		selectToken:  build("SELECT " + tokenColumns + " FROM {refresh_tokens} WHERE tenant_id = ? AND token_hash = ?"),
		deleteTokens: build("DELETE FROM {refresh_tokens} WHERE tenant_id = ? AND expires_at < ?"),
		insertSecret: build("INSERT INTO {secrets} (" + onetimeColumns + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, NULL)"),
		endSecrets: build("UPDATE {secrets} SET used_at = ? " +
			"WHERE tenant_id = ? AND user_id = ? AND purpose = ? AND used_at IS NULL"),
		endChannel: build("UPDATE {secrets} SET used_at = ? " +
			"WHERE tenant_id = ? AND user_id = ? AND purpose = ? AND channel_type = ? AND channel_value = ? AND used_at IS NULL"),
		useLink: build("UPDATE {secrets} SET used_at = ? " +
			"WHERE tenant_id = ? AND kind = 'link' AND purpose = ? AND secret_hash = ? AND used_at IS NULL AND expires_at > ?"),
		selectLink: build("SELECT " + onetimeColumns + " FROM {secrets} WHERE tenant_id = ? AND secret_hash = ?"),
		selectCodes: build("SELECT " + onetimeColumns + " FROM {secrets} " +
			"WHERE tenant_id = ? AND user_id = ? AND purpose = ? AND kind = 'code' AND used_at IS NULL AND expires_at > ? AND attempts < ?"),
		selectChannel: build("SELECT " + onetimeColumns + " FROM {secrets} " +
			"WHERE tenant_id = ? AND user_id = ? AND purpose = ? AND kind = 'code' AND used_at IS NULL AND expires_at > ? AND attempts < ? " +
			"AND channel_type = ? AND channel_value = ?"),
		countAttempt: build("UPDATE {secrets} SET attempts = attempts + 1 " +
			"WHERE tenant_id = ? AND id = ? AND used_at IS NULL AND attempts < ?"),
		useCode: build("UPDATE {secrets} SET used_at = ? " +
			"WHERE tenant_id = ? AND id = ? AND kind = 'code' AND used_at IS NULL AND expires_at > ?"),
		deleteSecrets: build("DELETE FROM {secrets} WHERE tenant_id = ? AND (expires_at < ? OR used_at < ?)"),
		insertAttempt: build(d.InsertIgnoring("{attempts}",
			[]string{"attempt_key", "window_start", "hit_count"}, []string{"?", "?", "1"}, []string{"attempt_key"})),
		bumpAttempt:    build("UPDATE {attempts} SET hit_count = hit_count + 1 WHERE attempt_key = ? AND window_start > ?"),
		restartAttempt: build("UPDATE {attempts} SET hit_count = 1, window_start = ? WHERE attempt_key = ? AND window_start <= ?"),
		selectAttempt:  build("SELECT " + attemptColumns + " FROM {attempts} WHERE attempt_key = ?"),
		holdBlock: build("UPDATE {attempts} SET blocked_until = ? " +
			"WHERE attempt_key = ? AND (blocked_until IS NULL OR blocked_until < ?)"),
		holdDelay: build("UPDATE {attempts} SET next_allowed_at = ? " +
			"WHERE attempt_key = ? AND (next_allowed_at IS NULL OR next_allowed_at < ?)"),
		resetAttempt: build("DELETE FROM {attempts} WHERE attempt_key = ?"),
		deleteAttempts: build("DELETE FROM {attempts} WHERE window_start < ? " +
			"AND (blocked_until IS NULL OR blocked_until < ?) AND (next_allowed_at IS NULL OR next_allowed_at < ?)"),
		insertKey: build("INSERT INTO {signing_keys} (kid, algorithm, generation, private_key, public_key, created_at) " +
			"VALUES (?, ?, ?, ?, ?, ?)"),
		listKeys:      build("SELECT " + keyColumns + " FROM {signing_keys} ORDER BY generation"),
		retireKey:     build("UPDATE {signing_keys} SET retire_after = ? WHERE kid = ? AND retire_after IS NULL"),
		keyExists:     build("SELECT 1 FROM {signing_keys} WHERE kid = ?"),
		deleteKeys:    build("DELETE FROM {signing_keys} WHERE retire_after < ?"),
		selectSetting: build("SELECT " + settingColumns + " FROM {settings} WHERE tenant_id = ? AND name = ?"),
		listSettings:  build("SELECT " + settingColumns + " FROM {settings} WHERE tenant_id = ?"),
		updateSetting: build("UPDATE {settings} SET value = ?, updated_at = ?, updated_by = ? WHERE tenant_id = ? AND name = ?"),
		insertSetting: build(d.InsertIgnoring("{settings}", strings.Split(settingColumns, ", "),
			[]string{"?", "?", "?", "?", "?"}, []string{"tenant_id", "name"})),
		settingExists:      build("SELECT 1 FROM {settings} WHERE tenant_id = ? AND name = ?"),
		deleteSetting:      build("DELETE FROM {settings} WHERE tenant_id = ? AND name = ?"),
		insertAudit:        build("INSERT INTO {audit_log} (" + auditColumns + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"),
		bind:               build,
		insertAdmin:        build("INSERT INTO {admins} (" + adminColumns + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)"),
		selectAdmin:        build("SELECT " + adminColumns + " FROM {admins} WHERE tenant_id = ? AND id = ?"),
		selectAdminByLogin: build("SELECT " + adminColumns + " FROM {admins} WHERE tenant_id = ? AND login = ?"),
		listAdmins:         build("SELECT " + adminColumns + " FROM {admins} WHERE tenant_id = ?"),
		updateAdmin: build("UPDATE {admins} SET password_hash = ?, totp_secret = ?, totp_confirmed_at = ?, status = ?, " +
			"version = version + 1 WHERE tenant_id = ? AND id = ? AND version = ?"),
		deleteAdmin: build("DELETE FROM {admins} WHERE tenant_id = ? AND id = ?"),
		adminMark:   build("SELECT version, totp_last_step FROM {admins} WHERE tenant_id = ? AND id = ?"),
		adminExists: build("SELECT 1 FROM {admins} WHERE tenant_id = ? AND id = ?"),
		acceptStep: build("UPDATE {admins} SET totp_last_step = ?, last_login_at = ? " +
			"WHERE tenant_id = ? AND id = ? AND version = ? AND totp_last_step < ?"),
		recordLogin:         build("UPDATE {admins} SET last_login_at = ? WHERE tenant_id = ? AND id = ? AND version = ?"),
		deleteRecoveryCodes: build("DELETE FROM {admin_recovery_codes} WHERE tenant_id = ? AND admin_id = ?"),
		insertRecoveryCode:  build("INSERT INTO {admin_recovery_codes} (tenant_id, admin_id, code_hash, used_at) VALUES (?, ?, ?, NULL)"),
		useRecoveryCode: build("UPDATE {admin_recovery_codes} SET used_at = ? " +
			"WHERE tenant_id = ? AND admin_id = ? AND code_hash = ? AND used_at IS NULL"),
		countRecoveryCodes: build("SELECT COUNT(*) FROM {admin_recovery_codes} WHERE tenant_id = ? AND admin_id = ? AND used_at IS NULL"),
		schemaVersion:      build("SELECT version FROM {schema} WHERE id = 1"),
		probeSchema:        build("SELECT 1 FROM {schema} WHERE id = 1"),
		touchSchema:        build("UPDATE {schema} SET version = version WHERE id = 1"),
		insertSchemaRow:    build("INSERT INTO {schema} (id, version, applied_at) VALUES (1, 0, ?)"),
		acquireLock: build("UPDATE {schema} SET lock_holder = ?, lock_expires_at = ? " +
			"WHERE id = 1 AND (lock_holder IS NULL OR lock_expires_at < ?)"),
		renewLock: build("UPDATE {schema} SET lock_expires_at = ? WHERE id = 1 AND lock_holder = ?"),
		lockHeld:  build("SELECT 1 FROM {schema} WHERE id = 1 AND lock_holder = ?"),
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

func optionalBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func optionalText(s string) any {
	if s == "" {
		return nil
	}
	return s
}
