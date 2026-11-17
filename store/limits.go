package store

// The longest values that a store has to keep, in bytes. They are the same for
// every store, so that a record that one store accepts is accepted by all of
// them: databases differ in how long an indexed column may be and in whether
// the length of a column counts bytes or characters. A store checks the limits
// before it writes anything, and a record that is over one of them is invalid. A
// lookup by a value that is over its limit finds nothing.
const (
	// SecretHashLength is the length in bytes of the hash of a secret: SHA-256.
	SecretHashLength = 32

	// MaxTenantIDLength is the longest ID of a tenant.
	MaxTenantIDLength = 64

	// MaxIDLength is the longest ID of a user or of a session, which are UUIDs in
	// text form.
	MaxIDLength = 64

	// MaxIdentifierTypeLength is the longest name of an identifier type.
	MaxIdentifierTypeLength = 32

	// MaxIdentifierValueLength is the longest normalized value of an identifier.
	// A key of an identifier is a tenant, a type and a value, and the longest key
	// that InnoDB indexes is 3072 bytes, at up to four bytes for a character.
	MaxIdentifierValueLength = 512

	// MaxDisplayValueLength is the longest display value of an identifier, which
	// is the text as the user wrote it.
	MaxDisplayValueLength = 1024

	// MaxPasswordHashLength is the longest encoded password hash. An Argon2id
	// hash with the largest parameters that limb accepts takes 292 bytes.
	MaxPasswordHashLength = 512

	// MaxBlockedReasonLength is the longest reason of a block.
	MaxBlockedReasonLength = 512

	// MaxIPLength is the longest text form of a client address that is stored.
	MaxIPLength = 45

	// MaxUserAgentLength is the longest user agent that is stored, in bytes.
	MaxUserAgentLength = 512

	// MaxKIDLength is the longest ID of a signing key.
	MaxKIDLength = 64

	// MaxAlgorithmLength is the longest name of a signing algorithm.
	MaxAlgorithmLength = 16

	// MaxAttemptKeyLength is the longest key of a counter of failed attempts.
	MaxAttemptKeyLength = 64

	// MaxKeyMaterialLength is the longest private or public key of a signing key,
	// as it is stored. A sealed RSA key of 8192 bits takes less than 5 KiB.
	MaxKeyMaterialLength = 16384

	// MaxSettingNameLength is the longest name of a setting.
	MaxSettingNameLength = 64

	// MaxSettingValueLength is the longest value of a setting.
	MaxSettingValueLength = 512

	// MaxAdminLoginLength is the longest login of an administrator.
	MaxAdminLoginLength = 64

	// MaxSealedSecretLength is the longest sealed secret of an administrator: the
	// seed of the one-time passwords with the version, the nonce and the tag of
	// the encryption around it.
	MaxSealedSecretLength = 256

	// MaxAuditActionLength is the longest name of an action in the audit log.
	MaxAuditActionLength = 64

	// MaxAuditDetailsLength is the longest details of a record in the audit log.
	MaxAuditDetailsLength = 4000

	// MaxRecoveryCodes is the largest number of recovery codes that an
	// administrator has.
	MaxRecoveryCodes = 32

	// MaxAuditActions is the largest number of actions that one query of the audit
	// log asks for.
	MaxAuditActions = 32

	// MaxUsersPage is the largest number of users that one query returns.
	MaxUsersPage = 500

	// MaxAuditPage is the largest number of records that one query returns.
	MaxAuditPage = 500
)
