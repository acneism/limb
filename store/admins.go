package store

import (
	"context"
	"time"
)

// AdminStatus is the state of the account of an administrator.
type AdminStatus string

// The states of the account of an administrator.
const (
	// AdminActive is an account that can sign in.
	AdminActive AdminStatus = "active"
	// AdminDisabled is an account that cannot sign in and has no sessions.
	AdminDisabled AdminStatus = "disabled"
)

// Admin is the account of an administrator of the service. It is kept apart
// from the accounts of users. The pair of TenantID and ID identifies it.
type Admin struct {
	// TenantID is the tenant the administrator belongs to.
	TenantID string
	// ID is the identifier of the administrator, a UUID in text form.
	ID string
	// Login is the normalized login. It is unique in its tenant.
	Login string
	// PasswordHash is the encoded password hash.
	PasswordHash string
	// TOTPSecret is the seed of the one-time passwords, sealed. It is empty until
	// the administrator starts to bind an authenticator.
	TOTPSecret []byte
	// TOTPConfirmedAt is when the administrator proved that the authenticator works,
	// the zero time while the binding is not confirmed.
	TOTPConfirmedAt time.Time
	// TOTPLastStep is the time step of the last one-time password that was
	// accepted. Update does not write it, AcceptStep does.
	TOTPLastStep int64
	// Status is the state of the account.
	Status AdminStatus
	// CreatedAt is when the account was created.
	CreatedAt time.Time
	// LastLoginAt is when the administrator last signed in, the zero time if they
	// never did. Update does not write it, RecordLogin and AcceptStep do.
	LastLoginAt time.Time
	// Version counts the changes that Update made. Create stores 1 and every
	// successful Update adds one, and nothing else does.
	Version int64
}

// Admins stores the accounts of administrators and their recovery codes.
type Admins interface {
	// Create stores a new administrator with version 1, whatever a.Version is. It
	// returns ErrConflict if the ID or the login is taken in the tenant.
	Create(ctx context.Context, a Admin) error

	// Get returns the administrator or ErrNotFound.
	Get(ctx context.Context, tenantID, id string) (Admin, error)

	// FindByLogin returns the administrator with the given login or ErrNotFound.
	FindByLogin(ctx context.Context, tenantID, login string) (Admin, error)

	// List returns the administrators of the tenant ordered by login, comparing
	// the bytes of the logins whatever the collation of the database is.
	List(ctx context.Context, tenantID string) ([]Admin, error)

	// Update replaces PasswordHash, TOTPSecret, TOTPConfirmedAt and Status if the
	// stored version equals a.Version, and returns a with the version increased.
	// It does not touch the other fields. It returns ErrNotFound if there is no
	// such administrator and ErrStale if the version differs.
	Update(ctx context.Context, a Admin) (Admin, error)

	// Delete removes the administrator together with their sessions and recovery
	// codes, or returns ErrNotFound.
	Delete(ctx context.Context, tenantID, id string) error

	// AcceptStep records that the one-time password of the time step was accepted
	// and that the administrator signed in at the given time. It succeeds only if
	// the stored version equals version and the step is greater than the last one
	// that was accepted, and then no other call can accept the same step. It
	// returns ErrNotFound if there is no such administrator, ErrStale if the
	// version differs and ErrConflict if the step is not greater, which is a
	// one-time password that was used already.
	//
	// The statement takes the row of the administrator, so call it inside InTx
	// together with whatever has to stand or fall with it: the changes of the
	// administrator that wait for the transaction wait until it ends, and
	// then fail on the version.
	AcceptStep(ctx context.Context, tenantID, id string, version, step int64, at time.Time) error

	// RecordLogin records that the administrator signed in at the given time,
	// with a recovery code and so without a time step, if the stored version equals
	// version. It returns ErrNotFound if there is no such administrator and
	// ErrStale if the version differs. Like AcceptStep, call it inside InTx.
	RecordLogin(ctx context.Context, tenantID, id string, version int64, at time.Time) error

	// ReplaceRecoveryCodes makes the given hashes the recovery codes of the
	// administrator, none of them used, and removes the codes that they had. Each
	// hash is SecretHashLength bytes, no hash is given twice and there are at
	// most MaxRecoveryCodes of them. It returns ErrNotFound if the administrator
	// does not exist. Call it inside InTx, so that nobody sees a half of the new
	// codes.
	ReplaceRecoveryCodes(ctx context.Context, tenantID, id string, hashes [][]byte) error

	// UseRecoveryCode marks the recovery code with the given hash as used at the
	// given time. The marking is atomic: when several calls use one code at once,
	// exactly one of them succeeds. It returns ErrNotFound if the administrator
	// has no such code or it was used already.
	UseRecoveryCode(ctx context.Context, tenantID, id string, hash []byte, at time.Time) error

	// CountRecoveryCodes returns how many recovery codes of the administrator
	// have not been used.
	CountRecoveryCodes(ctx context.Context, tenantID, id string) (int, error)
}
