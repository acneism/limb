package limb

import (
	"cmp"
	"context"
	"errors"
	"time"

	"github.com/acneism/limb/internal/admin"
	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/internal/password"
)

// Admin is an administrator of the service as the administration shows it. It
// holds nothing that signs in.
type Admin struct {
	// ID is the identifier of the administrator, a UUID in text form.
	ID string
	// Login is the login in its normalized form: lower case, from 3 to 64
	// characters from a to z, 0 to 9, the dot, the underscore and the hyphen.
	Login string
	// Disabled tells that the administrator cannot sign in.
	Disabled bool
	// TOTPBound tells that the administrator has bound an authenticator and
	// confirmed it.
	TOTPBound bool
	// RecoveryCodes is how many recovery codes the administrator has not used.
	RecoveryCodes int
	// CreatedAt is when the account was made.
	CreatedAt time.Time
	// LastLoginAt is when the administrator last signed in, the zero time if they
	// never did.
	LastLoginAt time.Time
}

// AdminAPI does what the administration does, from the code of the
// application: it manages the administrators and the users, and reads the audit
// log and the settings. It is returned by Auth.Admin. What it changes is written
// to the audit log as done by the code of the application, the actor "system"
// named "api".
type AdminAPI struct {
	a *Auth
}

// Admin returns the operations of the administration for the code of the
// application.
func (a *Auth) Admin() *AdminAPI {
	return &AdminAPI{a: a}
}

// CreateAdmin makes an administrator. The account has no authenticator: the
// administrator binds one at the first sign-in to the administration, which is
// why the administrators are made only here and by the command line, never from
// the web.
//
// The login is normalized, see Admin.Login. The password has to meet the password
// policy of the service, and it is never the login, even when the policy lets
// users choose their login as a password.
//
// It returns a *ValidationError with the field "login" for a login that breaks
// the rules, a *PolicyError for a password that breaks the policy and
// ErrAdminLoginTaken if another administrator has the login.
func (x *AdminAPI) CreateAdmin(ctx context.Context, login, password string) (Admin, error) {
	account, err := x.a.admins.Create(ctx, audit.API, login, password)
	if err != nil {
		return Admin{}, adminError(err)
	}
	return adminOf(account), nil
}

// DeleteAdmin removes the administrator together with their sessions. It returns
// ErrAdminNotFound if there is no such administrator.
func (x *AdminAPI) DeleteAdmin(ctx context.Context, login string) error {
	return adminError(x.a.admins.Delete(ctx, audit.API, login))
}

// ListAdmins returns the administrators ordered by login.
func (x *AdminAPI) ListAdmins(ctx context.Context) ([]Admin, error) {
	accounts, err := x.a.admins.List(ctx)
	if err != nil {
		return nil, adminError(err)
	}
	list := make([]Admin, 0, len(accounts))
	for _, account := range accounts {
		list = append(list, adminOf(account))
	}
	return list, nil
}

// DisableAdmin stops the administrator from signing in and ends their sessions.
// The account stays, and EnableAdmin lets the administrator in again. It does
// nothing if the account is disabled already, and returns ErrAdminNotFound if
// there is no such administrator.
func (x *AdminAPI) DisableAdmin(ctx context.Context, login string) error {
	return adminError(x.a.admins.Disable(ctx, audit.API, login))
}

// EnableAdmin lets a disabled administrator sign in again. It does nothing if the
// account is enabled already, and returns ErrAdminNotFound if there is no such
// administrator.
func (x *AdminAPI) EnableAdmin(ctx context.Context, login string) error {
	return adminError(x.a.admins.Enable(ctx, audit.API, login))
}

// ResetAdminPassword gives the administrator a new password, which has to meet the
// password policy, and ends all their sessions. It returns a *PolicyError for a
// password that breaks the policy and ErrAdminNotFound if there is no such
// administrator.
func (x *AdminAPI) ResetAdminPassword(ctx context.Context, login, password string) error {
	return adminError(x.a.admins.ResetPassword(ctx, audit.API, login, password))
}

// ResetAdminTOTP removes the authenticator of the administrator and their recovery
// codes and ends all their sessions, so that they bind a new authenticator at the
// next sign-in. It returns ErrAdminNotFound if there is no such administrator.
func (x *AdminAPI) ResetAdminTOTP(ctx context.Context, login string) error {
	return adminError(x.a.admins.ResetTOTP(ctx, audit.API, login))
}

func adminOf(a admin.Account) Admin {
	return Admin{
		ID: a.ID, Login: a.Login, Disabled: a.Disabled, TOTPBound: a.TOTPBound, RecoveryCodes: a.RecoveryCodes,
		CreatedAt: a.CreatedAt, LastLoginAt: a.LastLoginAt,
	}
}

func adminError(err error) error {
	var login *admin.LoginError
	var policy *admin.PolicyError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, admin.ErrNotFound):
		return ErrAdminNotFound
	case errors.Is(err, admin.ErrLoginTaken):
		return ErrAdminLoginTaken
	case errors.As(err, &login):
		return &ValidationError{Field: "login", Reason: login.Reason}
	case errors.As(err, &policy):
		return &PolicyError{Rules: policy.Rules}
	case errors.Is(err, password.ErrTooLong):
		return &PolicyError{Rules: []string{password.RuleMaxLength}}
	}
	return err
}

type adminHasher struct{ a *Auth }

func (h adminHasher) Hash(ctx context.Context, password string) (string, error) {
	return h.a.hasher.Hash(ctx, password)
}

func (a *Auth) newAdminService(serviceName string) *admin.Service {
	return admin.New(admin.Config{
		Store:  a.store,
		Keys:   a.keys,
		Hasher: adminHasher{a: a},
		Policy: func(ctx context.Context, password string, logins []string) []string {
			policy := a.policy
			policy.AllowLogin = false
			return policy.Check(ctx, password, logins)
		},
		Tenant: a.tenant,
		Issuer: cmp.Or(serviceName, defaultIssuer),
		Now:    func() time.Time { return a.now() },
		NewID:  func() (string, error) { return a.newID() },
	})
}
