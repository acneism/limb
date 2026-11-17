package limb

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/internal/password"
	"github.com/acneism/limb/store"
)

const adminPassword = "correct horse battery staple"

func auditRecords(t *testing.T, a *Auth) []store.AuditRecord {
	t.Helper()
	list, err := a.store.Audit().List(t.Context(), store.AuditQuery{TenantID: a.tenant, Limit: store.MaxAuditPage})
	if err != nil {
		t.Fatalf("List of the audit log failed: %v", err)
	}
	return list
}

func TestAnAdministratorIsMadeAndListedFromTheCode(t *testing.T) {
	a, clock := newLimitedAuth(t, WithServiceName("Acme"))
	admin, err := a.Admin().CreateAdmin(t.Context(), "  Root ", adminPassword)
	if err != nil {
		t.Fatalf("CreateAdmin failed: %v", err)
	}
	if admin.Login != "root" || admin.ID == "" || admin.Disabled || admin.TOTPBound || admin.RecoveryCodes != 0 || !admin.CreatedAt.Equal(clock.now()) || !admin.LastLoginAt.IsZero() {
		t.Fatalf("the administrator is %+v", admin)
	}
	clock.advance(time.Hour)
	if _, err = a.Admin().CreateAdmin(t.Context(), "ann", adminPassword); err != nil {
		t.Fatal(err)
	}
	if err = a.Admin().DisableAdmin(t.Context(), "ann"); err != nil {
		t.Fatal(err)
	}
	list, err := a.Admin().ListAdmins(t.Context())
	if err != nil || len(list) != 2 || list[0].Login != "ann" || !list[0].Disabled || list[1].Login != "root" || list[1].Disabled {
		t.Fatalf("ListAdmins = %+v, %v", list, err)
	}
	if err = a.Admin().EnableAdmin(t.Context(), "ann"); err != nil {
		t.Fatal(err)
	}
	if err = a.Admin().ResetAdminPassword(t.Context(), "ann", adminPassword+" again"); err != nil {
		t.Fatal(err)
	}
	if err = a.Admin().ResetAdminTOTP(t.Context(), "ann"); err != nil {
		t.Fatal(err)
	}
	if err = a.Admin().DeleteAdmin(t.Context(), "ANN"); err != nil {
		t.Fatal(err)
	}
	list, err = a.Admin().ListAdmins(t.Context())
	if err != nil || len(list) != 1 || list[0].Login != "root" {
		t.Fatalf("ListAdmins after a deletion = %+v, %v", list, err)
	}
	var actions []string
	for _, r := range auditRecords(t, a) {
		if r.ActorKind != store.ActorSystem || r.ActorID != "api" {
			t.Fatalf("the code of the application is the system actor api: %+v", r)
		}
		actions = append(actions, r.Action)
	}
	want := "admin.deleted admin.totp_reset admin.password_reset admin.enabled admin.disabled admin.created admin.created"
	if strings.Join(actions, " ") != want {
		t.Fatalf("the actions are %v, want %v", actions, want)
	}
}

func TestTheErrorsOfTheOperationsOnAdministratorsArePublic(t *testing.T) {
	a := newTestAuth(t)
	api := a.Admin()
	if _, err := api.CreateAdmin(t.Context(), "root", adminPassword); err != nil {
		t.Fatal(err)
	}

	var validation *ValidationError
	for _, login := range []string{"", "ab", "-root", "ro ot", strings.Repeat("a", 65)} {
		if _, err := api.CreateAdmin(t.Context(), login, adminPassword); !errors.As(err, &validation) || validation.Field != "login" || validation.Reason == "" {
			t.Errorf("CreateAdmin(%q) = %v, want a *ValidationError of the login", login, err)
		}
	}
	var policy *PolicyError
	for name, c := range map[string]struct{ login, password, rule string }{
		"short":  {"second", "short", "min_length"},
		"common": {"second", "password1234", "common_password"},
		"login":  {"second-admin", "SECOND-ADMIN", "login_identifier"},
		"long":   {"second", strings.Repeat("x", 129), "max_length"},
	} {
		if _, err := api.CreateAdmin(t.Context(), c.login, c.password); !errors.As(err, &policy) || !containsString(policy.Rules, c.rule) {
			t.Errorf("%s: CreateAdmin = %v, want a *PolicyError with %s", name, err, c.rule)
		}
	}
	if _, err := api.CreateAdmin(t.Context(), "ROOT", adminPassword); !errors.Is(err, ErrAdminLoginTaken) {
		t.Errorf("CreateAdmin with a taken login = %v, want ErrAdminLoginTaken", err)
	}
	if err := api.ResetAdminPassword(t.Context(), "root", "short"); !errors.As(err, &policy) {
		t.Errorf("ResetAdminPassword with a short password = %v, want a *PolicyError", err)
	}
	calls := map[string]func() error{
		"DeleteAdmin":               func() error { return api.DeleteAdmin(t.Context(), "nobody") },
		"DisableAdmin":              func() error { return api.DisableAdmin(t.Context(), "nobody") },
		"EnableAdmin":               func() error { return api.EnableAdmin(t.Context(), "nobody") },
		"ResetAdminPassword":        func() error { return api.ResetAdminPassword(t.Context(), "nobody", adminPassword) },
		"ResetAdminTOTP":            func() error { return api.ResetAdminTOTP(t.Context(), "nobody") },
		"a login that cannot exist": func() error { return api.DeleteAdmin(t.Context(), "!") },
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, ErrAdminNotFound) {
			t.Errorf("%s = %v, want ErrAdminNotFound", name, err)
		}
	}
	if got := auditRecords(t, a); len(got) != 1 {
		t.Fatalf("a refused change was written to the audit log: %d records", len(got))
	}
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func TestAnAdministratorIsHashedWithTheHasherOfTheService(t *testing.T) {
	a := newTestAuth(t)
	hasher := &countingHasher{passwordHasher: a.hasher}
	a.hasher = hasher
	if _, err := a.Admin().CreateAdmin(t.Context(), "root", adminPassword); err != nil {
		t.Fatal(err)
	}
	if hasher.hashes.Load() != 1 {
		t.Fatalf("the hasher of the service hashed %d passwords, want 1", hasher.hashes.Load())
	}
	hasher.hashErr = password.ErrTooLong
	if _, err := a.Admin().CreateAdmin(t.Context(), "second", adminPassword); !errors.As(err, new(*PolicyError)) {
		t.Fatalf("CreateAdmin with a password that the hasher refuses as too long = %v, want a *PolicyError", err)
	}
	broken := errors.New("the hasher failed")
	hasher.hashErr = broken
	if err := a.Admin().ResetAdminPassword(t.Context(), "root", adminPassword+"x"); !errors.Is(err, broken) {
		t.Fatalf("ResetAdminPassword = %v, want the failure of the hasher", err)
	}
}

func TestAnAdministratorIsMadeAtTheTimeOfTheService(t *testing.T) {
	a, clock := newLimitedAuth(t)
	clock.advance(48 * time.Hour)
	admin, err := a.Admin().CreateAdmin(t.Context(), "root", adminPassword)
	if err != nil || !admin.CreatedAt.Equal(clock.now()) {
		t.Fatalf("CreateAdmin = %+v, %v; want the time of the clock of the service", admin, err)
	}
	records := auditRecords(t, a)
	if len(records) != 1 || !records[0].At.Equal(clock.now().Truncate(time.Microsecond)) {
		t.Fatalf("the record is %+v, want the time of the clock of the service", records)
	}
}

func TestTheOperationsOnAdministratorsStopWhenTheContextEnds(t *testing.T) {
	a := newTestAuth(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := a.Admin().CreateAdmin(ctx, "root", adminPassword); !errors.Is(err, context.Canceled) {
		t.Fatalf("CreateAdmin with a canceled context = %v", err)
	}
	if _, err := a.Admin().ListAdmins(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("ListAdmins with a canceled context = %v", err)
	}
}

func TestTheLoginIsNeverThePasswordOfAnAdministrator(t *testing.T) {
	a := newTestAuth(t, WithPasswordPolicy(PasswordPolicy{MinLength: 8, AllowLoginIdentifier: true, AllowCommon: true}))
	var policy *PolicyError
	if _, err := a.Admin().CreateAdmin(t.Context(), "second-admin", "second-admin"); !errors.As(err, &policy) || !containsString(policy.Rules, "login_identifier") || len(policy.Rules) != 1 {
		t.Fatalf("CreateAdmin with the login as the password = %v, want only the rule login_identifier although users may do so", err)
	}
	if _, err := a.Admin().CreateAdmin(t.Context(), "second-admin", "password1234"); err != nil {
		t.Fatalf("the other rules of the policy of the service apply to administrators: %v", err)
	}
	if err := a.Admin().ResetAdminPassword(t.Context(), "second-admin", "SECOND-ADMIN"); !errors.As(err, &policy) || len(policy.Rules) != 1 || policy.Rules[0] != "login_identifier" {
		t.Fatalf("ResetAdminPassword with the login as the password = %v, want only the rule login_identifier", err)
	}
	if err := a.Admin().ResetAdminPassword(t.Context(), "second-admin", "SECOND-ADMIN-2"); err != nil {
		t.Fatalf("a password that is not the login = %v", err)
	}
}
