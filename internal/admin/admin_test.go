package admin

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/internal/memstore"
	"github.com/acneism/limb/internal/password"
	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/store"
)

const goodPassword = "correct horse battery staple"

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) read() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type fixture struct {
	*Service
	store store.Store
	clock *clock
	keys  *secret.Keys
}

func newFixture(t *testing.T, wrap ...func(store.Store) store.Store) *fixture {
	t.Helper()
	memory := memstore.New()
	if err := memory.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	var s store.Store = memory
	for _, w := range wrap {
		s = w(s)
	}
	keys, err := secret.NewKeys(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	hasher, err := password.NewHasher(password.WithParams(password.Params{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}))
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{now: time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC)}
	var mu sync.Mutex
	n := 0
	policy := password.DefaultPolicy()
	service := New(Config{
		Store: s, Keys: keys, Hasher: hasher, Tenant: store.DefaultTenant, Issuer: "Acme", Now: c.read,
		Policy: policy.Check,
		NewID: func() (string, error) {
			mu.Lock()
			defer mu.Unlock()
			n++
			return fmt.Sprintf("00000000-0000-7000-8000-%012d", n), nil
		},
	})
	return &fixture{Service: service, store: s, clock: c, keys: keys}
}

func (f *fixture) records(t *testing.T) []store.AuditRecord {
	t.Helper()
	list, err := f.store.Audit().List(t.Context(), store.AuditQuery{TenantID: store.DefaultTenant, Limit: store.MaxAuditPage})
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func (f *fixture) create(t *testing.T, login string) Account {
	t.Helper()
	account, err := f.Create(t.Context(), audit.CLI, login, goodPassword)
	if err != nil {
		t.Fatalf("Create(%q) failed: %v", login, err)
	}
	return account
}

func (f *fixture) stored(t *testing.T, login string) store.Admin {
	t.Helper()
	a, err := f.store.Admins().FindByLogin(t.Context(), store.DefaultTenant, login)
	if err != nil {
		t.Fatalf("FindByLogin(%q) failed: %v", login, err)
	}
	return a
}

func (f *fixture) session(t *testing.T, a store.Admin, n int) {
	t.Helper()
	s := store.AdminSession{
		TenantID: a.TenantID, ID: fmt.Sprintf("session-%d", n), AdminID: a.ID, Stage: store.AdminStageFull,
		SecretHash: []byte(fmt.Sprintf("%032d", n)), AdminVersion: a.Version, CreatedAt: f.clock.read(), LastSeenAt: f.clock.read(),
		ExpiresAt: f.clock.read().Add(time.Hour),
	}
	if err := f.store.AdminSessions().Create(t.Context(), s); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) sessions(t *testing.T, a store.Admin) int {
	t.Helper()
	list, err := f.store.AdminSessions().ListByAdmin(t.Context(), a.TenantID, a.ID, f.clock.read())
	if err != nil {
		t.Fatal(err)
	}
	return len(list)
}

func TestTheLoginOfAnAdministratorIsNormalized(t *testing.T) {
	good := map[string]string{
		"root": "root", "  Root  ": "root", "ROOT": "root", "ｒｏｏｔ": "root", "a.b_c-d": "a.b_c-d", "007": "007",
		"abc": "abc", strings.Repeat("a", store.MaxAdminLoginLength): strings.Repeat("a", store.MaxAdminLoginLength), "r ": "r",
	}
	delete(good, "r ")
	for in, want := range good {
		got, err := NormalizeLogin(in)
		if err != nil || got != want {
			t.Errorf("NormalizeLogin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", "ab", "  ab  ", strings.Repeat("a", store.MaxAdminLoginLength+1), "ro ot", "ro\tot", "root@example.com", "rоot",
		"-root", ".root", "_root", "ro/ot", "ro\x00ot", "ro\u200bot", "роот", "root!", "ééé", "a\nb\nc",
	}
	for _, in := range bad {
		got, err := NormalizeLogin(in)
		var loginErr *LoginError
		if !errors.As(err, &loginErr) || got != "" || loginErr.Reason == "" || !strings.Contains(err.Error(), loginErr.Reason) {
			t.Errorf("NormalizeLogin(%q) = %q, %v; want a *LoginError", in, got, err)
		}
	}
}

var loginPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

func FuzzNormalizeLogin(f *testing.F) {
	for _, in := range []string{"root", " Root ", "ｒｏｏｔ", "-x-", "a", "", "\xff\xfe", strings.Repeat("a", 100), "ro ot", "Kelvin"} {
		f.Add(in)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got, err := NormalizeLogin(in)
		if err != nil {
			var loginErr *LoginError
			if !errors.As(err, &loginErr) || got != "" {
				t.Fatalf("NormalizeLogin(%q) = %q, %v; want a *LoginError and no login", in, got, err)
			}
			return
		}
		if !loginPattern.MatchString(got) {
			t.Fatalf("NormalizeLogin(%q) = %q, which breaks the rules", in, got)
		}
		again, err := NormalizeLogin(got)
		if err != nil || again != got {
			t.Fatalf("a normalized login must stay as it is: %q became %q, %v", got, again, err)
		}
	})
}

func TestAnAdministratorIsCreated(t *testing.T) {
	f := newFixture(t)
	account, err := f.Create(t.Context(), audit.CLI, "  Root ", goodPassword)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	want := Account{ID: "00000000-0000-7000-8000-000000000001", Login: "root", CreatedAt: f.clock.read()}
	if account != want {
		t.Fatalf("the account is %+v, want %+v", account, want)
	}
	a := f.stored(t, "root")
	if a.ID != account.ID || a.Status != store.AdminActive || a.Version != 1 || len(a.TOTPSecret) != 0 || !a.TOTPConfirmedAt.IsZero() || !a.LastLoginAt.IsZero() {
		t.Fatalf("the stored administrator is %+v", a)
	}
	hasher, err := password.NewHasher(password.WithParams(password.Params{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}))
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, verifyErr := hasher.Verify(t.Context(), goodPassword, a.PasswordHash); verifyErr != nil || !ok {
		t.Fatalf("the stored hash does not verify the password: %v", verifyErr)
	}
	records := f.records(t)
	if len(records) != 1 || records[0].Action != audit.AdminCreated || records[0].ActorKind != store.ActorSystem || records[0].ActorID != "cli" ||
		records[0].Details != `{"admin_id":"00000000-0000-7000-8000-000000000001","login":"root"}` || records[0].TargetUserID != "" {
		t.Fatalf("the audit log holds %+v", records)
	}
	if strings.Contains(records[0].Details, goodPassword) || strings.Contains(records[0].Details, a.PasswordHash) {
		t.Fatal("the audit log holds the password or its hash")
	}
}

func TestACreationThatBreaksTheRulesIsRefused(t *testing.T) {
	f := newFixture(t)
	f.create(t, "root")
	var loginErr *LoginError
	if _, err := f.Create(t.Context(), audit.CLI, "-root", goodPassword); !errors.As(err, &loginErr) {
		t.Fatalf("Create with a bad login = %v, want a *LoginError", err)
	}
	for _, login := range []string{"root", "ROOT", " Root ", "ｒｏｏｔ"} {
		if _, err := f.Create(t.Context(), audit.CLI, login, goodPassword); !errors.Is(err, ErrLoginTaken) {
			t.Fatalf("Create with the taken login %q = %v, want ErrLoginTaken", login, err)
		}
	}
	cases := map[string]struct {
		login, password string
		rules           []string
	}{
		"a short password":      {"second", "short", []string{password.RuleMinLength}},
		"a common password":     {"second", "password1234", []string{password.RuleCommon}},
		"the login as password": {"second-admin", "second-admin", []string{password.RuleLogin}},
		"a long password":       {"second", strings.Repeat("x", 129), []string{password.RuleMaxLength}},
		"the login in capitals": {"mississippi-admin", "MISSISSIPPI-ADMIN", []string{password.RuleLogin}},
	}
	for name, c := range cases {
		var policyErr *PolicyError
		_, err := f.Create(t.Context(), audit.CLI, c.login, c.password)
		if !errors.As(err, &policyErr) {
			t.Errorf("%s: Create = %v, want a *PolicyError", name, err)
			continue
		}
		for _, rule := range c.rules {
			if !contains(policyErr.Rules, rule) {
				t.Errorf("%s: the broken rules are %v, want %s among them", name, policyErr.Rules, rule)
			}
		}
		if !strings.Contains(err.Error(), policyErr.Rules[0]) {
			t.Errorf("%s: the message %q does not name the rules", name, err)
		}
	}
	if list, err := f.List(t.Context()); err != nil || len(list) != 1 {
		t.Fatalf("a refused creation must leave nothing: %v, %v", list, err)
	}
	if records := f.records(t); len(records) != 1 {
		t.Fatalf("a refused creation must write no record: %d", len(records))
	}
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

type refusingHasher struct{ err error }

func (h refusingHasher) Hash(context.Context, string) (string, error) { return "", h.err }

func TestAFailureToHashOrToMakeAnIDIsReported(t *testing.T) {
	f := newFixture(t)
	f.create(t, "second")
	broken := errors.New("broken")
	f.hasher = refusingHasher{err: broken}
	if _, err := f.Create(t.Context(), audit.CLI, "root", goodPassword); !errors.Is(err, broken) {
		t.Fatalf("Create = %v, want the failure of the hasher", err)
	}
	if err := f.ResetPassword(t.Context(), audit.CLI, "second", goodPassword+"x"); !errors.Is(err, broken) {
		t.Fatalf("ResetPassword = %v, want the failure of the hasher", err)
	}
	g := newFixture(t)
	g.newID = func() (string, error) { return "", broken }
	if _, err := g.Create(t.Context(), audit.CLI, "root", goodPassword); !errors.Is(err, broken) {
		t.Fatalf("Create = %v, want the failure of the generator of IDs", err)
	}
}

type auditFails struct {
	store.Store
}

func (a auditFails) InTx(ctx context.Context, fn func(ctx context.Context, tx store.Repositories) error) error {
	return a.Store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		return fn(ctx, brokenAudit{tx})
	})
}

type brokenAudit struct{ store.Repositories }

func (b brokenAudit) Audit() store.Audit { return noAudit{} }

type noAudit struct{}

var errNoAudit = errors.New("the audit log is gone")

func (noAudit) Add(context.Context, store.AuditRecord) error { return errNoAudit }
func (noAudit) List(context.Context, store.AuditQuery) ([]store.AuditRecord, error) {
	return nil, errNoAudit
}
func (noAudit) DeleteBefore(context.Context, string, time.Time, int) (int, error) {
	return 0, errNoAudit
}

func TestAChangeThatCannotBeWrittenToTheAuditLogDoesNotHappen(t *testing.T) {
	plain := newFixture(t)
	plain.create(t, "root")
	f := &fixture{Service: plain.Service, store: plain.store, clock: plain.clock, keys: plain.keys}
	f.Service.store = auditFails{Store: plain.store}
	if _, err := f.Create(t.Context(), audit.CLI, "second", goodPassword); !errors.Is(err, errNoAudit) {
		t.Fatalf("Create = %v, want the failure of the audit log", err)
	}
	if _, err := plain.store.Admins().FindByLogin(t.Context(), store.DefaultTenant, "second"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an administrator whose creation could not be recorded exists: %v", err)
	}
	before := plain.stored(t, "root")
	for name, call := range map[string]func() error{
		"Delete":        func() error { return f.Delete(t.Context(), audit.CLI, "root") },
		"Disable":       func() error { return f.Disable(t.Context(), audit.CLI, "root") },
		"ResetPassword": func() error { return f.ResetPassword(t.Context(), audit.CLI, "root", goodPassword+"x") },
		"ResetTOTP":     func() error { return f.ResetTOTP(t.Context(), audit.CLI, "root") },
	} {
		if err := call(); !errors.Is(err, errNoAudit) {
			t.Errorf("%s = %v, want the failure of the audit log", name, err)
		}
	}
	if after := plain.stored(t, "root"); after.Version != before.Version || after.PasswordHash != before.PasswordHash || after.Status != store.AdminActive {
		t.Fatalf("a change that could not be recorded was made: %+v", after)
	}
}

func TestAnAdministratorIsDeleted(t *testing.T) {
	f := newFixture(t)
	account := f.create(t, "root")
	a := f.stored(t, "root")
	f.session(t, a, 1)
	if err := f.store.Admins().ReplaceRecoveryCodes(t.Context(), a.TenantID, a.ID, [][]byte{[]byte(strings.Repeat("h", 32))}); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(time.Minute)
	if err := f.Delete(t.Context(), audit.API, " ROOT "); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := f.store.Admins().Get(t.Context(), a.TenantID, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the administrator is still there: %v", err)
	}
	if left, err := f.store.Admins().CountRecoveryCodes(t.Context(), a.TenantID, a.ID); err != nil || left != 0 {
		t.Fatalf("the recovery codes stayed: %d, %v", left, err)
	}
	records := f.records(t)
	if len(records) != 2 || records[0].Action != audit.AdminDeleted || records[0].ActorID != "api" ||
		records[0].Details != `{"admin_id":"`+account.ID+`","login":"root"}` || !records[0].At.Equal(f.clock.read()) {
		t.Fatalf("the audit log holds %+v", records)
	}
	for _, login := range []string{"root", "nobody", "-bad-", ""} {
		if err := f.Delete(t.Context(), audit.CLI, login); !errors.Is(err, ErrNotFound) {
			t.Errorf("Delete(%q) = %v, want ErrNotFound", login, err)
		}
	}
	f.create(t, "root")
}

func TestTheAdministratorsAreListedByLogin(t *testing.T) {
	f := newFixture(t)
	for _, login := range []string{"zed", "ann", "mia"} {
		f.create(t, login)
		f.clock.advance(time.Hour)
	}
	mia := f.stored(t, "mia")
	mia.TOTPSecret = []byte("sealed")
	mia.TOTPConfirmedAt = f.clock.read()
	if _, err := f.store.Admins().Update(t.Context(), mia); err != nil {
		t.Fatal(err)
	}
	codes := [][]byte{[]byte(strings.Repeat("a", 32)), []byte(strings.Repeat("b", 32)), []byte(strings.Repeat("c", 32))}
	if err := f.store.Admins().ReplaceRecoveryCodes(t.Context(), mia.TenantID, mia.ID, codes); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Admins().UseRecoveryCode(t.Context(), mia.TenantID, mia.ID, codes[1], f.clock.read()); err != nil {
		t.Fatal(err)
	}
	if err := f.Disable(t.Context(), audit.CLI, "zed"); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Admins().RecordLogin(t.Context(), mia.TenantID, mia.ID, 2, f.clock.read()); err != nil {
		t.Fatal(err)
	}
	list, err := f.List(t.Context())
	if err != nil || len(list) != 3 {
		t.Fatalf("List = %v, %v", list, err)
	}
	if list[0].Login != "ann" || list[1].Login != "mia" || list[2].Login != "zed" {
		t.Fatalf("the accounts are %v, want them in the order of the logins", list)
	}
	if list[0].Disabled || list[0].TOTPBound || list[0].RecoveryCodes != 0 || !list[0].LastLoginAt.IsZero() {
		t.Fatalf("ann is %+v", list[0])
	}
	if list[1].Disabled || !list[1].TOTPBound || list[1].RecoveryCodes != 2 || !list[1].LastLoginAt.Equal(f.clock.read()) || !list[1].CreatedAt.Before(list[1].LastLoginAt) {
		t.Fatalf("mia is %+v", list[1])
	}
	if !list[2].Disabled {
		t.Fatalf("zed is %+v, want a disabled account", list[2])
	}
}

func TestAnAdministratorIsDisabledAndEnabled(t *testing.T) {
	f := newFixture(t)
	f.create(t, "root")
	a := f.stored(t, "root")
	f.session(t, a, 1)
	f.session(t, a, 2)
	other := f.create(t, "second")
	f.session(t, f.stored(t, other.Login), 3)

	if err := f.Disable(t.Context(), audit.CLI, "Root"); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}
	after := f.stored(t, "root")
	if after.Status != store.AdminDisabled || after.Version != a.Version+1 || f.sessions(t, a) != 0 {
		t.Fatalf("the administrator is %+v with %d sessions, want a disabled account without sessions", after, f.sessions(t, a))
	}
	if f.sessions(t, f.stored(t, "second")) != 1 {
		t.Fatal("the sessions of another administrator were ended")
	}
	if err := f.Disable(t.Context(), audit.CLI, "root"); err != nil {
		t.Fatalf("a second Disable = %v, want nothing to do", err)
	}
	if got := f.stored(t, "root"); got.Version != after.Version {
		t.Fatal("a second Disable changed the account")
	}
	if err := f.Enable(t.Context(), audit.CLI, "root"); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}
	if got := f.stored(t, "root"); got.Status != store.AdminActive || got.Version != after.Version+1 {
		t.Fatalf("the administrator is %+v after Enable", got)
	}
	if err := f.Enable(t.Context(), audit.CLI, "root"); err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, r := range f.records(t) {
		actions = append(actions, r.Action)
	}
	if strings.Join(actions, " ") != "admin.enabled admin.disabled admin.created admin.created" {
		t.Fatalf("the actions in the audit log are %v: a change that did nothing is not recorded", actions)
	}
	for _, call := range []func(context.Context, audit.Actor, string) error{f.Disable, f.Enable, f.ResetTOTP} {
		if err := call(t.Context(), audit.CLI, "nobody"); !errors.Is(err, ErrNotFound) {
			t.Errorf("a change of an administrator that does not exist = %v, want ErrNotFound", err)
		}
		if err := call(t.Context(), audit.CLI, "x"); !errors.Is(err, ErrNotFound) {
			t.Errorf("a change of a login that cannot exist = %v, want ErrNotFound", err)
		}
	}
}

func TestThePasswordOfAnAdministratorIsReset(t *testing.T) {
	f := newFixture(t)
	f.create(t, "root")
	before := f.stored(t, "root")
	f.session(t, before, 1)
	f.clock.advance(time.Minute)
	if err := f.ResetPassword(t.Context(), audit.API, " Root", "another very good password"); err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}
	after := f.stored(t, "root")
	if after.PasswordHash == before.PasswordHash || after.Version != before.Version+1 || f.sessions(t, before) != 0 {
		t.Fatalf("the administrator is %+v with %d sessions", after, f.sessions(t, before))
	}
	hasher, err := password.NewHasher(password.WithParams(password.Params{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}))
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, verifyErr := hasher.Verify(t.Context(), "another very good password", after.PasswordHash); verifyErr != nil || !ok {
		t.Fatalf("the new password does not verify: %v", verifyErr)
	}
	if ok, _, verifyErr := hasher.Verify(t.Context(), goodPassword, after.PasswordHash); verifyErr != nil || ok {
		t.Fatalf("the old password still verifies: %v", verifyErr)
	}
	records := f.records(t)
	if records[0].Action != audit.AdminPasswordReset || records[0].ActorID != "api" || strings.Contains(records[0].Details, "another") || strings.Contains(records[0].Details, after.PasswordHash) {
		t.Fatalf("the audit log holds %+v", records[0])
	}
	var policyErr *PolicyError
	if err = f.ResetPassword(t.Context(), audit.CLI, "root", "root"); !errors.As(err, &policyErr) || !contains(policyErr.Rules, password.RuleLogin) {
		t.Fatalf("ResetPassword with the login as the password = %v", err)
	}
	if err = f.ResetPassword(t.Context(), audit.CLI, "nobody", goodPassword); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ResetPassword of an administrator that does not exist = %v, want ErrNotFound", err)
	}
	if err = f.ResetPassword(t.Context(), audit.CLI, "?", goodPassword); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ResetPassword of a login that cannot exist = %v, want ErrNotFound", err)
	}
	if got := f.stored(t, "root"); got.PasswordHash != after.PasswordHash {
		t.Fatal("a refused reset changed the password")
	}
}

func TestTheAuthenticatorOfAnAdministratorIsReset(t *testing.T) {
	f := newFixture(t)
	f.create(t, "root")
	a := f.stored(t, "root")
	enrollment, err := f.NewEnrollment(a)
	if err != nil {
		t.Fatal(err)
	}
	a.TOTPSecret = enrollment.Sealed
	a.TOTPConfirmedAt = f.clock.read()
	if _, err = f.store.Admins().Update(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if err = f.store.Admins().ReplaceRecoveryCodes(t.Context(), a.TenantID, a.ID, [][]byte{[]byte(strings.Repeat("h", 32))}); err != nil {
		t.Fatal(err)
	}
	a = f.stored(t, "root")
	f.session(t, a, 1)
	f.create(t, "second")
	if err = f.ResetTOTP(t.Context(), audit.CLI, "root"); err != nil {
		t.Fatalf("ResetTOTP failed: %v", err)
	}
	after := f.stored(t, "root")
	if len(after.TOTPSecret) != 0 || !after.TOTPConfirmedAt.IsZero() || after.Version != a.Version+1 || after.PasswordHash != a.PasswordHash || f.sessions(t, a) != 0 {
		t.Fatalf("the administrator is %+v with %d sessions", after, f.sessions(t, a))
	}
	if left, countErr := f.store.Admins().CountRecoveryCodes(t.Context(), a.TenantID, a.ID); countErr != nil || left != 0 {
		t.Fatalf("the recovery codes stayed: %d, %v", left, countErr)
	}
	if records := f.records(t); records[0].Action != audit.AdminTOTPReset || records[0].ActorID != "cli" {
		t.Fatalf("the audit log holds %+v", records[0])
	}
}

type staleAdmins struct {
	store.Admins
	stale *int
}

func (s staleAdmins) Update(ctx context.Context, a store.Admin) (store.Admin, error) {
	if *s.stale > 0 {
		*s.stale--
		return store.Admin{}, store.ErrStale
	}
	return s.Admins.Update(ctx, a)
}

type staleStore struct {
	store.Store
	stale *int
}

func (s staleStore) InTx(ctx context.Context, fn func(ctx context.Context, tx store.Repositories) error) error {
	return s.Store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		return fn(ctx, staleRepositories{Repositories: tx, stale: s.stale})
	})
}

type staleRepositories struct {
	store.Repositories
	stale *int
}

func (s staleRepositories) Admins() store.Admins {
	return staleAdmins{Admins: s.Repositories.Admins(), stale: s.stale}
}

func TestAChangeThatLosesTheRaceIsMadeAgain(t *testing.T) {
	stale := 0
	f := newFixture(t, func(s store.Store) store.Store { return staleStore{Store: s, stale: &stale} })
	f.create(t, "root")
	stale = 2
	if err := f.Disable(t.Context(), audit.CLI, "root"); err != nil {
		t.Fatalf("Disable = %v, want the change to be made again", err)
	}
	if got := f.stored(t, "root"); got.Status != store.AdminDisabled {
		t.Fatalf("the administrator is %+v", got)
	}
	if records := f.records(t); len(records) != 2 {
		t.Fatalf("the change was recorded %d times, want once", len(records)-1)
	}
	stale = maxChangeAttempts
	if err := f.Enable(t.Context(), audit.CLI, "root"); !errors.Is(err, ErrConcurrent) {
		t.Fatalf("Enable = %v, want ErrConcurrent after %d lost races", err, maxChangeAttempts)
	}
	if got := f.stored(t, "root"); got.Status != store.AdminDisabled {
		t.Fatal("a change that lost every race was made")
	}
	if records := f.records(t); len(records) != 2 {
		t.Fatalf("a change that lost every race was recorded: %d records", len(records))
	}
}

func TestTheStoreFailsWhileAnAdministratorIsChanged(t *testing.T) {
	f := newFixture(t)
	f.create(t, "root")
	broken := errors.New("the store is gone")
	f.Service.store = failingStore{Store: f.store, err: broken}
	for name, err := range map[string]error{
		"Create":        func() error { _, e := f.Create(t.Context(), audit.CLI, "second", goodPassword); return e }(),
		"Delete":        f.Delete(t.Context(), audit.CLI, "root"),
		"Disable":       f.Disable(t.Context(), audit.CLI, "root"),
		"ResetPassword": f.ResetPassword(t.Context(), audit.CLI, "root", goodPassword+"x"),
		"ResetTOTP":     f.ResetTOTP(t.Context(), audit.CLI, "root"),
	} {
		if !errors.Is(err, broken) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrLoginTaken) {
			t.Errorf("%s = %v, want the failure of the store", name, err)
		}
	}
	if _, err := f.List(t.Context()); !errors.Is(err, broken) {
		t.Errorf("List = %v, want the failure of the store", err)
	}
}

type failingStore struct {
	store.Store
	err error
}

func (f failingStore) InTx(context.Context, func(ctx context.Context, tx store.Repositories) error) error {
	return f.err
}

func (f failingStore) Admins() store.Admins { return failingAdmins{err: f.err} }

type failingAdmins struct {
	store.Admins
	err error
}

func (f failingAdmins) List(context.Context, string) ([]store.Admin, error) { return nil, f.err }

type faults struct {
	find, remove, update, create, count, replace, endSessions error
}

type faultyAdmins struct {
	store.Admins
	faults
}

func (f faultyAdmins) FindByLogin(ctx context.Context, tenantID, login string) (store.Admin, error) {
	if f.find != nil {
		return store.Admin{}, f.find
	}
	return f.Admins.FindByLogin(ctx, tenantID, login)
}

func (f faultyAdmins) Create(ctx context.Context, a store.Admin) error {
	if f.create != nil {
		return f.create
	}
	return f.Admins.Create(ctx, a)
}

func (f faultyAdmins) Update(ctx context.Context, a store.Admin) (store.Admin, error) {
	if f.update != nil {
		return store.Admin{}, f.update
	}
	return f.Admins.Update(ctx, a)
}

func (f faultyAdmins) Delete(ctx context.Context, tenantID, id string) error {
	if f.remove != nil {
		return f.remove
	}
	return f.Admins.Delete(ctx, tenantID, id)
}

func (f faultyAdmins) CountRecoveryCodes(ctx context.Context, tenantID, id string) (int, error) {
	if f.count != nil {
		return 0, f.count
	}
	return f.Admins.CountRecoveryCodes(ctx, tenantID, id)
}

func (f faultyAdmins) ReplaceRecoveryCodes(ctx context.Context, tenantID, id string, hashes [][]byte) error {
	if f.replace != nil {
		return f.replace
	}
	return f.Admins.ReplaceRecoveryCodes(ctx, tenantID, id, hashes)
}

type faultySessions struct {
	store.AdminSessions
	err error
}

func (f faultySessions) DeleteForAdmin(context.Context, string, string, string) (int, error) {
	return 0, f.err
}

type faultyRepositories struct {
	store.Repositories
	faults
}

func (f faultyRepositories) Admins() store.Admins {
	return faultyAdmins{Admins: f.Repositories.Admins(), faults: f.faults}
}

func (f faultyRepositories) AdminSessions() store.AdminSessions {
	if f.endSessions == nil {
		return f.Repositories.AdminSessions()
	}
	return faultySessions{AdminSessions: f.Repositories.AdminSessions(), err: f.endSessions}
}

type faultyStore struct {
	store.Store
	faults
}

func (s faultyStore) Admins() store.Admins {
	return faultyAdmins{Admins: s.Store.Admins(), faults: s.faults}
}

func (s faultyStore) InTx(ctx context.Context, fn func(ctx context.Context, tx store.Repositories) error) error {
	return s.Store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		return fn(ctx, faultyRepositories{Repositories: tx, faults: s.faults})
	})
}

func TestAFailureInTheMiddleOfAChangeIsReportedAndLeavesNothingBehind(t *testing.T) {
	broken := errors.New("the store failed")
	disable := func(f *fixture) error { return f.Disable(t.Context(), audit.CLI, "root") }
	cases := []struct {
		name   string
		faults faults
		run    func(f *fixture) error
		want   error
	}{
		{"a creation that fails", faults{create: broken}, func(f *fixture) error {
			_, err := f.Create(t.Context(), audit.CLI, "second", goodPassword)
			return err
		}, broken},
		{"finding the administrator to delete", faults{find: broken}, func(f *fixture) error { return f.Delete(t.Context(), audit.CLI, "root") }, broken},
		{"deleting the administrator", faults{remove: broken}, func(f *fixture) error { return f.Delete(t.Context(), audit.CLI, "root") }, broken},
		{"deleting an administrator that another call deleted", faults{remove: store.ErrNotFound}, func(f *fixture) error {
			return f.Delete(t.Context(), audit.CLI, "root")
		}, ErrNotFound},
		{"finding the administrator to change", faults{find: broken}, disable, broken},
		{"updating the administrator", faults{update: broken}, disable, broken},
		{"ending the sessions", faults{endSessions: broken}, disable, broken},
		{"removing the recovery codes", faults{replace: broken}, func(f *fixture) error { return f.ResetTOTP(t.Context(), audit.CLI, "root") }, broken},
		{"counting the recovery codes", faults{count: broken}, func(f *fixture) error {
			_, err := f.List(t.Context())
			return err
		}, broken},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			f.create(t, "root")
			before := f.stored(t, "root")
			f.session(t, before, 1)
			f.Service.store = faultyStore{Store: f.store, faults: c.faults}
			if err := c.run(f); !errors.Is(err, c.want) {
				t.Fatalf("the error is %v, want %v", err, c.want)
			}
			if after := f.stored(t, "root"); after.Version != before.Version || after.Status != before.Status || after.PasswordHash != before.PasswordHash {
				t.Fatalf("a change that failed was made: %+v", after)
			}
			if f.sessions(t, before) != 1 {
				t.Fatal("a change that failed ended the sessions")
			}
			if records := f.records(t); len(records) != 1 || records[0].Action != audit.AdminCreated {
				t.Fatalf("a change that failed was recorded: %+v", records)
			}
		})
	}
}
