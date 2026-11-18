package admin

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

type nth struct {
	mu     sync.Mutex
	calls  int
	failAt int
	fired  bool
	err    error
}

func (n *nth) hit() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls++
	if n.calls == n.failAt {
		n.fired = true
		return n.err
	}
	return nil
}

func (n *nth) reached() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.fired
}

type nthAdmins struct {
	store.Admins
	n *nth
}

func (a nthAdmins) Get(ctx context.Context, tenantID, id string) (store.Admin, error) {
	if err := a.n.hit(); err != nil {
		return store.Admin{}, err
	}
	return a.Admins.Get(ctx, tenantID, id)
}

func (a nthAdmins) FindByLogin(ctx context.Context, tenantID, login string) (store.Admin, error) {
	if err := a.n.hit(); err != nil {
		return store.Admin{}, err
	}
	return a.Admins.FindByLogin(ctx, tenantID, login)
}

func (a nthAdmins) Update(ctx context.Context, x store.Admin) (store.Admin, error) {
	if err := a.n.hit(); err != nil {
		return store.Admin{}, err
	}
	return a.Admins.Update(ctx, x)
}

func (a nthAdmins) AcceptStep(ctx context.Context, tenantID, id string, version, step int64, at time.Time) error {
	if err := a.n.hit(); err != nil {
		return err
	}
	return a.Admins.AcceptStep(ctx, tenantID, id, version, step, at)
}

func (a nthAdmins) RecordLogin(ctx context.Context, tenantID, id string, version int64, at time.Time) error {
	if err := a.n.hit(); err != nil {
		return err
	}
	return a.Admins.RecordLogin(ctx, tenantID, id, version, at)
}

func (a nthAdmins) ReplaceRecoveryCodes(ctx context.Context, tenantID, id string, hashes [][]byte) error {
	if err := a.n.hit(); err != nil {
		return err
	}
	return a.Admins.ReplaceRecoveryCodes(ctx, tenantID, id, hashes)
}

func (a nthAdmins) UseRecoveryCode(ctx context.Context, tenantID, id string, hash []byte, at time.Time) error {
	if err := a.n.hit(); err != nil {
		return err
	}
	return a.Admins.UseRecoveryCode(ctx, tenantID, id, hash, at)
}

func (a nthAdmins) CountRecoveryCodes(ctx context.Context, tenantID, id string) (int, error) {
	if err := a.n.hit(); err != nil {
		return 0, err
	}
	return a.Admins.CountRecoveryCodes(ctx, tenantID, id)
}

type nthSessions struct {
	store.AdminSessions
	n *nth
}

func (s nthSessions) Create(ctx context.Context, row store.AdminSession) error {
	if err := s.n.hit(); err != nil {
		return err
	}
	return s.AdminSessions.Create(ctx, row)
}

func (s nthSessions) ResolveBySecret(ctx context.Context, tenantID string, hash []byte) (store.ResolvedAdminSession, error) {
	if err := s.n.hit(); err != nil {
		return store.ResolvedAdminSession{}, err
	}
	return s.AdminSessions.ResolveBySecret(ctx, tenantID, hash)
}

func (s nthSessions) Touch(ctx context.Context, tenantID, id string, at time.Time) error {
	if err := s.n.hit(); err != nil {
		return err
	}
	return s.AdminSessions.Touch(ctx, tenantID, id, at)
}

func (s nthSessions) TryAttempt(ctx context.Context, tenantID, id string, limit int) (bool, error) {
	if err := s.n.hit(); err != nil {
		return false, err
	}
	return s.AdminSessions.TryAttempt(ctx, tenantID, id, limit)
}

func (s nthSessions) Rebind(ctx context.Context, tenantID, adminID, id string, version int64) error {
	if err := s.n.hit(); err != nil {
		return err
	}
	return s.AdminSessions.Rebind(ctx, tenantID, adminID, id, version)
}

func (s nthSessions) Delete(ctx context.Context, tenantID, adminID, id string) error {
	if err := s.n.hit(); err != nil {
		return err
	}
	return s.AdminSessions.Delete(ctx, tenantID, adminID, id)
}

func (s nthSessions) DeleteForAdmin(ctx context.Context, tenantID, adminID, exceptID string) (int, error) {
	if err := s.n.hit(); err != nil {
		return 0, err
	}
	return s.AdminSessions.DeleteForAdmin(ctx, tenantID, adminID, exceptID)
}

func (s nthSessions) ListByAdmin(ctx context.Context, tenantID, adminID string, now time.Time) ([]store.AdminSession, error) {
	if err := s.n.hit(); err != nil {
		return nil, err
	}
	return s.AdminSessions.ListByAdmin(ctx, tenantID, adminID, now)
}

type nthAudit struct {
	store.Audit
	n *nth
}

func (a nthAudit) Add(ctx context.Context, r store.AuditRecord) error {
	if err := a.n.hit(); err != nil {
		return err
	}
	return a.Audit.Add(ctx, r)
}

type nthRepositories struct {
	store.Repositories
	n *nth
}

func (r nthRepositories) Admins() store.Admins {
	return nthAdmins{Admins: r.Repositories.Admins(), n: r.n}
}
func (r nthRepositories) AdminSessions() store.AdminSessions {
	return nthSessions{AdminSessions: r.Repositories.AdminSessions(), n: r.n}
}
func (r nthRepositories) Audit() store.Audit { return nthAudit{Audit: r.Repositories.Audit(), n: r.n} }

type nthStore struct {
	store.Store
	n *nth
}

func (s nthStore) Admins() store.Admins { return nthAdmins{Admins: s.Store.Admins(), n: s.n} }
func (s nthStore) AdminSessions() store.AdminSessions {
	return nthSessions{AdminSessions: s.Store.AdminSessions(), n: s.n}
}
func (s nthStore) Audit() store.Audit { return nthAudit{Audit: s.Store.Audit(), n: s.n} }

func (s nthStore) InTx(ctx context.Context, fn func(ctx context.Context, tx store.Repositories) error) error {
	return s.Store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		return fn(ctx, nthRepositories{Repositories: tx, n: s.n})
	})
}

type scenario struct {
	f      *fixture
	run    func() error
	effect func() int
}

func (f *fixture) effects(t *testing.T, adminID string) func() int {
	t.Helper()
	return func() int {
		sessions, err := f.store.AdminSessions().ListByAdmin(t.Context(), store.DefaultTenant, adminID, f.clock.read())
		if err != nil {
			t.Fatal(err)
		}
		logins := 0
		for _, r := range f.records(t) {
			if r.Action == audit.AdminLogin || r.Action == audit.AdminLogout {
				logins++
			}
		}
		return len(sessions)*100 + logins
	}
}

func TestAFailureOfTheStoreAtAnyStepOfASignInIsReportedAndChangesNothing(t *testing.T) {
	broken := errors.New("the store failed")
	scenarios := map[string]struct {
		ignorable bool
		prepare   func(t *testing.T) scenario
	}{
		"the password": {true, func(t *testing.T) scenario {
			f := newFixture(t)
			f.create(t, "root")
			return scenario{f: f, effect: func() int { return 0 }, run: func() error {
				_, err := f.CheckPassword(t.Context(), "root", goodPassword)
				return err
			}}
		}},
		"the start of the second step": {false, func(t *testing.T) scenario {
			f := newFixture(t)
			e := f.enroll(t, "root")
			return scenario{f: f, effect: f.effects(t, e.account.ID), run: func() error {
				_, err := f.Begin(t.Context(), e.admin, browser)
				return err
			}}
		}},
		"the second step with a one-time password": {false, func(t *testing.T) scenario {
			f := newFixture(t)
			e := f.enroll(t, "root")
			in, _ := f.begin(t, "root")
			return scenario{f: f, effect: f.effects(t, e.account.ID), run: func() error {
				_, err := f.Complete(t.Context(), in, f.code(e.seed), browser)
				return err
			}}
		}},
		"the second step with a recovery code": {false, func(t *testing.T) scenario {
			f := newFixture(t)
			e := f.enroll(t, "root")
			in, _ := f.begin(t, "root")
			return scenario{f: f, effect: f.effects(t, e.account.ID), run: func() error {
				_, err := f.Complete(t.Context(), in, e.codes[0], browser)
				return err
			}}
		}},
		"the binding of an authenticator": {false, func(t *testing.T) scenario {
			f := newFixture(t)
			f.create(t, "root")
			in, _ := f.begin(t, "root")
			return scenario{f: f, effect: func() int { return len(f.stored(t, "root").TOTPSecret) }, run: func() error {
				_, err := f.Enroll(t.Context(), in)
				return err
			}}
		}},
		"the confirmation of an authenticator": {false, func(t *testing.T) scenario {
			f := newFixture(t)
			account := f.create(t, "root")
			in, secret := f.begin(t, "root")
			enrollment, err := f.Enroll(t.Context(), in)
			if err != nil {
				t.Fatal(err)
			}
			if in, err = f.Pending(t.Context(), secret); err != nil {
				t.Fatal(err)
			}
			effect := f.effects(t, account.ID)
			return scenario{f: f, effect: func() int {
				if f.stored(t, "root").TOTPConfirmedAt.IsZero() {
					return effect()
				}
				return effect() + 1000
			}, run: func() error {
				_, _, completeErr := f.CompleteEnrollment(t.Context(), in, f.code(enrollment.Seed), browser)
				return completeErr
			}}
		}},
		"the use of a session": {false, func(t *testing.T) scenario {
			f := newFixture(t)
			e := f.enroll(t, "root")
			f.clock.advance(2 * time.Minute)
			return scenario{f: f, effect: func() int { return 0 }, run: func() error {
				_, err := f.Resolve(t.Context(), e.opened.Secret)
				return err
			}}
		}},
		"signing out": {false, func(t *testing.T) scenario {
			f := newFixture(t)
			e := f.enroll(t, "root")
			return scenario{f: f, effect: f.effects(t, e.account.ID), run: func() error { return f.End(t.Context(), e.opened.Session, browser) }}
		}},
		"the sign-in without a second factor": {false, func(t *testing.T) scenario {
			f := newFixture(t)
			account := f.create(t, "root")
			f.noTOTP = true
			a := f.stored(t, "root")
			return scenario{f: f, effect: f.effects(t, account.ID), run: func() error {
				_, err := f.Open(t.Context(), a, browser)
				return err
			}}
		}},
		"the record of a failure": {false, func(t *testing.T) scenario {
			f := newFixture(t)
			return scenario{f: f, effect: func() int { return len(f.records(t)) }, run: func() error {
				return f.RecordFailure(t.Context(), browser, "root", "", "password", "unknown_login")
			}}
		}},
	}
	for name, c := range scenarios {
		for failAt := 1; ; failAt++ {
			sc := c.prepare(t)
			before := sc.effect()
			n := &nth{failAt: failAt, err: broken}
			sc.f.Service.store = nthStore{Store: sc.f.store, n: n}
			err := sc.run()
			sc.f.Service.store = sc.f.store
			if !n.reached() {
				if err != nil {
					t.Errorf("%s: with no failure the call returned %v", name, err)
				}
				if failAt == 1 {
					t.Errorf("%s: the call does not touch the store", name)
				}
				break
			}
			if err == nil {
				if !c.ignorable {
					t.Errorf("%s: the failure of call %d was not reported", name, failAt)
				}
				continue
			}
			if !errors.Is(err, broken) && !errors.Is(err, ErrNoSignIn) && !errors.Is(err, ErrNoSession) {
				t.Errorf("%s: the failure of call %d came back as %v", name, failAt, err)
			}
			if after := sc.effect(); after != before {
				t.Errorf("%s: the failure of call %d left a trace: %d before and %d after", name, failAt, before, after)
			}
		}
	}
}
