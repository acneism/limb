package limb

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/acneism/limb/internal/memstore"
	"github.com/acneism/limb/store"
)

var errFirstRunRolledBack = errors.New("the first run was rolled back")

type repeatingStore struct {
	store.Store
	between func()
}

func (s *repeatingStore) InTx(ctx context.Context, fn func(ctx context.Context, tx store.Repositories) error) error {
	err := s.Store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if err := fn(ctx, tx); err != nil {
			return err
		}
		return errFirstRunRolledBack
	})
	if !errors.Is(err, errFirstRunRolledBack) {
		return err
	}
	if s.between != nil {
		s.between()
	}
	return s.Store.InTx(ctx, fn)
}

type repeatFixture struct {
	*sessionFixture
	inner  store.Store
	repeat *repeatingStore
}

func newRepeatFixture(t *testing.T) *repeatFixture {
	t.Helper()
	inner := memstore.New()
	repeat := &repeatingStore{Store: inner}
	a, err := NewWithStore(repeat, []byte(testKey), WithAutoMigrate(), WithLogger(discardingLogger()), emailAndUsername())
	if err != nil {
		t.Fatalf("NewWithStore failed: %v", err)
	}
	a.hasher = newHasher(t, weakParams)
	user := mustRegister(t, a, map[string]string{"email": "Nina@Example.com", "username": "nina_n"}, goodPassword)
	clock := newFakeClock()
	a.now = clock.now
	return &repeatFixture{
		sessionFixture: &sessionFixture{fixture: &fixture{a: a, user: user}, clock: clock},
		inner:          inner,
		repeat:         repeat,
	}
}

func TestRegisterIsTheSameWhenItsTransactionRunsTwice(t *testing.T) {
	f := newRepeatFixture(t)
	other := mustRegister(t, f.a, map[string]string{"email": "omar@example.com", "username": "omar_o"}, goodPassword)
	if other.ID == f.user.ID || other.ID == "" {
		t.Fatalf("users = %v and %v", f.user.ID, other.ID)
	}
	_, err := f.a.Register(t.Context(), Registration{Identifiers: map[string]string{"email": "omar@example.com"}, Password: goodPassword})
	if !errors.Is(err, ErrIdentifierTaken) {
		t.Fatalf("Register of a taken e-mail address = %v, want ErrIdentifierTaken", err)
	}
	found, err := f.inner.Identifiers().Find(t.Context(), f.a.tenant, "email", "omar@example.com")
	if err != nil || found.UserID != string(other.ID) {
		t.Fatalf("identifier = %+v, %v", found, err)
	}
}

func TestSigningInWithTokensIsTheSameWhenItsTransactionRunsTwice(t *testing.T) {
	f := newRepeatFixture(t)
	login := f.tokenLogin(t)
	if !f.works(t, login) {
		t.Fatal("the access token must work")
	}
	sessions, err := f.a.Sessions(t.Context(), login.Principal)
	if err != nil || len(sessions) != 1 || sessions[0].ID != login.Principal.SessionID {
		t.Fatalf("sessions = %+v, %v; want only the new one", sessions, err)
	}
	if keys, listErr := f.inner.SigningKeys().List(t.Context()); listErr != nil || len(keys) != 1 || keys[0].Generation != 1 {
		t.Fatalf("signing keys = %+v, %v; want the first one only", keys, listErr)
	}
	renewed := f.mustRefresh(t, login.Tokens.RefreshToken)
	if renewed.RefreshToken == "" || renewed.RefreshToken == login.Tokens.RefreshToken {
		t.Fatalf("tokens after the refresh = %+v", renewed)
	}
}

func TestRefreshIsTheSameWhenItsTransactionRunsTwice(t *testing.T) {
	f := newRepeatFixture(t)
	login := f.tokenLogin(t)
	renewed := f.mustRefresh(t, login.Tokens.RefreshToken)
	f.refused(t, "the used token", login.Tokens.RefreshToken)
	again := f.mustRefresh(t, renewed.RefreshToken)
	if again.RefreshToken == renewed.RefreshToken {
		t.Fatal("every refresh must give a new token")
	}
}

func TestRefreshForgetsWhatTheFirstRunDid(t *testing.T) {
	f := newRepeatFixture(t)
	login := f.tokenLogin(t)
	f.repeat.between = func() {
		if _, err := f.inner.RefreshTokens().DeleteExpired(t.Context(), f.a.tenant, f.clock.now().Add(365*24*time.Hour)); err != nil {
			t.Error(err)
		}
	}
	tokens, outcome, err := f.a.refresh(t.Context(), login.Tokens.RefreshToken)
	if err != ErrUnauthenticated || tokens != (Tokens{}) || outcome != refreshRefused { //nolint:errorlint
		t.Fatalf("refresh = %+v, %v, %v; the token that disappeared between the runs must be refused", tokens, outcome, err)
	}
}

func TestChangingThePasswordIsTheSameWhenItsTransactionRunsTwice(t *testing.T) {
	f := newRepeatFixture(t)
	opens := map[string]func() Login{
		"cookie": func() Login { return f.login(t) },
		"token":  func() Login { return f.tokenLogin(t) },
	}
	for name, open := range opens {
		old, other := open(), f.login(t)
		changed, err := f.a.ChangePassword(t.Context(), old.Principal, goodPassword, newPassword)
		if err != nil {
			t.Fatalf("%s: ChangePassword = %v", name, err)
		}
		if !f.works(t, changed) || f.works(t, old) || f.works(t, other) {
			t.Fatalf("%s: only the new session may work", name)
		}
		if _, err = f.a.ChangePassword(t.Context(), changed.Principal, newPassword, goodPassword); err != nil {
			t.Fatalf("%s: changing it back = %v", name, err)
		}
	}
}

func TestChangingThePasswordFailsWhenTheFirstRunWasRightAndTheSecondOneIsNot(t *testing.T) {
	f := newRepeatFixture(t)
	login := f.login(t)
	f.repeat.between = func() {
		f.change(t, func(u *store.User) { u.PasswordHash = "$changed" })
	}
	got, err := f.a.ChangePassword(t.Context(), login.Principal, goodPassword, newPassword)
	if err != ErrInvalidCredentials || got.Secret != "" || got.Principal != (Principal{}) { //nolint:errorlint
		t.Fatalf("ChangePassword = %+v, %v; the password that changed between the runs must be refused", got, err)
	}
}

func TestKeyRotationIsTheSameWhenItsTransactionRunsTwice(t *testing.T) {
	f := newRepeatFixture(t)
	f.tokenLogin(t)
	f.clock.advance(keyRotation - publishDelay)
	f.tokenLogin(t)
	keys, err := f.inner.SigningKeys().List(t.Context())
	if err != nil || len(keys) != 2 || keys[0].Generation != 1 || keys[1].Generation != 2 || keys[0].RetireAfter.IsZero() || !keys[1].RetireAfter.IsZero() {
		t.Fatalf("signing keys = %+v, %v; want two, the first one retired", keys, err)
	}
	request := f.bearer(t, http.MethodGet, f.tokenLogin(t).Tokens.AccessToken)
	if _, err = f.a.Authenticate(request); err != nil {
		t.Fatalf("a token signed after the rotation does not work: %v", err)
	}
}
