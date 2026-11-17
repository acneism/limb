package limb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/store"
)

const recoveredPassword = "a password that is new and long 8"

func newRecoveryDatabase(t *testing.T, d *database) (*Auth, *recordingSender) {
	t.Helper()
	sender := &recordingSender{}
	all := []Option{
		WithTablePrefix(d.Prefix(t)), WithAutoMigrate(), WithLogger(discardingLogger()),
		WithIdentifiers(identifier.Email(identifier.Required()), identifier.Username()),
		WithSender(sender), WithSignup(), WithServiceName("Acme"), manyRequests(),
		WithVerifyURL("https://app.example.com/verify"), WithResetURL("https://app.example.com/reset"),
	}
	a, err := New(d.DB, d.dialect, []byte(testKey), all...)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	a.hasher = newHasher(t, weakParams)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = a.Shutdown(ctx)
	})
	return a, sender
}

func waitForMessage(t *testing.T, s *recordingSender, from int, kind MessageKind, to string) Message {
	t.Helper()
	var found Message
	eventually(t, fmt.Sprintf("a message of the kind %s for %s", kind, to), func() bool {
		sent := s.sent()
		for _, m := range sent[min(from, len(sent)):] {
			if m.Kind == kind && m.To == to {
				found = m
				return true
			}
		}
		return false
	})
	return found
}

func signupOf(email, nick string) SignupRequest {
	return SignupRequest{
		Registration: Registration{Identifiers: map[string]string{"email": email, "username": nick}, Password: goodPassword},
		IP:           ipOne,
	}
}

func cookieLogin(login, password string) Credentials {
	return Credentials{Login: login, Password: password, IP: ipOne, Kind: SessionCookie}
}

func TestVisitorsSignUpConfirmAndRecoverOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		a, sender := newRecoveryDatabase(t, d)
		ctx := t.Context()

		if err := a.Signup(ctx, signupOf("Olga@Example.com", "olga_o")); err != nil {
			t.Fatalf("Signup = %v", err)
		}
		confirm := waitForMessage(t, sender, 0, MessageVerification, "olga@example.com")
		if _, err := a.Login(ctx, cookieLogin("olga_o", goodPassword)); !errors.Is(err, ErrVerificationRequired) {
			t.Fatalf("Login before the confirmation = %v, want ErrVerificationRequired", err)
		}
		if err := a.Verify(ctx, VerifyRequest{Token: tokenOf(confirm.Link), IP: ipOne}); err != nil {
			t.Fatalf("Verify = %v", err)
		}
		if err := a.Verify(ctx, VerifyRequest{Login: "olga_o", Code: confirm.Code, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
			t.Fatalf("the code that was sent with a link that is used = %v, want it ended with the link", err)
		}
		first, err := a.Login(ctx, cookieLogin("olga_o", goodPassword))
		if err != nil {
			t.Fatalf("Login after the confirmation = %v", err)
		}

		from := len(sender.sent())
		if err = a.Signup(ctx, signupOf("OLGA@example.com", "other_o")); err != nil {
			t.Fatalf("Signup with a taken address = %v, want nil", err)
		}
		notice := waitForMessage(t, sender, from, MessageSignupAttempt, "olga@example.com")
		if notice.Code != "" || notice.Link != "" {
			t.Fatalf("notice = %+v", notice)
		}
		if _, err = a.store.Identifiers().Find(ctx, store.DefaultTenant, "username", "other_o"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the nickname of a registration that used a taken address was stored: %v", err)
		}
		err = a.Signup(ctx, signupOf("third@example.com", "OLGA_O"))
		wantInvalid(t, err, "username")
		if _, err = a.store.Identifiers().Find(ctx, store.DefaultTenant, "email", "third@example.com"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the address of a registration that used a taken nickname was stored: %v", err)
		}

		from = len(sender.sent())
		if err = a.RequestPasswordReset(ctx, ResetRequest{Login: "olga_o", IP: ipOne}); err != nil {
			t.Fatalf("RequestPasswordReset = %v", err)
		}
		reset := waitForMessage(t, sender, from, MessagePasswordReset, "olga@example.com")
		var policy *PolicyError
		if err = a.ResetPassword(ctx, ResetPasswordRequest{Token: tokenOf(reset.Link), Password: "short", IP: ipOne}); !errors.As(err, &policy) {
			t.Fatalf("a weak password = %v, want a *PolicyError", err)
		}
		from = len(sender.sent())
		if err = a.ResetPassword(ctx, ResetPasswordRequest{Token: tokenOf(reset.Link), Password: recoveredPassword, IP: ipOne}); err != nil {
			t.Fatalf("ResetPassword = %v", err)
		}
		if err = a.ResetPassword(ctx, ResetPasswordRequest{Token: tokenOf(reset.Link), Password: recoveredPassword + "2", IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
			t.Fatalf("the link a second time = %v, want ErrInvalidSecret", err)
		}
		waitForMessage(t, sender, from, MessagePasswordChanged, "olga@example.com")
		resolved, err := a.store.Sessions().ResolveByID(ctx, store.DefaultTenant, first.Principal.SessionID)
		if err != nil || resolved.Session.RevokedAt.IsZero() {
			t.Fatalf("the session of before the reset = %+v, %v; it must have ended", resolved.Session, err)
		}
		if _, err = a.Login(ctx, cookieLogin("olga_o", goodPassword)); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("the old password = %v, want ErrInvalidCredentials", err)
		}
		if _, err = a.Login(ctx, cookieLogin("olga@example.com", recoveredPassword)); err != nil {
			t.Fatalf("the new password = %v", err)
		}
	})
}

func TestACodeSurvivesFiveGuessesOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		a, sender := newRecoveryDatabase(t, d)
		ctx := t.Context()
		if err := a.Signup(ctx, signupOf("ivan@example.com", "ivan_i")); err != nil {
			t.Fatal(err)
		}
		m := waitForMessage(t, sender, 0, MessageVerification, "ivan@example.com")
		for i := range 5 {
			err := a.Verify(ctx, VerifyRequest{Login: "ivan_i", Code: wrongCode(m.Code), IP: ipOne})
			if !errors.Is(err, ErrInvalidSecret) {
				t.Fatalf("guess %d = %v, want ErrInvalidSecret", i, err)
			}
		}
		if err := a.Verify(ctx, VerifyRequest{Login: "ivan_i", Code: m.Code, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
			t.Fatalf("the right code after five guesses = %v, want it dead", err)
		}
		from := len(sender.sent())
		if err := a.RequestVerification(ctx, VerificationRequest{Login: "ivan@example.com", IP: ipOne}); err != nil {
			t.Fatal(err)
		}
		again := waitForMessage(t, sender, from, MessageVerification, "ivan@example.com")
		if err := a.Verify(ctx, VerifyRequest{Channel: "ivan@example.com", Code: again.Code, IP: ipOne}); err != nil {
			t.Fatalf("the code of a new request = %v", err)
		}
	})
}

func TestOnlyOneSignupForAnAddressCreatesTheUserOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		a, sender := newRecoveryDatabase(t, d)
		ctx := t.Context()
		const racers = 8
		var wg sync.WaitGroup
		for n := range racers {
			wg.Go(func() {
				if err := a.Signup(ctx, signupOf("race@example.com", fmt.Sprintf("racer_%d", n))); err != nil {
					t.Errorf("racer %d: %v", n, err)
				}
			})
		}
		wg.Wait()
		left := 0
		for n := range racers {
			if _, err := a.store.Identifiers().Find(ctx, store.DefaultTenant, "username", fmt.Sprintf("racer_%d", n)); err == nil {
				left++
			}
		}
		if left != 1 {
			t.Fatalf("%d users were created for one address, want 1", left)
		}
		owner := waitForMessage(t, sender, 0, MessageVerification, "race@example.com")
		eventually(t, "the tasks of the messages to end", func() bool { return a.dispatcher.pending.Load() == 0 })
		notices := 0
		for _, m := range sender.sent() {
			if m.Kind == MessageSignupAttempt && m.To == "race@example.com" && m.UserID == owner.UserID {
				notices++
			}
		}
		if notices < 1 || notices > messagesPerHour {
			t.Fatalf("%d notices were sent to the owner, want at least one and at most %d", notices, messagesPerHour)
		}
		for _, m := range sender.sent() {
			if strings.Contains(m.Text, goodPassword) {
				t.Fatalf("a message holds the password: %+v", m)
			}
		}
	})
}

func TestARegistrationThatTheApplicationConfirmsNeedsNoMessageOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		a, sender := newRecoveryDatabase(t, d)
		ctx := t.Context()
		_, err := a.Register(ctx, Registration{
			Identifiers: map[string]string{"email": "boris@example.com", "username": "boris_b"}, Password: goodPassword, Verified: []string{"email"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = a.Login(ctx, cookieLogin("boris_b", goodPassword)); err != nil {
			t.Fatalf("Login = %v", err)
		}
		stored, err := a.store.Identifiers().Find(ctx, store.DefaultTenant, "email", "boris@example.com")
		if err != nil || stored.VerifiedAt.IsZero() {
			t.Fatalf("identifier = %+v, %v", stored, err)
		}
		if got := sender.sent(); len(got) != 0 {
			t.Fatalf("messages = %+v, want none", got)
		}
	})
}
