package limb

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

const resetPassword = "a brand new password that is long 7"

func (f *recoveryFixture) ofKind(t *testing.T, kind MessageKind, n int) []Message {
	t.Helper()
	eventually(t, "the messages to be sent", func() bool {
		count := 0
		for _, m := range f.sender.sent() {
			if m.Kind == kind {
				count++
			}
		}
		return count >= n
	})
	f.idle(t)
	var got []Message
	for _, m := range f.sender.sent() {
		if m.Kind == kind {
			got = append(got, m)
		}
	}
	if len(got) != n {
		t.Fatalf("%d messages of the kind %s were sent, want %d: %+v", len(got), kind, n, got)
	}
	return got
}

func (f *recoveryFixture) requestReset(t *testing.T, login string) {
	t.Helper()
	if err := f.a.RequestPasswordReset(t.Context(), ResetRequest{Login: login, IP: ipOne}); err != nil {
		t.Fatalf("RequestPasswordReset(%q) = %v", login, err)
	}
}

func (f *recoveryFixture) sendReset(t *testing.T) Message {
	t.Helper()
	f.sender.clear()
	f.requestReset(t, "nina_n")
	return f.ofKind(t, MessagePasswordReset, 1)[0]
}

func (f *recoveryFixture) signIn(t *testing.T, login, password string) (Login, error) {
	t.Helper()
	return f.a.Login(t.Context(), Credentials{Login: login, Password: password, IP: ipOne, Kind: SessionCookie})
}

func newResetFixture(t *testing.T, opts ...Option) *recoveryFixture {
	t.Helper()
	f := newRecoveryFixture(t, append([]Option{manyRequests()}, opts...)...)
	f.verify(t, "email", "nina@example.com")
	return f
}

func TestAResetSendsALinkAndACodeToTheConfirmedChannel(t *testing.T) {
	f := newResetFixture(t)
	f.requestReset(t, "nina_n")
	m := f.ofKind(t, MessagePasswordReset, 1)[0]
	now := f.clock.now().UTC()
	if m.UserID != string(f.user.ID) || m.Channel != "email" || m.To != "nina@example.com" || !strings.HasPrefix(m.Link, "https://app.example.com/reset#token=") ||
		!sixDigitCode.MatchString(m.Code) || !strings.Contains(m.Subject, "Reset your password on Acme") {
		t.Fatalf("message = %+v", m)
	}
	if !m.LinkExpiresAt.Equal(now.Add(30*time.Minute)) || !m.CodeExpiresAt.Equal(now.Add(10*time.Minute)) || !strings.Contains(m.Text, "30 minutes") {
		t.Fatalf("the link ends %v and the code %v; text:\n%s", m.LinkExpiresAt, m.CodeExpiresAt, m.Text)
	}
}

func TestAResetGoesOnlyToTheChannelsThatAreConfirmed(t *testing.T) {
	f := newRecoveryFixture(t, manyRequests())
	f.requestReset(t, "nina_n")
	f.noMessages(t)
	f.addPhone(t)
	f.verify(t, "email", "nina@example.com")
	f.requestReset(t, "nina_n")
	got := f.ofKind(t, MessagePasswordReset, 1)
	if got[0].Channel != "email" {
		t.Fatalf("message = %+v, want only the channel that is confirmed", got[0])
	}
	f.verify(t, "sms", ninaPhone)
	f.sender.clear()
	f.clock.advance(time.Minute)
	f.requestReset(t, "nina_n")
	both := f.ofKind(t, MessagePasswordReset, 2)
	channels := []string{both[0].Channel, both[1].Channel}
	slices.Sort(channels)
	if !slices.Equal(channels, []string{"email", "sms"}) {
		t.Fatalf("channels = %v", channels)
	}
}

func TestAResetIsSentToABlockedUserAndNotToADeletedOne(t *testing.T) {
	f := newResetFixture(t)
	f.change(t, func(u *store.User) { u.Status = store.StatusDeleted })
	f.requestReset(t, "nina_n")
	f.noMessages(t)
	f.change(t, func(u *store.User) { u.Status = store.StatusBlocked })
	f.clock.advance(time.Minute)
	f.requestReset(t, "nina_n")
	f.ofKind(t, MessagePasswordReset, 1)
}

func TestTheRequestOfAResetIsAnsweredAlikeWhateverTheLogin(t *testing.T) {
	f := newResetFixture(t, WithSending(SendingOptions{Workers: 1, Queue: 8}))
	release := f.block(t)
	log := &accessLog{Store: f.a.store}
	f.a.store = log
	var seen [][]string
	for _, login := range []string{"nina_n", "nina@example.com", "nobody_here", "nobody@example.com"} {
		before := len(log.taken())
		f.requestReset(t, login)
		seen = append(seen, log.taken()[before:])
	}
	for i, names := range seen {
		if !slices.Equal(names, seen[0]) {
			t.Errorf("the request %d touched %v, the first one %v", i, names, seen[0])
		}
		for _, forbidden := range []string{"users", "identifiers", "secrets", "transaction", "sessions"} {
			if slices.Contains(names, forbidden) {
				t.Errorf("the request %d touched %q before it answered: %v", i, forbidden, names)
			}
		}
	}
	release()
	f.ofKind(t, MessagePasswordReset, 2)
}

func TestResetNeedsASenderAndAChannel(t *testing.T) {
	plain := newTestAuth(t, emailAndUsername())
	if err := plain.RequestPasswordReset(t.Context(), ResetRequest{Login: "nina@example.com"}); !errors.Is(err, ErrRecoveryDisabled) {
		t.Fatalf("RequestPasswordReset = %v, want ErrRecoveryDisabled", err)
	}
	if err := plain.ResetPassword(t.Context(), ResetPasswordRequest{Token: strings.Repeat("A", 43), Password: resetPassword}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("ResetPassword without a Sender = %v, want ErrInvalidSecret: there is no secret that could be right", err)
	}
}

func TestTheLinkOfAResetChoosesANewPasswordAndEndsTheSessions(t *testing.T) {
	f := newResetFixture(t)
	old, err := f.signIn(t, "nina_n", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	f.change(t, func(u *store.User) { u.MustChangePassword = true })
	m := f.sendReset(t)
	f.events.take()
	f.sender.clear()
	f.clock.advance(time.Minute)
	err = f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: resetPassword, IP: ipOne, Language: "ru"})
	if err != nil {
		t.Fatalf("ResetPassword = %v", err)
	}
	events := f.events.take()
	wantTypes(t, events, EventPasswordReset, EventSessionEnded)
	if events[0].UserID != string(f.user.ID) || events[0].Channel != "email" || events[0].Address != "n***@example.com" || events[0].IP != ipOne.String() ||
		events[1].Details["reason"] != "password_reset" || events[1].Details["count"] != "1" {
		t.Fatalf("events = %+v", events)
	}
	if _, err = f.signIn(t, "nina_n", goodPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("the old password = %v, want it refused", err)
	}
	fresh, err := f.signIn(t, "nina_n", resetPassword)
	if err != nil || fresh.Principal.MustChangePassword {
		t.Fatalf("the new password = %+v, %v; the user must not have to change it again", fresh, err)
	}
	if f.sessionAlive(t, old) {
		t.Fatal("a session that existed before the reset survived it")
	}
	notice := f.ofKind(t, MessagePasswordChanged, 1)[0]
	if notice.Language != "ru" || notice.To != "nina@example.com" || notice.Code != "" || notice.Link != "" || !strings.Contains(notice.Subject, "Пароль изменён") {
		t.Fatalf("notice = %+v", notice)
	}
	if err = f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: resetPassword + "2", IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("the link a second time = %v, want ErrInvalidSecret", err)
	}
}

func (f *recoveryFixture) sessionAlive(t *testing.T, login Login) bool {
	t.Helper()
	resolved, err := f.a.store.Sessions().ResolveByID(t.Context(), f.a.tenant, login.Principal.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	return resolved.Session.RevokedAt.IsZero()
}

func TestTheCodeOfAResetChoosesANewPassword(t *testing.T) {
	for _, by := range []string{"login", "channel"} {
		f := newResetFixture(t)
		m := f.sendReset(t)
		r := ResetPasswordRequest{Code: m.Code[:3] + " " + m.Code[3:], Password: resetPassword, IP: ipOne}
		if by == "login" {
			r.Login = "nina_n"
		} else {
			r.Channel = "NINA@example.com"
		}
		if err := f.a.ResetPassword(t.Context(), r); err != nil {
			t.Fatalf("by %s: %v", by, err)
		}
		if _, err := f.signIn(t, "nina_n", resetPassword); err != nil {
			t.Fatalf("by %s: the new password does not work: %v", by, err)
		}
		if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: resetPassword + "2", IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
			t.Fatalf("by %s: the link of the same message = %v, want it ended", by, err)
		}
	}
}

func TestTheSessionsOfAUserSurviveAResetOnRequest(t *testing.T) {
	f := newResetFixture(t, WithKeepSessionsAfterReset())
	old, err := f.signIn(t, "nina_n", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	m := f.sendReset(t)
	f.events.take()
	if err = f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: resetPassword, IP: ipOne}); err != nil {
		t.Fatal(err)
	}
	if !f.sessionAlive(t, old) {
		t.Fatal("a session ended although WithKeepSessionsAfterReset was given")
	}
	wantTypes(t, f.events.take(), EventPasswordReset)
}

func TestAPasswordThatBreaksThePolicyLeavesTheSecretUsable(t *testing.T) {
	f := newResetFixture(t)
	m := f.sendReset(t)
	var policy *PolicyError
	weak := map[string]string{"short": "min_length", "unbelievable": "common_password", "NINA@example.com": "login_identifier"}
	for password, rule := range weak {
		err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: password, IP: ipOne})
		if !errors.As(err, &policy) || !slices.Contains(policy.Rules, rule) {
			t.Fatalf("password %q = %v, want a *PolicyError with the rule %s", password, err, rule)
		}
	}
	if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: resetPassword, IP: ipOne}); err != nil {
		t.Fatalf("the link after weak passwords = %v, it must still work", err)
	}
	f.events.take()
	g := newResetFixture(t)
	m = g.sendReset(t)
	for range 4 {
		if err := g.a.ResetPassword(t.Context(), ResetPasswordRequest{Login: "nina_n", Code: m.Code, Password: "short", IP: ipOne}); !errors.As(err, &policy) {
			t.Fatalf("a weak password with the right code = %v, want a *PolicyError", err)
		}
	}
	if err := g.a.ResetPassword(t.Context(), ResetPasswordRequest{Login: "nina_n", Code: m.Code, Password: resetPassword, IP: ipOne}); err != nil {
		t.Fatalf("the fifth guess with a good password = %v", err)
	}
	h := newResetFixture(t)
	m = h.sendReset(t)
	for range 5 {
		_ = h.a.ResetPassword(t.Context(), ResetPasswordRequest{Login: "nina_n", Code: m.Code, Password: "short", IP: ipOne})
	}
	if err := h.a.ResetPassword(t.Context(), ResetPasswordRequest{Login: "nina_n", Code: m.Code, Password: resetPassword, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("a code that has been guessed five times = %v, want it dead", err)
	}
}

func TestASecretOfOnePurposeDoesNotWorkForAnother(t *testing.T) {
	f := newResetFixture(t)
	reset := f.sendReset(t)
	f.sender.clear()
	f.addPhone(t)
	f.requestVerification(t, "nina_n")
	verification := f.ofKind(t, MessageVerification, 1)[0]
	if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(verification.Link), Password: resetPassword, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("a link of verification for a reset = %v, want ErrInvalidSecret", err)
	}
	if err := f.a.Verify(t.Context(), VerifyRequest{Token: tokenOf(reset.Link), IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("a link of a reset for a verification = %v, want ErrInvalidSecret", err)
	}
	if err := f.a.Verify(t.Context(), VerifyRequest{Token: tokenOf(verification.Link), IP: ipOne}); err != nil {
		t.Fatalf("the link of verification still works for a verification: %v", err)
	}
	if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(reset.Link), Password: resetPassword, IP: ipOne}); err != nil {
		t.Fatalf("the link of the reset still works for a reset: %v", err)
	}
}

func TestResetSecretsExpireAtTheirTime(t *testing.T) {
	f := newResetFixture(t)
	m := f.sendReset(t)
	f.clock.advance(30*time.Minute - time.Second)
	if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: resetPassword, IP: ipOne}); err != nil {
		t.Fatalf("the link a second before it expires = %v", err)
	}
	g := newResetFixture(t)
	m = g.sendReset(t)
	g.clock.advance(30 * time.Minute)
	if err := g.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: resetPassword, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("the link when it expires = %v, want ErrInvalidSecret", err)
	}
	h := newResetFixture(t)
	m = h.sendReset(t)
	h.clock.advance(10 * time.Minute)
	if err := h.a.ResetPassword(t.Context(), ResetPasswordRequest{Login: "nina_n", Code: m.Code, Password: resetPassword, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("the code when it expires = %v, want ErrInvalidSecret", err)
	}
}

func TestAResetEndsTheSecretsOfEveryChannel(t *testing.T) {
	f := newResetFixture(t)
	f.addPhone(t)
	f.verify(t, "sms", ninaPhone)
	f.sender.clear()
	f.requestReset(t, "nina_n")
	messages := f.ofKind(t, MessagePasswordReset, 2)
	var email, phone Message
	for _, m := range messages {
		if m.Channel == "email" {
			email = m
		} else {
			phone = m
		}
	}
	if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(email.Link), Password: resetPassword, IP: ipOne}); err != nil {
		t.Fatal(err)
	}
	if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Channel: ninaPhone, Code: phone.Code, Password: resetPassword + "x", IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("the code of the other channel after a reset = %v, want it ended", err)
	}
	if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(phone.Link), Password: resetPassword + "x", IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("the link of the other channel after a reset = %v, want it ended", err)
	}
	f.ofKind(t, MessagePasswordChanged, 2)
}

func TestAResetNeedsAChannelThatIsStillConfirmedAndAUserWhoIsNotDeleted(t *testing.T) {
	f := newResetFixture(t)
	token, hash, err := newSecret()
	if err != nil {
		t.Fatal(err)
	}
	f.addPhone(t)
	now := f.clock.now().UTC().Truncate(time.Microsecond)
	forged := store.Secret{
		TenantID: f.a.tenant, ID: "00000000-0000-7000-8000-00000000f002", Kind: store.SecretLink, Hash: hash, UserID: string(f.user.ID),
		Purpose: store.PurposeReset, ChannelType: "sms", ChannelValue: ninaPhone, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err = f.a.store.Secrets().Add(t.Context(), forged); err != nil {
		t.Fatal(err)
	}
	if err = f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: token, Password: resetPassword, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("a secret of a channel that is not confirmed = %v, want ErrInvalidSecret", err)
	}
	g := newResetFixture(t)
	m := g.sendReset(t)
	g.change(t, func(u *store.User) { u.Status = store.StatusDeleted })
	if err = g.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: resetPassword, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("a deleted user = %v, want ErrInvalidSecret", err)
	}
}

func TestABlockedUserCanResetAndStaysBlocked(t *testing.T) {
	f := newResetFixture(t)
	m := f.sendReset(t)
	f.change(t, func(u *store.User) { u.Status = store.StatusBlocked })
	if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: resetPassword, IP: ipOne}); err != nil {
		t.Fatalf("ResetPassword = %v", err)
	}
	if _, err := f.signIn(t, "nina_n", resetPassword); !errors.Is(err, ErrUserBlocked) {
		t.Fatalf("sign-in of the blocked user = %v, want ErrUserBlocked: a reset does not lift a block", err)
	}
}

func TestOneLinkResetsThePasswordOnceWhateverTheNumberOfCallers(t *testing.T) {
	f := newResetFixture(t)
	m := f.sendReset(t)
	var wins atomic.Int32
	var winner atomic.Value
	var wg sync.WaitGroup
	for i := range 12 {
		password := resetPassword + string(rune('a'+i))
		wg.Go(func() {
			switch err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: password}); {
			case err == nil:
				wins.Add(1)
				winner.Store(password)
			case !errors.Is(err, ErrInvalidSecret):
				t.Errorf("ResetPassword = %v", err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d callers reset the password with one link, want exactly 1", wins.Load())
	}
	if _, err := f.signIn(t, "nina_n", winner.Load().(string)); err != nil { //nolint:forcetypeassert
		t.Fatalf("the password of the winner does not work: %v", err)
	}
	if got := len(f.ofKind(t, MessagePasswordChanged, 1)); got != 1 {
		t.Fatalf("%d notices were sent, want one", got)
	}
}

func TestAResetIsRepeatedWhenTheUserChangedMeanwhile(t *testing.T) {
	f := newResetFixture(t)
	m := f.sendReset(t)
	stale := &atomic.Int32{}
	stale.Store(2)
	f.a.store = staleOnceStore{Store: f.a.store, stale: stale}
	if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: resetPassword, IP: ipOne}); err != nil {
		t.Fatalf("ResetPassword = %v, want success after two retries", err)
	}
	if _, err := f.signIn(t, "nina_n", resetPassword); err != nil {
		t.Fatal(err)
	}
}

func TestResetNeedsOneKindOfProof(t *testing.T) {
	f := newResetFixture(t)
	cases := map[string]ResetPasswordRequest{
		"nothing":                 {Password: resetPassword},
		"a login without a code":  {Login: "nina_n", Password: resetPassword},
		"a token and a code":      {Token: strings.Repeat("A", 43), Code: "123456", Password: resetPassword},
		"a login and a channel":   {Login: "nina_n", Channel: "nina@example.com", Code: "123456", Password: resetPassword},
		"a code without anything": {Code: "123456", Password: resetPassword},
	}
	for name, r := range cases {
		var invalid *ValidationError
		if err := f.a.ResetPassword(t.Context(), r); !errors.As(err, &invalid) {
			t.Errorf("%s: ResetPassword = %v, want a *ValidationError", name, err)
		}
	}
}

func TestWrongResetSecretsLockTheAddress(t *testing.T) {
	f := newResetFixture(t, WithRecoveryLimits(RecoveryLimits{IPFailures: Limit{Attempts: 2}}))
	m := f.sendReset(t)
	for range 2 {
		if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: strings.Repeat("A", 43), Password: resetPassword, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
			t.Fatal(err)
		}
	}
	err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: resetPassword, IP: ipOne})
	asRateLimit(t, err)
	if err = f.a.Verify(t.Context(), VerifyRequest{Token: strings.Repeat("A", 43), IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("the other purpose has its own counter: %v", err)
	}
}

func TestAChangedPasswordIsToldOnEveryConfirmedChannel(t *testing.T) {
	f := newResetFixture(t)
	f.addPhone(t)
	f.verify(t, "sms", ninaPhone)
	login, err := f.signIn(t, "nina_n", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	ctx := ContextWithLanguage(t.Context(), "ru")
	if _, err = f.a.ChangePassword(ctx, login.Principal, goodPassword, resetPassword); err != nil {
		t.Fatal(err)
	}
	notices := f.ofKind(t, MessagePasswordChanged, 2)
	for _, m := range notices {
		if m.Language != "ru" || m.UserID != string(f.user.ID) || m.Code != "" || m.Link != "" {
			t.Errorf("notice = %+v", m)
		}
	}
	if notices[0].Channel == notices[1].Channel {
		t.Fatalf("notices = %+v, want one for each channel", notices)
	}
}

func TestAChangedPasswordIsNotToldOnAChannelThatIsNotConfirmed(t *testing.T) {
	f := newRecoveryFixture(t)
	login, err := f.signIn(t, "nina_n", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.ChangePassword(t.Context(), login.Principal, goodPassword, resetPassword); err != nil {
		t.Fatal(err)
	}
	f.noMessages(t)
}

func TestAFailedChangeOfThePasswordSendsNoNotice(t *testing.T) {
	f := newResetFixture(t)
	login, err := f.signIn(t, "nina_n", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.ChangePassword(t.Context(), login.Principal, "the wrong current password", resetPassword); err == nil {
		t.Fatal("a wrong current password was accepted")
	}
	f.noMessages(t)
}

func TestAServiceWithoutASenderChangesPasswordsWithoutNotices(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	if _, err := f.a.ChangePassword(t.Context(), login.Principal, goodPassword, newPassword); err != nil {
		t.Fatalf("ChangePassword = %v", err)
	}
}

func TestANoticeThatFailsIsReportedAndDoesNotUndoTheChange(t *testing.T) {
	events := &eventLog{}
	sender := senderFunc(func(context.Context, Message) error { return errors.New("the mail service is down") })
	f := newResetFixture(t, WithSender(sender), WithHooks(events.hooks()))
	login, err := f.signIn(t, "nina_n", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.ChangePassword(t.Context(), login.Principal, goodPassword, resetPassword); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the failure to be reported", func() bool {
		for _, e := range events.peek() {
			if e.Type == EventMessageFailed {
				return true
			}
		}
		return false
	})
	if _, err = f.signIn(t, "nina_n", resetPassword); err != nil {
		t.Fatalf("the new password does not work: %v", err)
	}
}

func TestNothingSecretReachesTheEventsOrTheLogOfAReset(t *testing.T) {
	logger, logs := capturingLogger()
	f := newResetFixture(t, WithLogger(logger))
	m := f.sendReset(t)
	f.events.take()
	if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: resetPassword, IP: ipOne}); err != nil {
		t.Fatal(err)
	}
	f.ofKind(t, MessagePasswordChanged, 1)
	raw, err := json.Marshal(f.events.take())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{resetPassword, tokenOf(m.Link), m.Code, m.Link, goodPassword} {
		if strings.Contains(string(raw), secret) || strings.Contains(logs.String(), secret) {
			t.Fatalf("a secret reached the events or the log:\n%s\n%s", raw, logs.String())
		}
	}
}

func TestAFailureInTheMiddleOfAResetChangesNothing(t *testing.T) {
	broken := errors.New("the database is gone")
	for _, name := range []string{"users.update", "secrets.end", "sessions.revoke", "identifiers.list"} {
		f := newResetFixture(t)
		faults := newFaults()
		f.a.store = faultStore{Store: f.a.store, faults: faults}
		old, err := f.signIn(t, "nina_n", goodPassword)
		if err != nil {
			t.Fatal(err)
		}
		m := f.sendReset(t)
		f.events.take()
		f.sender.clear()
		faults.set(name, broken)
		err = f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: resetPassword, IP: ipOne})
		var invalid *ValidationError
		var policy *PolicyError
		if !errors.Is(err, broken) || errors.Is(err, ErrInvalidSecret) || errors.As(err, &invalid) || errors.As(err, &policy) {
			t.Fatalf("%s: ResetPassword = %v, want the error of the store", name, err)
		}
		if events := f.events.take(); len(events) != 0 {
			t.Fatalf("%s: events = %+v, want none for a reset that failed", name, events)
		}
		f.noMessages(t)
		faults.clear()
		if !f.sessionAlive(t, old) {
			t.Fatalf("%s: a session ended although the reset failed", name)
		}
		if _, err = f.signIn(t, "nina_n", goodPassword); err != nil {
			t.Fatalf("%s: the old password stopped working: %v", name, err)
		}
		if err = f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: resetPassword, IP: ipOne}); err != nil {
			t.Fatalf("%s: the link of a reset that failed must stay usable: %v", name, err)
		}
	}
}

func TestAFailureToHashThePasswordLeavesTheLinkUsable(t *testing.T) {
	f := newResetFixture(t)
	m := f.sendReset(t)
	broken := errors.New("no memory for the hash")
	good := f.a.hasher
	f.a.hasher = failingHasher{passwordHasher: good, err: broken}
	if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: resetPassword, IP: ipOne}); !errors.Is(err, broken) {
		t.Fatalf("ResetPassword = %v, want the error of the hasher", err)
	}
	f.a.hasher = good
	if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: resetPassword, IP: ipOne}); err != nil {
		t.Fatalf("the link after a failed hash = %v", err)
	}
}

func TestAUserOrAChannelThatIsGoneRefusesTheSecret(t *testing.T) {
	for _, name := range []string{"users.get", "identifiers.find"} {
		f := newResetFixture(t)
		faults := newFaults()
		f.a.store = faultStore{Store: f.a.store, faults: faults}
		m := f.sendReset(t)
		faults.set(name, store.ErrNotFound)
		if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: resetPassword, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
			t.Fatalf("%s: ResetPassword = %v, want ErrInvalidSecret", name, err)
		}
		faults.set(name, errors.New("the database is gone"))
		if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(m.Link), Password: resetPassword, IP: ipOne}); err == nil || errors.Is(err, ErrInvalidSecret) {
			t.Fatalf("%s: ResetPassword = %v, want the error of the store", name, err)
		}
	}
}

func TestAChannelOfAnotherUserDoesNotResetThePassword(t *testing.T) {
	f := newResetFixture(t)
	mustRegister(t, f.a, map[string]string{"email": "boris@example.com", "username": "boris_b"}, goodPassword)
	f.verify(t, "email", "boris@example.com")
	token, hash, err := newSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := f.clock.now().UTC().Truncate(time.Microsecond)
	forged := store.Secret{
		TenantID: f.a.tenant, ID: "00000000-0000-7000-8000-00000000f003", Kind: store.SecretLink, Hash: hash, UserID: string(f.user.ID),
		Purpose: store.PurposeReset, ChannelType: "email", ChannelValue: "boris@example.com", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err = f.a.store.Secrets().Add(t.Context(), forged); err != nil {
		t.Fatal(err)
	}
	if err = f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: token, Password: resetPassword, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("a secret of one user for the channel of another = %v, want ErrInvalidSecret", err)
	}
	for _, login := range []string{"nina_n", "boris_b"} {
		if _, err = f.signIn(t, login, goodPassword); err != nil {
			t.Fatalf("%s: the password changed or the user is locked: %v", login, err)
		}
	}
}

func TestOnlyFiveNoticesOfAChangedPasswordAreSentInAnHour(t *testing.T) {
	f := newResetFixture(t)
	password := goodPassword
	login, err := f.signIn(t, "nina_n", password)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 6 {
		next := resetPassword + string(rune('a'+i))
		if login, err = f.a.ChangePassword(t.Context(), login.Principal, password, next); err != nil {
			t.Fatal(err)
		}
		password = next
	}
	f.idle(t)
	if got := len(f.sender.sent()); got != 5 {
		t.Fatalf("%d notices were sent for six changes, want five", got)
	}
}

func TestANoticeIsNotSentWhenTheUserIsGoneOrCannotBeRead(t *testing.T) {
	f := newResetFixture(t)
	faults := newFaults()
	f.a.store = faultStore{Store: f.a.store, faults: faults}
	f.change(t, func(u *store.User) { u.Status = store.StatusDeleted })
	f.a.notifyPasswordChanged(t.Context(), string(f.user.ID), "")
	f.noMessages(t)
	f.a.notifyPasswordChanged(t.Context(), "00000000-0000-7000-8000-0000000000aa", "")
	f.noMessages(t)
	if events := f.events.take(); len(events) != 0 {
		t.Fatalf("events = %+v, want none for a user who is not there", events)
	}
	f.change(t, func(u *store.User) { u.Status = store.StatusActive })
	for _, name := range []string{"users.get", "identifiers.list"} {
		f.events.take()
		faults.set(name, errors.New("the database is gone"))
		f.a.notifyPasswordChanged(t.Context(), string(f.user.ID), "")
		eventually(t, "the failure to be reported", func() bool {
			for _, e := range f.events.peek() {
				if e.Type == EventMessageFailed && e.Details["kind"] == string(MessagePasswordChanged) {
					return true
				}
			}
			return false
		})
		faults.clear()
	}
	f.noMessages(t)
}

func TestANoticeThatCannotBeQueuedIsLoggedAndTheChangeStands(t *testing.T) {
	logger, logs := capturingLogger()
	f := newResetFixture(t, WithLogger(logger), WithSending(SendingOptions{Workers: 1, Queue: 1}))
	release := f.block(t)
	login, err := f.signIn(t, "nina_n", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if login, err = f.a.ChangePassword(t.Context(), login.Principal, goodPassword, resetPassword); err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.ChangePassword(t.Context(), login.Principal, resetPassword, resetPassword+"2"); err != nil {
		t.Fatalf("a queue that is full must not fail the change: %v", err)
	}
	if !strings.Contains(logs.String(), "the notice that a password was changed is not sent") {
		t.Fatalf("log:\n%s", logs.String())
	}
	release()
	f.idle(t)
}

func TestTheLanguageOfANoticeIsNormalized(t *testing.T) {
	f := newResetFixture(t)
	if err := f.a.sendNoticeToUser(t.Context(), string(f.user.ID), MessagePasswordChanged, " RU-ru "); err != nil {
		t.Fatal(err)
	}
	if m := f.ofKind(t, MessagePasswordChanged, 1)[0]; m.Language != "ru" {
		t.Fatalf("language = %q, want %q", m.Language, "ru")
	}
}
