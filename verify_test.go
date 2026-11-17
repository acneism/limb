package limb

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/internal/memstore"
	"github.com/acneism/limb/store"
)

var sixDigitCode = regexp.MustCompile(`^[0-9]{6}$`)

func (s *recordingSender) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = nil
}

func wrongCode(code string) string {
	if code[5] == '0' {
		return code[:5] + "1"
	}
	return code[:5] + "0"
}

func manyRequests() Option {
	return WithRecoveryLimits(RecoveryLimits{
		ChannelRequests: Limit{Attempts: 1000}, IPRequests: Limit{Attempts: 1000}, IPFailures: Limit{Attempts: 1000},
	})
}

func (f *recoveryFixture) requestVerification(t *testing.T, login string) {
	t.Helper()
	if err := f.a.RequestVerification(t.Context(), VerificationRequest{Login: login, IP: ipOne}); err != nil {
		t.Fatalf("RequestVerification(%q) = %v", login, err)
	}
}

func (f *recoveryFixture) sendVerification(t *testing.T) Message {
	t.Helper()
	f.sender.clear()
	f.requestVerification(t, "nina_n")
	return f.messages(t, 1)[0]
}

func TestARequestSendsALinkAndACodeToTheUnconfirmedAddress(t *testing.T) {
	f := newRecoveryFixture(t)
	f.requestVerification(t, "nina_n")
	m := f.messages(t, 1)[0]
	now := f.clock.now().UTC()
	if m.Kind != MessageVerification || m.UserID != string(f.user.ID) || m.Channel != "email" || m.To != "nina@example.com" || m.Language != "en" {
		t.Fatalf("message = %+v", m)
	}
	if !strings.HasPrefix(m.Link, "https://app.example.com/verify#token=") || len(tokenOf(m.Link)) != 43 || !sixDigitCode.MatchString(m.Code) {
		t.Fatalf("the link and the code = %q, %q", m.Link, m.Code)
	}
	if !m.LinkExpiresAt.Equal(now.Add(24*time.Hour)) || !m.CodeExpiresAt.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("the link ends %v and the code %v", m.LinkExpiresAt, m.CodeExpiresAt)
	}
	if !strings.Contains(m.Subject, "Acme") || !strings.Contains(m.Text, m.Link) || !strings.Contains(m.Text, m.Code) ||
		!strings.Contains(m.Text, "24 hours") || !strings.Contains(m.Text, "10 minutes") || !strings.Contains(m.HTML, m.Code) {
		t.Fatalf("the texts do not carry the data: %+v", m)
	}
}

func TestTheLoginMayBeAnyIdentifierOfTheAccount(t *testing.T) {
	f := newRecoveryFixture(t, manyRequests())
	for _, login := range []string{"nina_n", "NINA@example.com", "  Nina@Example.com "} {
		f.sender.clear()
		f.requestVerification(t, login)
		if m := f.messages(t, 1)[0]; m.To != "nina@example.com" {
			t.Fatalf("login %q: message = %+v", login, m)
		}
	}
}

func TestTheLanguageComesFromTheRequestThenFromTheContext(t *testing.T) {
	f := newRecoveryFixture(t, manyRequests())
	russian := ContextWithLanguage(t.Context(), "ru")
	cases := []struct {
		name     string
		ctx      context.Context
		language string
		want     string
		subject  string
	}{
		{"explicit Russian", t.Context(), "ru-RU", "ru", "Подтверждение адреса: Acme"},
		{"explicit English wins over the context", russian, "en", "en", "Confirm your address on Acme"},
		{"the context", russian, "", "ru", "Подтверждение адреса: Acme"},
		{"an unsupported language", t.Context(), "de", "en", "Confirm your address on Acme"},
		{"nothing", t.Context(), "", "en", "Confirm your address on Acme"},
	}
	for _, c := range cases {
		f.sender.clear()
		if err := f.a.RequestVerification(c.ctx, VerificationRequest{Login: "nina_n", IP: ipOne, Language: c.language}); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		m := f.messages(t, 1)[0]
		if m.Language != c.want || m.Subject != c.subject {
			t.Errorf("%s: language %q, subject %q; want %q and %q", c.name, m.Language, m.Subject, c.want, c.subject)
		}
	}
}

func TestWithoutAVerifyURLTheMessageCarriesOnlyACode(t *testing.T) {
	f := newRecoveryFixture(t, WithVerifyURL(""))
	f.requestVerification(t, "nina_n")
	m := f.messages(t, 1)[0]
	if m.Link != "" || !m.LinkExpiresAt.IsZero() || !sixDigitCode.MatchString(m.Code) || strings.Contains(m.Text, "https://") || strings.Contains(m.HTML, "href") {
		t.Fatalf("message = %+v", m)
	}
	if err := f.a.Verify(t.Context(), VerifyRequest{Login: "nina_n", Code: m.Code, IP: ipOne}); err != nil {
		t.Fatalf("the code of a message without a link does not work: %v", err)
	}
}

func TestOnlyTheChannelsThatAreNotConfirmedGetAMessage(t *testing.T) {
	f := newRecoveryFixture(t, manyRequests())
	f.addPhone(t)
	f.requestVerification(t, "nina_n")
	messages := f.messages(t, 2)
	channels := []string{messages[0].Channel, messages[1].Channel}
	slices.Sort(channels)
	if !slices.Equal(channels, []string{"email", "sms"}) {
		t.Fatalf("channels = %v, want both", channels)
	}
	for _, m := range messages {
		if m.Channel == "sms" && (m.Subject != "" || m.HTML != "" || !strings.Contains(m.Text, m.Code) || strings.Contains(m.Text, "https://")) {
			t.Fatalf("the message to a phone = %+v, want a short text with the code only", m)
		}
	}
	if messages[0].Code == messages[1].Code && messages[0].Link == messages[1].Link {
		t.Fatal("every channel needs secrets of its own")
	}
	f.verify(t, "email", "nina@example.com")
	f.sender.clear()
	f.requestVerification(t, "nina_n")
	if only := f.messages(t, 1); only[0].Channel != "sms" {
		t.Fatalf("message = %+v, want only the channel that is not confirmed", only[0])
	}
}

func TestNothingIsSentWhenThereIsNothingToConfirmOrNoAccount(t *testing.T) {
	f := newRecoveryFixture(t, manyRequests(), WithIdentifiers(identifier.Email(), identifier.Username(identifier.Required())))
	olga := mustRegister(t, f.a, map[string]string{"username": "olga_o"}, goodPassword)
	f.requestVerification(t, "olga_o")
	f.requestVerification(t, "nobody@example.com")
	f.requestVerification(t, "somebody_else")
	f.noMessages(t)
	if olga.ID == "" {
		t.Fatal("the user was not created")
	}
	if err := f.a.store.Identifiers().Add(t.Context(), store.Identifier{
		TenantID: f.a.tenant, Type: "email", Value: "olga@example.com", DisplayValue: "olga@example.com", UserID: string(olga.ID), VerifiedAt: f.clock.now(),
	}); err != nil {
		t.Fatal(err)
	}
	f.requestVerification(t, "olga_o")
	f.noMessages(t)
}

func TestTheRequestDoesTheSameWorkWhetherOrNotTheAccountExists(t *testing.T) {
	f := newRecoveryFixture(t, WithSending(SendingOptions{Workers: 1, Queue: 8}), manyRequests())
	release := f.block(t)
	log := &accessLog{Store: f.a.store}
	f.a.store = log
	var seen [][]string
	for _, login := range []string{"nina_n", "nina@example.com", "nobody_here", "nobody@example.com"} {
		before := len(log.taken())
		f.requestVerification(t, login)
		seen = append(seen, log.taken()[before:])
	}
	for i, names := range seen {
		if !slices.Equal(names, seen[0]) {
			t.Errorf("the request %d touched %v, the first one %v: the work must not depend on the login", i, names, seen[0])
		}
		for _, forbidden := range []string{"users", "identifiers", "secrets", "transaction", "sessions"} {
			if slices.Contains(names, forbidden) {
				t.Errorf("the request %d touched %q before it answered: %v", i, forbidden, names)
			}
		}
	}
	if len(seen[0]) == 0 {
		t.Fatal("the request counted nothing, the test does not see the work")
	}
	release()
	f.messages(t, 2)
}

func TestARequestDoesNotWaitForTheSender(t *testing.T) {
	gate := make(chan struct{})
	a, _ := newLimitedAuth(t, emailAndUsername(), WithSender(senderFunc(func(ctx context.Context, _ Message) error {
		select {
		case <-gate:
		case <-ctx.Done():
		}
		return nil
	})))
	t.Cleanup(func() { close(gate) })
	mustRegister(t, a, map[string]string{"email": "nina@example.com"}, goodPassword)
	begin := time.Now()
	if err := a.RequestVerification(t.Context(), VerificationRequest{Login: "nina@example.com", IP: ipOne}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(begin); elapsed > 2*time.Second {
		t.Fatalf("the request waited %v for a Sender that has not answered", elapsed)
	}
}

func TestANewRequestEndsTheSecretsOfTheEarlierOne(t *testing.T) {
	f := newRecoveryFixture(t)
	first := f.sendVerification(t)
	f.clock.advance(time.Minute)
	second := f.sendVerification(t)
	scope := store.SecretScope{
		TenantID: f.a.tenant, UserID: string(f.user.ID), Purpose: store.PurposeVerify, ChannelType: "email", ChannelValue: "nina@example.com",
	}
	live, err := f.a.store.Secrets().TryCodes(t.Context(), scope, f.clock.now(), 5)
	if err != nil || len(live) != 1 || !f.a.keys.CodeMatches(live[0].Hash, codeBinding(live[0]), second.Code) {
		t.Fatalf("live codes = %+v, %v; want only the code of the second request", live, err)
	}
	if err = f.a.Verify(t.Context(), VerifyRequest{Token: tokenOf(first.Link), IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("the link of the first request = %v, want ErrInvalidSecret", err)
	}
	if err = f.a.Verify(t.Context(), VerifyRequest{Token: tokenOf(second.Link), IP: ipOne}); err != nil {
		t.Fatalf("the link of the second request = %v", err)
	}
}

func TestOnlyFiveMessagesOfAKindAreSentToAUserInAnHour(t *testing.T) {
	f := newRecoveryFixture(t, manyRequests())
	for range 7 {
		f.requestVerification(t, "nina_n")
		f.idle(t)
	}
	if got := len(f.sender.sent()); got != 5 {
		t.Fatalf("%d messages were sent in an hour, want 5", got)
	}
	f.clock.advance(30 * time.Minute)
	f.requestVerification(t, "nina_n")
	f.idle(t)
	if got := len(f.sender.sent()); got != 5 {
		t.Fatalf("%d messages half an hour later, want still 5", got)
	}
	f.clock.advance(31 * time.Minute)
	f.requestVerification(t, "nina_n")
	f.idle(t)
	if got := len(f.sender.sent()); got != 6 {
		t.Fatalf("%d messages after the hour, want 6", got)
	}
}

func TestVerificationNeedsASenderAndAChannel(t *testing.T) {
	plain := newTestAuth(t, emailAndUsername())
	if err := plain.RequestVerification(t.Context(), VerificationRequest{Login: "nina@example.com"}); !errors.Is(err, ErrRecoveryDisabled) {
		t.Fatalf("a service without a Sender: %v, want ErrRecoveryDisabled", err)
	}
	noChannel := newTestAuth(t, WithIdentifiers(identifier.Username(identifier.Required())), WithSender(&recordingSender{}))
	if err := noChannel.RequestVerification(t.Context(), VerificationRequest{Login: "nina"}); !errors.Is(err, ErrRecoveryDisabled) {
		t.Fatalf("a service without a channel: %v, want ErrRecoveryDisabled", err)
	}
}

func TestARequestWithoutALoginIsInvalid(t *testing.T) {
	f := newRecoveryFixture(t)
	for _, login := range []string{"", "   ", "\t\n", strings.Repeat("a", 1025)} {
		var invalid *ValidationError
		if err := f.a.RequestVerification(t.Context(), VerificationRequest{Login: login, IP: ipOne}); !errors.As(err, &invalid) || invalid.Field != "login" {
			t.Errorf("login %.10q: %v, want a *ValidationError about the login", login, err)
		}
	}
	for range 4 {
		var invalid *ValidationError
		_ = f.a.RequestVerification(t.Context(), VerificationRequest{Login: "", IP: ipOne})
		if err := f.a.RequestVerification(t.Context(), VerificationRequest{Login: " ", IP: ipOne}); !errors.As(err, &invalid) {
			t.Fatalf("a request that is not valid must not be counted: %v", err)
		}
	}
}

func TestTheRequestsOfOneLoginAreLimited(t *testing.T) {
	f := newRecoveryFixture(t)
	for range 3 {
		f.requestVerification(t, "nina_n")
	}
	err := f.a.RequestVerification(t.Context(), VerificationRequest{Login: "nina_n", IP: ipOne})
	if got := asRateLimit(t, err); got <= 0 {
		t.Fatalf("RetryAfter = %v", got)
	}
	f.idle(t)
	if got := len(f.sender.sent()); got != 3 {
		t.Fatalf("%d messages were sent, want the three that were accepted", got)
	}
}

func TestAFullQueueRefusesEveryLoginAlike(t *testing.T) {
	f := newRecoveryFixture(t, WithSending(SendingOptions{Workers: 1, Queue: 1}), manyRequests())
	release := f.block(t)
	f.requestVerification(t, "nina_n")
	for _, login := range []string{"nina_n", "nobody@example.com"} {
		if err := f.a.RequestVerification(t.Context(), VerificationRequest{Login: login, IP: ipOne}); !errors.Is(err, ErrBusy) {
			t.Fatalf("login %q: %v, want ErrBusy", login, err)
		}
	}
	release()
	f.messages(t, 1)
}

func TestAFailureOfTheSenderIsReportedAndTheOtherChannelsStillGetTheirs(t *testing.T) {
	logger, logs := capturingLogger()
	var calls atomic.Int32
	sender := senderFunc(func(_ context.Context, m Message) error {
		calls.Add(1)
		if m.Channel == "email" {
			return errors.New("refused " + m.To + " with " + m.Code)
		}
		return nil
	})
	events := &eventLog{}
	a, _ := newLimitedAuth(t, WithLogger(logger), WithSender(sender), WithHooks(events.hooks()), WithIdentifiers(identifier.Email(identifier.Required()), smsType()))
	user := mustRegister(t, a, map[string]string{"email": "nina@example.com", "sms": "+79991234567"}, goodPassword)
	events.take()
	if err := a.RequestVerification(t.Context(), VerificationRequest{Login: "nina@example.com", IP: ipOne}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "both messages", func() bool { return calls.Load() == 2 && len(events.peek()) == 1 })
	failed := events.take()[0]
	if failed.Type != EventMessageFailed || failed.UserID != string(user.ID) || failed.Channel != "email" || failed.Address != "n***@example.com" ||
		failed.Details["kind"] != "verification" || failed.Details["reason"] != "rejected" {
		t.Fatalf("event = %+v", failed)
	}
	if text := logs.String(); strings.Contains(text, "nina@example.com") || strings.Contains(text, "+79991234567") || sixDigitCode.MatchString(text) {
		t.Fatalf("the log has an address or a code:\n%s", text)
	}
}

func TestVerifyConfirmsTheChannelWithTheLink(t *testing.T) {
	f := newRecoveryFixture(t)
	m := f.sendVerification(t)
	f.clock.advance(time.Minute)
	if err := f.a.Verify(t.Context(), VerifyRequest{Token: tokenOf(m.Link), IP: ipOne}); err != nil {
		t.Fatalf("Verify = %v", err)
	}
	got := f.identifierOf(t, "email")
	if !got.VerifiedAt.Equal(f.clock.now().UTC()) {
		t.Fatalf("VerifiedAt = %v, want %v", got.VerifiedAt, f.clock.now())
	}
	events := f.events.take()
	wantTypes(t, events, EventChannelVerified)
	e := events[0]
	if e.UserID != string(f.user.ID) || e.Channel != "email" || e.Address != "n***@example.com" || e.IP != ipOne.String() {
		t.Fatalf("event = %+v", e)
	}
	if err := f.a.Verify(t.Context(), VerifyRequest{Token: tokenOf(m.Link), IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("a link that was used = %v, want ErrInvalidSecret", err)
	}
	if err := f.a.Verify(t.Context(), VerifyRequest{Login: "nina_n", Code: m.Code, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("the code of a message whose link was used = %v, want ErrInvalidSecret: the secrets of one message end together", err)
	}
}

func TestVerifyConfirmsTheChannelWithTheCode(t *testing.T) {
	for _, form := range []struct {
		name  string
		write func(code string) string
	}{
		{"plain", func(c string) string { return c }},
		{"with spaces around", func(c string) string { return "  " + c + " " }},
		{"with a space in the middle", func(c string) string { return c[:3] + " " + c[3:] }},
		{"with a hyphen in the middle", func(c string) string { return c[:3] + "-" + c[3:] }},
	} {
		for _, by := range []string{"login", "channel"} {
			f := newRecoveryFixture(t)
			m := f.sendVerification(t)
			r := VerifyRequest{Code: form.write(m.Code), IP: ipOne}
			if by == "login" {
				r.Login = "NINA_N"
			} else {
				r.Channel = " Nina@Example.com "
			}
			if err := f.a.Verify(t.Context(), r); err != nil {
				t.Errorf("%s by %s: Verify = %v", form.name, by, err)
				continue
			}
			if f.identifierOf(t, "email").VerifiedAt.IsZero() {
				t.Errorf("%s by %s: the channel is not confirmed", form.name, by)
			}
			if err := f.a.Verify(t.Context(), VerifyRequest{Token: tokenOf(m.Link), IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
				t.Errorf("%s by %s: the link of the same message = %v, want it ended", form.name, by, err)
			}
		}
	}
}

func TestACodeThatIsWrongOrMalformedIsRefused(t *testing.T) {
	f := newRecoveryFixture(t)
	m := f.sendVerification(t)
	for _, code := range []string{wrongCode(m.Code), "", "12345", "1234567", "abcdef", "١٢٣٤٥٦", m.Code + "0"} {
		if err := f.a.Verify(t.Context(), VerifyRequest{Login: "nina_n", Code: code, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) && code != "" {
			t.Errorf("code %q = %v, want ErrInvalidSecret", code, err)
		}
	}
	if !f.identifierOf(t, "email").VerifiedAt.IsZero() {
		t.Fatal("the channel was confirmed by a wrong code")
	}
}

func TestACodeSurvivesFiveGuessesAndTheRightOneCountsToo(t *testing.T) {
	f := newRecoveryFixture(t)
	m := f.sendVerification(t)
	guess := func(code string) error {
		return f.a.Verify(t.Context(), VerifyRequest{Login: "nina_n", Code: code, IP: ipOne})
	}
	for range 4 {
		if err := guess(wrongCode(m.Code)); !errors.Is(err, ErrInvalidSecret) {
			t.Fatal(err)
		}
	}
	if err := guess(m.Code); err != nil {
		t.Fatalf("the fifth guess, the right one: %v", err)
	}
	other := newRecoveryFixture(t)
	m = other.sendVerification(t)
	for range 5 {
		if err := other.a.Verify(t.Context(), VerifyRequest{Login: "nina_n", Code: wrongCode(m.Code), IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
			t.Fatal(err)
		}
	}
	if err := other.a.Verify(t.Context(), VerifyRequest{Login: "nina_n", Code: m.Code, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("the right code after five wrong ones = %v, want ErrInvalidSecret: the code is dead", err)
	}
	if !other.identifierOf(t, "email").VerifiedAt.IsZero() {
		t.Fatal("a dead code confirmed the channel")
	}
	other.clock.advance(time.Minute)
	fresh := other.sendVerification(t)
	if err := other.a.Verify(t.Context(), VerifyRequest{Login: "nina_n", Code: fresh.Code, IP: ipOne}); err != nil {
		t.Fatalf("a new code after a dead one = %v", err)
	}
}

func TestTheNumberOfGuessesIsAnOption(t *testing.T) {
	f := newRecoveryFixture(t, WithRecoveryLimits(RecoveryLimits{CodeAttempts: 2}))
	m := f.sendVerification(t)
	for range 2 {
		_ = f.a.Verify(t.Context(), VerifyRequest{Login: "nina_n", Code: wrongCode(m.Code), IP: ipOne})
	}
	if err := f.a.Verify(t.Context(), VerifyRequest{Login: "nina_n", Code: m.Code, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("the right code after two guesses = %v, want it dead", err)
	}
}

func TestSecretsExpireAtTheirTime(t *testing.T) {
	f := newRecoveryFixture(t)
	m := f.sendVerification(t)
	f.clock.advance(10*time.Minute - time.Second)
	if err := f.a.Verify(t.Context(), VerifyRequest{Login: "nina_n", Code: m.Code, IP: ipOne}); err != nil {
		t.Fatalf("the code a second before it expires = %v", err)
	}
	g := newRecoveryFixture(t)
	m = g.sendVerification(t)
	g.clock.advance(10 * time.Minute)
	if err := g.a.Verify(t.Context(), VerifyRequest{Login: "nina_n", Code: m.Code, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("the code at the moment it expires = %v, want ErrInvalidSecret", err)
	}
	if err := g.a.Verify(t.Context(), VerifyRequest{Token: tokenOf(m.Link), IP: ipOne}); err != nil {
		t.Fatalf("the link after ten minutes = %v, it works for 24 hours", err)
	}
	h := newRecoveryFixture(t)
	m = h.sendVerification(t)
	h.clock.advance(24 * time.Hour)
	if err := h.a.Verify(t.Context(), VerifyRequest{Token: tokenOf(m.Link), IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("the link at the moment it expires = %v, want ErrInvalidSecret", err)
	}
}

func TestAnUnknownLoginOrChannelOrTokenIsRefusedAlike(t *testing.T) {
	f := newRecoveryFixture(t)
	f.sendVerification(t)
	bad := []VerifyRequest{
		{Login: "nobody@example.com", Code: "123456"},
		{Login: "olga_o", Code: "123456"},
		{Channel: "nobody@example.com", Code: "123456"},
		{Channel: "+79990000000", Code: "123456"},
		{Channel: "nina_n", Code: "123456"},
		{Token: "x"},
		{Token: strings.Repeat("A", 43)},
		{Token: strings.Repeat("A", 44)},
		{Token: "ñ" + strings.Repeat("A", 42)},
	}
	for _, r := range bad {
		r.IP = ipOne
		if err := f.a.Verify(t.Context(), r); !errors.Is(err, ErrInvalidSecret) {
			t.Errorf("Verify(%+v) = %v, want ErrInvalidSecret", r, err)
		}
	}
}

func TestVerifyNeedsOneKindOfProof(t *testing.T) {
	f := newRecoveryFixture(t)
	cases := map[string]VerifyRequest{
		"nothing":                       {},
		"a login without a code":        {Login: "nina_n"},
		"a code alone":                  {Code: "123456"},
		"a login and a channel":         {Login: "nina_n", Channel: "nina@example.com", Code: "123456"},
		"a token and a code":            {Token: strings.Repeat("A", 43), Code: "123456"},
		"a token and a login":           {Token: strings.Repeat("A", 43), Login: "nina_n"},
		"a token and a channel":         {Token: strings.Repeat("A", 43), Channel: "nina@example.com"},
		"a channel without a code":      {Channel: "nina@example.com"},
		"a token with every other part": {Token: "t", Login: "l", Channel: "c", Code: "1"},
	}
	for name, r := range cases {
		r.IP = ipOne
		var invalid *ValidationError
		if err := f.a.Verify(t.Context(), r); !errors.As(err, &invalid) {
			t.Errorf("%s: Verify = %v, want a *ValidationError", name, err)
		}
	}
}

func TestWrongSecretsLockTheAddressNotTheAccount(t *testing.T) {
	f := newRecoveryFixture(t, WithRecoveryLimits(RecoveryLimits{IPFailures: Limit{Attempts: 3}}))
	m := f.sendVerification(t)
	for range 3 {
		if err := f.a.Verify(t.Context(), VerifyRequest{Token: strings.Repeat("A", 43), IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
			t.Fatal(err)
		}
	}
	err := f.a.Verify(t.Context(), VerifyRequest{Token: tokenOf(m.Link), IP: ipOne})
	if got := asRateLimit(t, err); got != 15*time.Minute {
		t.Fatalf("RetryAfter = %v, want 15 minutes", got)
	}
	if err = f.a.Verify(t.Context(), VerifyRequest{Token: tokenOf(m.Link), IP: ipTwo}); err != nil {
		t.Fatalf("the owner from another address = %v, the account must stay open", err)
	}
}

func TestOneLinkIsUsedOnceWhateverTheNumberOfCallers(t *testing.T) {
	f := newRecoveryFixture(t)
	m := f.sendVerification(t)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			switch err := f.a.Verify(t.Context(), VerifyRequest{Token: tokenOf(m.Link)}); {
			case err == nil:
				wins.Add(1)
			case !errors.Is(err, ErrInvalidSecret):
				t.Errorf("Verify = %v", err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d callers used one link, want exactly 1", wins.Load())
	}
	if got := len(f.events.take()); got != 1 {
		t.Fatalf("%d events, want one", got)
	}
}

func TestOneCodeIsUsedOnceAndGuessesAreCountedWhateverTheNumberOfCallers(t *testing.T) {
	f := newRecoveryFixture(t)
	m := f.sendVerification(t)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			switch err := f.a.Verify(t.Context(), VerifyRequest{Login: "nina_n", Code: m.Code}); {
			case err == nil:
				wins.Add(1)
			case !errors.Is(err, ErrInvalidSecret):
				t.Errorf("Verify = %v", err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d callers used one code, want exactly 1", wins.Load())
	}
	g := newRecoveryFixture(t)
	m = g.sendVerification(t)
	for i := range 40 {
		wg.Go(func() {
			code := m.Code
			if i%2 == 0 {
				code = wrongCode(code)
			}
			_ = g.a.Verify(t.Context(), VerifyRequest{Login: "nina_n", Code: code})
		})
	}
	wg.Wait()
	if err := g.a.Verify(t.Context(), VerifyRequest{Login: "nina_n", Code: m.Code}); !errors.Is(err, ErrInvalidSecret) && g.identifierOf(t, "email").VerifiedAt.IsZero() {
		t.Fatalf("after a storm of guesses the code is %v, want it used or dead", err)
	}
}

func TestAChannelThatIsConfirmedAlreadyKeepsItsTimeAndReportsNothing(t *testing.T) {
	f := newRecoveryFixture(t, manyRequests())
	m := f.sendVerification(t)
	f.clock.advance(time.Hour)
	f.verify(t, "email", "nina@example.com")
	before := f.identifierOf(t, "email").VerifiedAt
	f.events.take()
	f.clock.advance(time.Hour)
	if err := f.a.Verify(t.Context(), VerifyRequest{Token: tokenOf(m.Link), IP: ipOne}); err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if got := f.identifierOf(t, "email").VerifiedAt; !got.Equal(before) {
		t.Fatalf("VerifiedAt changed from %v to %v", before, got)
	}
	if events := f.events.take(); len(events) != 0 {
		t.Fatalf("events = %+v, want none", events)
	}
}

func TestASecretOfAChannelThatWasRemovedIsRefused(t *testing.T) {
	f := newRecoveryFixture(t)
	m := f.sendVerification(t)
	f.addPhone(t)
	if err := f.a.store.Identifiers().Remove(t.Context(), f.a.tenant, "email", "nina@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := f.a.Verify(t.Context(), VerifyRequest{Token: tokenOf(m.Link), IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("Verify = %v, want ErrInvalidSecret", err)
	}
	if err := f.a.Verify(t.Context(), VerifyRequest{Login: "nina_n", Code: m.Code, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("Verify = %v, want ErrInvalidSecret", err)
	}
}

func TestNewChecksTheAddressesOfTheLinks(t *testing.T) {
	bad := map[string]string{
		"a relative address":      "/verify",
		"no scheme":               "app.example.com/verify",
		"an address without host": "https:///verify",
		"plain http":              "http://app.example.com/verify",
		"another scheme":          "ftp://app.example.com/verify",
		"a script":                "javascript:alert(1)",
		"a user name":             "https://user@app.example.com/verify",
		"a user name and a part":  "https://user" + ":" + "x@app.example.com/verify",
		"a fragment":              "https://app.example.com/verify#section",
		"an empty fragment":       "https://app.example.com/verify#",
		"a space":                 "https://app.example.com/ver ify",
		"a line feed":             "https://app.example.com/verify\n",
		"a NUL":                   "https://app.example.com/\x00",
		"an opaque address":       "https:app.example.com",
		"a line separator":        "https://app.example.com/a" + string(rune(0x2028)) + "b",
		"a very long address":     "https://app.example.com/" + strings.Repeat("a", 1100),
		"text that is not an url": "https://%zz",
	}
	for name, address := range bad {
		for option, opt := range map[string]Option{"WithResetURL": WithResetURL(address), "WithVerifyURL": WithVerifyURL(address)} {
			_, err := NewWithStore(memstore.New(), []byte(testKey), WithAutoMigrate(), opt)
			if err == nil || !strings.Contains(err.Error(), option) {
				t.Errorf("%s with %s: New = %v, want an error that names the option", name, option, err)
			}
		}
	}
	good := []string{"", "https://app.example.com/verify", "https://app.example.com", "https://app.example.com:8443/a/b?lang=ru", "https://[2001:db8::1]/verify"}
	for _, address := range good {
		if _, err := NewWithStore(memstore.New(), []byte(testKey), WithAutoMigrate(), WithResetURL(address), WithVerifyURL(address)); err != nil {
			t.Errorf("address %q: New = %v", address, err)
		}
	}
	if _, err := NewWithStore(memstore.New(), []byte(testKey), WithAutoMigrate(), WithDevelopmentMode(), WithResetURL("http://localhost:3000/reset"), WithVerifyURL("http://localhost:3000/verify")); err != nil {
		t.Errorf("plain http is allowed in the development mode: %v", err)
	}
	if _, err := NewWithStore(memstore.New(), []byte(testKey), WithAutoMigrate(), WithResetURL("http://localhost:3000/reset"), WithDevelopmentMode()); err != nil {
		t.Errorf("the order of the options must not matter: %v", err)
	}
}

func TestAMessageToADeletedUserIsNotSentAndToABlockedOneIs(t *testing.T) {
	f := newRecoveryFixture(t, manyRequests())
	set := func(status store.Status) {
		u, err := f.a.store.Users().Get(t.Context(), f.a.tenant, string(f.user.ID))
		if err != nil {
			t.Fatal(err)
		}
		u.Status = status
		if _, err = f.a.store.Users().Update(t.Context(), u); err != nil {
			t.Fatal(err)
		}
	}
	set(store.StatusDeleted)
	f.requestVerification(t, "nina_n")
	f.noMessages(t)
	set(store.StatusBlocked)
	f.requestVerification(t, "nina_n")
	f.messages(t, 1)
}

type failingSecrets struct {
	store.Secrets
	addErr error
}

func (s failingSecrets) Add(ctx context.Context, secret store.Secret) error {
	if s.addErr != nil {
		return s.addErr
	}
	return s.Secrets.Add(ctx, secret)
}

type secretsFaultStore struct {
	store.Store
	secrets failingSecrets
}

func (s secretsFaultStore) Secrets() store.Secrets { return s.secrets }

func (s secretsFaultStore) InTx(ctx context.Context, fn func(ctx context.Context, tx store.Repositories) error) error {
	return s.Store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		return fn(ctx, secretsFaultRepositories{Repositories: tx, secrets: s.secrets})
	})
}

type secretsFaultRepositories struct {
	store.Repositories
	secrets failingSecrets
}

func (r secretsFaultRepositories) Secrets() store.Secrets {
	return failingSecrets{Secrets: r.Repositories.Secrets(), addErr: r.secrets.addErr}
}

func TestAChannelThatVanishesBeforeTheSecretsAreStoredGetsNothing(t *testing.T) {
	f := newRecoveryFixture(t)
	f.a.store = secretsFaultStore{Store: f.a.store, secrets: failingSecrets{addErr: store.ErrNotFound}}
	f.requestVerification(t, "nina_n")
	f.noMessages(t)
	if events := f.events.take(); len(events) != 0 {
		t.Fatalf("events = %+v, a channel that is gone is not a failure", events)
	}
}

func TestAFailureToStoreTheSecretsIsReportedWithoutAMessage(t *testing.T) {
	logger, logs := capturingLogger()
	f := newRecoveryFixture(t, WithLogger(logger))
	f.a.store = secretsFaultStore{Store: f.a.store, secrets: failingSecrets{addErr: errors.New("the disk is full")}}
	f.requestVerification(t, "nina_n")
	eventually(t, "the event", func() bool { return len(f.events.peek()) == 1 })
	f.noMessages(t)
	e := f.events.take()[0]
	if e.Type != EventMessageFailed || e.UserID != string(f.user.ID) || e.Channel != "email" || e.Address != "n***@example.com" || e.Details["reason"] != "storage" {
		t.Fatalf("event = %+v", e)
	}
	if !strings.Contains(logs.String(), "the disk is full") {
		t.Fatalf("the cause must be logged:\n%s", logs.String())
	}
}

func TestATemplateThatFailsWhenTheMessageIsMadeIsReportedWithoutAMessage(t *testing.T) {
	f := newRecoveryFixture(t)
	key := templateKey{MessageVerification, "en"}
	set := f.a.renderer.sets[key]
	set.subject = parseOrFail(t, "{{index .Code 99}}")
	f.a.renderer.sets[key] = set
	f.requestVerification(t, "nina_n")
	eventually(t, "the event", func() bool { return len(f.events.peek()) == 1 })
	f.noMessages(t)
	if e := f.events.take()[0]; e.Type != EventMessageFailed || e.Details["reason"] != "render" || e.Details["kind"] != "verification" {
		t.Fatalf("event = %+v", e)
	}
}

func TestASecretMadeForAnotherUsersChannelDoesNotConfirmIt(t *testing.T) {
	f := newRecoveryFixture(t)
	olga := mustRegister(t, f.a, map[string]string{"email": "olga@example.com"}, goodPassword)
	token, hash, err := newSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := f.clock.now().UTC().Truncate(time.Microsecond)
	forged := store.Secret{
		TenantID: f.a.tenant, ID: "00000000-0000-7000-8000-00000000f001", Kind: store.SecretLink, Hash: hash, UserID: string(olga.ID),
		Purpose: store.PurposeVerify, ChannelType: "email", ChannelValue: "nina@example.com", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err = f.a.store.Secrets().Add(t.Context(), forged); err != nil {
		t.Fatal(err)
	}
	if err = f.a.Verify(t.Context(), VerifyRequest{Token: token, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("Verify = %v, want ErrInvalidSecret", err)
	}
	if !f.identifierOf(t, "email").VerifiedAt.IsZero() {
		t.Fatal("the channel of one user was confirmed by a secret of another")
	}
}

func TestAConfirmationIsRepeatedWhenTheUserChangedMeanwhile(t *testing.T) {
	f := newRecoveryFixture(t)
	m := f.sendVerification(t)
	runs := 0
	err := f.a.confirmSecret(t.Context(), store.PurposeVerify, confirmation{token: tokenOf(m.Link)},
		func(ctx context.Context, tx store.Repositories, s store.Secret, now time.Time) error {
			runs++
			if runs < 3 {
				return store.ErrStale
			}
			return f.a.markVerified(ctx, tx, s, now, &confirmedChannel{})
		})
	if err != nil || runs != 3 {
		t.Fatalf("confirmSecret = %v after %d runs, want success on the third", err, runs)
	}
	runs = 0
	g := newRecoveryFixture(t)
	m = g.sendVerification(t)
	err = g.a.confirmSecret(t.Context(), store.PurposeVerify, confirmation{token: tokenOf(m.Link)},
		func(context.Context, store.Repositories, store.Secret, time.Time) error {
			runs++
			return store.ErrStale
		})
	if !errors.Is(err, store.ErrStale) || runs != changeAttempts {
		t.Fatalf("confirmSecret = %v after %d runs, want ErrStale after %d", err, runs, changeAttempts)
	}
}

func TestACodeIsGuessedWithTheCodesOfEveryChannelOfTheAccount(t *testing.T) {
	f := newRecoveryFixture(t, manyRequests())
	f.addPhone(t)
	f.requestVerification(t, "nina_n")
	messages := f.messages(t, 2)
	for _, m := range messages {
		if err := f.a.Verify(t.Context(), VerifyRequest{Login: "nina_n", Code: m.Code, IP: ipOne}); err != nil {
			t.Fatalf("the code of the channel %s: %v", m.Channel, err)
		}
	}
	if f.identifierOf(t, "email").VerifiedAt.IsZero() || f.identifierOf(t, "sms").VerifiedAt.IsZero() {
		t.Fatal("both channels must be confirmed")
	}
}

func TestAMessageForAUserWhoIsNotThereIsNotSentAndTheLanguageIsNormalized(t *testing.T) {
	f := newRecoveryFixture(t)
	job := recoveryJob{purpose: store.PurposeVerify, kind: MessageVerification, language: "RU-ru"}
	if err := f.a.sendSecretsToUser(t.Context(), "00000000-0000-7000-8000-00000000dead", job); err != nil {
		t.Fatalf("sendSecretsToUser for a user who is not there = %v, want nothing to do", err)
	}
	f.noMessages(t)
	if err := f.a.sendSecretsToUser(t.Context(), string(f.user.ID), job); err != nil {
		t.Fatal(err)
	}
	if m := f.messages(t, 1)[0]; m.Language != "ru" {
		t.Fatalf("language = %q, want %q", m.Language, "ru")
	}
}

func TestTheQuietLimitIsPerUserAndPerKind(t *testing.T) {
	f := newRecoveryFixture(t, manyRequests())
	olga := mustRegister(t, f.a, map[string]string{"email": "olga@example.com"}, goodPassword)
	for range 7 {
		f.requestVerification(t, "nina_n")
		f.idle(t)
	}
	if got := len(f.sender.sent()); got != 5 {
		t.Fatalf("%d messages to the first user, want 5", got)
	}
	f.requestVerification(t, "olga@example.com")
	f.idle(t)
	last := f.sender.sent()[5]
	if len(f.sender.sent()) != 6 || last.UserID != string(olga.ID) {
		t.Fatalf("the messages to one user must not use the allowance of another: %+v", f.sender.sent())
	}
	if !f.a.allowMessage(t.Context(), MessagePasswordReset, string(f.user.ID)) {
		t.Fatal("the allowance of one kind of messages must not be used by another kind")
	}
}

func TestAMessageIsNotSentWhenTheAllowanceCannotBeCounted(t *testing.T) {
	logger, logs := capturingLogger()
	f := newRecoveryFixture(t, WithLogger(logger))
	f.a.store = brokenAttemptsStore{Store: f.a.store, attempts: failingAttempts{Attempts: f.a.store.Attempts(), hitErr: errors.New("the counter is down")}}
	if f.a.allowMessage(t.Context(), MessageVerification, string(f.user.ID)) {
		t.Fatal("a message was allowed although the counter is down")
	}
	if !strings.Contains(logs.String(), "cannot be counted") {
		t.Fatalf("the failure must be logged:\n%s", logs.String())
	}
}

func TestACodeIsBoundToEverythingItIsMadeFor(t *testing.T) {
	s := store.Secret{
		TenantID: "t", ID: "i", UserID: "u", Purpose: store.PurposeReset, ChannelType: "email", ChannelValue: "a@example.com",
	}
	got := codeBinding(s)
	if got.TenantID != "t" || got.ID != "i" || got.UserID != "u" || got.Purpose != "reset" || got.ChannelType != "email" || got.ChannelValue != "a@example.com" {
		t.Fatalf("binding = %+v, want every field of the secret", got)
	}
}

func TestAMalformedTokenIsRefusedWithoutOpeningATransaction(t *testing.T) {
	f := newRecoveryFixture(t)
	log := &accessLog{Store: f.a.store}
	f.a.store = log
	for _, token := range []string{"x", strings.Repeat("A", 44), "ñ" + strings.Repeat("A", 42)} {
		if err := f.a.Verify(t.Context(), VerifyRequest{Token: token, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
			t.Fatalf("Verify(%.10q) = %v", token, err)
		}
	}
	for _, name := range log.taken() {
		if name != "attempts" {
			t.Fatalf("a malformed token touched %q, want the counters only: %v", name, log.taken())
		}
	}
}

func TestAMalformedCodeDoesNotUseUpTheGuessesOfTheRealOne(t *testing.T) {
	f := newRecoveryFixture(t, manyRequests())
	m := f.sendVerification(t)
	for range 10 {
		if err := f.a.Verify(t.Context(), VerifyRequest{Login: "nina_n", Code: "12x", IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
			t.Fatal(err)
		}
	}
	if err := f.a.Verify(t.Context(), VerifyRequest{Login: "nina_n", Code: m.Code, IP: ipOne}); err != nil {
		t.Fatalf("the right code after malformed ones = %v", err)
	}
}

type barrierSecrets struct {
	store.Secrets
	ready   *sync.WaitGroup
	release chan struct{}
}

func (b barrierSecrets) TryCodes(ctx context.Context, scope store.SecretScope, at time.Time, limit int) ([]store.Secret, error) {
	got, err := b.Secrets.TryCodes(ctx, scope, at, limit)
	b.ready.Done()
	<-b.release
	return got, err
}

type barrierStore struct {
	store.Store
	secrets barrierSecrets
}

func (s barrierStore) Secrets() store.Secrets { return s.secrets }

func TestOnlyOneOfTheCallersThatHoldTheSameCodeUsesIt(t *testing.T) {
	f := newRecoveryFixture(t)
	m := f.sendVerification(t)
	const callers = 4
	ready := &sync.WaitGroup{}
	ready.Add(callers)
	release := make(chan struct{})
	f.a.store = barrierStore{Store: f.a.store, secrets: barrierSecrets{Secrets: f.a.store.Secrets(), ready: ready, release: release}}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			switch err := f.a.Verify(t.Context(), VerifyRequest{Login: "nina_n", Code: m.Code}); {
			case err == nil:
				wins.Add(1)
			case !errors.Is(err, ErrInvalidSecret):
				t.Errorf("Verify = %v", err)
			}
		})
	}
	ready.Wait()
	close(release)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d callers that held the same code used it, want exactly 1", wins.Load())
	}
}

func TestAChannelThatIsNamedOnlyTakesTheCodeOfThatChannel(t *testing.T) {
	f := newRecoveryFixture(t, manyRequests())
	f.addPhone(t)
	var emailCode, smsCode string
	for attempt := 0; attempt < 3 && (emailCode == "" || emailCode == smsCode); attempt++ {
		f.sender.clear()
		f.clock.advance(time.Minute)
		f.requestVerification(t, "nina_n")
		for _, m := range f.messages(t, 2) {
			if m.Channel == "email" {
				emailCode = m.Code
			} else {
				smsCode = m.Code
			}
		}
	}
	if emailCode == smsCode {
		t.Fatal("three pairs of codes were equal, the generator of codes is broken")
	}
	if err := f.a.Verify(t.Context(), VerifyRequest{Channel: "nina@example.com", Code: smsCode, IP: ipOne}); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("the code of the phone for the e-mail address = %v, want ErrInvalidSecret", err)
	}
	if !f.identifierOf(t, "sms").VerifiedAt.IsZero() || !f.identifierOf(t, "email").VerifiedAt.IsZero() {
		t.Fatal("a channel was confirmed with the code of another")
	}
}
