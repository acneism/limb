package limb

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

func recordsOf(t *testing.T, a *Auth, action string) []store.AuditRecord {
	t.Helper()
	list, err := a.store.Audit().List(t.Context(), store.AuditQuery{TenantID: a.tenant, Actions: []string{action}, Limit: store.MaxAuditPage})
	if err != nil {
		t.Fatalf("List of the audit log failed: %v", err)
	}
	return list
}

func detailsOf(t *testing.T, r store.AuditRecord) map[string]any {
	t.Helper()
	var details map[string]any
	if r.Details == "" {
		return details
	}
	if err := json.Unmarshal([]byte(r.Details), &details); err != nil {
		t.Fatalf("the details %q are not JSON: %v", r.Details, err)
	}
	return details
}

func TestTheEventsOfAUserAreWrittenToTheAuditLog(t *testing.T) {
	f := newSessionFixture(t)
	cookie := f.login(t)
	at := f.clock.now().Truncate(time.Microsecond)
	f.clock.advance(time.Minute)
	changed, err := f.a.ChangePassword(t.Context(), cookie.Principal, goodPassword, "a new password that is long enough 1")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.a.Logout(t.Context(), changed.Principal); err != nil {
		t.Fatal(err)
	}

	created := recordsOf(t, f.a, "auth.user_created")
	if len(created) != 1 || created[0].ActorKind != store.ActorUser || created[0].ActorID != string(f.user.ID) || created[0].TargetUserID != string(f.user.ID) {
		t.Fatalf("the registration is recorded as %+v", created)
	}
	logins := recordsOf(t, f.a, "auth.login")
	if len(logins) != 1 {
		t.Fatalf("the audit log holds %d sign-ins, want 1", len(logins))
	}
	login := logins[0]
	details := detailsOf(t, login)
	if login.ActorKind != store.ActorUser || login.ActorID != string(f.user.ID) || login.TargetUserID != string(f.user.ID) ||
		login.IP != testIP.String() || !login.At.Equal(at) || details["kind"] != "cookie" || details["session"] != cookie.Principal.SessionID {
		t.Fatalf("the sign-in is recorded as %+v %v", login, details)
	}
	changes := recordsOf(t, f.a, "auth.password_changed")
	if len(changes) != 1 || detailsOf(t, changes[0])["session"] != changed.Principal.SessionID || !changes[0].At.Equal(at.Add(time.Minute)) {
		t.Fatalf("the change of the password is recorded as %+v", changes)
	}
	ended := recordsOf(t, f.a, "auth.session_ended")
	if len(ended) != 1 || detailsOf(t, ended[0])["reason"] != "password_changed" {
		t.Fatalf("the ended sessions are recorded as %+v", ended)
	}
	logouts := recordsOf(t, f.a, "auth.logout")
	if len(logouts) != 1 || logouts[0].ActorID != string(f.user.ID) {
		t.Fatalf("the sign-out is recorded as %+v", logouts)
	}
}

func TestTheConfirmationOfAChannelAndTheResetOfAPasswordAreWrittenToTheAuditLog(t *testing.T) {
	f := newRecoveryFixture(t, manyRequests())
	m := f.sendVerification(t)
	if err := f.a.Verify(t.Context(), VerifyRequest{Token: tokenOf(m.Link), IP: ipOne}); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	verified := recordsOf(t, f.a, "auth.channel_verified")
	if len(verified) != 1 || verified[0].ActorKind != store.ActorUser || verified[0].ActorID != string(f.user.ID) ||
		verified[0].TargetUserID != string(f.user.ID) || verified[0].IP != ipOne.String() {
		t.Fatalf("the confirmation is recorded as %+v", verified)
	}
	if details := detailsOf(t, verified[0]); details["channel"] != "email" || details["address"] != "n***@example.com" {
		t.Fatalf("the details of the confirmation are %v", details)
	}
	reset := f.sendReset(t)
	if err := f.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(reset.Link), Password: resetPassword, IP: ipOne}); err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}
	resets := recordsOf(t, f.a, "auth.password_reset")
	if len(resets) != 1 || resets[0].ActorID != string(f.user.ID) || resets[0].IP != ipOne.String() {
		t.Fatalf("the reset is recorded as %+v", resets)
	}
	if details := detailsOf(t, resets[0]); details["channel"] != "email" || details["address"] != "n***@example.com" {
		t.Fatalf("the details of the reset are %v", details)
	}
	if strings.Contains(resets[0].Details, resetPassword) || strings.Contains(verified[0].Details, tokenOf(m.Link)) {
		t.Fatal("a secret was written to the audit log")
	}
}

func TestAReusedRefreshTokenIsWrittenToTheAuditLogWithTheEndOfTheSession(t *testing.T) {
	f := newSessionFixture(t)
	login := f.tokenLogin(t)
	f.mustRefresh(t, login.Tokens.RefreshToken)
	f.clock.advance(time.Minute)
	f.refused(t, "a stolen token", login.Tokens.RefreshToken)
	reused := recordsOf(t, f.a, "auth.refresh_token_reused")
	if len(reused) != 1 || reused[0].ActorID != string(f.user.ID) || reused[0].TargetUserID != string(f.user.ID) || detailsOf(t, reused[0])["session"] != login.Principal.SessionID {
		t.Fatalf("the reuse is recorded as %+v", reused)
	}
	ended := recordsOf(t, f.a, "auth.session_ended")
	if len(ended) != 1 || detailsOf(t, ended[0])["reason"] != "refresh_token_reused" {
		t.Fatalf("the end of the session is recorded as %+v", ended)
	}
}

func TestARecordHasTheTimeOfTheEventAndNotTheTimeItWasWritten(t *testing.T) {
	f := newSessionFixture(t)
	happened := f.clock.now().Add(-time.Hour).Truncate(time.Microsecond)
	f.a.recordEvent(t.Context(), Event{Type: EventLogout, UserID: string(f.user.ID), IP: ipOne.String(), At: happened})
	records := recordsOf(t, f.a, "auth.logout")
	if len(records) != 1 || !records[0].At.Equal(happened) || records[0].IP != ipOne.String() {
		t.Fatalf("the record is %+v, want the time %v and the address", records, happened)
	}
}

func TestAFailedLoginIsWrittenInTheBackgroundWithAMaskedLogin(t *testing.T) {
	f := newSessionFixture(t)
	c := f.credentials()
	c.Password = "the wrong password"
	if _, err := f.a.Login(t.Context(), c); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login = %v", err)
	}
	c.Login = "nobody@example.com"
	if _, err := f.a.Login(t.Context(), c); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login = %v", err)
	}
	eventually(t, "the records of the failed sign-ins", func() bool { return len(recordsOf(t, f.a, "auth.login_failed")) == 2 })
	records := recordsOf(t, f.a, "auth.login_failed")
	unknown, known := records[0], records[1]
	if known.ActorID != string(f.user.ID) || known.TargetUserID != string(f.user.ID) || known.IP != testIP.String() {
		t.Errorf("the failure of a known login is recorded as %+v", known)
	}
	if unknown.ActorKind != store.ActorUser || unknown.ActorID != "" || unknown.TargetUserID != "" || unknown.IP != testIP.String() {
		t.Errorf("the failure of an unknown login is recorded as %+v: no user is named", unknown)
	}
	for _, r := range records {
		details := detailsOf(t, r)
		if details["reason"] != "invalid_credentials" || details["address"] != "n***@example.com" {
			t.Errorf("the details are %v, want the reason and the masked login", details)
		}
		if strings.Contains(r.Details, "nobody") || strings.Contains(r.Details, "nina") {
			t.Errorf("the login is not masked in %q", r.Details)
		}
	}
}

func TestTheAuditLogHoldsNoSecrets(t *testing.T) {
	f := newSessionFixture(t)
	const wrong = "a wrong password that nobody uses"
	const next = "a new password that is long enough 1"
	c := f.credentials()
	c.Password = wrong
	_, _ = f.a.Login(t.Context(), c)
	cookie := f.login(t)
	token := f.tokenLogin(t)
	refreshed := f.mustRefresh(t, token.Tokens.RefreshToken)
	changed, err := f.a.ChangePassword(t.Context(), cookie.Principal, goodPassword, next)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.advance(time.Minute)
	f.refused(t, "a stolen token", token.Tokens.RefreshToken)
	_ = f.a.Logout(t.Context(), changed.Principal)
	eventually(t, "the record of the failed sign-in", func() bool { return len(recordsOf(t, f.a, "auth.login_failed")) == 1 })
	list, err := f.a.store.Audit().List(t.Context(), store.AuditQuery{TenantID: f.a.tenant, Limit: store.MaxAuditPage})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range list {
		seen[r.Action] = true
	}
	for _, action := range []string{"auth.user_created", "auth.login", "auth.login_failed", "auth.password_changed", "auth.session_ended", "auth.logout"} {
		if !seen[action] {
			t.Fatalf("the flow left no record of %s: %s", action, raw)
		}
	}
	for _, secret := range []string{
		goodPassword, wrong, next, cookie.Secret, cookie.CSRFToken, changed.Secret, changed.CSRFToken,
		token.Tokens.AccessToken, token.Tokens.RefreshToken, refreshed.AccessToken, refreshed.RefreshToken, "nina@example.com", "nina_n",
	} {
		if secret != "" && strings.Contains(strings.ToLower(string(raw)), strings.ToLower(secret)) {
			t.Fatalf("the audit log contains %q: %s", secret, raw)
		}
	}
}

func TestAFailureToWriteARecordIsLoggedAndHarmsNothing(t *testing.T) {
	logger, logs := capturingLogger()
	f := newSessionFixture(t, WithLogger(logger))
	faults := newFaults()
	f.a.store = faultStore{Store: f.a.store, faults: faults}
	broken := errors.New("the audit log is gone")
	faults.set("audit.add", broken)
	cookie := f.login(t)
	if err := f.a.Logout(t.Context(), cookie.Principal); err != nil {
		t.Fatalf("Logout failed because the audit log did: %v", err)
	}
	if got := strings.Count(logs.String(), "the audit record of an event could not be written"); got != 2 {
		t.Fatalf("the failures are logged %d times, want 2: %s", got, logs.String())
	}
	if !strings.Contains(logs.String(), "the audit log is gone") || strings.Contains(logs.String(), goodPassword) {
		t.Fatalf("the log says %s", logs.String())
	}
}

type blockedAudit struct {
	store.Audit
	gate  chan struct{}
	added atomic.Int64
}

func (b *blockedAudit) Add(ctx context.Context, r store.AuditRecord) error {
	select {
	case <-b.gate:
	case <-ctx.Done():
		return ctx.Err()
	}
	b.added.Add(1)
	return b.Audit.Add(ctx, r)
}

type blockedAuditStore struct {
	store.Store
	audit *blockedAudit
}

func (s blockedAuditStore) Audit() store.Audit { return s.audit }

func newBlockedAudit(t *testing.T) (*Auth, *blockedAudit, *logBuffer) {
	t.Helper()
	logger, logs := capturingLogger()
	f := newSessionFixture(t, WithLogger(logger))
	blocked := &blockedAudit{Audit: f.a.store.Audit(), gate: make(chan struct{})}
	f.a.store = blockedAuditStore{Store: f.a.store, audit: blocked}
	return f.a, blocked, logs
}

func TestAFullQueueDropsTheRecordsOfFailedLogins(t *testing.T) {
	a, blocked, logs := newBlockedAudit(t)
	const sent = 400
	for i := range sent {
		a.emit(t.Context(), Event{Type: EventLoginFailed, Address: "a***@example.com", Details: map[string]string{"reason": "invalid_credentials", "n": string(rune('a' + i%26))}})
	}
	dropped := strings.Count(logs.String(), "an audit record was dropped")
	if dropped < sent-eventQueueSize-2 || dropped > sent-eventQueueSize {
		t.Fatalf("%d records were dropped of %d with a queue of %d", dropped, sent, eventQueueSize)
	}
	close(blocked.gate)
	want := int64(sent - dropped)
	eventually(t, "the queued records", func() bool { return blocked.added.Load() == want })
	if got := len(recordsOf(t, a, "auth.login_failed")); int64(got) != want {
		t.Fatalf("the audit log holds %d records of failed sign-ins, want %d", got, want)
	}
}

func TestShutdownWritesTheRecordsThatWait(t *testing.T) {
	a, blocked, logs := newBlockedAudit(t)
	for range 3 {
		a.emit(t.Context(), Event{Type: EventLoginFailed, Details: map[string]string{"reason": "invalid_credentials"}})
	}
	done := make(chan error, 1)
	go func() { done <- a.Shutdown(t.Context()) }()
	select {
	case err := <-done:
		t.Fatalf("Shutdown returned %v while the records were not written", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(blocked.gate)
	if err := <-done; err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	if got := len(recordsOf(t, a, "auth.login_failed")); got != 3 {
		t.Fatalf("the audit log holds %d records, want 3", got)
	}
	a.emit(t.Context(), Event{Type: EventLoginFailed})
	if !strings.Contains(logs.String(), "an audit record was dropped") {
		t.Fatalf("a record after the shutdown was not refused: %s", logs.String())
	}
}

func TestShutdownCountsTheRecordsThatWereNotWritten(t *testing.T) {
	a, blocked, logs := newBlockedAudit(t)
	defer close(blocked.gate)
	for range 2 {
		a.emit(t.Context(), Event{Type: EventLoginFailed})
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	err := a.Shutdown(ctx)
	if err == nil || !strings.Contains(err.Error(), "audit records were not written") || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want an error that counts the records that were not written", err)
	}
	if !strings.Contains(logs.String(), "the service stopped before all audit records were written") {
		t.Fatalf("the loss was not logged: %s", logs.String())
	}
}

func TestOnlyTheEventsOfUsersAreWrittenToTheAuditLog(t *testing.T) {
	a := newTestAuth(t)
	a.emit(t.Context(), Event{Type: EventMessageFailed, Details: map[string]string{"kind": "verification", "reason": "failed"}})
	a.emitHook(t.Context(), Event{Type: EventLogin, UserID: "00000000-0000-7000-8000-000000000001"})
	if list, err := a.store.Audit().List(t.Context(), store.AuditQuery{TenantID: a.tenant, Limit: 10}); err != nil || len(list) != 0 {
		t.Fatalf("the audit log holds %+v, %v: a failed message is no event of a user, and an event for the hook alone is not written", list, err)
	}
}

func TestEveryEventOfAUserHasAnAction(t *testing.T) {
	for typ := range auditedEvents {
		action := audit.AuthPrefix + string(typ)
		if len(action) > store.MaxAuditActionLength {
			t.Errorf("the action %q is longer than %d bytes", action, store.MaxAuditActionLength)
		}
	}
}

func TestAccountsRememberHowTheyCameToBe(t *testing.T) {
	f := newFixture(t, WithSignup(), WithoutVerificationRequired())
	if got := f.stored(t).CreatedVia; got != store.CreatedViaAPI {
		t.Fatalf("a user of Register came via %q, want %q", got, store.CreatedViaAPI)
	}
	err := f.a.Signup(t.Context(), SignupRequest{Registration: Registration{
		Identifiers: map[string]string{"email": "visitor@example.com", "username": "visitor_v"}, Password: goodPassword,
	}})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	found, err := f.a.store.Identifiers().Find(t.Context(), f.a.tenant, "email", "visitor@example.com")
	if err != nil {
		t.Fatal(err)
	}
	visitor, err := f.a.store.Users().Get(t.Context(), f.a.tenant, found.UserID)
	if err != nil || visitor.CreatedVia != store.CreatedViaSignup {
		t.Fatalf("a user of Signup = %+v, %v; want created_via %q", visitor, err, store.CreatedViaSignup)
	}
	eventually(t, "the record of the registration", func() bool {
		for _, r := range recordsOf(t, f.a, "auth.user_created") {
			if r.TargetUserID == visitor.ID {
				return true
			}
		}
		return false
	})
}
