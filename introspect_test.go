package limb

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func serviceKeyOf(label string) string {
	return label + strings.Repeat("-key-", 8)
}

func newIntrospectionFixture(t *testing.T, opts ...Option) *sessionFixture {
	t.Helper()
	all := append([]Option{WithServiceKey("billing", serviceKeyOf("billing")), WithServiceKey("search", serviceKeyOf("search"))}, opts...)
	return newSessionFixture(t, all...)
}

func (f *sessionFixture) introspect(t *testing.T, key, token string) introspection {
	t.Helper()
	got, err := f.a.introspect(t.Context(), key, token)
	if err != nil {
		t.Fatalf("introspect failed: %v", err)
	}
	return got
}

func TestAnActiveTokenIsIntrospected(t *testing.T) {
	f := newIntrospectionFixture(t)
	login := f.tokenLogin(t)
	f.clock.advance(time.Minute)
	got := f.introspect(t, serviceKeyOf("billing"), login.Tokens.AccessToken)
	claims, err := f.a.verifyAccessToken(t.Context(), login.Tokens.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	want := introspection{
		Active: true, Subject: string(f.user.ID), SessionID: login.Principal.SessionID,
		IssuedAt: claims.IssuedAt.Time, ExpiresAt: claims.ExpiresAt.Time,
	}
	if got != want {
		t.Fatalf("introspect = %+v, want %+v", got, want)
	}
	if !got.ExpiresAt.Equal(login.Tokens.AccessExpiresAt) || got.IssuedAt.After(f.clock.now()) {
		t.Fatalf("times: %+v, access token expires at %v", got, login.Tokens.AccessExpiresAt)
	}
	if again := f.introspect(t, serviceKeyOf("search"), login.Tokens.AccessToken); again != want {
		t.Fatalf("another service gets %+v, want %+v", again, want)
	}
}

func TestAnInactiveTokenSaysNothingElse(t *testing.T) {
	f := newIntrospectionFixture(t, WithSessionTTL(24*time.Hour, 30*time.Minute))
	key := serviceKeyOf("billing")
	inactive := func(name, token string) {
		t.Helper()
		if got := f.introspect(t, key, token); got != (introspection{}) {
			t.Errorf("%s: introspect = %+v, want only active: false", name, got)
		}
	}
	good := f.tokenLogin(t)
	inactive("nothing", "")
	inactive("junk", "junk")
	inactive("a refresh token", good.Tokens.RefreshToken)
	inactive("a token with a damaged signature", good.Tokens.AccessToken[:len(good.Tokens.AccessToken)-4]+"AAAA")

	ended := f.tokenLogin(t)
	if err := f.a.Logout(t.Context(), ended.Principal); err != nil {
		t.Fatal(err)
	}
	inactive("an ended session", ended.Tokens.AccessToken)

	for name, edit := range map[string]func(*store.User){
		"a blocked user": func(u *store.User) { u.Status = store.StatusBlocked },
		"a deleted user": func(u *store.User) { u.Status = store.StatusDeleted },
	} {
		login := f.tokenLogin(t)
		f.change(t, edit)
		inactive(name, login.Tokens.AccessToken)
		f.change(t, func(u *store.User) { u.Status = store.StatusActive })
	}

	restricted := f.tokenLogin(t)
	f.change(t, func(u *store.User) { u.MustChangePassword = true })
	inactive("a user who must change the password", restricted.Tokens.AccessToken)
	f.change(t, func(u *store.User) { u.MustChangePassword = false })

	flagged := f.tokenLogin(t)
	f.change(t, func(u *store.User) { u.MustChangePassword = true })
	withClaim := f.tokenLogin(t)
	f.change(t, func(u *store.User) { u.MustChangePassword = false })
	inactive("a token that carries the service claim", withClaim.Tokens.AccessToken)
	if got := f.introspect(t, key, flagged.Tokens.AccessToken); !got.Active {
		t.Fatalf("a token of a user who has changed the password is good again: %+v", got)
	}

	cookie := f.login(t)
	inactive("a token of a cookie session", a2token(t, f.a, string(f.user.ID), cookie.Principal.SessionID))
	inactive("a token of an unknown session", a2token(t, f.a, string(f.user.ID), "00000000-0000-7000-8000-00000000dead"))

	expired := f.tokenLogin(t)
	f.clock.advance(10*time.Minute + tokenLeeway + time.Second)
	inactive("an expired token", expired.Tokens.AccessToken)

	idle := f.tokenLogin(t)
	f.clock.advance(30 * time.Minute)
	token := a2token(t, f.a, string(f.user.ID), idle.Principal.SessionID)
	inactive("an idle session", token)
}

func TestIntrospectionIsInstantWhateverTheRevocationMode(t *testing.T) {
	f := newIntrospectionFixture(t, WithRevocation(RevocationAfterTTL))
	login := f.tokenLogin(t)
	if _, err := f.authenticateToken(t, login); err != nil {
		t.Fatal(err)
	}
	if err := f.a.Logout(t.Context(), login.Principal); err != nil {
		t.Fatal(err)
	}
	if _, err := f.authenticateToken(t, login); err != nil {
		t.Fatalf("in this mode the token keeps working for the application: %v", err)
	}
	if got := f.introspect(t, serviceKeyOf("billing"), login.Tokens.AccessToken); got.Active {
		t.Fatalf("introspect = %+v: a service that asks must always get the truth", got)
	}
}

func TestIntrospectionCountsAsUseOfTheSession(t *testing.T) {
	f := newIntrospectionFixture(t)
	login := f.tokenLogin(t)
	start := f.session(t, login.Principal.SessionID).Session.LastSeenAt
	f.clock.advance(touchInterval)
	if got := f.introspect(t, serviceKeyOf("billing"), login.Tokens.AccessToken); !got.Active {
		t.Fatalf("introspect = %+v", got)
	}
	if got := f.session(t, login.Principal.SessionID).Session.LastSeenAt; !got.Equal(start.Add(touchInterval)) {
		t.Fatalf("LastSeenAt = %v, want %v: a session that only an external service uses must not go idle", got, start.Add(touchInterval))
	}
}

func TestOnlyAServiceWithAKeyMayAsk(t *testing.T) {
	f := newIntrospectionFixture(t)
	login := f.tokenLogin(t)
	for name, key := range map[string]string{
		"no key":                  "",
		"a key that is not known": serviceKeyOf("other"),
		"a key cut short":         serviceKeyOf("billing")[:40],
		"a key extended":          serviceKeyOf("billing") + "x",
		"a key in capitals":       strings.ToUpper(serviceKeyOf("billing")),
		"a key with a space":      " " + serviceKeyOf("billing"),
		"the access token":        login.Tokens.AccessToken,
		"the refresh token":       login.Tokens.RefreshToken,
		"a huge key":              strings.Repeat("k", 1<<20),
	} {
		if got, err := f.a.introspect(t.Context(), key, login.Tokens.AccessToken); err != ErrUnauthenticated || got != (introspection{}) { //nolint:errorlint
			t.Errorf("%s: introspect = %+v, %v; want ErrUnauthenticated exactly and no answer", name, got, err)
		}
	}
	for _, label := range []string{"billing", "search"} {
		if got := f.introspect(t, serviceKeyOf(label), login.Tokens.AccessToken); !got.Active {
			t.Errorf("the key of %s must be accepted", label)
		}
	}
}

func TestWithoutServiceKeysNobodyMayAsk(t *testing.T) {
	f := newSessionFixture(t)
	login := f.tokenLogin(t)
	for _, key := range []string{"", serviceKeyOf("billing"), strings.Repeat("a", 40)} {
		if _, err := f.a.introspect(t.Context(), key, login.Tokens.AccessToken); err != ErrUnauthenticated { //nolint:errorlint
			t.Errorf("introspect with %q = %v, want ErrUnauthenticated", key, err)
		}
	}
}

func TestIntrospectionReportsStoreFailures(t *testing.T) {
	f := newIntrospectionFixture(t)
	login := f.tokenLogin(t)
	boom := errors.New("database is down")
	f.breakSessions(func(s *sessionsFault) { s.resolveErr = boom })
	if got, err := f.a.introspect(t.Context(), serviceKeyOf("billing"), login.Tokens.AccessToken); !errors.Is(err, boom) || got != (introspection{}) {
		t.Fatalf("introspect = %+v, %v; a failure must not be taken for an inactive token", got, err)
	}
	other := newIntrospectionFixture(t)
	token, _ := other.a.mustIssue(t, false)
	other.a.store = &keysFaultStore{Store: other.a.store, listErr: boom}
	other.a.ring = newKeyring(other.a)
	if _, err := other.a.introspect(t.Context(), serviceKeyOf("billing"), token); !errors.Is(err, boom) {
		t.Fatalf("introspect = %v, want %v", err, boom)
	}
}

func TestServiceKeysAreValidated(t *testing.T) {
	good := serviceKeyOf("billing")
	cases := map[string][]Option{
		"no name":             {WithServiceKey("", good)},
		"a long name":         {WithServiceKey(strings.Repeat("n", 65), good)},
		"a control name":      {WithServiceKey("a\nb", good)},
		"a short key":         {WithServiceKey("billing", good[:31])},
		"an empty key":        {WithServiceKey("billing", "")},
		"a key with space":    {WithServiceKey("billing", good[:20]+" "+good[21:])},
		"a key with a tab":    {WithServiceKey("billing", good[:20]+"\t"+good[21:])},
		"a key with a byte":   {WithServiceKey("billing", good[:20]+"\xff"+good[21:])},
		"a key with Cyrillic": {WithServiceKey("billing", good[:20]+"ж"+good[21:])},
		"the same name":       {WithServiceKey("billing", good), WithServiceKey("billing", serviceKeyOf("other"))},
		"the same key":        {WithServiceKey("billing", good), WithServiceKey("search", good)},
	}
	for name, opts := range cases {
		err := newFixtureErr(t, opts...)
		if err == nil || !strings.HasPrefix(err.Error(), "limb: ") {
			t.Errorf("%s: New = %v, want a configuration error", name, err)
		}
		if err != nil && strings.Contains(err.Error(), good) {
			t.Errorf("%s: the error must not contain the key: %v", name, err)
		}
	}
	if err := newFixtureErr(t, WithServiceKey("billing", good[:32])); err != nil {
		t.Fatalf("a key of 32 bytes is enough: %v", err)
	}
	a, _ := newTokenAuth(t, WithServiceKey("billing", good))
	if len(a.services) != 1 || a.services[0].name != "billing" {
		t.Fatalf("services = %+v", a.services)
	}
	if strings.Contains(string(a.services[0].hash[:]), good[:8]) {
		t.Fatal("only the hash of the key may be kept")
	}
}

func TestABearerRequestForAServiceIsNotAnAccessToken(t *testing.T) {
	f := newIntrospectionFixture(t)
	f.tokenLogin(t)
	r := f.bearer(t, http.MethodPost, serviceKeyOf("billing"))
	if _, err := f.a.Authenticate(r); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("a service key presented as an access token = %v, want ErrUnauthenticated", err)
	}
}
