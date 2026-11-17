package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

type channel struct{ typ, value string }

var (
	aliceEmail = channel{"email", "alice@example.com"}
	alicePhone = channel{"phone", "+15550100"}
	bobEmail   = channel{"email", "bob@example.com"}
)

const attemptLimit = 5

func prepareSecrets(t *testing.T, s store.Store) {
	t.Helper()
	mustCreate(t, s, newUser(tenantA, id(1)))
	mustCreate(t, s, newUser(tenantA, id(2)))
	mustAdd(t, s, newIdentifier(tenantA, aliceEmail.typ, aliceEmail.value, id(1)))
	mustAdd(t, s, newIdentifier(tenantA, alicePhone.typ, alicePhone.value, id(1)))
	mustAdd(t, s, newIdentifier(tenantA, bobEmail.typ, bobEmail.value, id(2)))
}

func newSecret(kind store.SecretKind, n int, userID string, purpose store.SecretPurpose, c channel) store.Secret {
	return store.Secret{
		TenantID:     tenantA,
		ID:           id(200 + n),
		Kind:         kind,
		Hash:         hashOf("secret", n),
		UserID:       userID,
		Purpose:      purpose,
		ChannelType:  c.typ,
		ChannelValue: c.value,
		CreatedAt:    sessionBase,
		ExpiresAt:    sessionBase.Add(30 * time.Minute),
	}
}

func mustAddSecret(t *testing.T, s store.Store, secret store.Secret) {
	t.Helper()
	if err := s.Secrets().Add(t.Context(), secret); err != nil {
		t.Fatalf("Add(secret %s) failed: %v", secret.ID, err)
	}
}

func scopeOf(userID string, purpose store.SecretPurpose, cs ...channel) store.SecretScope {
	scope := store.SecretScope{TenantID: tenantA, UserID: userID, Purpose: purpose}
	if len(cs) > 0 {
		scope.ChannelType, scope.ChannelValue = cs[0].typ, cs[0].value
	}
	return scope
}

func checkSecret(t *testing.T, got, want store.Secret) {
	t.Helper()
	if got.TenantID != want.TenantID || got.ID != want.ID || got.Kind != want.Kind || !bytes.Equal(got.Hash, want.Hash) ||
		got.UserID != want.UserID || got.Purpose != want.Purpose || got.ChannelType != want.ChannelType ||
		got.ChannelValue != want.ChannelValue || got.Attempts != want.Attempts {
		t.Fatalf("secret differs:\n got %+v\nwant %+v", got, want)
	}
	if !sameTime(got.CreatedAt, want.CreatedAt) || !sameTime(got.ExpiresAt, want.ExpiresAt) || !sameTime(got.UsedAt, want.UsedAt) {
		t.Fatalf("secret times differ, they must be UTC with microsecond precision:\n got %+v\nwant %+v", got, want)
	}
}

func addAndScramble(t *testing.T, s store.Store, secret store.Secret) {
	t.Helper()
	given := secret
	given.Hash = bytes.Clone(secret.Hash)
	mustAddSecret(t, s, given)
	for i := range given.Hash {
		given.Hash[i] ^= 0xff
	}
}

func scramble(secrets []store.Secret) {
	for _, secret := range secrets {
		for i := range secret.Hash {
			secret.Hash[i] ^= 0xff
		}
	}
}

func tried(t *testing.T, s store.Store, scope store.SecretScope, at time.Time, limit int) []store.Secret {
	t.Helper()
	got, err := s.Secrets().TryCodes(t.Context(), scope, at, limit)
	if err != nil {
		t.Fatalf("TryCodes failed: %v", err)
	}
	return got
}

func testSecretLink(t *testing.T, s store.Store) {
	ctx := t.Context()
	prepareSecrets(t, s)
	link := newSecret(store.SecretLink, 1, id(1), store.PurposeReset, aliceEmail)
	link.CreatedAt = sessionBase.Add(123 * time.Nanosecond)
	link.ExpiresAt = link.CreatedAt.Add(30*time.Minute + 456*time.Nanosecond)
	mustAddSecret(t, s, link)

	at := link.CreatedAt.Add(time.Minute + 789*time.Nanosecond)
	got, err := s.Secrets().UseLink(ctx, tenantA, store.PurposeReset, link.Hash, at)
	if err != nil {
		t.Fatalf("UseLink failed: %v", err)
	}
	want := link
	want.UsedAt = at
	checkSecret(t, got, want)
	scramble([]store.Secret{got})
	for range 2 {
		if _, err = s.Secrets().UseLink(ctx, tenantA, store.PurposeReset, link.Hash, at.Add(time.Second)); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("UseLink of a link that was used = %v, want ErrNotFound", err)
		}
	}
}

func testSecretLinkRefusals(t *testing.T, s store.Store) {
	ctx := t.Context()
	prepareSecrets(t, s)
	link := newSecret(store.SecretLink, 1, id(1), store.PurposeVerify, aliceEmail)
	code := newSecret(store.SecretCode, 2, id(1), store.PurposeVerify, aliceEmail)
	mustAddSecret(t, s, link)
	mustAddSecret(t, s, code)

	refused := map[string]struct {
		tenant  string
		purpose store.SecretPurpose
		hash    []byte
		at      time.Time
	}{
		"another purpose":           {tenantA, store.PurposeReset, link.Hash, sessionBase},
		"another tenant":            {tenantB, store.PurposeVerify, link.Hash, sessionBase},
		"an unknown hash":           {tenantA, store.PurposeVerify, hashOf("secret", 99), sessionBase},
		"the hash of a code":        {tenantA, store.PurposeVerify, code.Hash, sessionBase},
		"a short hash":              {tenantA, store.PurposeVerify, link.Hash[:31], sessionBase},
		"no hash":                   {tenantA, store.PurposeVerify, nil, sessionBase},
		"the moment it expires":     {tenantA, store.PurposeVerify, link.Hash, link.ExpiresAt},
		"a time after it expired":   {tenantA, store.PurposeVerify, link.Hash, link.ExpiresAt.Add(time.Second)},
		"a NUL byte in the tenant":  {"a\x00", store.PurposeVerify, link.Hash, sessionBase},
		"a tenant of a long length": {strings.Repeat("a", store.MaxIdentifierValueLength+1), store.PurposeVerify, link.Hash, sessionBase},
	}
	for name, c := range refused {
		if _, err := s.Secrets().UseLink(ctx, c.tenant, c.purpose, c.hash, c.at); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UseLink with %s = %v, want ErrNotFound", name, err)
		}
	}
	if _, err := s.Secrets().UseLink(ctx, tenantA, "other", link.Hash, sessionBase); err == nil || isDomainError(err) {
		t.Errorf("UseLink with an unknown purpose = %v, want a validation error", err)
	}
	if _, err := s.Secrets().UseLink(ctx, tenantA, store.PurposeVerify, link.Hash, time.Time{}); err == nil || isDomainError(err) {
		t.Errorf("UseLink without a time = %v, want a validation error", err)
	}
	if got, err := s.Secrets().UseLink(ctx, tenantA, store.PurposeVerify, link.Hash, sessionBase.Add(time.Minute)); err != nil || got.ID != link.ID {
		t.Fatalf("refused calls must leave the link unused: %+v, %v", got, err)
	}
}

func testSecretAddErrors(t *testing.T, s store.Store) {
	ctx := t.Context()
	prepareSecrets(t, s)
	mustCreate(t, s, newUser(tenantB, id(1)))
	mustAddSecret(t, s, newSecret(store.SecretLink, 1, id(1), store.PurposeReset, aliceEmail))

	sameID := newSecret(store.SecretCode, 2, id(1), store.PurposeReset, aliceEmail)
	sameID.ID = id(201)
	if err := s.Secrets().Add(ctx, sameID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Add of a taken ID = %v, want ErrConflict", err)
	}
	sameHash := newSecret(store.SecretCode, 3, id(1), store.PurposeReset, aliceEmail)
	sameHash.Hash = hashOf("secret", 1)
	if err := s.Secrets().Add(ctx, sameHash); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Add of a taken hash = %v, want ErrConflict", err)
	}
	missing := map[string]func(*store.Secret){
		"a missing user":                 func(x *store.Secret) { x.UserID = id(99) },
		"a missing channel":              func(x *store.Secret) { x.ChannelValue = "nobody@example.com" },
		"a channel of another type":      func(x *store.Secret) { x.ChannelType = "phone" },
		"the user of another tenant":     func(x *store.Secret) { x.TenantID = tenantB; x.UserID = id(2) },
		"the channel of another tenant":  func(x *store.Secret) { x.TenantID = tenantB; x.UserID = id(1) },
		"a channel that differs in case": func(x *store.Secret) { x.ChannelValue = "Alice@example.com" },
		"a channel with a space":         func(x *store.Secret) { x.ChannelValue = aliceEmail.value + " " },
	}
	for name, edit := range missing {
		secret := newSecret(store.SecretCode, 4, id(1), store.PurposeReset, aliceEmail)
		edit(&secret)
		if err := s.Secrets().Add(ctx, secret); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Add with %s = %v, want ErrNotFound", name, err)
		}
	}
	invalid := map[string]func(*store.Secret){
		"no tenant":            func(x *store.Secret) { x.TenantID = "" },
		"no ID":                func(x *store.Secret) { x.ID = "" },
		"no user":              func(x *store.Secret) { x.UserID = "" },
		"no kind":              func(x *store.Secret) { x.Kind = "" },
		"an unknown kind":      func(x *store.Secret) { x.Kind = "token" },
		"no purpose":           func(x *store.Secret) { x.Purpose = "" },
		"an unknown purpose":   func(x *store.Secret) { x.Purpose = "invite" },
		"no hash":              func(x *store.Secret) { x.Hash = nil },
		"a short hash":         func(x *store.Secret) { x.Hash = x.Hash[:31] },
		"a long hash":          func(x *store.Secret) { x.Hash = append(bytes.Clone(x.Hash), 0) },
		"no channel type":      func(x *store.Secret) { x.ChannelType = "" },
		"no channel value":     func(x *store.Secret) { x.ChannelValue = "" },
		"attempts":             func(x *store.Secret) { x.Attempts = 1 },
		"no creation time":     func(x *store.Secret) { x.CreatedAt = time.Time{} },
		"no expiry":            func(x *store.Secret) { x.ExpiresAt = time.Time{} },
		"an expiry before":     func(x *store.Secret) { x.ExpiresAt = x.CreatedAt.Add(-time.Second) },
		"an expiry at once":    func(x *store.Secret) { x.ExpiresAt = x.CreatedAt },
		"a use":                func(x *store.Secret) { x.UsedAt = sessionBase },
		"a NUL byte in the ID": func(x *store.Secret) { x.ID = "a\x00" },
		"a NUL byte in value":  func(x *store.Secret) { x.ChannelValue = "a\x00" },
		"text that is not UTF-8": func(x *store.Secret) {
			x.ID = string([]byte{0xff, 0xfe})
		},
	}
	for name, edit := range invalid {
		secret := newSecret(store.SecretCode, 5, id(1), store.PurposeReset, aliceEmail)
		edit(&secret)
		if err := s.Secrets().Add(ctx, secret); err == nil || isDomainError(err) {
			t.Errorf("Add with %s = %v, want a validation error", name, err)
		}
	}
	if ended, err := s.Secrets().End(ctx, scopeOf(id(1), store.PurposeReset), sessionBase); err != nil || ended != 1 {
		t.Fatalf("End = %d, %v; want only the one secret that was stored", ended, err)
	}
}

func testSecretTryCodes(t *testing.T, s store.Store) {
	prepareSecrets(t, s)
	email := newSecret(store.SecretCode, 1, id(1), store.PurposeReset, aliceEmail)
	phone := newSecret(store.SecretCode, 2, id(1), store.PurposeReset, alicePhone)
	phone.CreatedAt = email.CreatedAt.Add(time.Second)
	phone.ExpiresAt = email.ExpiresAt.Add(time.Second)
	addAndScramble(t, s, email)
	addAndScramble(t, s, phone)
	mustAddSecret(t, s, newSecret(store.SecretLink, 3, id(1), store.PurposeReset, aliceEmail))
	mustAddSecret(t, s, newSecret(store.SecretCode, 4, id(1), store.PurposeVerify, aliceEmail))
	mustAddSecret(t, s, newSecret(store.SecretCode, 5, id(2), store.PurposeReset, bobEmail))

	at := sessionBase.Add(time.Minute)
	for count := range 3 {
		got := tried(t, s, scopeOf(id(1), store.PurposeReset), at, 3)
		if len(got) != 2 {
			t.Fatalf("attempt %d: TryCodes returned %d codes, want the code of each channel", count+1, len(got))
		}
		email.Attempts, phone.Attempts = count, count
		checkSecret(t, got[0], email)
		checkSecret(t, got[1], phone)
		scramble(got)
	}
	if got := tried(t, s, scopeOf(id(1), store.PurposeReset), at, 3); len(got) != 0 {
		t.Fatalf("TryCodes after the limit returned %+v, want nothing", got)
	}
	got := tried(t, s, scopeOf(id(1), store.PurposeReset, aliceEmail), at, attemptLimit)
	email.Attempts = 3
	if len(got) != 1 {
		t.Fatalf("TryCodes of one channel returned %d codes, want 1", len(got))
	}
	checkSecret(t, got[0], email)
	got = tried(t, s, scopeOf(id(1), store.PurposeReset), at, attemptLimit)
	email.Attempts, phone.Attempts = 4, 3
	if len(got) != 2 {
		t.Fatalf("TryCodes of every channel returned %d codes, want 2", len(got))
	}
	checkSecret(t, got[0], email)
	checkSecret(t, got[1], phone)
	if got = tried(t, s, scopeOf(id(1), store.PurposeReset, aliceEmail), at, attemptLimit); len(got) != 0 {
		t.Fatalf("TryCodes after the fifth attempt returned %+v, want nothing", got)
	}
	bob := tried(t, s, scopeOf(id(2), store.PurposeReset), at, attemptLimit)
	if len(bob) != 1 || bob[0].Attempts != 0 {
		t.Fatalf("the attempts of other users must not be counted: %+v", bob)
	}
	if got = tried(t, s, scopeOf(id(1), store.PurposeVerify), at, attemptLimit); len(got) != 1 || got[0].Attempts != 0 {
		t.Fatalf("the attempts of other purposes must not be counted: %+v", got)
	}
}

func testSecretTryCodesRefusals(t *testing.T, s store.Store) {
	ctx := t.Context()
	prepareSecrets(t, s)
	code := newSecret(store.SecretCode, 1, id(1), store.PurposeReset, aliceEmail)
	mustAddSecret(t, s, code)
	scope := scopeOf(id(1), store.PurposeReset)

	if got := tried(t, s, scope, code.ExpiresAt, attemptLimit); len(got) != 0 {
		t.Fatalf("TryCodes at the moment the code expires returned %+v, want nothing", got)
	}
	if got := tried(t, s, scope, code.ExpiresAt.Add(time.Hour), attemptLimit); len(got) != 0 {
		t.Fatalf("TryCodes after the code expired returned %+v, want nothing", got)
	}
	notFound := []store.SecretScope{
		{TenantID: tenantB, UserID: id(1), Purpose: store.PurposeReset},
		{TenantID: tenantA, UserID: id(99), Purpose: store.PurposeReset},
		{TenantID: "", UserID: id(1), Purpose: store.PurposeReset},
		{TenantID: tenantA, UserID: "", Purpose: store.PurposeReset},
		{TenantID: "a\x00", UserID: id(1), Purpose: store.PurposeReset},
		{TenantID: tenantA, UserID: id(1), Purpose: store.PurposeReset, ChannelType: "email", ChannelValue: "Alice@example.com"},
	}
	for _, scope := range notFound {
		if got := tried(t, s, scope, sessionBase, attemptLimit); len(got) != 0 {
			t.Errorf("TryCodes in %+v returned %+v, want nothing", scope, got)
		}
	}
	invalid := map[string]store.SecretScope{
		"an unknown purpose":        {TenantID: tenantA, UserID: id(1), Purpose: "other"},
		"no purpose":                {TenantID: tenantA, UserID: id(1)},
		"a channel without a value": {TenantID: tenantA, UserID: id(1), Purpose: store.PurposeReset, ChannelType: "email"},
		"a channel without a type":  {TenantID: tenantA, UserID: id(1), Purpose: store.PurposeReset, ChannelValue: aliceEmail.value},
	}
	for name, scope := range invalid {
		if _, err := s.Secrets().TryCodes(ctx, scope, sessionBase, attemptLimit); err == nil || isDomainError(err) {
			t.Errorf("TryCodes with %s = %v, want a validation error", name, err)
		}
		if _, err := s.Secrets().End(ctx, scope, sessionBase); err == nil || isDomainError(err) {
			t.Errorf("End with %s = %v, want a validation error", name, err)
		}
	}
	if _, err := s.Secrets().TryCodes(ctx, scope, time.Time{}, attemptLimit); err == nil || isDomainError(err) {
		t.Errorf("TryCodes without a time = %v, want a validation error", err)
	}
	for _, limit := range []int{0, -1} {
		if _, err := s.Secrets().TryCodes(ctx, scope, sessionBase, limit); err == nil || isDomainError(err) {
			t.Errorf("TryCodes with the limit %d = %v, want a validation error", limit, err)
		}
	}
	if got := tried(t, s, scope, sessionBase, 1); len(got) != 1 || got[0].Attempts != 0 {
		t.Fatalf("refused calls must not count attempts: %+v", got)
	}
}

func testConcurrentSecretTryCodes(t *testing.T, s store.Store) {
	ctx := t.Context()
	prepareSecrets(t, s)
	mustAddSecret(t, s, newSecret(store.SecretCode, 1, id(1), store.PurposeReset, aliceEmail))
	scope := scopeOf(id(1), store.PurposeReset)
	var returned atomic.Int64
	parallel(16, func(int) {
		got, err := s.Secrets().TryCodes(ctx, scope, sessionBase.Add(time.Minute), attemptLimit)
		if err != nil {
			t.Errorf("TryCodes failed: %v", err)
			return
		}
		returned.Add(int64(len(got)))
	})
	if got := returned.Load(); got != attemptLimit {
		t.Fatalf("the code was returned %d times to 16 callers at once, want exactly %d", got, attemptLimit)
	}
	if got := tried(t, s, scope, sessionBase.Add(time.Minute), attemptLimit); len(got) != 0 {
		t.Fatalf("TryCodes after the limit returned %+v, want nothing", got)
	}
}

func testSecretUseCode(t *testing.T, s store.Store) {
	ctx := t.Context()
	prepareSecrets(t, s)
	code := newSecret(store.SecretCode, 1, id(1), store.PurposeVerify, aliceEmail)
	mustAddSecret(t, s, code)
	mustAddSecret(t, s, newSecret(store.SecretLink, 2, id(1), store.PurposeVerify, aliceEmail))

	refused := map[string]struct {
		tenant, id string
		at         time.Time
	}{
		"an unknown ID":                {tenantA, id(299), sessionBase},
		"the ID of a link":             {tenantA, id(202), sessionBase},
		"another tenant":               {tenantB, code.ID, sessionBase},
		"the moment it expires":        {tenantA, code.ID, code.ExpiresAt},
		"a time after it expired":      {tenantA, code.ID, code.ExpiresAt.Add(time.Second)},
		"an ID with a NUL byte":        {tenantA, code.ID + "\x00", sessionBase},
		"an ID that is over its limit": {tenantA, strings.Repeat("a", store.MaxIDLength+1), sessionBase},
	}
	for name, c := range refused {
		if err := s.Secrets().UseCode(ctx, c.tenant, c.id, c.at); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UseCode with %s = %v, want ErrNotFound", name, err)
		}
	}
	if err := s.Secrets().UseCode(ctx, tenantA, code.ID, time.Time{}); err == nil || isDomainError(err) {
		t.Errorf("UseCode without a time = %v, want a validation error", err)
	}
	if err := s.Secrets().UseCode(ctx, tenantA, code.ID, sessionBase.Add(time.Minute)); err != nil {
		t.Fatalf("UseCode failed: %v", err)
	}
	if err := s.Secrets().UseCode(ctx, tenantA, code.ID, sessionBase.Add(2*time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UseCode of a code that was used = %v, want ErrNotFound", err)
	}
	if got := tried(t, s, scopeOf(id(1), store.PurposeVerify), sessionBase.Add(3*time.Minute), attemptLimit); len(got) != 0 {
		t.Fatalf("TryCodes returned %+v for a code that was used", got)
	}
}

func testConcurrentSecretUse(t *testing.T, s store.Store) {
	ctx := t.Context()
	prepareSecrets(t, s)
	link := newSecret(store.SecretLink, 1, id(1), store.PurposeReset, aliceEmail)
	code := newSecret(store.SecretCode, 2, id(1), store.PurposeReset, aliceEmail)
	mustAddSecret(t, s, link)
	mustAddSecret(t, s, code)
	var links, codes atomic.Int32
	parallel(16, func(i int) {
		at := sessionBase.Add(time.Duration(i+1) * time.Millisecond)
		if _, err := s.Secrets().UseLink(ctx, tenantA, store.PurposeReset, link.Hash, at); err == nil {
			links.Add(1)
		} else if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UseLink failed: %v", err)
		}
		if err := s.Secrets().UseCode(ctx, tenantA, code.ID, at); err == nil {
			codes.Add(1)
		} else if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UseCode failed: %v", err)
		}
	})
	if links.Load() != 1 || codes.Load() != 1 {
		t.Fatalf("16 callers used the link %d times and the code %d times, want once each", links.Load(), codes.Load())
	}
}

func testSecretEnd(t *testing.T, s store.Store) {
	ctx := t.Context()
	prepareSecrets(t, s)
	emailLink := newSecret(store.SecretLink, 1, id(1), store.PurposeReset, aliceEmail)
	emailCode := newSecret(store.SecretCode, 2, id(1), store.PurposeReset, aliceEmail)
	phoneCode := newSecret(store.SecretCode, 3, id(1), store.PurposeReset, alicePhone)
	verifyLink := newSecret(store.SecretLink, 4, id(1), store.PurposeVerify, aliceEmail)
	bobCode := newSecret(store.SecretCode, 5, id(2), store.PurposeReset, bobEmail)
	for _, secret := range []store.Secret{emailLink, emailCode, phoneCode, verifyLink, bobCode} {
		mustAddSecret(t, s, secret)
	}
	at := sessionBase.Add(time.Minute)

	if ended, err := s.Secrets().End(ctx, scopeOf(id(1), store.PurposeReset, aliceEmail), at); err != nil || ended != 2 {
		t.Fatalf("End of one channel = %d, %v; want 2", ended, err)
	}
	if _, err := s.Secrets().UseLink(ctx, tenantA, store.PurposeReset, emailLink.Hash, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UseLink of an ended link = %v, want ErrNotFound", err)
	}
	if err := s.Secrets().UseCode(ctx, tenantA, emailCode.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UseCode of an ended code = %v, want ErrNotFound", err)
	}
	if got := tried(t, s, scopeOf(id(1), store.PurposeReset, aliceEmail), at, attemptLimit); len(got) != 0 {
		t.Fatalf("TryCodes returned %+v for an ended code", got)
	}
	if ended, err := s.Secrets().End(ctx, scopeOf(id(1), store.PurposeReset, aliceEmail), at); err != nil || ended != 0 {
		t.Fatalf("a second End = %d, %v; want 0", ended, err)
	}
	if ended, err := s.Secrets().End(ctx, scopeOf(id(1), store.PurposeReset), at); err != nil || ended != 1 {
		t.Fatalf("End of every channel = %d, %v; want the code of the phone only", ended, err)
	}
	if err := s.Secrets().UseCode(ctx, tenantA, phoneCode.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UseCode of an ended code = %v, want ErrNotFound", err)
	}
	if _, err := s.Secrets().UseLink(ctx, tenantA, store.PurposeVerify, verifyLink.Hash, at); err != nil {
		t.Fatalf("a link of another purpose must not be ended: %v", err)
	}
	if err := s.Secrets().UseCode(ctx, tenantA, bobCode.ID, at); err != nil {
		t.Fatalf("a code of another user must not be ended: %v", err)
	}
	if _, err := s.Secrets().End(ctx, scopeOf(id(1), store.PurposeReset), time.Time{}); err == nil || isDomainError(err) {
		t.Fatalf("End without a time = %v, want a validation error", err)
	}
}

func testSecretDeleteStale(t *testing.T, s store.Store) {
	ctx := t.Context()
	prepareSecrets(t, s)
	mustCreate(t, s, newUser(tenantB, id(1)))
	mustAdd(t, s, newIdentifier(tenantB, aliceEmail.typ, aliceEmail.value, id(1)))
	expired := newSecret(store.SecretLink, 1, id(1), store.PurposeReset, aliceEmail)
	expired.ExpiresAt = sessionBase.Add(10 * time.Minute)
	used := newSecret(store.SecretLink, 2, id(1), store.PurposeReset, aliceEmail)
	used.ExpiresAt = sessionBase.Add(time.Hour)
	live := newSecret(store.SecretLink, 3, id(1), store.PurposeReset, aliceEmail)
	live.ExpiresAt = sessionBase.Add(time.Hour)
	usedAfterExpiry := newSecret(store.SecretCode, 4, id(1), store.PurposeReset, aliceEmail)
	usedAfterExpiry.ExpiresAt = sessionBase.Add(10 * time.Minute)
	other := newSecret(store.SecretLink, 5, id(1), store.PurposeReset, aliceEmail)
	other.TenantID = tenantB
	other.ExpiresAt = sessionBase.Add(10 * time.Minute)
	for _, secret := range []store.Secret{expired, used, live, usedAfterExpiry, other} {
		mustAddSecret(t, s, secret)
	}
	if _, err := s.Secrets().UseLink(ctx, tenantA, store.PurposeReset, used.Hash, sessionBase.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.Secrets().UseCode(ctx, tenantA, usedAfterExpiry.ID, sessionBase.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}

	before := sessionBase.Add(30 * time.Minute)
	if removed, err := s.Secrets().DeleteStale(ctx, tenantA, before.Add(-30*time.Minute)); err != nil || removed != 0 {
		t.Fatalf("DeleteStale at the creation time = %d, %v; want nothing to go", removed, err)
	}
	if removed, err := s.Secrets().DeleteStale(ctx, tenantA, before); err != nil || removed != 3 {
		t.Fatalf("DeleteStale = %d, %v; want the expired and the used secrets to go", removed, err)
	}
	if removed, err := s.Secrets().DeleteStale(ctx, tenantA, before); err != nil || removed != 0 {
		t.Fatalf("a second DeleteStale = %d, %v; want 0", removed, err)
	}
	if _, err := s.Secrets().UseLink(ctx, tenantA, store.PurposeReset, live.Hash, before); err != nil {
		t.Fatalf("the live link must stay: %v", err)
	}
	if removed, err := s.Secrets().DeleteStale(ctx, "a\x00", before); err != nil || removed != 0 {
		t.Fatalf("DeleteStale of a tenant that is not valid = %d, %v; want 0", removed, err)
	}
	if removed, err := s.Secrets().DeleteStale(ctx, tenantB, before); err != nil || removed != 1 {
		t.Fatalf("DeleteStale of the other tenant = %d, %v; want its own expired secret", removed, err)
	}
}

func testSecretsFollowTheirOwners(t *testing.T, s store.Store) {
	ctx := t.Context()
	prepareSecrets(t, s)
	emailLink := newSecret(store.SecretLink, 1, id(1), store.PurposeReset, aliceEmail)
	emailCode := newSecret(store.SecretCode, 2, id(1), store.PurposeReset, aliceEmail)
	phoneLink := newSecret(store.SecretLink, 3, id(1), store.PurposeVerify, alicePhone)
	bobLink := newSecret(store.SecretLink, 4, id(2), store.PurposeReset, bobEmail)
	for _, secret := range []store.Secret{emailLink, emailCode, phoneLink, bobLink} {
		mustAddSecret(t, s, secret)
	}
	at := sessionBase.Add(time.Minute)

	if err := s.Identifiers().Remove(ctx, tenantA, aliceEmail.typ, aliceEmail.value); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Secrets().UseLink(ctx, tenantA, store.PurposeReset, emailLink.Hash, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UseLink of a link whose channel was removed = %v, want ErrNotFound", err)
	}
	if err := s.Secrets().UseCode(ctx, tenantA, emailCode.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UseCode of a code whose channel was removed = %v, want ErrNotFound", err)
	}
	if err := s.Secrets().Add(ctx, newSecret(store.SecretCode, 5, id(1), store.PurposeReset, aliceEmail)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Add for a channel that was removed = %v, want ErrNotFound", err)
	}
	if got := tried(t, s, scopeOf(id(1), store.PurposeReset), at, attemptLimit); len(got) != 0 {
		t.Fatalf("TryCodes returned %+v after the only channel with a code was removed", got)
	}

	if err := s.Users().Delete(ctx, tenantA, id(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Secrets().UseLink(ctx, tenantA, store.PurposeVerify, phoneLink.Hash, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UseLink of a link of a user who was deleted = %v, want ErrNotFound", err)
	}
	if err := s.Secrets().Add(ctx, newSecret(store.SecretCode, 6, id(1), store.PurposeVerify, alicePhone)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Add for a user who was deleted = %v, want ErrNotFound", err)
	}
	if _, err := s.Secrets().UseLink(ctx, tenantA, store.PurposeReset, bobLink.Hash, at); err != nil {
		t.Fatalf("a link of another user must stay: %v", err)
	}
	if removed, err := s.Secrets().DeleteStale(ctx, tenantA, sessionBase.Add(24*time.Hour)); err != nil || removed != 1 {
		t.Fatalf("DeleteStale = %d, %v; want only the link of the other user, which was used", removed, err)
	}
}

func testSecretTenantIsolation(t *testing.T, s store.Store) {
	ctx := t.Context()
	prepareSecrets(t, s)
	mustCreate(t, s, newUser(tenantB, id(1)))
	mustAdd(t, s, newIdentifier(tenantB, aliceEmail.typ, aliceEmail.value, id(1)))
	first := newSecret(store.SecretCode, 1, id(1), store.PurposeReset, aliceEmail)
	second := newSecret(store.SecretCode, 2, id(1), store.PurposeReset, aliceEmail)
	second.TenantID = tenantB
	second.ID = first.ID
	mustAddSecret(t, s, first)
	mustAddSecret(t, s, second)
	at := sessionBase.Add(time.Minute)

	got, err := s.Secrets().TryCodes(ctx, store.SecretScope{TenantID: tenantB, UserID: id(1), Purpose: store.PurposeReset}, at, attemptLimit)
	if err != nil || len(got) != 1 || got[0].TenantID != tenantB || !bytes.Equal(got[0].Hash, second.Hash) {
		t.Fatalf("TryCodes in the second tenant = %+v, %v; want its own code", got, err)
	}
	if ended, endErr := s.Secrets().End(ctx, scopeOf(id(1), store.PurposeReset), at); endErr != nil || ended != 1 {
		t.Fatalf("End in the first tenant = %d, %v; want 1", ended, endErr)
	}
	if err = s.Secrets().UseCode(ctx, tenantB, second.ID, at); err != nil {
		t.Fatalf("a code of another tenant must not be ended: %v", err)
	}
	if err = s.Secrets().UseCode(ctx, tenantA, first.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UseCode of the code that was ended = %v, want ErrNotFound", err)
	}
}

func testSecretRollback(t *testing.T, s store.Store) {
	ctx := t.Context()
	prepareSecrets(t, s)
	link := newSecret(store.SecretLink, 1, id(1), store.PurposeReset, aliceEmail)
	code := newSecret(store.SecretCode, 2, id(1), store.PurposeReset, aliceEmail)
	mustAddSecret(t, s, link)
	mustAddSecret(t, s, code)
	scope := scopeOf(id(1), store.PurposeReset)
	at := sessionBase.Add(time.Minute)

	err := s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if _, useErr := tx.Secrets().UseLink(ctx, tenantA, store.PurposeReset, link.Hash, at); useErr != nil {
			return useErr
		}
		if got, tryErr := tx.Secrets().TryCodes(ctx, scope, at, attemptLimit); tryErr != nil || len(got) != 1 {
			return fmt.Errorf("TryCodes in the transaction = %v, %w", got, tryErr)
		}
		if _, endErr := tx.Secrets().End(ctx, scope, at); endErr != nil {
			return endErr
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatalf("InTx = %v, want the error of the function", err)
	}
	if _, err = s.Secrets().UseLink(ctx, tenantA, store.PurposeReset, link.Hash, at); err != nil {
		t.Fatalf("a link that a rolled back transaction used must still work: %v", err)
	}
	got := tried(t, s, scope, at, attemptLimit)
	if len(got) != 1 || got[0].Attempts != 0 {
		t.Fatalf("TryCodes = %+v, want the code with the attempts of the rolled back transaction forgotten", got)
	}

	err = s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if _, endErr := tx.Secrets().End(ctx, scope, at); endErr != nil {
			return endErr
		}
		return tx.Secrets().Add(ctx, newSecret(store.SecretLink, 3, id(1), store.PurposeReset, aliceEmail))
	})
	if err != nil {
		t.Fatalf("a transaction that replaces the secrets failed: %v", err)
	}
	if _, err = s.Secrets().UseLink(ctx, tenantA, store.PurposeReset, hashOf("secret", 3), at); err != nil {
		t.Fatalf("the new link must work after the commit: %v", err)
	}
	if err = s.Secrets().UseCode(ctx, tenantA, code.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UseCode of a code that the transaction ended = %v, want ErrNotFound", err)
	}
}

func testSecretLongestValues(t *testing.T, s store.Store) {
	for n, c := range characters {
		t.Run(c.name, func(t *testing.T) { storeTheLongestSecret(t, s, c.unit, n+1) })
	}
}

func storeTheLongestSecret(t *testing.T, s store.Store, unit string, n int) {
	ctx := t.Context()
	tenant := fill(unit, store.MaxTenantIDLength)
	userID := fill(unit, store.MaxIDLength)
	mustCreate(t, s, store.User{TenantID: tenant, ID: userID, Status: store.StatusActive, CreatedAt: sessionBase})
	ident := store.Identifier{
		TenantID:     tenant,
		Type:         fill(unit, store.MaxIdentifierTypeLength),
		Value:        fill(unit, store.MaxIdentifierValueLength),
		DisplayValue: "display",
		UserID:       userID,
	}
	mustAdd(t, s, ident)
	link := store.Secret{
		TenantID: tenant, ID: fill(unit, store.MaxIDLength), Kind: store.SecretLink, Hash: hashOf("longest", n),
		UserID: userID, Purpose: store.PurposeVerify, ChannelType: ident.Type, ChannelValue: ident.Value,
		CreatedAt: sessionBase, ExpiresAt: sessionBase.Add(time.Hour),
	}
	code := link
	code.ID, code.Kind, code.Hash = strings.Repeat("c", store.MaxIDLength), store.SecretCode, hashOf("longest", n+10)
	mustAddSecret(t, s, link)
	mustAddSecret(t, s, code)

	at := sessionBase.Add(time.Minute)
	got, err := s.Secrets().TryCodes(ctx, store.SecretScope{
		TenantID: tenant, UserID: userID, Purpose: store.PurposeVerify, ChannelType: ident.Type, ChannelValue: ident.Value,
	}, at, attemptLimit)
	if err != nil || len(got) != 1 {
		t.Fatalf("TryCodes with the longest values = %+v, %v; want the code", got, err)
	}
	checkSecret(t, got[0], code)
	used, err := s.Secrets().UseLink(ctx, tenant, store.PurposeVerify, link.Hash, at)
	if err != nil {
		t.Fatalf("UseLink with the longest values failed: %v", err)
	}
	link.UsedAt = at
	checkSecret(t, used, link)
	if err = s.Secrets().UseCode(ctx, tenant, code.ID, at); err != nil {
		t.Fatalf("UseCode with the longest values failed: %v", err)
	}
}

func testSecretValuesOverTheLimit(t *testing.T, s store.Store) {
	ctx := t.Context()
	prepareSecrets(t, s)
	fields := []struct {
		name  string
		limit int
		set   func(*store.Secret, string)
	}{
		{"tenant", store.MaxTenantIDLength, func(x *store.Secret, v string) { x.TenantID = v }},
		{"id", store.MaxIDLength, func(x *store.Secret, v string) { x.ID = v }},
		{"user", store.MaxIDLength, func(x *store.Secret, v string) { x.UserID = v }},
		{"channel type", store.MaxIdentifierTypeLength, func(x *store.Secret, v string) { x.ChannelType = v }},
		{"channel value", store.MaxIdentifierValueLength, func(x *store.Secret, v string) { x.ChannelValue = v }},
	}
	for _, f := range fields {
		for name, value := range overTheLimit(f.limit) {
			secret := newSecret(store.SecretLink, 1, id(1), store.PurposeReset, aliceEmail)
			f.set(&secret, value)
			if err := s.Secrets().Add(ctx, secret); err == nil || isDomainError(err) {
				t.Errorf("Add with %s over the limit of the %s = %v, want a validation error", name, f.name, err)
			}
		}
	}
	long := strings.Repeat("\U0001F600", 10000)
	if _, err := s.Secrets().UseLink(ctx, long, store.PurposeReset, hashOf("secret", 1), sessionBase); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("UseLink with a long tenant = %v, want ErrNotFound", err)
	}
	if err := s.Secrets().UseCode(ctx, tenantA, long, sessionBase); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("UseCode with a long ID = %v, want ErrNotFound", err)
	}
	scope := store.SecretScope{TenantID: tenantA, UserID: long, Purpose: store.PurposeReset}
	if got := tried(t, s, scope, sessionBase, attemptLimit); len(got) != 0 {
		t.Errorf("TryCodes with a long user returned %+v", got)
	}
	if ended, err := s.Secrets().End(ctx, scope, sessionBase); err != nil || ended != 0 {
		t.Errorf("End with a long user = %d, %v; want 0", ended, err)
	}
	if removed, err := s.Secrets().DeleteStale(ctx, long, sessionBase); err != nil || removed != 0 {
		t.Errorf("DeleteStale with a long tenant = %d, %v; want 0", removed, err)
	}
	if ended, err := s.Secrets().End(ctx, scopeOf(id(1), store.PurposeReset), sessionBase); err != nil || ended != 0 {
		t.Fatalf("End = %d, %v; want that no secret over the limit was stored", ended, err)
	}
}

func testSecretChannelsAreComparedByByte(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	values := []string{"a@example.com", "A@example.com", "a@example.com ", "\u00e1@example.com", "a\u0301@example.com"}
	for n, value := range values {
		mustAdd(t, s, newIdentifier(tenantA, "email", value, id(1)))
		mustAddSecret(t, s, newSecret(store.SecretCode, n+1, id(1), store.PurposeReset, channel{"email", value}))
	}
	for n, value := range values {
		scope := scopeOf(id(1), store.PurposeReset, channel{"email", value})
		got := tried(t, s, scope, sessionBase, attemptLimit)
		if len(got) != 1 || got[0].ChannelValue != value || !bytes.Equal(got[0].Hash, hashOf("secret", n+1)) {
			t.Errorf("TryCodes for %q = %+v, want only its own code", value, got)
		}
	}
	for _, value := range []string{"a@example.com  ", "\u00c1@example.com", "A\u0301@example.com"} {
		if err := s.Secrets().Add(ctx, newSecret(store.SecretCode, 20, id(1), store.PurposeReset, channel{"email", value})); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Add for the channel %q that does not exist = %v, want ErrNotFound", value, err)
		}
		if got := tried(t, s, scopeOf(id(1), store.PurposeReset, channel{"email", value}), sessionBase, attemptLimit); len(got) != 0 {
			t.Errorf("TryCodes for the channel %q that does not exist returned %+v", value, got)
		}
	}
	if ended, err := s.Secrets().End(ctx, scopeOf(id(1), store.PurposeReset, channel{"email", "A@example.com"}), sessionBase); err != nil || ended != 1 {
		t.Fatalf("End of one channel = %d, %v; want 1, not the channels that differ in case, spaces or accents", ended, err)
	}
}

func testSecretHashesAreExact(t *testing.T, s store.Store) {
	ctx := t.Context()
	prepareSecrets(t, s)
	hashes := [][]byte{
		bytes.Repeat([]byte{0}, store.SecretHashLength),
		append(bytes.Repeat([]byte{7}, store.SecretHashLength-1), 0),
		append([]byte{0}, bytes.Repeat([]byte{9}, store.SecretHashLength-1)...),
		bytes.Repeat([]byte{0xff}, store.SecretHashLength),
	}
	for n, hash := range hashes {
		link := newSecret(store.SecretLink, 30+n, id(1), store.PurposeReset, aliceEmail)
		link.Hash = hash
		mustAddSecret(t, s, link)
	}
	for n, hash := range hashes {
		got, err := s.Secrets().UseLink(ctx, tenantA, store.PurposeReset, hash, sessionBase)
		if err != nil || !bytes.Equal(got.Hash, hash) || got.ID != id(230+n) {
			t.Fatalf("UseLink of hash %d = %+v, %v; want the link with exactly that hash", n, got, err)
		}
	}
}
