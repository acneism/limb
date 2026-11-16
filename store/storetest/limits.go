package storetest

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

var characters = []struct{ name, unit string }{
	{"ASCII", "a"},
	{"two byte characters", "é"},
	{"four byte characters", "\U0001F600"},
}

func fill(unit string, size int) string {
	return strings.Repeat(unit, size/len(unit)) + strings.Repeat("a", size%len(unit))
}

func overTheLimit(limit int) map[string]string {
	return map[string]string{
		"one byte over":                     strings.Repeat("a", limit+1),
		"two byte characters over":          strings.Repeat("é", limit/2+1),
		"four byte characters over":         strings.Repeat("\U0001F600", limit/4+1),
		"as many characters as the limit":   strings.Repeat("я", limit),
		"many times the limit in one value": strings.Repeat("a", limit*40),
	}
}

func testLongestValuesAreStored(t *testing.T, s store.Store) {
	for n, c := range characters {
		t.Run(c.name, func(t *testing.T) { storeTheLongestValues(t, s, c.unit, n+1) })
	}
}

func storeTheLongestValues(t *testing.T, s store.Store, unit string, n int) {
	ctx := t.Context()
	tenant := fill(unit, store.MaxTenantIDLength)
	userID := fill(unit, store.MaxIDLength)
	user := store.User{
		TenantID:      tenant,
		ID:            userID,
		Status:        store.StatusBlocked,
		PasswordHash:  fill(unit, store.MaxPasswordHashLength),
		BlockedReason: fill(unit, store.MaxBlockedReasonLength),
		CreatedAt:     sessionBase,
	}
	created := mustCreate(t, s, user)
	user.Version = 1
	checkUser(t, created, user)

	created.PasswordHash = fill("z", store.MaxPasswordHashLength)
	created.BlockedReason = fill("y", store.MaxBlockedReasonLength)
	updated, err := s.Users().Update(ctx, created)
	if err != nil {
		t.Fatalf("Update with the longest values failed: %v", err)
	}
	created.Version++
	checkUser(t, updated, created)

	ident := store.Identifier{
		TenantID:     tenant,
		Type:         fill(unit, store.MaxIdentifierTypeLength),
		Value:        fill(unit, store.MaxIdentifierValueLength),
		DisplayValue: fill(unit, store.MaxDisplayValueLength),
		UserID:       userID,
	}
	mustAdd(t, s, ident)
	found, err := s.Identifiers().Find(ctx, tenant, ident.Type, ident.Value)
	if err != nil {
		t.Fatalf("Find of the longest identifier failed: %v", err)
	}
	checkIdentifier(t, found, ident)
	listed, err := s.Identifiers().ListByUser(ctx, tenant, userID)
	if err != nil || len(listed) != 1 {
		t.Fatalf("ListByUser = %v, %v; want the longest identifier", listed, err)
	}
	checkIdentifier(t, listed[0], ident)

	sess := newCookieSession(tenant, fill(unit, store.MaxIDLength), userID, n)
	sess.IP = fill(unit, store.MaxIPLength)
	sess.UserAgent = fill(unit, store.MaxUserAgentLength)
	mustCreateSession(t, s, sess)
	resolved, err := s.Sessions().ResolveByID(ctx, tenant, sess.ID)
	if err != nil {
		t.Fatalf("ResolveByID of the longest session failed: %v", err)
	}
	checkSession(t, resolved.Session, sess)

	mustAddToken(t, s, tenant, sess.ID, n, sessionBase.Add(time.Hour))
	use, err := s.RefreshTokens().Use(ctx, tenant, hashOf("refresh", n), sessionBase.Add(time.Minute))
	if err != nil || use.Token.TenantID != tenant || use.Token.SessionID != sess.ID {
		t.Fatalf("Use of a token of the longest session = %+v, %v", use, err)
	}

	key := fill(unit, store.MaxAttemptKeyLength)
	if counter := mustHit(t, s, key, attemptBase, attemptWindow); counter.Key != key || counter.Count != 1 {
		t.Fatalf("Hit with the longest key = %+v", counter)
	}
	if counter := mustGetOne(t, s, key); counter.Key != key {
		t.Fatalf("Get with the longest key = %+v", counter)
	}

	signing := newSigningKey(n, int64(n))
	signing.KID = fill(unit, store.MaxKIDLength)
	signing.Algorithm = fill(unit, store.MaxAlgorithmLength)
	mustAddKey(t, s, signing)
	var seen bool
	for _, k := range listKeys(t, s) {
		if k.KID == signing.KID {
			checkKey(t, k, signing)
			seen = true
		}
	}
	if !seen {
		t.Fatal("the signing key with the longest kid is not listed")
	}
}

func testLongestArgon2idHash(t *testing.T, s store.Store) {
	hash := "$argon2id$v=19$m=262144,t=64,p=64$" + strings.Repeat("A", 86) + "$" + strings.Repeat("B", 171)
	if len(hash) != 292 {
		t.Fatalf("the test hash has %d bytes, want 292", len(hash))
	}
	u := newUser(tenantA, id(1))
	u.PasswordHash = hash
	if got := mustCreate(t, s, u); got.PasswordHash != hash {
		t.Fatalf("the hash of the largest parameters came back as %q", got.PasswordHash)
	}
}

func testValuesOverTheLimitAreInvalid(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	mustCreateSession(t, s, newTokenSession(tenantA, id(10), id(1)))
	current, getErr := s.Users().Get(ctx, tenantA, id(1))
	if getErr != nil {
		t.Fatal(getErr)
	}
	user := func(edit func(*store.User, string)) func(string) error {
		return func(v string) error {
			u := newUser(tenantA, id(2))
			edit(&u, v)
			return s.Users().Create(ctx, u)
		}
	}
	update := func(edit func(*store.User, string)) func(string) error {
		return func(v string) error {
			u := current
			edit(&u, v)
			_, updateErr := s.Users().Update(ctx, u)
			return updateErr
		}
	}
	identifier := func(edit func(*store.Identifier, string)) func(string) error {
		return func(v string) error {
			i := newIdentifier(tenantA, "email", "a@example.com", id(1))
			edit(&i, v)
			return s.Identifiers().Add(ctx, i)
		}
	}
	session := func(edit func(*store.Session, string)) func(string) error {
		return func(v string) error {
			x := newTokenSession(tenantA, id(11), id(1))
			edit(&x, v)
			return s.Sessions().Create(ctx, x)
		}
	}
	token := func(edit func(*store.RefreshToken, string)) func(string) error {
		return func(v string) error {
			x := newRefreshToken(tenantA, id(10), 1, sessionBase.Add(time.Hour))
			edit(&x, v)
			return s.RefreshTokens().Add(ctx, x)
		}
	}
	signing := func(edit func(*store.SigningKey, string)) func(string) error {
		return func(v string) error {
			k := newSigningKey(1, 1)
			edit(&k, v)
			return s.SigningKeys().Add(ctx, k)
		}
	}
	fields := []struct {
		name  string
		limit int
		write func(string) error
	}{
		{"user tenant_id", store.MaxTenantIDLength, user(func(u *store.User, v string) { u.TenantID = v })},
		{"user id", store.MaxIDLength, user(func(u *store.User, v string) { u.ID = v })},
		{"user password_hash", store.MaxPasswordHashLength, user(func(u *store.User, v string) { u.PasswordHash = v })},
		{"user blocked_reason", store.MaxBlockedReasonLength, user(func(u *store.User, v string) { u.BlockedReason = v })},
		{"updated password_hash", store.MaxPasswordHashLength, update(func(u *store.User, v string) { u.PasswordHash = v })},
		{"updated blocked_reason", store.MaxBlockedReasonLength, update(func(u *store.User, v string) { u.BlockedReason = v })},
		{"identifier tenant_id", store.MaxTenantIDLength, identifier(func(i *store.Identifier, v string) { i.TenantID = v })},
		{"identifier type", store.MaxIdentifierTypeLength, identifier(func(i *store.Identifier, v string) { i.Type = v })},
		{"identifier value", store.MaxIdentifierValueLength, identifier(func(i *store.Identifier, v string) { i.Value = v })},
		{"identifier display_value", store.MaxDisplayValueLength, identifier(func(i *store.Identifier, v string) { i.DisplayValue = v })},
		{"identifier user_id", store.MaxIDLength, identifier(func(i *store.Identifier, v string) { i.UserID = v })},
		{"session tenant_id", store.MaxTenantIDLength, session(func(x *store.Session, v string) { x.TenantID = v })},
		{"session id", store.MaxIDLength, session(func(x *store.Session, v string) { x.ID = v })},
		{"session user_id", store.MaxIDLength, session(func(x *store.Session, v string) { x.UserID = v })},
		{"session ip", store.MaxIPLength, session(func(x *store.Session, v string) { x.IP = v })},
		{"session user_agent", store.MaxUserAgentLength, session(func(x *store.Session, v string) { x.UserAgent = v })},
		{"refresh token tenant_id", store.MaxTenantIDLength, token(func(x *store.RefreshToken, v string) { x.TenantID = v })},
		{"refresh token session_id", store.MaxIDLength, token(func(x *store.RefreshToken, v string) { x.SessionID = v })},
		{"attempt key", store.MaxAttemptKeyLength, func(v string) error {
			_, hitErr := s.Attempts().Hit(ctx, v, attemptBase, attemptWindow)
			return hitErr
		}},
		{"signing key kid", store.MaxKIDLength, signing(func(k *store.SigningKey, v string) { k.KID = v })},
		{"signing key algorithm", store.MaxAlgorithmLength, signing(func(k *store.SigningKey, v string) { k.Algorithm = v })},
	}
	for _, f := range fields {
		for name, value := range overTheLimit(f.limit) {
			if writeErr := f.write(value); writeErr == nil || isDomainError(writeErr) {
				t.Errorf("%s, %s (%d bytes): %v, want a validation error", f.name, name, len(value), writeErr)
			}
		}
	}
	after, getErr := s.Users().Get(ctx, tenantA, id(1))
	if getErr != nil {
		t.Fatal(getErr)
	}
	checkUser(t, after, current)
	if list, listErr := s.Identifiers().ListByUser(ctx, tenantA, id(1)); listErr != nil || len(list) != 0 {
		t.Errorf("a rejected identifier was stored: %v, %v", list, listErr)
	}
	if list := listKeys(t, s); len(list) != 0 {
		t.Errorf("a rejected signing key was stored: %v", list)
	}
}

func testSigningKeyMaterialLimit(t *testing.T, s store.Store) {
	ctx := t.Context()
	for _, size := range []int{store.MaxKeyMaterialLength + 1, store.MaxKeyMaterialLength * 4} {
		for name, edit := range map[string]func(*store.SigningKey){
			"private key": func(k *store.SigningKey) { k.PrivateKey = bytes.Repeat([]byte{7}, size) },
			"public key":  func(k *store.SigningKey) { k.PublicKey = bytes.Repeat([]byte{7}, size) },
		} {
			k := newSigningKey(1, 1)
			edit(&k)
			if err := s.SigningKeys().Add(ctx, k); err == nil || isDomainError(err) {
				t.Errorf("Add with a %s of %d bytes = %v, want a validation error", name, size, err)
			}
		}
	}
	if list := listKeys(t, s); len(list) != 0 {
		t.Fatalf("a rejected signing key was stored: %v", list)
	}
}

func testBinaryValuesAreExact(t *testing.T, s store.Store) {
	patterns := []struct {
		name  string
		value []byte
	}{
		{"one zero byte", []byte{0}},
		{"trailing zeros", []byte{1, 2, 0, 0}},
		{"leading zeros", []byte{0, 0, 1}},
		{"only zeros", make([]byte, 32)},
		{"only 0xFF", bytes.Repeat([]byte{0xff}, 33)},
		{"one byte short of 2000", bytes.Repeat([]byte{3}, 1999)},
		{"2000 bytes", bytes.Repeat([]byte{4}, 2000)},
		{"2001 bytes", bytes.Repeat([]byte{5}, 2001)},
		{"4000 bytes", bytes.Repeat([]byte{6, 0}, 2000)},
		{"the longest allowed", append(bytes.Repeat([]byte{8}, store.MaxKeyMaterialLength-1), 0)},
	}
	for n, p := range patterns {
		k := newSigningKey(n+1, int64(n+1))
		k.PrivateKey = p.value
		k.PublicKey = bytes.Clone(p.value)
		mustAddKey(t, s, k)
	}
	list := listKeys(t, s)
	if len(list) != len(patterns) {
		t.Fatalf("List returned %d keys, want %d", len(list), len(patterns))
	}
	for n, p := range patterns {
		want := newSigningKey(n+1, int64(n+1))
		want.PrivateKey = p.value
		want.PublicKey = p.value
		checkKey(t, list[n], want)
		if len(list[n].PrivateKey) != len(p.value) {
			t.Errorf("%s: the key came back with %d bytes, want %d", p.name, len(list[n].PrivateKey), len(p.value))
		}
	}
}

func testHashesAreExact(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	hashes := [][]byte{
		make([]byte, store.SecretHashLength),
		append(make([]byte, store.SecretHashLength-1), 1),
		append([]byte{1}, make([]byte, store.SecretHashLength-1)...),
		bytes.Repeat([]byte{0xff}, store.SecretHashLength),
		append(bytes.Repeat([]byte{0xff}, store.SecretHashLength-1), 0),
	}
	for n, hash := range hashes {
		sess := newCookieSession(tenantA, id(10+n), id(1), 0)
		sess.SecretHash = hash
		mustCreateSession(t, s, sess)
		token := store.RefreshToken{TenantID: tenantA, Hash: hash, SessionID: sess.ID, ExpiresAt: sessionBase.Add(time.Hour)}
		if err := s.RefreshTokens().Add(ctx, token); err != nil {
			t.Fatalf("Add(refresh token %d) failed: %v", n, err)
		}
	}
	for n, hash := range hashes {
		resolved, err := s.Sessions().ResolveBySecret(ctx, tenantA, hash)
		if err != nil || resolved.Session.ID != id(10+n) || !bytes.Equal(resolved.Session.SecretHash, hash) {
			t.Fatalf("ResolveBySecret for hash %d = %+v, %v; want session %s", n, resolved.Session, err, id(10+n))
		}
		use, err := s.RefreshTokens().Use(ctx, tenantA, hash, sessionBase.Add(time.Minute))
		if err != nil || use.Reused || use.Token.SessionID != id(10+n) || !bytes.Equal(use.Token.Hash, hash) {
			t.Fatalf("Use for hash %d = %+v, %v; want session %s", n, use, err, id(10+n))
		}
	}
}

var twins = []string{
	"twin", "Twin", "TWIN", "twin ", "twin  ", " twin", "twin\t", "twin\u00a0", "twin\u200b",
	"caf\u00e9", "cafe\u0301", "CAF\u00c9", "stra\u00dfe", "strasse", "\u01c5", "\u01c6", "\u0130", "\u0131", "i", "I",
	"a_b", "a%b", "axb", "\u0430", "a",
}

func testKeysAreComparedByteByByte(t *testing.T, s store.Store) {
	ctx := t.Context()
	for _, twin := range twins {
		u := newUser(tenantA, twin)
		got := mustCreate(t, s, u)
		if got.ID != twin {
			t.Fatalf("a user with the ID %q was stored as %q", twin, got.ID)
		}
	}
	for _, twin := range twins {
		got, err := s.Users().Get(ctx, tenantA, twin)
		if err != nil || got.ID != twin {
			t.Fatalf("Get(%q) = %+v, %v: user IDs must be compared byte by byte", twin, got, err)
		}
	}
	for _, twin := range twins {
		got := mustCreate(t, s, newUser(twin, id(1)))
		if got.TenantID != twin {
			t.Fatalf("a user of the tenant %q was stored as %q", twin, got.TenantID)
		}
	}
	for _, twin := range twins {
		got, err := s.Users().Get(ctx, twin, id(1))
		if err != nil || got.TenantID != twin {
			t.Fatalf("Get of the tenant %q = %+v, %v: tenants must be compared byte by byte", twin, got, err)
		}
	}
	mustCreate(t, s, newUser(tenantA, id(1)))
	for _, twin := range twins {
		mustAdd(t, s, newIdentifier(tenantA, twin, "value", id(1)))
	}
	for _, twin := range twins {
		got, err := s.Identifiers().Find(ctx, tenantA, twin, "value")
		if err != nil || got.Type != twin {
			t.Fatalf("Find of the type %q = %+v, %v: types must be compared byte by byte", twin, got, err)
		}
	}
	for n, twin := range twins {
		mustCreateSession(t, s, newCookieSession(tenantA, twin, id(1), n+1))
	}
	for _, twin := range twins {
		resolved, err := s.Sessions().ResolveByID(ctx, tenantA, twin)
		if err != nil || resolved.Session.ID != twin {
			t.Fatalf("ResolveByID(%q) = %+v, %v: session IDs must be compared byte by byte", twin, resolved.Session, err)
		}
	}
	for _, twin := range twins {
		if counter := mustHit(t, s, twin, attemptBase, attemptWindow); counter.Key != twin || counter.Count != 1 {
			t.Fatalf("Hit(%q) = %+v, want a counter of its own: keys must be compared byte by byte", twin, counter)
		}
	}
	counters, err := s.Attempts().Get(ctx, twins...)
	if err != nil || len(counters) != len(twins) {
		t.Fatalf("Get returned %d counters, %v; want %d", len(counters), err, len(twins))
	}
	for n, twin := range twins {
		mustAddKey(t, s, store.SigningKey{
			KID: twin, Algorithm: "EdDSA", Generation: int64(n + 1),
			PrivateKey: hashOf("private", n), PublicKey: hashOf("public", n), CreatedAt: keyBase,
		})
	}
	kids := map[string]bool{}
	for _, k := range listKeys(t, s) {
		kids[k.KID] = true
	}
	for _, twin := range twins {
		if !kids[twin] {
			t.Fatalf("the signing key %q is not listed: kids must be compared byte by byte", twin)
		}
	}
	if err := s.SigningKeys().Retire(ctx, twins[0], keyBase.Add(time.Hour)); err != nil {
		t.Fatalf("Retire(%q) failed: %v", twins[0], err)
	}
	for _, k := range listKeys(t, s) {
		if retired := !k.RetireAfter.IsZero(); retired != (k.KID == twins[0]) {
			t.Fatalf("Retire(%q) changed the key %q: %+v", twins[0], k.KID, k)
		}
	}
}

func testLongValuesAreNotFound(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	mustAdd(t, s, newIdentifier(tenantA, "nick", "value", id(1)))
	mustCreateSession(t, s, newCookieSession(tenantA, id(10), id(1), 1))
	mustAddKey(t, s, newSigningKey(1, 1))
	mustHit(t, s, attemptKey(1), attemptBase, attemptWindow)
	longs := map[string]string{
		"one byte over the longest ID": strings.Repeat("a", store.MaxIDLength+1),
		"over the longest value":       strings.Repeat("a", store.MaxIdentifierValueLength+1),
		"far over every limit":         strings.Repeat("\U0001F600", 10000),
	}
	for name, long := range longs {
		notFound := func(call string, err error) {
			t.Helper()
			if !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s with %s = %v, want ErrNotFound", call, name, err)
			}
		}
		_, err := s.Users().Get(ctx, long, id(1))
		notFound("Users.Get by tenant", err)
		_, err = s.Users().Get(ctx, tenantA, long)
		notFound("Users.Get by ID", err)
		notFound("Users.Delete", s.Users().Delete(ctx, tenantA, long))
		_, err = s.Identifiers().Find(ctx, tenantA, "nick", long)
		notFound("Identifiers.Find by value", err)
		_, err = s.Identifiers().Find(ctx, tenantA, long, "value")
		notFound("Identifiers.Find by type", err)
		_, err = s.Identifiers().Find(ctx, long, "nick", "value")
		notFound("Identifiers.Find by tenant", err)
		notFound("Identifiers.Remove", s.Identifiers().Remove(ctx, tenantA, "nick", long))
		notFound("Identifiers.MarkVerified", s.Identifiers().MarkVerified(ctx, tenantA, "nick", long, sessionBase))
		_, err = s.Sessions().ResolveByID(ctx, tenantA, long)
		notFound("Sessions.ResolveByID", err)
		_, err = s.Sessions().ResolveByID(ctx, long, id(10))
		notFound("Sessions.ResolveByID by tenant", err)
		if err = s.Sessions().Touch(ctx, tenantA, long, sessionBase); err != nil {
			t.Errorf("Sessions.Touch with %s = %v, want nil: it does nothing for a missing session", name, err)
		}
		notFound("Sessions.Revoke", s.Sessions().Revoke(ctx, tenantA, id(1), long, sessionBase))
		notFound("SigningKeys.Retire", s.SigningKeys().Retire(ctx, long, sessionBase))
		if list, listErr := s.Identifiers().ListByUser(ctx, tenantA, long); listErr != nil || len(list) != 0 {
			t.Errorf("Identifiers.ListByUser with %s = %v, %v; want an empty list", name, list, listErr)
		}
		if list, listErr := s.Sessions().ListByUser(ctx, tenantA, long, sessionBase); listErr != nil || len(list) != 0 {
			t.Errorf("Sessions.ListByUser with %s = %v, %v; want an empty list", name, list, listErr)
		}
		if list, getErr := s.Attempts().Get(ctx, long); getErr != nil || len(list) != 0 {
			t.Errorf("Attempts.Get with %s = %v, %v; want an empty list", name, list, getErr)
		}
	}
}
