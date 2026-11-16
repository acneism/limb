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

var keyBase = time.Date(2026, 8, 9, 10, 11, 12, 123456789, time.UTC)

func newSigningKey(n int, generation int64) store.SigningKey {
	return store.SigningKey{
		KID:        fmt.Sprintf("kid-%d", n),
		Algorithm:  "EdDSA",
		Generation: generation,
		PrivateKey: hashOf("private", n),
		PublicKey:  hashOf("public", n),
		CreatedAt:  keyBase.Add(time.Duration(n) * time.Minute),
	}
}

func mustAddKey(t *testing.T, s store.Store, k store.SigningKey) {
	t.Helper()
	if err := s.SigningKeys().Add(t.Context(), k); err != nil {
		t.Fatalf("Add(%s) failed: %v", k.KID, err)
	}
}

func listKeys(t *testing.T, s store.Store) []store.SigningKey {
	t.Helper()
	list, err := s.SigningKeys().List(t.Context())
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	return list
}

func checkKey(t *testing.T, got, want store.SigningKey) {
	t.Helper()
	if got.KID != want.KID || got.Algorithm != want.Algorithm || got.Generation != want.Generation ||
		!bytes.Equal(got.PrivateKey, want.PrivateKey) || !bytes.Equal(got.PublicKey, want.PublicKey) {
		t.Fatalf("signing key differs:\n got %+v\nwant %+v", got, want)
	}
	if !sameTime(got.CreatedAt, want.CreatedAt) || !sameTime(got.RetireAfter, want.RetireAfter) {
		t.Fatalf("signing key times differ, they must be UTC with microsecond precision:\n got %+v\nwant %+v", got, want)
	}
}

func testSigningKeyLifecycle(t *testing.T, s store.Store) {
	if list := listKeys(t, s); len(list) != 0 {
		t.Fatalf("a new store has signing keys: %v", list)
	}
	keys := []store.SigningKey{newSigningKey(3, 30), newSigningKey(1, 10), newSigningKey(2, 20)}
	keys[1].Algorithm = "ES256"
	local := time.FixedZone("UTC+3", 3*3600)
	keys[2].CreatedAt = keys[2].CreatedAt.In(local)
	for _, k := range keys {
		mustAddKey(t, s, k)
	}
	list := listKeys(t, s)
	if len(list) != 3 {
		t.Fatalf("List = %d keys, want 3", len(list))
	}
	checkKey(t, list[0], keys[1])
	checkKey(t, list[1], keys[2])
	checkKey(t, list[2], keys[0])
	if list[0].Generation != 10 || list[1].Generation != 20 || list[2].Generation != 30 {
		t.Fatalf("List must order the keys by generation, the oldest first: %+v", list)
	}
}

func testSigningKeyConflicts(t *testing.T, s store.Store) {
	ctx := t.Context()
	first := newSigningKey(1, 1)
	mustAddKey(t, s, first)
	if err := s.SigningKeys().Add(ctx, first); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Add of the same key = %v, want ErrConflict", err)
	}
	sameKID := newSigningKey(2, 2)
	sameKID.KID = first.KID
	if err := s.SigningKeys().Add(ctx, sameKID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Add with a taken KID = %v, want ErrConflict", err)
	}
	sameGeneration := newSigningKey(3, 1)
	if err := s.SigningKeys().Add(ctx, sameGeneration); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Add with a taken generation = %v, want ErrConflict", err)
	}
	if list := listKeys(t, s); len(list) != 1 {
		t.Fatalf("a rejected key was stored: %v", list)
	}
	mustAddKey(t, s, newSigningKey(4, 2))
}

func testSigningKeyInvalidRecords(t *testing.T, s store.Store) {
	ctx := t.Context()
	edits := map[string]func(*store.SigningKey){
		"no kid":            func(k *store.SigningKey) { k.KID = "" },
		"long kid":          func(k *store.SigningKey) { k.KID = strings.Repeat("k", 129) },
		"NUL in the kid":    func(k *store.SigningKey) { k.KID = "a\x00" },
		"no algorithm":      func(k *store.SigningKey) { k.Algorithm = "" },
		"zero generation":   func(k *store.SigningKey) { k.Generation = 0 },
		"negative":          func(k *store.SigningKey) { k.Generation = -5 },
		"no private key":    func(k *store.SigningKey) { k.PrivateKey = nil },
		"no public key":     func(k *store.SigningKey) { k.PublicKey = nil },
		"no creation time":  func(k *store.SigningKey) { k.CreatedAt = time.Time{} },
		"already retired":   func(k *store.SigningKey) { k.RetireAfter = keyBase },
		"invalid algorithm": func(k *store.SigningKey) { k.Algorithm = "\xff" },
	}
	for name, edit := range edits {
		k := newSigningKey(1, 1)
		edit(&k)
		if err := s.SigningKeys().Add(ctx, k); err == nil || isDomainError(err) {
			t.Errorf("Add with %s = %v, want a validation error", name, err)
		}
	}
	if list := listKeys(t, s); len(list) != 0 {
		t.Fatalf("a rejected key was stored: %v", list)
	}
	longest := newSigningKey(2, 2)
	longest.KID = strings.Repeat("k", 128)
	mustAddKey(t, s, longest)
}

func testSigningKeyRetire(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustAddKey(t, s, newSigningKey(1, 1))
	mustAddKey(t, s, newSigningKey(2, 2))
	until := keyBase.Add(time.Hour).Add(789 * time.Nanosecond)
	if err := s.SigningKeys().Retire(ctx, "kid-1", until); err != nil {
		t.Fatalf("Retire failed: %v", err)
	}
	list := listKeys(t, s)
	if !sameTime(list[0].RetireAfter, until) || !list[1].RetireAfter.IsZero() {
		t.Fatalf("Retire must set the time of that key only: %+v", list)
	}
	if err := s.SigningKeys().Retire(ctx, "kid-1", until.Add(time.Hour)); err != nil {
		t.Fatalf("a second Retire = %v, want nil", err)
	}
	if list = listKeys(t, s); !sameTime(list[0].RetireAfter, until) {
		t.Fatalf("a second Retire must keep the first time %v: %+v", until, list[0])
	}
	if err := s.SigningKeys().Retire(ctx, "kid-9", until); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Retire of a missing key = %v, want ErrNotFound", err)
	}
	if err := s.SigningKeys().Retire(ctx, "a\x00", until); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Retire with a NUL byte = %v, want ErrNotFound", err)
	}
	if err := s.SigningKeys().Retire(ctx, "kid-2", time.Time{}); err == nil || isDomainError(err) {
		t.Fatalf("Retire without a time = %v, want a validation error", err)
	}
	if list = listKeys(t, s); !list[1].RetireAfter.IsZero() {
		t.Fatalf("a refused Retire changed the key: %+v", list[1])
	}
}

func testSigningKeyDeleteRetired(t *testing.T, s store.Store) {
	ctx := t.Context()
	for n := 1; n <= 5; n++ {
		mustAddKey(t, s, newSigningKey(n, int64(n)))
	}
	now := keyBase.Add(24 * time.Hour)
	for n, at := range map[int]time.Time{1: now.Add(-time.Hour), 2: now.Add(-time.Microsecond), 3: now, 4: now.Add(time.Hour)} {
		if err := s.SigningKeys().Retire(ctx, fmt.Sprintf("kid-%d", n), at); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := s.SigningKeys().DeleteRetired(ctx, now)
	if err != nil || removed != 2 {
		t.Fatalf("DeleteRetired = %d, %v; want 2: keys retired before the given time", removed, err)
	}
	var kids []string
	for _, k := range listKeys(t, s) {
		kids = append(kids, k.KID)
	}
	if got := strings.Join(kids, ","); got != "kid-3,kid-4,kid-5" {
		t.Fatalf("keys left = %s, want kid-3,kid-4,kid-5: a key that is not retired is never removed", got)
	}
	if removed, err = s.SigningKeys().DeleteRetired(ctx, now); err != nil || removed != 0 {
		t.Fatalf("a second DeleteRetired = %d, %v; want 0", removed, err)
	}
}

func testConcurrentSigningKeyRotation(t *testing.T, s store.Store) {
	ctx := t.Context()
	const racers = 8
	mustAddKey(t, s, newSigningKey(100, 1))
	var wins, conflicts atomic.Int32
	parallel(racers, func(i int) {
		err := s.SigningKeys().Add(ctx, newSigningKey(i+1, 2))
		switch {
		case err == nil:
			wins.Add(1)
		case errors.Is(err, store.ErrConflict):
			conflicts.Add(1)
		default:
			t.Errorf("racer %d: unexpected error %v", i, err)
		}
	})
	if wins.Load() != 1 || conflicts.Load() != racers-1 {
		t.Fatalf("%d keys of one generation were stored and %d were refused; want exactly 1 and %d", wins.Load(), conflicts.Load(), racers-1)
	}
	if list := listKeys(t, s); len(list) != 2 {
		t.Fatalf("List = %d keys, want the old one and the winner", len(list))
	}
}

func testSigningKeyRotationInTransaction(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustAddKey(t, s, newSigningKey(1, 1))
	until := keyBase.Add(time.Hour)
	err := s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if addErr := tx.SigningKeys().Add(ctx, newSigningKey(2, 2)); addErr != nil {
			return addErr
		}
		return tx.SigningKeys().Retire(ctx, "kid-1", until)
	})
	if err != nil {
		t.Fatalf("a rotation in a transaction failed: %v", err)
	}
	list := listKeys(t, s)
	if len(list) != 2 || !sameTime(list[0].RetireAfter, until) || !list[1].RetireAfter.IsZero() {
		t.Fatalf("keys after the rotation = %+v", list)
	}

	err = s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if retireErr := tx.SigningKeys().Retire(ctx, "kid-2", until); retireErr != nil {
			return retireErr
		}
		return tx.SigningKeys().Add(ctx, newSigningKey(3, 2))
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a rotation that loses the race = %v, want ErrConflict", err)
	}
	if list = listKeys(t, s); len(list) != 2 || !list[1].RetireAfter.IsZero() {
		t.Fatalf("a failed rotation must leave no trace: %+v", list)
	}
}

func testSigningKeySlicesAreCopies(t *testing.T, s store.Store) {
	k := newSigningKey(1, 1)
	private, public := bytes.Clone(k.PrivateKey), bytes.Clone(k.PublicKey)
	mustAddKey(t, s, k)
	k.PrivateKey[0] ^= 0xff
	k.PublicKey[0] ^= 0xff
	list := listKeys(t, s)
	if !bytes.Equal(list[0].PrivateKey, private) || !bytes.Equal(list[0].PublicKey, public) {
		t.Fatal("the store kept the slices it was given")
	}
	list[0].PrivateKey[0] ^= 0xff
	if again := listKeys(t, s); !bytes.Equal(again[0].PrivateKey, private) {
		t.Fatal("the store returned a slice it still uses")
	}
}
