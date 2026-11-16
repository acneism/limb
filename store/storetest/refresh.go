package storetest

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func newRefreshToken(tenant, sessionID string, n int, expires time.Time) store.RefreshToken {
	return store.RefreshToken{TenantID: tenant, Hash: hashOf("refresh", n), SessionID: sessionID, ExpiresAt: expires}
}

func mustAddToken(t *testing.T, s store.Store, tenant, sessionID string, n int, expires time.Time) {
	t.Helper()
	if err := s.RefreshTokens().Add(t.Context(), newRefreshToken(tenant, sessionID, n, expires)); err != nil {
		t.Fatalf("Add(refresh token %d) failed: %v", n, err)
	}
}

func prepareSession(t *testing.T, s store.Store) store.Session {
	t.Helper()
	mustCreate(t, s, newUser(tenantA, id(1)))
	sess := newTokenSession(tenantA, id(10), id(1))
	mustCreateSession(t, s, sess)
	return sess
}

func testRefreshTokenUse(t *testing.T, s store.Store) {
	ctx := t.Context()
	sess := prepareSession(t, s)
	expires := sessionBase.Add(7 * 24 * time.Hour).Add(789 * time.Nanosecond)
	if err := s.RefreshTokens().Add(ctx, newRefreshToken(tenantA, sess.ID, 1, expires)); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	first := sessionBase.Add(time.Hour).Add(123456789 * time.Nanosecond)
	use, err := s.RefreshTokens().Use(ctx, tenantA, hashOf("refresh", 1), first)
	if err != nil {
		t.Fatalf("Use failed: %v", err)
	}
	if use.Reused {
		t.Fatal("the first Use of a token must not report a reuse")
	}
	token := use.Token
	if token.TenantID != tenantA || token.SessionID != sess.ID || !bytes.Equal(token.Hash, hashOf("refresh", 1)) ||
		!sameTime(token.ExpiresAt, expires) || !sameTime(token.UsedAt, first) {
		t.Fatalf("token after the first Use = %+v, want session %s used at %v expiring at %v", token, sess.ID, first, expires)
	}

	second := first.Add(5 * time.Second)
	for range 2 {
		again, useErr := s.RefreshTokens().Use(ctx, tenantA, hashOf("refresh", 1), second)
		if useErr != nil {
			t.Fatalf("a second Use failed: %v", useErr)
		}
		if !again.Reused || !sameTime(again.Token.UsedAt, first) {
			t.Fatalf("a second Use = %+v, want a reuse that reports the first time %v", again, first)
		}
	}
}

func testRefreshTokenErrors(t *testing.T, s store.Store) {
	ctx := t.Context()
	sess := prepareSession(t, s)
	mustCreate(t, s, newUser(tenantB, id(1)))
	expires := sessionBase.Add(time.Hour)
	mustAddToken(t, s, tenantA, sess.ID, 1, expires)

	if err := s.RefreshTokens().Add(ctx, newRefreshToken(tenantA, sess.ID, 1, expires)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Add of a taken hash = %v, want ErrConflict", err)
	}
	if err := s.RefreshTokens().Add(ctx, newRefreshToken(tenantA, id(99), 2, expires)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Add for a missing session = %v, want ErrNotFound", err)
	}
	if err := s.RefreshTokens().Add(ctx, newRefreshToken(tenantB, sess.ID, 3, expires)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Add for the session of another tenant = %v, want ErrNotFound", err)
	}
	invalid := map[string]func(*store.RefreshToken){
		"no tenant":   func(x *store.RefreshToken) { x.TenantID = "" },
		"no session":  func(x *store.RefreshToken) { x.SessionID = "" },
		"no hash":     func(x *store.RefreshToken) { x.Hash = nil },
		"short hash":  func(x *store.RefreshToken) { x.Hash = x.Hash[:31] },
		"long hash":   func(x *store.RefreshToken) { x.Hash = append(bytes.Clone(x.Hash), 0) },
		"no expiry":   func(x *store.RefreshToken) { x.ExpiresAt = time.Time{} },
		"used":        func(x *store.RefreshToken) { x.UsedAt = sessionBase },
		"NUL session": func(x *store.RefreshToken) { x.SessionID = "a\x00" },
	}
	for name, edit := range invalid {
		token := newRefreshToken(tenantA, sess.ID, 4, expires)
		edit(&token)
		if err := s.RefreshTokens().Add(ctx, token); err == nil || isDomainError(err) {
			t.Errorf("Add with %s = %v, want a validation error", name, err)
		}
	}
	if _, err := s.RefreshTokens().Use(ctx, tenantA, hashOf("refresh", 4), sessionBase); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a rejected token must not be stored, Use = %v", err)
	}

	notFound := map[string]struct {
		tenant string
		hash   []byte
	}{
		"an unknown hash":      {tenantA, hashOf("refresh", 99)},
		"another tenant":       {tenantB, hashOf("refresh", 1)},
		"no hash":              {tenantA, nil},
		"a short hash":         {tenantA, hashOf("refresh", 1)[:31]},
		"a NUL byte in tenant": {"a\x00", hashOf("refresh", 1)},
		"an empty tenant":      {"", hashOf("refresh", 1)},
	}
	for name, c := range notFound {
		if _, err := s.RefreshTokens().Use(ctx, c.tenant, c.hash, sessionBase); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Use with %s = %v, want ErrNotFound", name, err)
		}
	}
	if _, err := s.RefreshTokens().Use(ctx, tenantA, hashOf("refresh", 1), time.Time{}); err == nil || isDomainError(err) {
		t.Errorf("Use without a time = %v, want a validation error", err)
	}
	if use, err := s.RefreshTokens().Use(ctx, tenantA, hashOf("refresh", 1), sessionBase); err != nil || use.Reused {
		t.Fatalf("a refused Use must leave the token unused: %+v, %v", use, err)
	}
}

func testConcurrentRefreshTokenUse(t *testing.T, s store.Store) {
	ctx := t.Context()
	sess := prepareSession(t, s)
	mustAddToken(t, s, tenantA, sess.ID, 1, sessionBase.Add(time.Hour))
	const racers = 16
	uses := make([]store.RefreshUse, racers)
	times := make([]time.Time, racers)
	var mu sync.Mutex
	parallel(racers, func(i int) {
		at := sessionBase.Add(time.Duration(i+1) * time.Millisecond)
		use, err := s.RefreshTokens().Use(ctx, tenantA, hashOf("refresh", 1), at)
		if err != nil {
			t.Errorf("racer %d: Use failed: %v", i, err)
			return
		}
		mu.Lock()
		uses[i], times[i] = use, at
		mu.Unlock()
	})
	winners := 0
	var winnerAt time.Time
	for i, use := range uses {
		if !use.Reused {
			winners++
			winnerAt = times[i]
		}
	}
	if winners != 1 {
		t.Fatalf("%d of %d concurrent Use calls got Reused false, want exactly one", winners, racers)
	}
	for i, use := range uses {
		if !sameTime(use.Token.UsedAt, winnerAt) {
			t.Fatalf("racer %d sees UsedAt %v, want the time of the winner %v", i, use.Token.UsedAt, winnerAt)
		}
	}
}

func testConcurrentRefreshTokenRotation(t *testing.T, s store.Store) {
	ctx := t.Context()
	sess := prepareSession(t, s)
	mustAddToken(t, s, tenantA, sess.ID, 1, sessionBase.Add(time.Hour))
	const racers = 6
	var wins, replays int
	var mu sync.Mutex
	parallel(racers, func(i int) {
		err := s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
			use, useErr := tx.RefreshTokens().Use(ctx, tenantA, hashOf("refresh", 1), sessionBase.Add(time.Duration(i+1)*time.Second))
			if useErr != nil {
				return useErr
			}
			if use.Reused {
				mu.Lock()
				replays++
				mu.Unlock()
				return nil
			}
			time.Sleep(50 * time.Millisecond)
			if addErr := tx.RefreshTokens().Add(ctx, newRefreshToken(tenantA, sess.ID, 100+i, sessionBase.Add(time.Hour))); addErr != nil {
				return addErr
			}
			mu.Lock()
			wins++
			mu.Unlock()
			return nil
		})
		if err != nil {
			t.Errorf("racer %d: rotation failed: %v", i, err)
		}
	})
	if wins != 1 || replays != racers-1 {
		t.Fatalf("%d rotations won and %d were replays; want exactly 1 and %d", wins, replays, racers-1)
	}
}

func testRefreshTokenRollback(t *testing.T, s store.Store) {
	ctx := t.Context()
	sess := prepareSession(t, s)
	mustAddToken(t, s, tenantA, sess.ID, 1, sessionBase.Add(time.Hour))
	boom := errors.New("boom")
	err := s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		use, useErr := tx.RefreshTokens().Use(ctx, tenantA, hashOf("refresh", 1), sessionBase)
		if useErr != nil || use.Reused {
			t.Errorf("Use in a transaction = %+v, %v", use, useErr)
		}
		if addErr := tx.RefreshTokens().Add(ctx, newRefreshToken(tenantA, sess.ID, 2, sessionBase.Add(time.Hour))); addErr != nil {
			t.Errorf("Add in a transaction failed: %v", addErr)
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("InTx = %v, want %v", err, boom)
	}
	if use, useErr := s.RefreshTokens().Use(ctx, tenantA, hashOf("refresh", 1), sessionBase); useErr != nil || use.Reused {
		t.Fatalf("a rolled back Use must leave the token unused: %+v, %v", use, useErr)
	}
	if _, useErr := s.RefreshTokens().Use(ctx, tenantA, hashOf("refresh", 2), sessionBase); !errors.Is(useErr, store.ErrNotFound) {
		t.Fatalf("a rolled back Add must not leave a token: %v", useErr)
	}
}

func testRefreshTokenDeleteExpired(t *testing.T, s store.Store) {
	ctx := t.Context()
	sess := prepareSession(t, s)
	mustCreate(t, s, newUser(tenantB, id(1)))
	otherSession := newTokenSession(tenantB, id(20), id(1))
	mustCreateSession(t, s, otherSession)
	now := sessionBase.Add(24 * time.Hour)
	mustAddToken(t, s, tenantA, sess.ID, 1, now.Add(-time.Hour))
	mustAddToken(t, s, tenantA, sess.ID, 2, now.Add(-time.Second))
	mustAddToken(t, s, tenantA, sess.ID, 3, now)
	mustAddToken(t, s, tenantA, sess.ID, 4, now.Add(time.Hour))
	mustAddToken(t, s, tenantB, otherSession.ID, 5, now.Add(-time.Hour))
	if _, err := s.RefreshTokens().Use(ctx, tenantA, hashOf("refresh", 2), sessionBase); err != nil {
		t.Fatal(err)
	}

	removed, err := s.RefreshTokens().DeleteExpired(ctx, tenantA, now)
	if err != nil || removed != 2 {
		t.Fatalf("DeleteExpired = %d, %v; want 2: tokens that expired before the given time, used or not", removed, err)
	}
	for _, n := range []int{1, 2} {
		if _, err = s.RefreshTokens().Use(ctx, tenantA, hashOf("refresh", n), now); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("token %d must be removed, Use = %v", n, err)
		}
	}
	for _, n := range []int{3, 4} {
		if _, err = s.RefreshTokens().Use(ctx, tenantA, hashOf("refresh", n), now); err != nil {
			t.Fatalf("token %d must stay: %v", n, err)
		}
	}
	if _, err = s.RefreshTokens().Use(ctx, tenantB, hashOf("refresh", 5), now); err != nil {
		t.Fatalf("DeleteExpired removed a token of another tenant: %v", err)
	}
	if removed, err = s.RefreshTokens().DeleteExpired(ctx, tenantA, now); err != nil || removed != 0 {
		t.Fatalf("a second DeleteExpired = %d, %v; want 0", removed, err)
	}
	if removed, err = s.RefreshTokens().DeleteExpired(ctx, "a\x00", now); err != nil || removed != 0 {
		t.Fatalf("DeleteExpired with a NUL byte = %d, %v; want 0", removed, err)
	}
}
