package storetest

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

const aWhile = 500 * time.Millisecond

type pending[T any] struct {
	done  chan struct{}
	value T
	err   error
}

func inBackground[T any](fn func() (T, error)) *pending[T] {
	p := &pending[T]{done: make(chan struct{})}
	go func() {
		defer close(p.done)
		p.value, p.err = fn()
	}()
	return p
}

func (p *pending[T]) settle() {
	select {
	case <-p.done:
	case <-time.After(aWhile):
	}
}

func (p *pending[T]) await(t *testing.T, what string) T {
	t.Helper()
	select {
	case <-p.done:
		if p.err != nil {
			t.Fatalf("%s failed: %v", what, p.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not finish", what)
	}
	return p.value
}

func testUseSeesACommitAfterTheFirstRead(t *testing.T, s store.Store) {
	ctx := t.Context()
	sess := prepareSession(t, s)
	mustAddToken(t, s, tenantA, sess.ID, 1, sessionBase.Add(time.Hour))
	hash := hashOf("refresh", 1)
	outsideAt, insideAt := sessionBase.Add(time.Second), sessionBase.Add(2*time.Second)
	var inside store.RefreshUse
	var outside *pending[store.RefreshUse]
	err := s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if _, err := tx.Users().Get(ctx, tenantA, id(1)); err != nil {
			return err
		}
		outside = inBackground(func() (store.RefreshUse, error) {
			return s.RefreshTokens().Use(ctx, tenantA, hash, outsideAt)
		})
		outside.settle()
		var err error
		inside, err = tx.RefreshTokens().Use(ctx, tenantA, hash, insideAt)
		return err
	})
	if err != nil {
		t.Fatalf("the transaction failed: %v", err)
	}
	other := outside.await(t, "the Use outside the transaction")
	winners, winnerAt := 0, time.Time{}
	if !inside.Reused {
		winners, winnerAt = winners+1, insideAt
	}
	if !other.Reused {
		winners, winnerAt = winners+1, outsideAt
	}
	if winners != 1 {
		t.Fatalf("Use inside the transaction reported Reused=%v and Use outside it Reused=%v, want exactly one winner", inside.Reused, other.Reused)
	}
	for name, use := range map[string]store.RefreshUse{"inside": inside, "outside": other} {
		if !sameTime(use.Token.UsedAt, winnerAt) {
			t.Fatalf("Use %s the transaction sees UsedAt %v, want the time of the winner %v: a statement must see what was committed before it began", name, use.Token.UsedAt, winnerAt)
		}
	}
}

func testHitSeesACommitAfterTheFirstRead(t *testing.T, s store.Store) {
	ctx := t.Context()
	mustCreate(t, s, newUser(tenantA, id(1)))
	const key = "isolation-counter"
	window := time.Hour
	var inside store.Attempt
	var outside *pending[store.Attempt]
	err := s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if _, err := tx.Users().Get(ctx, tenantA, id(1)); err != nil {
			return err
		}
		outside = inBackground(func() (store.Attempt, error) {
			return s.Attempts().Hit(ctx, key, sessionBase, window)
		})
		outside.settle()
		var err error
		inside, err = tx.Attempts().Hit(ctx, key, sessionBase.Add(time.Second), window)
		return err
	})
	if err != nil {
		t.Fatalf("the transaction failed: %v", err)
	}
	other := outside.await(t, "the Hit outside the transaction")
	counts := []int{inside.Count, other.Count}
	slices.Sort(counts)
	if !slices.Equal(counts, []int{1, 2}) {
		t.Fatalf("the two Hit calls counted %d and %d, want 1 and 2: a statement must see what was committed before it began", inside.Count, other.Count)
	}
}

func testUpdateTellsAMissingUserFromAStaleOne(t *testing.T, s store.Store) {
	ctx := t.Context()
	user := mustCreate(t, s, newUser(tenantA, id(1)))
	var outside *pending[struct{}]
	var updateErr error
	err := s.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if _, err := tx.Users().Get(ctx, tenantA, user.ID); err != nil {
			return err
		}
		outside = inBackground(func() (struct{}, error) {
			return struct{}{}, s.Users().Delete(ctx, tenantA, user.ID)
		})
		outside.settle()
		_, updateErr = tx.Users().Update(ctx, user)
		return nil
	})
	if err != nil {
		t.Fatalf("the transaction failed: %v", err)
	}
	outside.await(t, "the Delete outside the transaction")
	if updateErr != nil && !errors.Is(updateErr, store.ErrNotFound) {
		t.Fatalf("Update of a user who was deleted after the first read = %v, want ErrNotFound: a statement must see what was committed before it began", updateErr)
	}
}
