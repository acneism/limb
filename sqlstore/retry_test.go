package sqlstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func aUser() store.User {
	return store.User{TenantID: store.DefaultTenant, ID: "00000000-0000-7000-8000-000000000001", Status: store.StatusActive, CreatedAt: time.Now()}
}

func TestATransactionThatTheDatabaseAbortsIsRunAgain(t *testing.T) {
	probe, s := newStubStore(t, func(_ string, n int) error {
		if n == 1 {
			return errDeadlock
		}
		return nil
	})
	runs := 0
	err := s.InTx(t.Context(), func(ctx context.Context, tx store.Repositories) error {
		runs++
		return tx.Users().Create(ctx, aUser())
	})
	if err != nil {
		t.Fatalf("InTx = %v, want the second run to succeed", err)
	}
	if runs != 2 || probe.begins != 2 || probe.rollbacks != 1 || probe.commits != 1 {
		t.Fatalf("runs = %d, begins = %d, rollbacks = %d, commits = %d", runs, probe.begins, probe.rollbacks, probe.commits)
	}
}

func TestATransactionIsRunAtMostThreeTimes(t *testing.T) {
	probe, s := newStubStore(t, func(string, int) error { return errDeadlock })
	runs := 0
	err := s.InTx(t.Context(), func(ctx context.Context, tx store.Repositories) error {
		runs++
		return tx.Users().Create(ctx, aUser())
	})
	var got stubError
	if !errors.As(err, &got) || got != errDeadlock {
		t.Fatalf("InTx = %v, want the error of the database", err)
	}
	if runs != 3 || probe.begins != 3 || probe.rollbacks != 3 || probe.commits != 0 {
		t.Fatalf("runs = %d, begins = %d, rollbacks = %d, commits = %d", runs, probe.begins, probe.rollbacks, probe.commits)
	}
}

func TestAnErrorThatCannotGoAwayIsNotRepeated(t *testing.T) {
	probe, s := newStubStore(t, func(string, int) error { return errOther })
	runs := 0
	err := s.InTx(t.Context(), func(ctx context.Context, tx store.Repositories) error {
		runs++
		return tx.Users().Create(ctx, aUser())
	})
	if !errors.Is(err, store.ErrConflict) || runs != 1 || probe.begins != 1 {
		t.Fatalf("InTx = %v after %d runs and %d transactions, want one run and a conflict", err, runs, probe.begins)
	}
	mine := errors.New("the application failed")
	if err = s.InTx(t.Context(), func(context.Context, store.Repositories) error { return mine }); err != mine { //nolint:errorlint
		t.Fatalf("InTx = %v, want the error of the function as it is", err)
	}
}

func TestAStatementOutsideATransactionIsRepeatedOnItsOwn(t *testing.T) {
	probe, s := newStubStore(t, func(_ string, n int) error {
		if n <= 2 {
			return errDeadlock
		}
		return nil
	})
	if err := s.Users().Create(t.Context(), aUser()); err != nil {
		t.Fatalf("Create = %v, want the third run to succeed", err)
	}
	if probe.begins != 0 || len(probe.queries) != 3 {
		t.Fatalf("begins = %d, statements = %d, want three runs of the statement outside any transaction", probe.begins, len(probe.queries))
	}
}

func TestAStatementInsideATransactionIsNotRepeatedOnItsOwn(t *testing.T) {
	probe, s := newStubStore(t, func(_ string, n int) error {
		if n == 1 {
			return errDeadlock
		}
		return nil
	})
	var seen error
	err := s.InTx(t.Context(), func(ctx context.Context, tx store.Repositories) error {
		err := tx.Users().Create(ctx, aUser())
		if seen == nil {
			seen = err
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var got stubError
	if !errors.As(seen, &got) || got != errDeadlock {
		t.Fatalf("the first run saw %v, want the error of the database from the statement itself", seen)
	}
	if probe.begins != 2 || len(probe.queries) != 2 {
		t.Fatalf("begins = %d, statements = %d, want the whole transaction twice and each statement once", probe.begins, len(probe.queries))
	}
}

func TestRepeatingStopsWhenTheContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	probe, s := newStubStore(t, func(string, int) error {
		cancel()
		return errDeadlock
	})
	err := s.Users().Create(ctx, aUser())
	var got stubError
	if !errors.As(err, &got) || got != errDeadlock {
		t.Fatalf("Create = %v, want the error of the database", err)
	}
	if len(probe.queries) != 1 {
		t.Fatalf("the statement ran %d times after the context was canceled", len(probe.queries))
	}
}

func TestPostgresRepeatsWhatItMayRepeat(t *testing.T) {
	for state, want := range map[string]bool{"40P01": true, "40001": true, "23505": false, "23503": false, "42P01": false, "": false} {
		if got := Postgres.IsRetryable(stubError{state: state}); got != want {
			t.Errorf("IsRetryable(%q) = %v, want %v", state, got, want)
		}
	}
	if Postgres.IsRetryable(nil) || Postgres.IsRetryable(errors.New("plain")) {
		t.Error("an error without a state must not be repeated")
	}
	wrapped := errors.Join(errors.New("context"), errDeadlock)
	if !Postgres.IsRetryable(wrapped) {
		t.Error("a wrapped deadlock must be repeated")
	}
}
