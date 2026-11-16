package store

import (
	"context"
	"time"
)

// Attempt is a counter of failed attempts. The key is not a login or an
// address but a keyed hash of them, so the database does not learn either.
type Attempt struct {
	// Key identifies the counter.
	Key string
	// WindowStart is when the current counting window began.
	WindowStart time.Time
	// Count is how many attempts the window has seen.
	Count int
	// BlockedUntil is when the pause that follows too many attempts ends, the
	// zero time if there is none.
	BlockedUntil time.Time
	// NextAllowedAt is the time before which a new attempt is turned down, the
	// zero time if there is none.
	NextAllowedAt time.Time
}

// Hold postpones the next attempts of a counter. A zero field is left alone.
type Hold struct {
	// BlockedUntil is the end of a pause.
	BlockedUntil time.Time
	// NextAllowedAt is the time before which a new attempt is turned down.
	NextAllowedAt time.Time
}

// Attempts stores the counters of failed attempts. All their state lives in the
// database, so several instances of an application count together.
type Attempts interface {
	// Hit counts one attempt made at the given time. An attempt belongs to the
	// window that began at the first attempt and lasts the given duration, and
	// the first attempt after the window ends opens a new one. Counting is
	// exact: when several calls hit one key at once, every one of them is
	// counted. Hit returns the counter after the call, which may already include
	// attempts counted at the same time by others.
	Hit(ctx context.Context, key string, at time.Time, window time.Duration) (Attempt, error)

	// Get returns the counters that exist among the given keys, in no particular
	// order. A key without a counter is skipped.
	Get(ctx context.Context, keys ...string) ([]Attempt, error)

	// Hold postpones the next attempts of a counter. It only ever moves a time
	// forward: it keeps the stored time if that is later than the given one. It
	// returns ErrNotFound if the counter does not exist.
	Hold(ctx context.Context, key string, h Hold) error

	// Reset removes the counter, and does nothing if there is none.
	Reset(ctx context.Context, key string) error

	// DeleteStale removes the counters whose window and holds all ended before
	// the given time and returns how many it removed.
	DeleteStale(ctx context.Context, before time.Time) (int, error)
}
