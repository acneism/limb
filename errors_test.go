package limb

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestRateLimitErrorMatchesErrRateLimited(t *testing.T) {
	err := error(&RateLimitError{RetryAfter: 90 * time.Second})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatal("a *RateLimitError must match ErrRateLimited")
	}
	wrapped := fmt.Errorf("sign in: %w", err)
	if !errors.Is(wrapped, ErrRateLimited) {
		t.Fatal("a wrapped *RateLimitError must match ErrRateLimited")
	}
	var limit *RateLimitError
	if !errors.As(wrapped, &limit) || limit.RetryAfter != 90*time.Second {
		t.Fatalf("errors.As = %v, %v; want the error with 90s", limit, errors.As(wrapped, &limit))
	}
	if text := err.Error(); !strings.Contains(text, "1m30s") || !strings.HasPrefix(text, "limb: ") {
		t.Fatalf("Error() = %q, want the wait in it", text)
	}
	for _, other := range []error{ErrUnauthenticated, ErrInvalidCredentials, ErrPasswordChangeRequired, ErrCSRF, ErrSessionNotFound} {
		if errors.Is(err, other) || errors.Is(other, ErrRateLimited) {
			t.Fatalf("%v must not match %v", err, other)
		}
	}
}

func TestSessionErrorsAreDistinct(t *testing.T) {
	all := []error{
		ErrInvalidCredentials, ErrUserBlocked, ErrIdentifierTaken, ErrUnauthenticated, ErrRateLimited,
		ErrPasswordChangeRequired, ErrCSRF, ErrSessionNotFound,
	}
	for i, a := range all {
		if !strings.HasPrefix(a.Error(), "limb: ") {
			t.Errorf("%q does not start with the package name", a)
		}
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("%q matches %q", a, b)
			}
		}
	}
}
