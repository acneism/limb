package limb

import (
	"testing"
	"time"
)

func TestCookieLifetimeIsAWholeNumberOfSecondsAndAtLeastOne(t *testing.T) {
	now := time.Date(2026, 9, 10, 11, 12, 13, 456789000, time.UTC)
	tests := []struct {
		name    string
		expires time.Time
		want    int
	}{
		{"a month", now.Add(30 * 24 * time.Hour), 30 * 24 * 3600},
		{"a minute and a half", now.Add(90 * time.Second), 90},
		{"almost two seconds", now.Add(1900 * time.Millisecond), 1},
		{"half a second", now.Add(500 * time.Millisecond), 1},
		{"this very moment", now, 1},
		{"in the past", now.Add(-time.Hour), 1},
	}
	for _, tc := range tests {
		if got := cookieLifetime(tc.expires, now); got != tc.want {
			t.Errorf("%s: cookieLifetime = %d, want %d", tc.name, got, tc.want)
		}
	}
}
