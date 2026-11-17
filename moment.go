package limb

import (
	"fmt"
	"time"
)

const (
	firstYear = 1
	lastYear  = 9999
)

func checkMoment(field string, at time.Time) error {
	if at.IsZero() {
		return nil
	}
	if year := at.UTC().Year(); year < firstYear || year > lastYear {
		return &ValidationError{Field: field, Reason: fmt.Sprintf("must be in the years from %d to %d", firstYear, lastYear)}
	}
	return nil
}

func momentOf(micro int64) (time.Time, bool) {
	at := time.UnixMicro(micro).UTC()
	return at, !at.IsZero() && at.Year() >= firstYear && at.Year() <= lastYear
}
