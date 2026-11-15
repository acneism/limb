// Package phone provides the phone number identifier type. It lives in its own
// package because the number metadata it depends on is large, so programs that
// do not use phone numbers do not link it.
package phone

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nyaruka/phonenumbers"
	"golang.org/x/text/unicode/norm"

	"github.com/acneism/limb/identifier"
)

const typeName = "phone"

var (
	errFormat = errors.New("invalid phone number")
	errRegion = errors.New("phone number needs a country code")
)

// Number returns the phone number type. It is a delivery type and users can
// sign in with it. Values are parsed with libphonenumber metadata, must be
// valid numbers and are stored in E.164 form, for example +79991234567.
// defaultRegion is the ISO 3166-1 alpha-2 code of the country assumed for
// numbers written without a country code; with an empty defaultRegion only
// numbers that start with + are accepted. Letters are never accepted, so
// vanity numbers and text around a number are rejected. Number panics if
// defaultRegion is not a supported region.
func Number(defaultRegion string, opts ...identifier.Option) identifier.Type {
	if defaultRegion != "" && !phonenumbers.GetSupportedRegions()[defaultRegion] {
		panic(fmt.Sprintf("phone: unsupported region %q", defaultRegion))
	}
	base := []identifier.Option{
		identifier.Normalize(normalizer(defaultRegion)),
		identifier.LoginAllowed(),
		identifier.Delivery(),
	}
	return identifier.Custom(typeName, append(base, opts...)...)
}

func normalizer(region string) func(string) (string, error) {
	return func(raw string) (string, error) {
		text := strings.TrimSpace(norm.NFKC.String(raw))
		if !plausible(text) {
			return "", errFormat
		}
		if region == "" && !strings.HasPrefix(text, "+") {
			return "", errRegion
		}
		number, err := phonenumbers.Parse(text, region)
		if err != nil || !phonenumbers.IsValidNumber(number) {
			return "", errFormat
		}
		return phonenumbers.Format(number, phonenumbers.E164), nil
	}
}

func plausible(text string) bool {
	digits := 0
	for i, r := range text {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == '+':
			if i != 0 {
				return false
			}
		case r == ' ', r == '-', r == '.', r == '(', r == ')':
		default:
			return false
		}
	}
	return digits > 0
}
