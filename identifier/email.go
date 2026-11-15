package identifier

import (
	"errors"
	"strings"

	"golang.org/x/net/idna"
)

const (
	emailMaxLength      = 254
	emailMaxLocalLength = 64
	emailLocalSpecials  = "!#$%&'*+/=?^_`{|}~-"
	emailTypeName       = "email"
)

var (
	errEmailDisplayName = errors.New("display names are not allowed in an e-mail address")
	errEmailFormat      = errors.New("invalid e-mail address")
	errEmailLocal       = errors.New("invalid local part of the e-mail address")
	errEmailDomain      = errors.New("invalid domain of the e-mail address")
	errEmailTooLong     = errors.New("e-mail address is too long")

	emailDomainProfile = idna.New(
		idna.MapForLookup(),
		idna.BidiRule(),
		idna.CheckHyphens(true),
		idna.CheckJoiners(true),
		idna.VerifyDNSLength(true),
		idna.Transitional(false),
	)
)

// Email returns the e-mail address type. It is a delivery type and users can
// sign in with it. Values are trimmed, lower cased and have their domain
// converted to punycode; the local part is limited to the ASCII characters of
// a dot-atom, at most 64 of them, and the whole address to 254 characters.
// Display names such as "Name <address>" are rejected.
func Email(opts ...Option) Type {
	return build(spec{
		name:     emailTypeName,
		base:     normalizeEmail,
		defaults: settings{login: true, delivery: true},
	}, opts)
}

func normalizeEmail(raw string) (string, error) {
	address := strings.TrimSpace(raw)
	if address == "" {
		return "", errEmpty
	}
	if strings.ContainsAny(address, "<>") {
		return "", errEmailDisplayName
	}
	if strings.Count(address, "@") != 1 {
		return "", errEmailFormat
	}
	local, domain, _ := strings.Cut(address, "@")
	local = strings.ToLower(local)
	if !validEmailLocal(local) {
		return "", errEmailLocal
	}
	ascii, err := normalizeEmailDomain(domain)
	if err != nil {
		return "", err
	}
	normalized := local + "@" + ascii
	if len(normalized) > emailMaxLength {
		return "", errEmailTooLong
	}
	return normalized, nil
}

func normalizeEmailDomain(domain string) (string, error) {
	if domain == "" || strings.HasSuffix(domain, ".") {
		return "", errEmailDomain
	}
	ascii, err := emailDomainProfile.ToASCII(domain)
	if err != nil {
		return "", errEmailDomain
	}
	ascii = strings.ToLower(ascii)
	if !strings.Contains(ascii, ".") || strings.HasSuffix(ascii, ".") {
		return "", errEmailDomain
	}
	if digitsOnly(ascii[strings.LastIndexByte(ascii, '.')+1:]) {
		return "", errEmailDomain
	}
	return ascii, nil
}

func validEmailLocal(local string) bool {
	if local == "" || len(local) > emailMaxLocalLength {
		return false
	}
	if local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") {
		return false
	}
	for i := range len(local) {
		if !emailLocalChar(local[i]) {
			return false
		}
	}
	return true
}

func emailLocalChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' ||
		strings.IndexByte(emailLocalSpecials, c) >= 0
}
