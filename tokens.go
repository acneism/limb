package limb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	accessTokenType = "at+jwt"
	maxTokenLength  = 8 << 10
	tokenLeeway     = 5 * time.Second
)

type accessClaims struct {
	jwt.RegisteredClaims
	SessionID      string `json:"sid"`
	ChangePassword bool   `json:"cpw,omitempty"`
}

func (a *Auth) issueAccessToken(ctx context.Context, userID, sessionID string, restricted bool, now time.Time) (string, time.Time, error) {
	key, err := a.ring.signer(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	issued := now.UTC().Truncate(time.Second)
	expires := issued.Add(a.accessTTL)
	claims := accessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    a.issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{a.audience},
			IssuedAt:  jwt.NewNumericDate(issued),
			ExpiresAt: jwt.NewNumericDate(expires),
		},
		SessionID:      sessionID,
		ChangePassword: restricted,
	}
	token := jwt.NewWithClaims(signingMethod(key.algorithm()), claims)
	token.Header["kid"] = key.record.KID
	token.Header["typ"] = accessTokenType
	signed, err := token.SignedString(key.private)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("limb: sign the access token: %w", err)
	}
	return signed, expires, nil
}

func signingMethod(alg SigningAlgorithm) jwt.SigningMethod {
	switch alg {
	case SigningEdDSA:
		return jwt.SigningMethodEdDSA
	case SigningES256:
		return jwt.SigningMethodES256
	case SigningRS256:
		return jwt.SigningMethodRS256
	}
	return jwt.SigningMethodNone
}

func (a *Auth) verifyAccessToken(ctx context.Context, raw string) (accessClaims, error) {
	if len(raw) > maxTokenLength || !tokenShaped(raw) {
		return accessClaims{}, ErrUnauthenticated
	}
	var claims accessClaims
	var lookupErr error
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{string(a.algorithm)}),
		jwt.WithIssuer(a.issuer),
		jwt.WithAudience(a.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(tokenLeeway),
		jwt.WithTimeFunc(a.now),
		jwt.WithStrictDecoding(),
	)
	token, err := parser.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("the token has no key ID")
		}
		key, err := a.ring.lookup(ctx, kid)
		if err != nil {
			lookupErr = err
			return nil, err
		}
		if key == nil || key.algorithm() != a.algorithm {
			return nil, errors.New("the key of the token is not known")
		}
		return key.public, nil
	})
	if lookupErr != nil {
		return accessClaims{}, lookupErr
	}
	if err != nil || !token.Valid || !wellFormedToken(token, claims) {
		return accessClaims{}, ErrUnauthenticated
	}
	return claims, nil
}

func tokenShaped(raw string) bool {
	dots := 0
	for i := range len(raw) {
		switch c := raw[i]; {
		case c == '.':
			dots++
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return dots == 2
}

func wellFormedToken(token *jwt.Token, claims accessClaims) bool {
	if typ, _ := token.Header["typ"].(string); !strings.EqualFold(typ, accessTokenType) {
		return false
	}
	if _, critical := token.Header["crit"]; critical {
		return false
	}
	return claims.Subject != "" && claims.SessionID != "" && claims.IssuedAt != nil && claims.ExpiresAt != nil
}
