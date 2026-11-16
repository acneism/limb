package limb

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

type jwk struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Curve     string `json:"crv,omitempty"`
	X         string `json:"x,omitempty"`
	Y         string `json:"y,omitempty"`
	N         string `json:"n,omitempty"`
	E         string `json:"e,omitempty"`
}

var jwkEncoding = base64.RawURLEncoding

func (a *Auth) publishedKeys(ctx context.Context) ([]jwk, error) {
	keys, err := a.ring.published(ctx)
	if err != nil {
		return nil, err
	}
	published := make([]jwk, 0, len(keys))
	for _, key := range keys {
		entry := jwk{Use: "sig", Algorithm: key.record.Algorithm, KeyID: key.record.KID}
		switch public := key.public.(type) {
		case ed25519.PublicKey:
			entry.KeyType, entry.Curve, entry.X = "OKP", "Ed25519", jwkEncoding.EncodeToString(public)
		case *ecdsa.PublicKey:
			point, err := public.Bytes()
			if err != nil {
				return nil, fmt.Errorf("limb: encode the signing key %s: %w", key.record.KID, err)
			}
			size := (len(point) - 1) / 2
			entry.KeyType, entry.Curve = "EC", "P-256"
			entry.X, entry.Y = jwkEncoding.EncodeToString(point[1:1+size]), jwkEncoding.EncodeToString(point[1+size:])
		case *rsa.PublicKey:
			entry.KeyType = "RSA"
			entry.N = jwkEncoding.EncodeToString(public.N.Bytes())
			entry.E = jwkEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes())
		default:
			return nil, fmt.Errorf("limb: the signing key %s has an unknown type", key.record.KID)
		}
		published = append(published, entry)
	}
	return published, nil
}
