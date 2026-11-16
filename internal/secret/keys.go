package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// MinMasterKeyLength is the shortest master key that is accepted.
	MinMasterKeyLength = 32

	sealVersion     = 1
	nonceLength     = 12
	maxSealedLength = 1 << 16
	subkeyLength    = 32

	infoSigningKeys = "limb/v1/signing-keys"
	infoAttempts    = "limb/v1/attempts"
	infoCSRF        = "limb/v1/csrf"
)

var (
	// ErrMasterKey is returned for a master key that is too short.
	ErrMasterKey = errors.New("secret: the master key is too short")
	// ErrOpen is returned when sealed data cannot be opened, whatever the reason.
	ErrOpen = errors.New("secret: cannot open the sealed data")
)

// Keys holds the keys derived from the master key. The master key itself is
// never used to encrypt or sign anything: every purpose gets its own subkey
// from HKDF-SHA256, with the purpose as the info string.
type Keys struct {
	aead     cipher.AEAD
	attempts []byte
	csrf     []byte
	random   io.Reader
}

// NewKeys derives the subkeys from the master key, which must be at least
// MinMasterKeyLength bytes long.
func NewKeys(master []byte) (*Keys, error) {
	if len(master) < MinMasterKeyLength {
		return nil, fmt.Errorf("%w: at least %d bytes are needed, got %d", ErrMasterKey, MinMasterKeyLength, len(master))
	}
	sealing, err := derive(master, infoSigningKeys)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sealing)
	if err != nil {
		return nil, fmt.Errorf("secret: create the cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secret: create the cipher: %w", err)
	}
	attempts, err := derive(master, infoAttempts)
	if err != nil {
		return nil, err
	}
	csrf, err := derive(master, infoCSRF)
	if err != nil {
		return nil, err
	}
	return &Keys{aead: aead, attempts: attempts, csrf: csrf, random: rand.Reader}, nil
}

func derive(master []byte, info string) ([]byte, error) {
	key := make([]byte, subkeyLength)
	if _, err := io.ReadFull(hkdf.New(sha256.New, master, nil, []byte(info)), key); err != nil {
		return nil, fmt.Errorf("secret: derive a subkey: %w", err)
	}
	return key, nil
}

// Seal encrypts plaintext with AES-256-GCM under a random 12-byte nonce. The
// context strings are authenticated but not stored, so Open succeeds only with
// the same strings in the same order. The result starts with a format version.
func (k *Keys) Seal(plaintext []byte, context ...string) ([]byte, error) {
	out := make([]byte, 1+nonceLength, 1+nonceLength+len(plaintext)+k.aead.Overhead())
	out[0] = sealVersion
	if _, err := io.ReadFull(k.random, out[1:]); err != nil {
		return nil, fmt.Errorf("secret: random source failed: %w", err)
	}
	return k.aead.Seal(out, out[1:], plaintext, additionalData(sealVersion, context)), nil
}

// Open decrypts the result of Seal. Every failure, whether the data is too
// short, of an unknown version, damaged or sealed for another context, gives
// the same ErrOpen.
func (k *Keys) Open(sealed []byte, context ...string) ([]byte, error) {
	if len(sealed) < 1+nonceLength+k.aead.Overhead() || len(sealed) > maxSealedLength || sealed[0] != sealVersion {
		return nil, ErrOpen
	}
	plaintext, err := k.aead.Open(nil, sealed[1:1+nonceLength], sealed[1+nonceLength:], additionalData(sealed[0], context))
	if err != nil {
		return nil, ErrOpen
	}
	return plaintext, nil
}

func additionalData(version byte, context []string) []byte {
	return appendFramed([]byte{version}, context)
}

func appendFramed(dst []byte, parts []string) []byte {
	for _, part := range parts {
		dst = binary.AppendUvarint(dst, uint64(len(part)))
		dst = append(dst, part...)
	}
	return dst
}

// AttemptKey returns the key under which failed attempts are counted: an HMAC
// of the kind of counter and its parts, in text form. The database never sees
// logins or addresses, only these keys.
func (k *Keys) AttemptKey(kind string, parts ...string) string {
	return encoding.EncodeToString(sum(k.attempts, appendFramed(nil, append([]string{kind}, parts...))))
}

// CSRFToken returns the token that proves a request comes from a page that
// knows the session: an HMAC of the session ID, in text form.
func (k *Keys) CSRFToken(sessionID string) string {
	return encoding.EncodeToString(sum(k.csrf, []byte(sessionID)))
}

// CheckCSRF reports whether token is the CSRF token of the session, comparing
// in constant time.
func (k *Keys) CheckCSRF(sessionID, token string) bool {
	return Equal([]byte(token), []byte(k.CSRFToken(sessionID)))
}

func sum(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
