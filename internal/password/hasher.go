package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

const (
	algorithm     = "argon2id"
	maxInputBytes = 4096

	minMemoryPerLane = 8
	maxMemory        = 1 << 20
	maxIterations    = 64
	maxParallelism   = 64
	minSaltLength    = 8
	maxSaltLength    = 64
	minKeyLength     = 16
	maxKeyLength     = 128
)

var (
	ErrInvalidHash = errors.New("password: invalid hash")
	ErrTooLong     = errors.New("password: password is too long")
	ErrParams      = errors.New("password: invalid argon2id parameters")

	b64 = base64.RawStdEncoding.Strict()
)

type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func DefaultParams() Params {
	return Params{Memory: 19456, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}
}

func (p Params) validate() error {
	switch {
	case p.Parallelism == 0 || p.Parallelism > maxParallelism:
		return fmt.Errorf("%w: parallelism %d is out of range", ErrParams, p.Parallelism)
	case p.Memory < minMemoryPerLane*uint32(p.Parallelism) || p.Memory > maxMemory:
		return fmt.Errorf("%w: memory %d KiB is out of range", ErrParams, p.Memory)
	case p.Iterations == 0 || p.Iterations > maxIterations:
		return fmt.Errorf("%w: iterations %d is out of range", ErrParams, p.Iterations)
	case p.SaltLength < minSaltLength || p.SaltLength > maxSaltLength:
		return fmt.Errorf("%w: salt length %d is out of range", ErrParams, p.SaltLength)
	case p.KeyLength < minKeyLength || p.KeyLength > maxKeyLength:
		return fmt.Errorf("%w: key length %d is out of range", ErrParams, p.KeyLength)
	}
	return nil
}

type HasherOption func(*Hasher)

func WithParams(p Params) HasherOption {
	return func(h *Hasher) {
		h.params = p
	}
}

func WithConcurrency(n int) HasherOption {
	return func(h *Hasher) {
		h.concurrency = n
	}
}

type Hasher struct {
	params      Params
	concurrency int
	sem         chan struct{}
	dummySalt   []byte
}

func NewHasher(opts ...HasherOption) (*Hasher, error) {
	h := &Hasher{params: DefaultParams(), concurrency: runtime.GOMAXPROCS(0)}
	for _, opt := range opts {
		opt(h)
	}
	if err := h.params.validate(); err != nil {
		return nil, err
	}
	if h.concurrency < 1 {
		return nil, fmt.Errorf("%w: concurrency must be positive", ErrParams)
	}
	h.sem = make(chan struct{}, h.concurrency)
	h.dummySalt = make([]byte, h.params.SaltLength)
	if _, err := rand.Read(h.dummySalt); err != nil {
		return nil, fmt.Errorf("password: random source failed: %w", err)
	}
	return h, nil
}

func (h *Hasher) Params() Params {
	return h.params
}

func Normalize(password string) string {
	return norm.NFKC.String(password)
}

func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	secret, fits := prepare(password)
	if !fits {
		return "", ErrTooLong
	}
	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: random source failed: %w", err)
	}
	key, err := h.derive(ctx, secret, salt, h.params)
	if err != nil {
		return "", err
	}
	return encode(h.params, salt, key), nil
}

func (h *Hasher) Verify(ctx context.Context, password, encoded string) (ok, needsRehash bool, err error) {
	params, salt, want, err := decode(encoded)
	if err != nil {
		return false, false, err
	}
	secret, fits := prepare(password)
	if !fits {
		return false, false, nil
	}
	got, err := h.derive(ctx, secret, salt, params)
	if err != nil {
		return false, false, err
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}
	return true, h.outdated(params), nil
}

func (h *Hasher) DummyVerify(ctx context.Context, password string) error {
	secret, fits := prepare(password)
	if !fits {
		return nil
	}
	_, err := h.derive(ctx, secret, h.dummySalt, h.params)
	return err
}

func (h *Hasher) outdated(p Params) bool {
	return p != h.params
}

func (h *Hasher) derive(ctx context.Context, secret, salt []byte, p Params) ([]byte, error) {
	if err := h.acquire(ctx); err != nil {
		return nil, err
	}
	defer h.release()
	return argon2.IDKey(secret, salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength), nil
}

func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() {
	<-h.sem
}

func prepare(password string) ([]byte, bool) {
	if len(password) > maxInputBytes {
		return nil, false
	}
	normalized := Normalize(password)
	if len(normalized) > maxInputBytes {
		return nil, false
	}
	return []byte(normalized), true
}

func encode(p Params, salt, key []byte) string {
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		algorithm, argon2.Version, p.Memory, p.Iterations, p.Parallelism,
		b64.EncodeToString(salt), b64.EncodeToString(key))
}

func decode(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != algorithm {
		return Params{}, nil, nil, fmt.Errorf("%w: not an %s hash", ErrInvalidHash, algorithm)
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return Params{}, nil, nil, fmt.Errorf("%w: unsupported version", ErrInvalidHash)
	}
	p, err := parseParams(parts[3])
	if err != nil {
		return Params{}, nil, nil, err
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: salt is not base64", ErrInvalidHash)
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: key is not base64", ErrInvalidHash)
	}
	p.SaltLength = uint32(len(salt)) //nolint:gosec
	p.KeyLength = uint32(len(key))   //nolint:gosec
	if err = p.validate(); err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: %w", ErrInvalidHash, err)
	}
	return p, salt, key, nil
}

func parseParams(text string) (Params, error) {
	fields := strings.Split(text, ",")
	if len(fields) != 3 {
		return Params{}, fmt.Errorf("%w: malformed parameters", ErrInvalidHash)
	}
	memory, err := parseField(fields[0], "m=", 32)
	if err != nil {
		return Params{}, err
	}
	iterations, err := parseField(fields[1], "t=", 32)
	if err != nil {
		return Params{}, err
	}
	parallelism, err := parseField(fields[2], "p=", 8)
	if err != nil {
		return Params{}, err
	}
	return Params{Memory: uint32(memory), Iterations: uint32(iterations), Parallelism: uint8(parallelism)}, nil //nolint:gosec
}

func parseField(field, prefix string, bits int) (uint64, error) {
	digits, ok := strings.CutPrefix(field, prefix)
	if !ok {
		return 0, fmt.Errorf("%w: expected %s", ErrInvalidHash, prefix)
	}
	value, err := strconv.ParseUint(digits, 10, bits)
	if err != nil {
		return 0, fmt.Errorf("%w: bad value for %s", ErrInvalidHash, prefix)
	}
	return value, nil
}
