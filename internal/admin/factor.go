package admin

import (
	"errors"
	"fmt"
	"time"

	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/internal/totp"
	"github.com/acneism/limb/store"
)

// RecoveryCodeCount is how many recovery codes an administrator gets when they
// confirm their authenticator.
const RecoveryCodeCount = 10

// ErrBadFactor is returned for a second factor that is not a one-time password
// that fits or a recovery code in a form that can be one.
var ErrBadFactor = errors.New("admin: the second factor is wrong")

// Enrollment is what an administrator needs to bind an authenticator.
type Enrollment struct {
	// Seed is the seed itself. It is kept in memory only for the time of one request,
	// and nothing logs it.
	Seed []byte
	// Sealed is the seed encrypted for the administrator, as it is stored.
	Sealed []byte
	// Secret is the seed in base32 for typing it by hand.
	Secret string
	// URI is the address that a QR code carries.
	URI string
}

// NewEnrollment makes a new seed for the administrator.
func (s *Service) NewEnrollment(a store.Admin) (Enrollment, error) {
	seed, err := totp.NewSecret()
	if err != nil {
		return Enrollment{}, fmt.Errorf("admin: make a seed: %w", err)
	}
	sealed, err := s.keys.SealTOTP(seed, a.ID)
	if err != nil {
		return Enrollment{}, fmt.Errorf("admin: seal the seed: %w", err)
	}
	return s.enrollment(a, seed, sealed), nil
}

// OpenEnrollment returns the enrollment of an administrator who has a seed that
// is not confirmed yet, so that the QR code of a page that is shown again is the
// same.
func (s *Service) OpenEnrollment(a store.Admin) (Enrollment, error) {
	seed, err := s.keys.OpenTOTP(a.TOTPSecret, a.ID)
	if err != nil {
		return Enrollment{}, fmt.Errorf("admin: open the seed: %w", err)
	}
	return s.enrollment(a, seed, a.TOTPSecret), nil
}

func (s *Service) enrollment(a store.Admin, seed, sealed []byte) Enrollment {
	return Enrollment{Seed: seed, Sealed: sealed, Secret: totp.EncodeSecret(seed), URI: totp.URI(s.issuer, a.Login, seed)}
}

// NewRecoveryCodes makes the recovery codes of an administrator. It returns them
// in the form that is shown, once, and the hashes that are stored.
func (s *Service) NewRecoveryCodes(adminID string) ([]string, [][]byte, error) {
	shown := make([]string, 0, RecoveryCodeCount)
	hashes := make([][]byte, 0, RecoveryCodeCount)
	for range RecoveryCodeCount {
		code, err := s.keys.NewRecoveryCode()
		if err != nil {
			return nil, nil, fmt.Errorf("admin: make a recovery code: %w", err)
		}
		shown = append(shown, secret.FormatRecoveryCode(code))
		hashes = append(hashes, s.keys.RecoveryHash(adminID, code))
	}
	return shown, hashes, nil
}

// FactorKind tells which second factor was given.
type FactorKind string

// The second factors.
const (
	// FactorTOTP is a one-time password from the authenticator.
	FactorTOTP FactorKind = "totp"
	// FactorRecovery is a recovery code.
	FactorRecovery FactorKind = "recovery"
)

// Factor is a second factor that was read. It is not accepted until the store
// has recorded that it was used: a time step with AcceptStep, a recovery code
// with UseRecoveryCode.
type Factor struct {
	// Kind says which factor it is.
	Kind FactorKind
	// Step is the time step of a one-time password, set for FactorTOTP.
	Step int64
	// Hash is the hash of a recovery code, set for FactorRecovery.
	Hash []byte
}

// ReadFactor reads what the administrator typed as the second step. A one-time
// password is checked against the seed at the moment now. A recovery code is only
// read and hashed, because the store checks it and uses it in one atomic step.
// It returns ErrBadFactor for a one-time password that is wrong, for text that
// is neither a password nor a code, and for an administrator who has no seed.
func (s *Service) ReadFactor(a store.Admin, input string, now time.Time) (Factor, error) {
	if len(a.TOTPSecret) == 0 {
		return Factor{}, ErrBadFactor
	}
	if _, isPassword := secret.ParseCode(input); isPassword {
		seed, err := s.keys.OpenTOTP(a.TOTPSecret, a.ID)
		if err != nil {
			return Factor{}, fmt.Errorf("admin: open the seed: %w", err)
		}
		step, ok := totp.Verify(seed, input, now)
		if !ok {
			return Factor{}, ErrBadFactor
		}
		return Factor{Kind: FactorTOTP, Step: step}, nil
	}
	code, ok := secret.ParseRecoveryCode(input)
	if !ok {
		return Factor{}, ErrBadFactor
	}
	return Factor{Kind: FactorRecovery, Hash: s.keys.RecoveryHash(a.ID, code)}, nil
}
