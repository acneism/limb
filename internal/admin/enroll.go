package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

// Enroll returns what the administrator needs to bind an authenticator at the
// sign-in that waits for it. The seed is made and kept, sealed, at the first call,
// and the same one comes back at the next, so that a page that is shown again has
// the same code. It returns ErrNoSignIn for a sign-in of an administrator who
// has an authenticator already, and for one whose account changed while the seed
// was stored, in which case the sign-in begins again with the password.
func (s *Service) Enroll(ctx context.Context, in SignIn) (Enrollment, error) {
	if !in.NeedsEnrollment() || s.noTOTP {
		return Enrollment{}, ErrNoSignIn
	}
	if len(in.Admin.TOTPSecret) > 0 {
		return s.OpenEnrollment(in.Admin)
	}
	enrollment, err := s.NewEnrollment(in.Admin)
	if err != nil {
		return Enrollment{}, err
	}
	err = s.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		next := in.Admin
		next.TOTPSecret = enrollment.Sealed
		updated, updateErr := tx.Admins().Update(ctx, next)
		if updateErr != nil {
			return mapSignInError(updateErr)
		}
		if bindErr := tx.AdminSessions().Rebind(ctx, s.tenant, in.Admin.ID, in.Session.ID, updated.Version); bindErr != nil {
			return mapSignInError(bindErr)
		}
		return nil
	})
	if err != nil {
		return Enrollment{}, err
	}
	return enrollment, nil
}

// CompleteEnrollment confirms the authenticator with the one-time password that
// it shows, makes the recovery codes, ends the sign-in and opens the session. It
// counts a guess first, as Complete does, and returns the recovery codes in the
// form that is shown, which nothing keeps but their hashes. A recovery code is not
// a second factor here, because there is none yet.
func (s *Service) CompleteEnrollment(ctx context.Context, in SignIn, input string, c Client) (Opened, []string, error) {
	if !in.NeedsEnrollment() || len(in.Admin.TOTPSecret) == 0 || s.noTOTP {
		return Opened{}, nil, ErrNoSignIn
	}
	c = c.clean()
	if err := s.guess(ctx, in); err != nil {
		return Opened{}, nil, err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	factor, err := s.ReadFactor(in.Admin, input, now)
	if err != nil {
		return Opened{}, nil, err
	}
	if factor.Kind != FactorTOTP {
		return Opened{}, nil, ErrBadFactor
	}
	shown, hashes, err := s.NewRecoveryCodes(in.Admin.ID)
	if err != nil {
		return Opened{}, nil, err
	}
	var opened Opened
	err = s.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		next := in.Admin
		next.TOTPConfirmedAt = now
		updated, updateErr := tx.Admins().Update(ctx, next)
		if updateErr != nil {
			return mapSignInError(updateErr)
		}
		if acceptErr := tx.Admins().AcceptStep(ctx, s.tenant, updated.ID, updated.Version, factor.Step, now); acceptErr != nil {
			if errors.Is(acceptErr, store.ErrConflict) {
				return ErrBadFactor
			}
			return mapSignInError(acceptErr)
		}
		if codesErr := tx.Admins().ReplaceRecoveryCodes(ctx, s.tenant, updated.ID, hashes); codesErr != nil {
			return fmt.Errorf("admin: store the recovery codes: %w", codesErr)
		}
		if endErr := tx.AdminSessions().Delete(ctx, s.tenant, updated.ID, in.Session.ID); endErr != nil {
			return mapSignInError(endErr)
		}
		var openErr error
		if opened, openErr = s.openSession(ctx, tx, updated, c, "password+totp"); openErr != nil {
			return openErr
		}
		opened.RecoveryCodes = len(hashes)
		if addErr := s.audit.Add(ctx, tx.Audit(), audit.Entry{
			Actor: adminActor(updated.ID), Action: audit.AdminTOTPEnrolled, IP: c.IP, Details: map[string]any{"recovery_codes": len(hashes)},
		}); addErr != nil {
			return addErr
		}
		return s.addLoginRecord(ctx, tx, opened, c)
	})
	if err != nil {
		return Opened{}, nil, err
	}
	return opened, shown, nil
}
