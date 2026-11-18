package admin

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/internal/totp"
	"github.com/acneism/limb/store"
)

const (
	// RebindLifetime is how long a binding of another authenticator waits for the
	// one-time password that confirms it.
	RebindLifetime = 10 * time.Minute

	// RuleSameAsCurrent is the rule that a new password breaks when it is the
	// current one.
	RuleSameAsCurrent = "same_as_current"

	rebindContext = "totp-rebind"
)

var (
	// ErrNoSecondFactor is returned when the service lets administrators in with
	// the password alone, so that there is no authenticator to change.
	ErrNoSecondFactor = errors.New("admin: the service has no second factor")

	// ErrNoRebind is returned for the token of a binding that was not made for this
	// session, was damaged or has run out.
	ErrNoRebind = errors.New("admin: there is no binding of an authenticator to confirm")

	// ErrNoSuchSession is returned when the administrator has no session to end
	// with that ID, or it is the session that asks.
	ErrNoSuchSession = errors.New("admin: the administrator has no such session")
)

// SessionInfo is a session of an administrator as the page of the account shows
// it. It holds nothing that signs in.
type SessionInfo struct {
	// ID identifies the session.
	ID string
	// IP and UserAgent are what the sign-in came with.
	IP, UserAgent string
	// CreatedAt is when the administrator signed in.
	CreatedAt time.Time
	// LastSeenAt is when the session was last used, roughly.
	LastSeenAt time.Time
	// Current tells that it is the session that asks.
	Current bool
}

// Profile is what the page of the account shows.
type Profile struct {
	// Account is the administrator.
	Account Account
	// Sessions are the sessions that work, the oldest first.
	Sessions []SessionInfo
}

// Rebinding is a binding of another authenticator that waits for the one-time
// password of the new one. It is kept in a token that the page carries and
// nothing else keeps, so the authenticator that works stays until the new one is
// confirmed. The token is of one session and of one state of the account, so it
// works once: the change that it makes ends it.
type Rebinding struct {
	Enrollment
	// Token is what the form sends back with the one-time password. It is sealed
	// for the administrator and the session, so a token that was copied to
	// another session does not open.
	Token string
	// ExpiresAt is when the binding runs out.
	ExpiresAt time.Time
}

func (s *Service) current(ctx context.Context, admins store.Admins, ses Session) (store.Admin, error) {
	a, err := admins.Get(ctx, s.tenant, ses.AdminID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.Admin{}, ErrNoSession
	case err != nil:
		return store.Admin{}, fmt.Errorf("admin: get the administrator: %w", err)
	case a.Status != store.AdminActive || a.Version != ses.Version:
		return store.Admin{}, ErrNoSession
	}
	return a, nil
}

func (s *Service) verifyOwnPassword(ctx context.Context, a store.Admin, password string) error {
	matched, _, err := s.hasher.Verify(ctx, password, a.PasswordHash)
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("admin: verify the password: %w", err)
	case err != nil:
		return &CredentialsError{Reason: "unusable_hash", AdminID: a.ID}
	case !matched:
		return &CredentialsError{Reason: "wrong_password", AdminID: a.ID}
	}
	return nil
}

// Profile returns the account of the administrator of the session and the
// sessions of theirs that work. It returns ErrNoSession when the session does not
// work any more.
func (s *Service) Profile(ctx context.Context, ses Session) (Profile, error) {
	a, err := s.current(ctx, s.store.Admins(), ses)
	if err != nil {
		return Profile{}, err
	}
	left, err := s.store.Admins().CountRecoveryCodes(ctx, s.tenant, a.ID)
	if err != nil {
		return Profile{}, fmt.Errorf("admin: count the recovery codes: %w", err)
	}
	rows, err := s.store.AdminSessions().ListByAdmin(ctx, s.tenant, a.ID, s.now())
	if err != nil {
		return Profile{}, fmt.Errorf("admin: list the sessions: %w", err)
	}
	profile := Profile{Account: accountOf(a, left)}
	now := s.now()
	for _, row := range rows {
		if row.AdminVersion != a.Version || !row.LastSeenAt.Add(s.idle).After(now) {
			continue
		}
		profile.Sessions = append(profile.Sessions, SessionInfo{
			ID: row.ID, IP: row.IP, UserAgent: row.UserAgent, CreatedAt: row.CreatedAt, LastSeenAt: row.LastSeenAt, Current: row.ID == ses.ID,
		})
	}
	return profile, nil
}

type ownChange struct {
	prepare func(a store.Admin) store.Admin
	after   func(ctx context.Context, tx store.Repositories, updated store.Admin) error
	entry   func(updated store.Admin, ended int) audit.Entry
}

func (s *Service) changeOwn(ctx context.Context, ses Session, change ownChange) error {
	for range maxChangeAttempts {
		err := s.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
			a, err := s.current(ctx, tx.Admins(), ses)
			if err != nil {
				return err
			}
			updated, err := tx.Admins().Update(ctx, change.prepare(a))
			if err != nil {
				if errors.Is(err, store.ErrStale) {
					return err
				}
				return fmt.Errorf("admin: update the administrator: %w", err)
			}
			if change.after != nil {
				if err = change.after(ctx, tx, updated); err != nil {
					return err
				}
			}
			if err = tx.AdminSessions().Rebind(ctx, s.tenant, a.ID, ses.ID, updated.Version); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return ErrNoSession
				}
				return fmt.Errorf("admin: keep the session: %w", err)
			}
			ended, err := tx.AdminSessions().DeleteForAdmin(ctx, s.tenant, a.ID, ses.ID)
			if err != nil {
				return fmt.Errorf("admin: end the other sessions: %w", err)
			}
			return s.audit.Add(ctx, tx.Audit(), change.entry(updated, ended))
		})
		if !errors.Is(err, store.ErrStale) {
			return err
		}
	}
	return ErrConcurrent
}

// ChangePassword gives the administrator of the session a new password after it
// has checked the current one, and ends their other sessions. The session that
// asks goes on. It returns a *CredentialsError, which is ErrBadCredentials, for a
// current password that is wrong, a *PolicyError for a new one that breaks the
// policy or is the current one, and ErrNoSession when the session does not work
// any more.
func (s *Service) ChangePassword(ctx context.Context, ses Session, current, next string, c Client) error {
	c = c.clean()
	a, err := s.current(ctx, s.store.Admins(), ses)
	if err != nil {
		return err
	}
	if err = s.verifyOwnPassword(ctx, a, current); err != nil {
		return err
	}
	if err = s.checkPassword(ctx, next, a.Login); err != nil {
		return err
	}
	if norm.NFKC.String(next) == norm.NFKC.String(current) {
		return &PolicyError{Rules: []string{RuleSameAsCurrent}}
	}
	hash, err := s.hasher.Hash(ctx, next)
	if err != nil {
		return fmt.Errorf("admin: hash the password: %w", err)
	}
	return s.changeOwn(ctx, ses, ownChange{
		prepare: func(a store.Admin) store.Admin {
			a.PasswordHash = hash
			return a
		},
		entry: func(updated store.Admin, ended int) audit.Entry {
			return audit.Entry{
				Actor: adminActor(updated.ID), Action: audit.AdminPasswordChanged, IP: c.IP, Details: map[string]any{"sessions_ended": ended},
			}
		},
	})
}

// RenewRecoveryCodes makes new recovery codes for the administrator of the
// session after it has checked their password. The old ones stop working. The
// codes come back in the form that is shown, which nothing keeps but their
// hashes. It returns ErrNoSecondFactor for a service without a second factor.
func (s *Service) RenewRecoveryCodes(ctx context.Context, ses Session, password string, c Client) ([]string, error) {
	if s.noTOTP {
		return nil, ErrNoSecondFactor
	}
	c = c.clean()
	a, err := s.current(ctx, s.store.Admins(), ses)
	if err != nil {
		return nil, err
	}
	if err = s.verifyOwnPassword(ctx, a, password); err != nil {
		return nil, err
	}
	shown, hashes, err := s.NewRecoveryCodes(a.ID)
	if err != nil {
		return nil, err
	}
	err = s.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if _, currentErr := s.current(ctx, tx.Admins(), ses); currentErr != nil {
			return currentErr
		}
		if replaceErr := tx.Admins().ReplaceRecoveryCodes(ctx, s.tenant, a.ID, hashes); replaceErr != nil {
			return fmt.Errorf("admin: store the recovery codes: %w", replaceErr)
		}
		return s.audit.Add(ctx, tx.Audit(), audit.Entry{
			Actor: adminActor(a.ID), Action: audit.AdminRecoveryCodesRenewed, IP: c.IP, Details: map[string]any{"recovery_codes": len(hashes)},
		})
	})
	if err != nil {
		return nil, err
	}
	return shown, nil
}

func (s *Service) rebindToken(seed []byte, a store.Admin, sessionID string, expires time.Time) (string, error) {
	plain := binary.BigEndian.AppendUint64(slices.Clone(seed), uint64(expires.Unix())) //nolint:gosec
	sealed, err := s.keys.Seal(plain, rebindContext, a.ID, sessionID, strconv.FormatInt(a.Version, 10))
	if err != nil {
		return "", fmt.Errorf("admin: seal the binding: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *Service) openRebindToken(token string, a store.Admin, sessionID string) ([]byte, time.Time, error) {
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil {
		return nil, time.Time{}, ErrNoRebind
	}
	plain, err := s.keys.Open(sealed, rebindContext, a.ID, sessionID, strconv.FormatInt(a.Version, 10))
	if err != nil || len(plain) != totp.SecretLength+8 {
		return nil, time.Time{}, ErrNoRebind
	}
	expires := time.Unix(int64(binary.BigEndian.Uint64(plain[totp.SecretLength:])), 0).UTC() //nolint:gosec
	if !expires.After(s.now()) {
		return nil, time.Time{}, ErrNoRebind
	}
	return plain[:totp.SecretLength], expires, nil
}

// BeginRebind makes the seed of another authenticator for the administrator of
// the session after it has checked their password, and returns what the page
// shows with the token that carries the seed. Nothing is stored: the
// authenticator that works stays until ConfirmRebind. It returns
// ErrNoSecondFactor for a service without a second factor.
func (s *Service) BeginRebind(ctx context.Context, ses Session, password string) (Rebinding, error) {
	if s.noTOTP {
		return Rebinding{}, ErrNoSecondFactor
	}
	a, err := s.current(ctx, s.store.Admins(), ses)
	if err != nil {
		return Rebinding{}, err
	}
	if err = s.verifyOwnPassword(ctx, a, password); err != nil {
		return Rebinding{}, err
	}
	seed, err := totp.NewSecret()
	if err != nil {
		return Rebinding{}, fmt.Errorf("admin: make a seed: %w", err)
	}
	expires := s.now().UTC().Add(RebindLifetime)
	token, err := s.rebindToken(seed, a, ses.ID, expires)
	if err != nil {
		return Rebinding{}, err
	}
	return Rebinding{Enrollment: s.enrollment(a, seed, nil), Token: token, ExpiresAt: expires}, nil
}

// OpenRebind returns the binding that a token carries, so that a page that is
// shown again has the same code. It returns ErrNoRebind for a token that is not
// one of this session or has run out.
func (s *Service) OpenRebind(ctx context.Context, ses Session, token string) (Rebinding, error) {
	if s.noTOTP {
		return Rebinding{}, ErrNoSecondFactor
	}
	a, err := s.current(ctx, s.store.Admins(), ses)
	if err != nil {
		return Rebinding{}, err
	}
	seed, expires, err := s.openRebindToken(token, a, ses.ID)
	if err != nil {
		return Rebinding{}, err
	}
	return Rebinding{Enrollment: s.enrollment(a, seed, nil), Token: token, ExpiresAt: expires}, nil
}

// ConfirmRebind binds the authenticator that a token carries, if the one-time
// password that it shows is right: the seed replaces the old one, new recovery
// codes replace the old ones and the other sessions of the administrator end.
// The session that asks goes on. It returns the recovery codes in the form that is
// shown, ErrBadFactor for a one-time password that is wrong or was used, and
// ErrNoRebind for a token that is not one of this session or has run out.
func (s *Service) ConfirmRebind(ctx context.Context, ses Session, token, input string, c Client) ([]string, error) {
	if s.noTOTP {
		return nil, ErrNoSecondFactor
	}
	c = c.clean()
	a, err := s.current(ctx, s.store.Admins(), ses)
	if err != nil {
		return nil, err
	}
	seed, _, err := s.openRebindToken(token, a, ses.ID)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	step, ok := totp.Verify(seed, input, now)
	if !ok {
		return nil, ErrBadFactor
	}
	sealed, err := s.keys.SealTOTP(seed, a.ID)
	if err != nil {
		return nil, fmt.Errorf("admin: seal the seed: %w", err)
	}
	shown, hashes, err := s.NewRecoveryCodes(a.ID)
	if err != nil {
		return nil, err
	}
	err = s.changeOwn(ctx, ses, ownChange{
		prepare: func(a store.Admin) store.Admin {
			a.TOTPSecret = sealed
			a.TOTPConfirmedAt = now
			return a
		},
		after: func(ctx context.Context, tx store.Repositories, updated store.Admin) error {
			if acceptErr := tx.Admins().AcceptStep(ctx, s.tenant, updated.ID, updated.Version, step, updated.LastLoginAt); acceptErr != nil {
				switch {
				case errors.Is(acceptErr, store.ErrConflict):
					return ErrBadFactor
				case errors.Is(acceptErr, store.ErrNotFound):
					return ErrNoSession
				case errors.Is(acceptErr, store.ErrStale):
					return acceptErr
				}
				return fmt.Errorf("admin: accept the one-time password: %w", acceptErr)
			}
			if codesErr := tx.Admins().ReplaceRecoveryCodes(ctx, s.tenant, updated.ID, hashes); codesErr != nil {
				return fmt.Errorf("admin: store the recovery codes: %w", codesErr)
			}
			return nil
		},
		entry: func(updated store.Admin, ended int) audit.Entry {
			return audit.Entry{
				Actor: adminActor(updated.ID), Action: audit.AdminTOTPRebound, IP: c.IP,
				Details: map[string]any{"recovery_codes": len(hashes), "sessions_ended": ended},
			}
		},
	})
	if err != nil {
		return nil, err
	}
	return shown, nil
}

// EndSession ends another session of the administrator of the session that
// asks. The session that asks is ended by signing out. It returns
// ErrNoSuchSession for a session that the administrator does not have.
func (s *Service) EndSession(ctx context.Context, ses Session, id string, c Client) error {
	if id == "" || id == ses.ID || len(id) > store.MaxIDLength {
		return ErrNoSuchSession
	}
	c = c.clean()
	return s.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if _, err := s.current(ctx, tx.Admins(), ses); err != nil {
			return err
		}
		if err := tx.AdminSessions().Delete(ctx, s.tenant, ses.AdminID, id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrNoSuchSession
			}
			return fmt.Errorf("admin: end the session: %w", err)
		}
		return s.audit.Add(ctx, tx.Audit(), audit.Entry{
			Actor: adminActor(ses.AdminID), Action: audit.AdminSessionEnded, IP: c.IP, Details: map[string]any{"session": id},
		})
	})
}

// EndOtherSessions ends every session of the administrator but the one that asks
// and returns how many it ended.
func (s *Service) EndOtherSessions(ctx context.Context, ses Session, c Client) (int, error) {
	c = c.clean()
	var ended int
	err := s.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if _, err := s.current(ctx, tx.Admins(), ses); err != nil {
			return err
		}
		var endErr error
		if ended, endErr = tx.AdminSessions().DeleteForAdmin(ctx, s.tenant, ses.AdminID, ses.ID); endErr != nil {
			return fmt.Errorf("admin: end the other sessions: %w", endErr)
		}
		if ended == 0 {
			return nil
		}
		return s.audit.Add(ctx, tx.Audit(), audit.Entry{
			Actor: adminActor(ses.AdminID), Action: audit.AdminSessionsEnded, IP: c.IP, Details: map[string]any{"sessions_ended": ended},
		})
	})
	if err != nil {
		return 0, err
	}
	return ended, nil
}
