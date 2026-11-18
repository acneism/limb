package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/store"
)

const (
	// PendingLifetime is how long an administrator has to give the second factor
	// after the password.
	PendingLifetime = 5 * time.Minute

	// MaxGuesses is how many wrong second factors one sign-in takes, after which
	// it has to begin again with the password.
	MaxGuesses = 3

	touchInterval = time.Minute
)

var (
	// ErrBadCredentials is returned for a login and a password that do not open an
	// account: the login does not exist, the password is wrong or the account is
	// disabled. It is the same after the same work in every case.
	ErrBadCredentials = errors.New("admin: the login or the password is wrong")

	// ErrNoSignIn is returned when a sign-in that waits for its second factor is
	// not there any more: it expired, was used, used up its guesses or belongs to
	// an account that changed.
	ErrNoSignIn = errors.New("admin: there is no sign-in in progress")

	// ErrNoSession is returned when the secret of a session does not belong to a
	// session that works: it never did, or it expired, was idle for too long or
	// was ended, or the account changed or was disabled.
	ErrNoSession = errors.New("admin: there is no session")
)

// CredentialsError is the ErrBadCredentials that says what was wrong, for the
// audit log and never for the person who signs in.
type CredentialsError struct {
	// Reason is "invalid_login", "unknown_login", "wrong_password",
	// "unusable_hash" or "disabled".
	Reason string
	// AdminID is the administrator the login belongs to, empty if there is none.
	AdminID string
}

// Error implements the error interface.
func (e *CredentialsError) Error() string {
	return ErrBadCredentials.Error() + ": " + e.Reason
}

// Is makes the error equal to ErrBadCredentials.
func (e *CredentialsError) Is(target error) bool {
	return target == ErrBadCredentials
}

// Client says where a request comes from.
type Client struct {
	// IP is the address of the client, empty if it is not known.
	IP string
	// UserAgent is the user agent of the client, empty if it is not known.
	UserAgent string
}

func (c Client) clean() Client {
	return Client{IP: c.IP, UserAgent: cleanAgent(c.UserAgent)}
}

func cleanAgent(agent string) string {
	var out strings.Builder
	for _, r := range agent {
		if r == utf8.RuneError || unicode.IsControl(r) {
			continue
		}
		if out.Len()+utf8.RuneLen(r) > store.MaxUserAgentLength {
			break
		}
		out.WriteRune(r)
	}
	return out.String()
}

// Session is a session of an administrator that gives access to the
// administration.
type Session struct {
	// ID identifies the session.
	ID string
	// AdminID is the administrator it belongs to.
	AdminID string
	// Login is the login of the administrator.
	Login string
	// Version is the version of the account that the session is valid for.
	Version int64
	// IP and UserAgent are what the sign-in came with.
	IP, UserAgent string
	// CreatedAt is when the administrator signed in.
	CreatedAt time.Time
	// LastSeenAt is when the session was last used, roughly.
	LastSeenAt time.Time
	// ExpiresAt is when the session ends whatever its activity is.
	ExpiresAt time.Time
}

func sessionOf(s store.AdminSession, login string) Session {
	return Session{
		ID: s.ID, AdminID: s.AdminID, Login: login, Version: s.AdminVersion, IP: s.IP, UserAgent: s.UserAgent,
		CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt, ExpiresAt: s.ExpiresAt,
	}
}

// Opened is a session that was just opened, with the secret of its cookie, which
// nothing keeps but a hash.
type Opened struct {
	Session
	// Secret is the value of the cookie of the session.
	Secret string
	// Method says how the administrator proved it was them.
	Method string
	// RecoveryCodes is how many recovery codes they have left.
	RecoveryCodes int
}

// Pending is a sign-in that has passed the password and waits for the second
// factor.
type Pending struct {
	// ID identifies the sign-in.
	ID string
	// Secret is the value of the cookie of the sign-in.
	Secret string
	// ExpiresAt is when the sign-in ends.
	ExpiresAt time.Time
}

// SignIn is a sign-in that waits for the second factor, as it is when the
// secret of its cookie comes back.
type SignIn struct {
	// Session is the record of the sign-in.
	Session store.AdminSession
	// Admin is the account that signs in.
	Admin store.Admin
}

// NeedsEnrollment tells that the administrator has no authenticator yet, so that
// the second step is to bind one.
func (s SignIn) NeedsEnrollment() bool {
	return s.Admin.TOTPConfirmedAt.IsZero()
}

// WithoutSecondFactor tells that the service lets administrators in with the
// password alone.
func (s *Service) WithoutSecondFactor() bool {
	return s.noTOTP
}

// CheckPassword finds the administrator with the login and checks the password.
// A login that does not exist, one that cannot be a login, a password that is
// wrong and an account that is disabled all give a *CredentialsError, which is
// ErrBadCredentials, after the same work: a password is hashed in every case. A
// hash made with weaker parameters than the current ones is made again.
func (s *Service) CheckPassword(ctx context.Context, login, password string) (store.Admin, error) {
	normalized, err := NormalizeLogin(login)
	if err != nil {
		return store.Admin{}, s.refuse(ctx, password, &CredentialsError{Reason: "invalid_login"})
	}
	a, err := s.store.Admins().FindByLogin(ctx, s.tenant, normalized)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.Admin{}, s.refuse(ctx, password, &CredentialsError{Reason: "unknown_login"})
	case err != nil:
		return store.Admin{}, fmt.Errorf("admin: find the administrator: %w", err)
	}
	matched, needsRehash, err := s.hasher.Verify(ctx, password, a.PasswordHash)
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return store.Admin{}, fmt.Errorf("admin: verify the password: %w", err)
	case err != nil:
		return store.Admin{}, s.refuse(ctx, password, &CredentialsError{Reason: "unusable_hash", AdminID: a.ID})
	case !matched:
		return store.Admin{}, &CredentialsError{Reason: "wrong_password", AdminID: a.ID}
	case a.Status != store.AdminActive:
		return store.Admin{}, &CredentialsError{Reason: "disabled", AdminID: a.ID}
	}
	if needsRehash {
		a = s.rehash(ctx, a, password)
	}
	return a, nil
}

func (s *Service) refuse(ctx context.Context, password string, reason *CredentialsError) error {
	if err := s.hasher.DummyVerify(ctx, password); err != nil {
		return fmt.Errorf("admin: verify the password: %w", err)
	}
	return reason
}

func (s *Service) rehash(ctx context.Context, a store.Admin, password string) store.Admin {
	hash, err := s.hasher.Hash(ctx, password)
	if err != nil {
		return a
	}
	next := a
	next.PasswordHash = hash
	updated, err := s.store.Admins().Update(ctx, next)
	if err == nil {
		return updated
	}
	if errors.Is(err, store.ErrStale) {
		if current, getErr := s.store.Admins().Get(ctx, s.tenant, a.ID); getErr == nil {
			return current
		}
	}
	return a
}

// Open opens a session of the administrator without a second step, for the
// service that lets administrators in with the password alone, see
// WithoutSecondFactor.
func (s *Service) Open(ctx context.Context, a store.Admin, c Client) (Opened, error) {
	if !s.noTOTP {
		return Opened{}, errors.New("admin: a session without the second factor is not allowed")
	}
	c = c.clean()
	var opened Opened
	err := s.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		var openErr error
		opened, openErr = s.openSession(ctx, tx, a, c, "password")
		if openErr != nil {
			return openErr
		}
		if recordErr := tx.Admins().RecordLogin(ctx, s.tenant, a.ID, a.Version, opened.CreatedAt); recordErr != nil {
			return mapSignInError(recordErr)
		}
		return s.addLoginRecord(ctx, tx, opened, c)
	})
	if err != nil {
		return Opened{}, err
	}
	return opened, nil
}

// Begin starts a sign-in that has passed the password and waits for the second
// factor, which has to come within PendingLifetime.
func (s *Service) Begin(ctx context.Context, a store.Admin, c Client) (Pending, error) {
	c = c.clean()
	now := s.now().UTC().Truncate(time.Microsecond)
	id, err := s.newID()
	if err != nil {
		return Pending{}, fmt.Errorf("admin: make the ID of a sign-in: %w", err)
	}
	text, hash, err := newSecret()
	if err != nil {
		return Pending{}, err
	}
	row := store.AdminSession{
		TenantID: s.tenant, ID: id, AdminID: a.ID, Stage: store.AdminStagePassword, SecretHash: hash, AdminVersion: a.Version,
		IP: c.IP, UserAgent: c.UserAgent, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(PendingLifetime),
	}
	if err = s.store.AdminSessions().Create(ctx, row); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Pending{}, ErrNoSignIn
		}
		return Pending{}, fmt.Errorf("admin: begin the sign-in: %w", err)
	}
	return Pending{ID: id, Secret: text, ExpiresAt: row.ExpiresAt}, nil
}

func newSecret() (string, []byte, error) {
	text, err := secret.New()
	if err != nil {
		return "", nil, fmt.Errorf("admin: %w", err)
	}
	hash, err := secret.Hash(text)
	if err != nil {
		return "", nil, fmt.Errorf("admin: %w", err)
	}
	return text, hash, nil
}

func (s *Service) resolve(ctx context.Context, text string) (store.ResolvedAdminSession, bool, error) {
	hash, err := secret.Hash(text)
	if errors.Is(err, secret.ErrMalformed) {
		return store.ResolvedAdminSession{}, false, nil
	}
	if err != nil {
		return store.ResolvedAdminSession{}, false, fmt.Errorf("admin: hash the secret: %w", err)
	}
	resolved, err := s.store.AdminSessions().ResolveBySecret(ctx, s.tenant, hash)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.ResolvedAdminSession{}, false, nil
	case err != nil:
		return store.ResolvedAdminSession{}, false, fmt.Errorf("admin: find the session: %w", err)
	}
	return resolved, true, nil
}

func (s *Service) discard(ctx context.Context, row store.AdminSession) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = s.store.AdminSessions().Delete(ctx, s.tenant, row.AdminID, row.ID)
}

func (s *Service) usable(resolved store.ResolvedAdminSession) bool {
	return resolved.Admin.Status == store.AdminActive && resolved.Session.AdminVersion == resolved.Admin.Version
}

// Pending returns the sign-in that the secret of its cookie belongs to. It
// returns ErrNoSignIn for a secret that belongs to none, to one that is complete,
// to one that has expired and to one of an account that changed or is disabled
// since the password was checked.
func (s *Service) Pending(ctx context.Context, text string) (SignIn, error) {
	resolved, found, err := s.resolve(ctx, text)
	if err != nil {
		return SignIn{}, err
	}
	if !found || resolved.Session.Stage != store.AdminStagePassword {
		return SignIn{}, ErrNoSignIn
	}
	if !resolved.Session.ExpiresAt.After(s.now()) || !s.usable(resolved) {
		s.discard(ctx, resolved.Session)
		return SignIn{}, ErrNoSignIn
	}
	a, err := s.store.Admins().Get(ctx, s.tenant, resolved.Session.AdminID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return SignIn{}, ErrNoSignIn
	case err != nil:
		return SignIn{}, fmt.Errorf("admin: get the administrator: %w", err)
	case a.Version != resolved.Session.AdminVersion:
		s.discard(ctx, resolved.Session)
		return SignIn{}, ErrNoSignIn
	}
	return SignIn{Session: resolved.Session, Admin: a}, nil
}

// Abandon ends a sign-in that waits for the second factor, for example when the
// administrator leaves the page.
func (s *Service) Abandon(ctx context.Context, in SignIn) {
	s.discard(ctx, in.Session)
}

func mapSignInError(err error) error {
	switch {
	case errors.Is(err, store.ErrStale), errors.Is(err, store.ErrNotFound):
		return ErrNoSignIn
	}
	return err
}

func (s *Service) guess(ctx context.Context, in SignIn) error {
	counted, err := s.store.AdminSessions().TryAttempt(ctx, s.tenant, in.Session.ID, MaxGuesses)
	if err != nil {
		return fmt.Errorf("admin: count the guess: %w", err)
	}
	if !counted {
		s.discard(ctx, in.Session)
		return ErrNoSignIn
	}
	return nil
}

// Complete takes what the administrator typed as the second factor, a one-time
// password or a recovery code, and opens the session if it is right. It counts a
// guess first, so that of any number of requests at once only MaxGuesses are
// judged, and it returns ErrNoSignIn when they are used up, and ErrBadFactor for a
// factor that is wrong, one that was used before and one that is not a factor
// at all. The sign-in ends when it succeeds, so it works once, and the session has
// a secret of its own.
func (s *Service) Complete(ctx context.Context, in SignIn, input string, c Client) (Opened, error) {
	if in.NeedsEnrollment() {
		return Opened{}, ErrNoSignIn
	}
	c = c.clean()
	if err := s.guess(ctx, in); err != nil {
		return Opened{}, err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	factor, err := s.ReadFactor(in.Admin, input, now)
	if err != nil {
		return Opened{}, err
	}
	var opened Opened
	err = s.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		method := "password+" + string(factor.Kind)
		switch factor.Kind {
		case FactorTOTP:
			if acceptErr := tx.Admins().AcceptStep(ctx, s.tenant, in.Admin.ID, in.Admin.Version, factor.Step, now); acceptErr != nil {
				if errors.Is(acceptErr, store.ErrConflict) {
					return ErrBadFactor
				}
				return mapSignInError(acceptErr)
			}
		case FactorRecovery:
			if useErr := tx.Admins().UseRecoveryCode(ctx, s.tenant, in.Admin.ID, factor.Hash, now); useErr != nil {
				if errors.Is(useErr, store.ErrNotFound) {
					return ErrBadFactor
				}
				return fmt.Errorf("admin: use the recovery code: %w", useErr)
			}
			if recordErr := tx.Admins().RecordLogin(ctx, s.tenant, in.Admin.ID, in.Admin.Version, now); recordErr != nil {
				return mapSignInError(recordErr)
			}
		}
		if endErr := tx.AdminSessions().Delete(ctx, s.tenant, in.Admin.ID, in.Session.ID); endErr != nil {
			return mapSignInError(endErr)
		}
		var openErr error
		if opened, openErr = s.openSession(ctx, tx, in.Admin, c, method); openErr != nil {
			return openErr
		}
		if factor.Kind == FactorRecovery {
			left, countErr := tx.Admins().CountRecoveryCodes(ctx, s.tenant, in.Admin.ID)
			if countErr != nil {
				return fmt.Errorf("admin: count the recovery codes: %w", countErr)
			}
			opened.RecoveryCodes = left
			if addErr := s.audit.Add(ctx, tx.Audit(), audit.Entry{
				Actor: adminActor(in.Admin.ID), Action: audit.AdminRecoveryCodeUsed, IP: c.IP, Details: map[string]any{"left": left},
			}); addErr != nil {
				return addErr
			}
		}
		return s.addLoginRecord(ctx, tx, opened, c)
	})
	if err != nil {
		return Opened{}, err
	}
	return opened, nil
}

func adminActor(id string) audit.Actor {
	return audit.Actor{Kind: store.ActorAdmin, ID: id}
}

func (s *Service) openSession(ctx context.Context, tx store.Repositories, a store.Admin, c Client, method string) (Opened, error) {
	now := s.now().UTC().Truncate(time.Microsecond)
	id, err := s.newID()
	if err != nil {
		return Opened{}, fmt.Errorf("admin: make the ID of a session: %w", err)
	}
	text, hash, err := newSecret()
	if err != nil {
		return Opened{}, err
	}
	row := store.AdminSession{
		TenantID: s.tenant, ID: id, AdminID: a.ID, Stage: store.AdminStageFull, SecretHash: hash, AdminVersion: a.Version,
		IP: c.IP, UserAgent: c.UserAgent, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(s.absolute),
	}
	if err = tx.AdminSessions().Create(ctx, row); err != nil {
		return Opened{}, mapSignInError(err)
	}
	return Opened{Session: sessionOf(row, a.Login), Secret: text, Method: method}, nil
}

func (s *Service) addLoginRecord(ctx context.Context, tx store.Repositories, opened Opened, c Client) error {
	return s.audit.Add(ctx, tx.Audit(), audit.Entry{
		Actor: adminActor(opened.AdminID), Action: audit.AdminLogin, IP: c.IP,
		Details: map[string]any{"method": opened.Method, "session": opened.ID},
	})
}

// RecordFailure writes a failed attempt to sign in to the audit log. adminID is
// the administrator it was made on, empty when the login is not one; login is
// written for a known administrator and masked for a login that does not exist,
// since a person may type a password into the field of the login.
func (s *Service) RecordFailure(ctx context.Context, c Client, login, adminID, stage, reason string) error {
	c = c.clean()
	shown := maskLogin(login)
	if adminID != "" {
		if normalized, err := NormalizeLogin(login); err == nil {
			shown = normalized
		}
	}
	return s.audit.Add(ctx, s.store.Audit(), audit.Entry{
		Actor: adminActor(adminID), Action: audit.AdminLoginFailed, IP: c.IP,
		Details: map[string]any{"stage": stage, "reason": reason, "login": shown},
	})
}

func maskLogin(login string) string {
	login = strings.TrimSpace(login)
	if login == "" {
		return ""
	}
	first, _ := utf8.DecodeRuneInString(login)
	if first == utf8.RuneError {
		return "***"
	}
	return string(first) + "***"
}

// Resolve returns the session that the secret of its cookie belongs to and counts
// the request as its use. It returns ErrNoSession for a secret that belongs to no
// session that works, and ends a session that is expired, idle or of an account
// that changed or is disabled.
func (s *Service) Resolve(ctx context.Context, text string) (Session, error) {
	resolved, found, err := s.resolve(ctx, text)
	if err != nil {
		return Session{}, err
	}
	if !found || resolved.Session.Stage != store.AdminStageFull {
		return Session{}, ErrNoSession
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	row := resolved.Session
	if !row.ExpiresAt.After(now) || !row.LastSeenAt.Add(s.idle).After(now) || !s.usable(resolved) {
		s.discard(ctx, row)
		return Session{}, ErrNoSession
	}
	if now.Sub(row.LastSeenAt) >= touchInterval {
		if touchErr := s.store.AdminSessions().Touch(ctx, s.tenant, row.ID, now); touchErr != nil {
			return Session{}, fmt.Errorf("admin: touch the session: %w", touchErr)
		}
		row.LastSeenAt = now
	}
	return sessionOf(row, resolved.Admin.Login), nil
}

// End ends the session of an administrator, for example when they sign out.
func (s *Service) End(ctx context.Context, ses Session, c Client) error {
	c = c.clean()
	return s.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		if err := tx.AdminSessions().Delete(ctx, s.tenant, ses.AdminID, ses.ID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			return fmt.Errorf("admin: end the session: %w", err)
		}
		return s.audit.Add(ctx, tx.Audit(), audit.Entry{
			Actor: adminActor(ses.AdminID), Action: audit.AdminLogout, IP: c.IP, Details: map[string]any{"session": ses.ID},
		})
	})
}
