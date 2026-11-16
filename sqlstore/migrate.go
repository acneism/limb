package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	bootstrapFile  = "bootstrap.sql"
	defaultLockTTL = 2 * time.Minute
	lockPoll       = 50 * time.Millisecond
	releaseGrace   = 5 * time.Second
	renewalsPerTTL = 4
	minRenewal     = time.Millisecond
)

var (
	migrationFile = regexp.MustCompile(`^(\d{4})_[a-z0-9_]+\.sql$`)

	errLeaseLost = errors.New("sqlstore: the migration lock was lost")
)

type migration struct {
	version    int
	name       string
	statements []string
}

func loadMigrations(fsys fs.FS, prefix string) ([]string, []migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, nil, fmt.Errorf("sqlstore: read migrations: %w", err)
	}
	var bootstrap []string
	var versions []migration
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		raw, readErr := fs.ReadFile(fsys, name)
		if readErr != nil {
			return nil, nil, fmt.Errorf("sqlstore: read migration %s: %w", name, readErr)
		}
		statements := splitStatements(strings.ReplaceAll(string(raw), "{prefix}", prefix))
		switch {
		case name == bootstrapFile:
			bootstrap = statements
		case migrationFile.MatchString(name):
			number, _ := strconv.Atoi(name[:4])
			versions = append(versions, migration{version: number, name: name, statements: statements})
		default:
			return nil, nil, fmt.Errorf("sqlstore: unexpected migration file %s", name)
		}
	}
	if len(bootstrap) == 0 {
		return nil, nil, fmt.Errorf("sqlstore: %s is missing or empty", bootstrapFile)
	}
	if len(versions) == 0 {
		return nil, nil, errors.New("sqlstore: there are no migrations")
	}
	for n, m := range versions {
		if m.version != n+1 || len(m.statements) == 0 {
			return nil, nil, fmt.Errorf("sqlstore: migration %s breaks the numbering or is empty", m.name)
		}
	}
	return bootstrap, versions, nil
}

func splitStatements(text string) []string {
	var statements []string
	for _, part := range strings.Split(text, ";") {
		if statement := strings.TrimSpace(part); statement != "" {
			statements = append(statements, statement)
		}
	}
	return statements
}

// Migrate creates the schema or brings it up to date. Only one process applies
// the migrations at a time: it takes a lease recorded in the schema table and
// the others wait for it, or take it over when it expires because its holder
// died. While the migrations run the lease is renewed in the background, and
// if that fails the migration is abandoned and an error is returned, so a slow
// migration is never run by two processes at once. The migrations are written
// so that applying one again is harmless.
func (s *Store) Migrate(ctx context.Context) (err error) {
	if err = s.createSchemaTable(ctx); err != nil {
		return err
	}
	holder, err := newHolder()
	if err != nil {
		return err
	}
	if err = s.acquire(ctx, holder); err != nil {
		return err
	}
	work, abandon := context.WithCancelCause(ctx)
	stopRenewing := s.renewLease(work, abandon, holder)
	defer func() {
		stopRenewing()
		abandon(nil)
		err = errors.Join(err, s.release(ctx, holder))
	}()
	err = s.applyPending(work, holder)
	if cause := context.Cause(work); errors.Is(cause, errLeaseLost) {
		return cause
	}
	return err
}

func (s *Store) applyPending(ctx context.Context, holder string) error {
	var current int
	if err := s.db.QueryRowContext(ctx, s.q.schemaVersion).Scan(&current); err != nil {
		return fmt.Errorf("sqlstore: read schema version: %w", err)
	}
	for _, m := range s.versions {
		if m.version <= current {
			continue
		}
		if err := s.apply(ctx, holder, m); err != nil {
			return fmt.Errorf("sqlstore: apply migration %s: %w", m.name, err)
		}
	}
	return nil
}

func (s *Store) renewLease(ctx context.Context, abandon context.CancelCauseFunc, holder string) (stop func()) {
	quit := make(chan struct{})
	finished := make(chan struct{})
	interval := max(s.lockTTL/renewalsPerTTL, minRenewal)
	go func() {
		defer close(finished)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-quit:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.extendLease(ctx, holder); err != nil {
					abandon(fmt.Errorf("%w: %w", errLeaseLost, err))
					return
				}
			}
		}
	}()
	return func() {
		close(quit)
		<-finished
	}
}

func (s *Store) extendLease(ctx context.Context, holder string) error {
	result, err := s.db.ExecContext(ctx, s.q.renewLock, storedTime(s.now().Add(s.lockTTL)), holder)
	if err != nil {
		return err
	}
	renewed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if renewed != 1 {
		return errors.New("the lease is held by another process")
	}
	return nil
}

func (s *Store) createSchemaTable(ctx context.Context) error {
	for _, statement := range s.bootstrap {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			exists, probeErr := s.schemaTableExists(ctx)
			if probeErr != nil || !exists {
				return fmt.Errorf("sqlstore: create the schema table: %w", err)
			}
		}
	}
	_, err := s.db.ExecContext(ctx, s.q.insertSchemaRow, storedTime(s.now()))
	if err != nil && !s.dialect.IsUniqueViolation(err) {
		return fmt.Errorf("sqlstore: record the schema version: %w", err)
	}
	return nil
}

func (s *Store) schemaTableExists(ctx context.Context) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, s.q.probeSchema).Scan(&one)
	switch {
	case err == nil, errors.Is(err, sql.ErrNoRows):
		return true, nil
	case s.dialect.IsMissingTable(err):
		return false, nil
	}
	return false, err
}

func newHolder() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("sqlstore: random source failed: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func (s *Store) acquire(ctx context.Context, holder string) error {
	for {
		now := s.now()
		result, err := s.db.ExecContext(ctx, s.q.acquireLock, holder, storedTime(now.Add(s.lockTTL)), storedTime(now))
		if err != nil {
			return fmt.Errorf("sqlstore: take the migration lock: %w", err)
		}
		taken, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlstore: take the migration lock: %w", err)
		}
		if taken == 1 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("sqlstore: wait for the migration lock: %w", ctx.Err())
		case <-time.After(lockPoll):
		}
	}
}

func (s *Store) apply(ctx context.Context, holder string, m migration) error {
	for _, statement := range m.statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	now := s.now()
	result, err := s.db.ExecContext(ctx, s.q.setVersion, m.version, storedTime(now), storedTime(now.Add(s.lockTTL)), holder)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return errLeaseLost
	}
	return nil
}

func (s *Store) release(ctx context.Context, holder string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseGrace)
	defer cancel()
	if _, err := s.db.ExecContext(ctx, s.q.releaseLock, holder); err != nil {
		return fmt.Errorf("sqlstore: release the migration lock: %w", err)
	}
	return nil
}
