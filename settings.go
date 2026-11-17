package limb

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

const (
	settingPasswordToEndSessions = "password_to_end_sessions"

	settingsTTL   = 15 * time.Second
	settingsRetry = 5 * time.Second
)

var knownSettings = map[string]func(value string) bool{
	settingPasswordToEndSessions: isBoolean,
}

func isBoolean(value string) bool {
	return value == "true" || value == "false"
}

type settingsCache struct {
	mu     sync.Mutex
	loaded time.Time
	values map[string]string
}

func (c *settingsCache) forget() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.values = nil
}

func (a *Auth) setting(ctx context.Context, name string) (string, bool, error) {
	c := &a.settings
	c.mu.Lock()
	defer c.mu.Unlock()
	now := a.now()
	if c.values == nil || now.Sub(c.loaded) >= settingsTTL || now.Before(c.loaded) {
		list, err := a.store.Settings().List(ctx, a.tenant)
		switch {
		case err != nil && c.values == nil:
			return "", false, fmt.Errorf("limb: read the settings: %w", err)
		case err != nil:
			a.logger.ErrorContext(ctx, "limb: the settings cannot be read, the cached ones are used", "error", err)
			c.loaded = now.Add(settingsRetry - settingsTTL)
		default:
			values := make(map[string]string, len(list))
			for _, s := range list {
				values[s.Name] = s.Value
			}
			c.values, c.loaded = values, now
		}
	}
	value, found := c.values[name]
	return value, found, nil
}

func (a *Auth) setSetting(ctx context.Context, by actorRef, name, value string) error {
	valid, known := knownSettings[name]
	switch {
	case !known:
		return &ValidationError{Field: "setting", Reason: "unknown setting"}
	case !valid(value):
		return &ValidationError{Field: name, Reason: "invalid value"}
	}
	now := a.now().UTC().Truncate(time.Microsecond)
	err := a.store.InTx(ctx, func(ctx context.Context, tx store.Repositories) error {
		old, err := tx.Settings().Get(ctx, a.tenant, name)
		switch {
		case errors.Is(err, store.ErrNotFound):
			old = store.Setting{}
		case err != nil:
			return fmt.Errorf("limb: read the setting %s: %w", name, err)
		}
		if old.Value == value {
			return nil
		}
		err = tx.Settings().Set(ctx, store.Setting{TenantID: a.tenant, Name: name, Value: value, UpdatedAt: now, UpdatedBy: by.adminID()})
		if err != nil {
			return fmt.Errorf("limb: write the setting %s: %w", name, err)
		}
		details := map[string]any{"name": name, "new": value}
		if old.Value != "" {
			details["old"] = old.Value
		}
		return a.auditWriter().Add(ctx, tx.Audit(), audit.Entry{Actor: by.actor, Action: audit.SettingChanged, IP: by.ip, Details: details})
	})
	a.settings.forget()
	return err
}

// PasswordToEndSessions tells whether ending the sessions of a user needs the
// password of the user. It is the value that an administrator set with
// SetPasswordToEndSessions, or when none was set the one that the code of the
// application gave with WithPasswordToEndSessions, which is off by default. A
// change that another instance of the service made takes at most 15 seconds to
// reach this one.
func (x *AdminAPI) PasswordToEndSessions(ctx context.Context) (bool, error) {
	return x.a.passwordToEndSessions(ctx)
}

// SetPasswordToEndSessions makes the service ask for the password of a user, or
// stop asking, when the user ends their sessions, see WithPasswordToEndSessions,
// which gives the value that holds until this is called. The change is written
// to the audit log, and it takes effect at once on this instance and within 15
// seconds on the others.
func (x *AdminAPI) SetPasswordToEndSessions(ctx context.Context, required bool) error {
	return x.a.setSetting(ctx, apiActor, settingPasswordToEndSessions, strconv.FormatBool(required))
}
