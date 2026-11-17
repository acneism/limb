package store

import (
	"context"
	"time"
)

// Setting is a value that an administrator changes while the service runs. The
// pair of TenantID and Name identifies it.
type Setting struct {
	// TenantID is the tenant the setting belongs to.
	TenantID string
	// Name identifies the setting.
	Name string
	// Value is what the setting is set to. It is never empty.
	Value string
	// UpdatedAt is when the setting was last written.
	UpdatedAt time.Time
	// UpdatedBy is the ID of the administrator who wrote it, empty if the code of
	// the application did.
	UpdatedBy string
}

// Settings stores the settings that administrators change at run time.
type Settings interface {
	// Get returns the setting or ErrNotFound.
	Get(ctx context.Context, tenantID, name string) (Setting, error)

	// List returns the settings of the tenant ordered by name, comparing the
	// bytes of the names whatever the collation of the database is.
	List(ctx context.Context, tenantID string) ([]Setting, error)

	// Set stores the setting, replacing the value that it has. When several calls
	// set one setting at once, one of them is the last and its value stays.
	Set(ctx context.Context, s Setting) error

	// Delete removes the setting, so that its default applies again, or returns
	// ErrNotFound.
	Delete(ctx context.Context, tenantID, name string) error
}
