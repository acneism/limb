package sqlstore

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

type beforeExec struct {
	executor
	before func(query string)
}

func (b beforeExec) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	b.before(query)
	return b.executor.ExecContext(ctx, query, args...)
}

func TestTryCodesDoNotCountACodeThatWasUsedMeanwhile(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		ctx := t.Context()
		s := d.newStore(t)
		if err := s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		created := time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC)
		userID := "00000000-0000-7000-8000-000000000001"
		if err := s.Users().Create(ctx, store.User{TenantID: store.DefaultTenant, ID: userID, Status: store.StatusActive, CreatedAt: created}); err != nil {
			t.Fatal(err)
		}
		channel := store.Identifier{TenantID: store.DefaultTenant, Type: "email", Value: "a@example.com", DisplayValue: "a@example.com", UserID: userID}
		if err := s.Identifiers().Add(ctx, channel); err != nil {
			t.Fatal(err)
		}
		code := store.Secret{
			TenantID: store.DefaultTenant, ID: "00000000-0000-7000-8000-000000000002", Kind: store.SecretCode,
			Hash: make([]byte, store.SecretHashLength), UserID: userID, Purpose: store.PurposeReset,
			ChannelType: channel.Type, ChannelValue: channel.Value, CreatedAt: created, ExpiresAt: created.Add(time.Hour),
		}
		if err := s.Secrets().Add(ctx, code); err != nil {
			t.Fatal(err)
		}
		at := created.Add(time.Minute)
		raced := false
		hooked := secrets{s: s, x: beforeExec{executor: s.auto, before: func(query string) {
			if query == s.q.countAttempt && !raced {
				raced = true
				if err := s.Secrets().UseCode(ctx, code.TenantID, code.ID, at); err != nil {
					t.Error(err)
				}
			}
		}}}
		scope := store.SecretScope{TenantID: code.TenantID, UserID: userID, Purpose: store.PurposeReset}
		got, err := hooked.TryCodes(ctx, scope, at, 5)
		if err != nil || len(got) != 0 || !raced {
			t.Fatalf("TryCodes = %+v, %v (raced %v); want no code, because it was used before the attempt was counted", got, err, raced)
		}
	})
}

func TestTheTableOfSecretsRefusesWhatTheStoreDoesNotWrite(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		ctx := t.Context()
		s := d.newStore(t)
		if err := s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		created := time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC)
		userID := "00000000-0000-7000-8000-000000000001"
		if err := s.Users().Create(ctx, store.User{TenantID: store.DefaultTenant, ID: userID, Status: store.StatusActive, CreatedAt: created}); err != nil {
			t.Fatal(err)
		}
		channel := store.Identifier{TenantID: store.DefaultTenant, Type: "email", Value: "a@example.com", DisplayValue: "a@example.com", UserID: userID}
		if err := s.Identifiers().Add(ctx, channel); err != nil {
			t.Fatal(err)
		}
		insert := func(id, kind string, hash byte, user, channelValue string, attempts int) error {
			placeholders := make([]string, 11)
			for i := range placeholders {
				placeholders[i] = d.p(i + 1)
			}
			query := "INSERT INTO " + s.prefix + "secrets (tenant_id, id, kind, secret_hash, user_id, purpose, channel_type, channel_value, " + //nolint:gosec
				"attempts, created_at, expires_at) VALUES (" + strings.Join(placeholders, ", ") + ")"
			raw := make([]byte, store.SecretHashLength)
			raw[0] = hash
			_, err := d.DB.ExecContext(ctx, query, store.DefaultTenant, id, kind, raw, user, "reset", "email", channelValue, attempts,
				storedTime(created), storedTime(created.Add(time.Hour)))
			return err
		}
		if err := insert("one", "link", 1, userID, channel.Value, 0); err != nil {
			t.Fatalf("a row that the store could write was refused: %v", err)
		}
		refused := map[string]error{
			"an unknown kind":     insert("two", "other", 2, userID, channel.Value, 0),
			"negative attempts":   insert("three", "code", 3, userID, channel.Value, -1),
			"a taken hash":        insert("four", "code", 1, userID, channel.Value, 0),
			"a taken ID":          insert("one", "code", 5, userID, channel.Value, 0),
			"an unknown user":     insert("six", "code", 6, "00000000-0000-7000-8000-000000000099", channel.Value, 0),
			"an unknown channel":  insert("seven", "code", 7, userID, "nobody@example.com", 0),
			"a channel with case": insert("eight", "code", 8, userID, "A@example.com", 0),
		}
		for name, err := range refused {
			if err == nil {
				t.Errorf("the table accepted %s", name)
			}
		}
	})
}
