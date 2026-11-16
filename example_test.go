package limb_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"log"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/acneism/limb"
	"github.com/acneism/limb/identifier"
)

func ExampleNew() {
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	masterKey, err := base64.StdEncoding.DecodeString(os.Getenv("LIMB_MASTER_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	auth, err := limb.New(db, limb.Postgres, masterKey,
		limb.WithIdentifiers(identifier.Email(identifier.Required()), identifier.Username()),
		limb.WithAutoMigrate(),
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = auth
}

func ExampleAuth_Register() {
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	masterKey, err := base64.StdEncoding.DecodeString(os.Getenv("LIMB_MASTER_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	auth, err := limb.New(db, limb.Postgres, masterKey,
		limb.WithIdentifiers(identifier.Email(identifier.Required()), identifier.Username()),
		limb.WithAutoMigrate(),
	)
	if err != nil {
		log.Fatal(err)
	}

	user, err := auth.Register(context.Background(), limb.Registration{
		Identifiers: map[string]string{"email": "alice@example.com", "username": "alice"},
		Password:    "correct horse battery staple",
	})

	var invalid *limb.ValidationError
	var weak *limb.PolicyError
	switch {
	case errors.As(err, &invalid):
		log.Printf("check %s: %s", invalid.Field, invalid.Reason)
	case errors.As(err, &weak):
		log.Printf("choose another password: %v", weak.Rules)
	case errors.Is(err, limb.ErrIdentifierTaken):
		log.Print("this e-mail address or nickname is already registered")
	case err != nil:
		log.Fatal(err)
	default:
		log.Printf("registered user %s", user.ID)
	}
}

func ExampleWithPasswordPolicy() {
	policy := limb.PasswordPolicy{
		MinLength: 14,
		Checks: []func(ctx context.Context, password string) error{
			func(ctx context.Context, password string) error {
				if leaked(ctx, password) {
					return errors.New("breached")
				}
				return nil
			},
		},
	}
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	masterKey, err := base64.StdEncoding.DecodeString(os.Getenv("LIMB_MASTER_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	if _, err = limb.New(db, limb.Postgres, masterKey, limb.WithPasswordPolicy(policy)); err != nil {
		log.Fatal(err)
	}
}

func leaked(context.Context, string) bool {
	return false
}
