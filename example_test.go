package limb_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

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

func openAuth(opts ...limb.Option) *limb.Auth {
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	masterKey, err := base64.StdEncoding.DecodeString(os.Getenv("LIMB_MASTER_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	opts = append([]limb.Option{limb.WithIdentifiers(identifier.Email(identifier.Required())), limb.WithAutoMigrate()}, opts...)
	auth, err := limb.New(db, limb.Postgres, masterKey, opts...)
	if err != nil {
		log.Fatal(err)
	}
	return auth
}

func ExampleAuth_Handler() {
	auth := openAuth(limb.WithMountPath("/auth"), limb.WithRefreshCookie())
	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", auth.Handler()))
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(server.ListenAndServe())
}

func ExampleAuth_RequireAuth() {
	auth := openAuth()
	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", auth.Handler()))
	mux.Handle("/api/me", auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := limb.CurrentUser(r.Context())
		_, _ = fmt.Fprintf(w, "user %s, session %s\n", principal.UserID, principal.SessionID)
	})))
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(server.ListenAndServe())
}

func ExampleAuth_OptionalAuth() {
	auth := openAuth()
	home := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if principal, signedIn := limb.CurrentUser(r.Context()); signedIn {
			_, _ = fmt.Fprintf(w, "welcome back, %s\n", principal.UserID)
			return
		}
		_, _ = fmt.Fprintln(w, "welcome, stranger")
	})
	server := &http.Server{Addr: ":8080", Handler: auth.OptionalAuth(home), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(server.ListenAndServe())
}
