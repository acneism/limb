package limb_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/acneism/limb"
	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/internal/memstore"
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

type courier struct{}

func (courier) Send(ctx context.Context, m limb.Message) error {
	if m.Channel != "email" {
		return deliverText(ctx, m.To, m.Text)
	}
	return deliverMail(ctx, m.To, m.Subject, m.Text, m.HTML)
}

func deliverMail(_ context.Context, to, subject, text, html string) error {
	log.Printf("mail to %s: %s (%d bytes of text, %d of HTML)", to, subject, len(text), len(html))
	return nil
}

func deliverText(_ context.Context, to, text string) error {
	log.Printf("text to %s: %d bytes", to, len(text))
	return nil
}

func ExampleWithSender() {
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
		limb.WithSender(courier{}),
		limb.WithServiceName("Acme"),
		limb.WithVerifyURL("https://app.example.com/confirm"),
		limb.WithResetURL("https://app.example.com/reset"),
		limb.WithAutoMigrate(),
	)
	if err != nil {
		log.Fatal(err)
	}

	err = auth.RequestPasswordReset(context.Background(), limb.ResetRequest{Login: "alice@example.com", Language: "en"})
	var limited *limb.RateLimitError
	switch {
	case errors.As(err, &limited):
		log.Printf("try again in %s", limited.RetryAfter)
	case errors.Is(err, limb.ErrBusy):
		log.Print("the queue of messages is full")
	case err != nil:
		log.Print(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = auth.Shutdown(ctx); err != nil {
		log.Print(err)
	}
}

func ExampleAuth_Signup() {
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
		limb.WithSender(courier{}),
		limb.WithSignup(),
		limb.WithHooks(limb.Hooks{BeforeRegister: func(_ context.Context, r limb.Registration) error {
			if r.Extra["invite"] != "welcome-2026" {
				return &limb.ValidationError{Field: "extra.invite", Reason: "the invitation is not valid"}
			}
			return nil
		}}),
		limb.WithAutoMigrate(),
	)
	if err != nil {
		log.Fatal(err)
	}

	err = auth.Signup(context.Background(), limb.SignupRequest{
		Registration: limb.Registration{
			Identifiers: map[string]string{"email": "alice@example.com", "username": "alice"},
			Password:    "correct horse battery staple",
			Extra:       map[string]string{"invite": "welcome-2026"},
		},
		Language: "en",
	})

	var invalid *limb.ValidationError
	var weak *limb.PolicyError
	var limited *limb.RateLimitError
	switch {
	case errors.As(err, &invalid):
		log.Printf("check %s: %s", invalid.Field, invalid.Reason)
	case errors.As(err, &weak):
		log.Printf("choose another password: %v", weak.Rules)
	case errors.As(err, &limited):
		log.Printf("try again in %s", limited.RetryAfter)
	case errors.Is(err, limb.ErrRegistrationRefused):
		log.Print("the registration was refused")
	case err != nil:
		log.Fatal(err)
	default:
		log.Print("check your mail: the message holds a link and a code that confirm the address")
	}
}

func ExampleHooks() {
	hooks := limb.Hooks{
		BeforeRegister: func(_ context.Context, r limb.Registration) error {
			if !strings.HasSuffix(r.Identifiers["email"], "@example.com") {
				return &limb.ValidationError{Field: "email", Reason: "only addresses of example.com can register"}
			}
			return nil
		},
		OnEvent: func(_ context.Context, e limb.Event) {
			log.Printf("%s user=%s channel=%s address=%s", e.Type, e.UserID, e.Channel, e.Address)
		},
	}
	_ = limb.WithHooks(hooks)
}

func newExampleService(opts ...limb.Option) *limb.Auth {
	masterKey := []byte(strings.Repeat("example master ", 3))
	auth, err := limb.NewWithStore(memstore.New(), masterKey, append([]limb.Option{limb.WithAutoMigrate()}, opts...)...)
	if err != nil {
		log.Fatal(err)
	}
	return auth
}

type inbox chan limb.Message

func (i inbox) Send(_ context.Context, m limb.Message) error {
	i <- m
	return nil
}

func ExampleAuth_Admin() {
	auth := newExampleService()
	created, err := auth.Admin().CreateAdmin(context.Background(), "Root", "a password that is long enough")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(created.Login, created.TOTPBound)
	_, err = auth.Admin().CreateAdmin(context.Background(), "root", "a password that is long enough")
	fmt.Println(errors.Is(err, limb.ErrAdminLoginTaken))
	// Output:
	// root false
	// true
}

func ExampleAuth_AdminHandler() {
	auth := newExampleService(limb.WithAdminMountPath("/admin"), limb.WithDevelopmentMode())
	mux := http.NewServeMux()
	mux.Handle("/admin/", http.StripPrefix("/admin", auth.AdminHandler()))

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin/login", nil))
	fmt.Println(recorder.Code, recorder.Header().Get("Content-Type"))
	fmt.Println(recorder.Header().Get("X-Frame-Options"))
	fmt.Println(strings.Contains(recorder.Body.String(), `action="/admin/login"`))

	recorder = httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin/", nil))
	fmt.Println(recorder.Code, recorder.Header().Get("Location"))
	// Output:
	// 200 text/html; charset=utf-8
	// DENY
	// true
	// 303 /admin/login
}

func ExampleWithAdminTexts() {
	auth := newExampleService(limb.WithAdminMountPath("/admin"),
		limb.WithAdminTexts("ru", map[string]string{"login.title": "Вход для сотрудников"}),
		limb.WithAdminTexts("de", map[string]string{"login.title": "Anmelden"}))
	handler := auth.AdminHandler()
	for _, language := range []string{"ru", "de", "fr"} {
		request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/login", nil)
		request.Header.Set("Accept-Language", language)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		body := recorder.Body.String()
		fmt.Println(language, strings.Contains(body, "Вход для сотрудников"), strings.Contains(body, "Anmelden"), strings.Contains(body, "Sign in"))
	}
	// Output:
	// ru true false false
	// de false true false
	// fr false false true
}

func ExampleAuth_RunCommandInput() {
	auth := newExampleService()
	password := strings.NewReader("a password that is long enough\n")
	code := auth.RunCommandInput(context.Background(), password,
		[]string{"admin", "create", "--login", "root", "--password-stdin"}, os.Stdout, os.Stderr)
	fmt.Println("exit code", code)
	code = auth.RunCommandInput(context.Background(), nil, []string{"admin", "disable", "root"}, os.Stdout, os.Stderr)
	fmt.Println("exit code", code)
	// Output:
	// the administrator root is created: the authenticator is bound at the first sign-in to the administration
	// exit code 0
	// the administrator root cannot sign in and has no sessions
	// exit code 0
}

func ExampleAdminAPI_BlockUser() {
	ctx := context.Background()
	auth := newExampleService(limb.WithIdentifiers(identifier.Username()))
	alice, err := auth.Register(ctx, limb.Registration{
		Identifiers: map[string]string{"username": "alice"},
		Password:    "correct horse battery staple",
	})
	if err != nil {
		log.Fatal(err)
	}
	signIn := limb.Credentials{Login: "alice", Password: "correct horse battery staple", IP: netip.MustParseAddr("203.0.113.7"), Kind: limb.SessionCookie}

	err = auth.Admin().BlockUser(ctx, alice.ID, "spam in the comments", time.Time{})
	fmt.Println("blocked:", err == nil)
	_, err = auth.Login(ctx, signIn)
	fmt.Println("sign-in refused:", errors.Is(err, limb.ErrUserBlocked))

	err = auth.Admin().UnblockUser(ctx, alice.ID)
	fmt.Println("unblocked:", err == nil)
	_, err = auth.Login(ctx, signIn)
	fmt.Println("sign-in works:", err == nil)

	page, err := auth.Admin().ListAudit(ctx, limb.AuditFilter{UserID: alice.ID, Actions: []string{"user.blocked", "user.unblocked"}})
	if err != nil {
		log.Fatal(err)
	}
	for _, entry := range page.Entries {
		fmt.Println(entry.ActorKind, entry.ActorID, entry.Action)
	}
	// Output:
	// blocked: true
	// sign-in refused: true
	// unblocked: true
	// sign-in works: true
	// system api user.unblocked
	// system api user.blocked
}

func ExampleAdminAPI_ListUsers() {
	ctx := context.Background()
	auth := newExampleService(limb.WithIdentifiers(identifier.Email(identifier.Required()), identifier.Username()))
	for _, name := range []string{"alice", "alina", "boris"} {
		_, err := auth.Register(ctx, limb.Registration{
			Identifiers: map[string]string{"email": name + "@example.com", "username": name},
			Password:    "correct horse battery staple",
		})
		if err != nil {
			log.Fatal(err)
		}
	}

	filter := limb.UserFilter{Search: "ali", Limit: 1}
	for {
		page, err := auth.Admin().ListUsers(ctx, filter)
		if err != nil {
			log.Fatal(err)
		}
		for _, user := range page.Users {
			fmt.Println(user.Status, user.CreatedVia, user.Identifiers[0].Value)
		}
		if page.Next == "" {
			break
		}
		filter.Cursor = page.Next
	}
	// Output:
	// active api alice@example.com
	// active api alina@example.com
}

func ExampleAdminAPI_InviteUser() {
	ctx := context.Background()
	mailbox := make(inbox, 1)
	auth := newExampleService(
		limb.WithIdentifiers(identifier.Email(identifier.Required())),
		limb.WithSender(mailbox),
		limb.WithResetURL("https://app.example.com/reset"),
	)
	invited, err := auth.Admin().InviteUser(ctx, limb.Invitation{Identifiers: map[string]string{"email": "ivan@example.com"}, Language: "en"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(invited.Status, invited.CreatedVia)

	message := <-mailbox
	fmt.Println(message.Kind, message.To)
	_, token, _ := strings.Cut(message.Link, "#token=")
	err = auth.ResetPassword(ctx, limb.ResetPasswordRequest{Token: token, Password: "correct horse battery staple"})
	fmt.Println("password chosen:", err == nil)
	err = auth.ResetPassword(ctx, limb.ResetPasswordRequest{Token: token, Password: "another horse battery staple"})
	fmt.Println("the link works once:", errors.Is(err, limb.ErrInvalidSecret))
	// Output:
	// active invite
	// invitation ivan@example.com
	// password chosen: true
	// the link works once: true
}

func ExampleMigrate() {
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	if err = limb.Migrate(context.Background(), db, limb.Postgres, limb.WithTablePrefix("app_")); err != nil {
		log.Fatal(err)
	}
}

func ExampleRunCommand() {
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	masterKey, err := base64.StdEncoding.DecodeString(os.Getenv("LIMB_MASTER_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(limb.RunCommand(context.Background(), db, limb.Postgres, masterKey, os.Args[1:], os.Stdout, os.Stderr))
}

func ExampleAuth_RunMaintenance() {
	auth := openAuth()
	ctx, stop := context.WithCancel(context.Background())
	go func() {
		if err := auth.RunMaintenance(ctx, time.Hour); err != nil {
			log.Print(err)
		}
	}()
	server := &http.Server{Addr: ":8080", Handler: auth.Handler(), ReadHeaderTimeout: 10 * time.Second}
	err := server.ListenAndServe()
	stop()
	log.Fatal(err)
}
