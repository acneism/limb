package limb

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/internal/password"
)

const (
	exitDone    = 0
	exitFailure = 1
	exitUsage   = 2

	maxPasswordInput = 4096
	commandTimeFmt   = time.RFC3339
)

const commandUsage = `commands:
  admin create --login LOGIN [--password-stdin]           make an administrator
  admin delete --login LOGIN                              remove an administrator
  admin list                                              list the administrators
  admin disable --login LOGIN                             stop an administrator from signing in
  admin enable --login LOGIN                              let a disabled administrator sign in
  admin reset-password --login LOGIN [--password-stdin]   give an administrator a new password
  admin reset-totp --login LOGIN                          remove the authenticator of an administrator
  migrate                                                 create or bring up to date the schema of the database
  cleanup                                                 remove old sessions, tokens, codes and records
  help                                                    show this text

The password is asked for in the terminal, twice and without echo. Without a
terminal it is the first line of the standard input and --password-stdin has to
say so. It is never an argument of the command line.
`

var terminal = struct {
	isTerminal   func(fd int) bool
	readPassword func(fd int) ([]byte, error)
}{
	isTerminal:   term.IsTerminal,
	readPassword: term.ReadPassword,
}

var errUsage = errors.New("usage")

// RunCommand runs a command of the command line of the application, which the
// application connects in its main function, for example when its first argument
// is "limb", and returns the exit code of the process: 0 when the command was
// done, 1 when it failed and 2 when it was not understood. The text of a command
// goes to stdout and the errors and the prompts go to stderr. The password is read
// from the standard input of the process, see RunCommandInput.
//
// The commands are:
//
//	admin create --login LOGIN [--password-stdin]
//	admin delete --login LOGIN
//	admin list
//	admin disable --login LOGIN
//	admin enable --login LOGIN
//	admin reset-password --login LOGIN [--password-stdin]
//	admin reset-totp --login LOGIN
//	migrate
//	cleanup
//	help
//
// The login may also be given as the argument that follows the command. What the
// commands that change an administrator do is written to the audit log as done by
// the command line.
//
// The password is never an argument. In a terminal it is asked for twice, without
// echo. Without a terminal it is the first line of the standard input, and the
// option --password-stdin says that this is meant.
//
// The commands migrate and cleanup do what Migrate and Cleanup do. The service
// has to exist to run them, and New refuses a database whose schema is not
// current unless WithAutoMigrate is given: to create the schema before the
// service exists, run the command with the function RunCommand, which makes the
// service itself and migrates without one.
func (a *Auth) RunCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return a.RunCommandInput(ctx, os.Stdin, args, stdout, stderr)
}

// RunCommand runs a command of the command line of the application for the main
// function of the application, with a database that the application opened and
// the master key and the options that it makes the service with. It does what the
// method Auth.RunCommand does, see there for the commands and the exit codes, but
// it needs no service to exist: it makes one with New for every call that needs
// one, and stops it before it returns, so it is for the process that runs a
// command and ends, never for the handlers of requests, which use the method of
// the service they have. The commands help and migrate do not need a service, so
// migrate creates the schema of an empty database, and help works without a
// database. The command migrate only looks at WithTablePrefix of the options, like
// the function Migrate, which it calls.
func RunCommand(ctx context.Context, db *sql.DB, dialect Dialect, masterKey []byte, args []string, stdout, stderr io.Writer, opts ...Option) int {
	return runStandalone(ctx, os.Stdin, db, dialect, masterKey, args, stdout, stderr, opts)
}

func runStandalone(ctx context.Context, stdin io.Reader, db *sql.DB, dialect Dialect, masterKey []byte, args []string, stdout, stderr io.Writer, opts []Option) int {
	run := newCommandRun(ctx, stdin, stdout, stderr)
	run.migrator = func(ctx context.Context) (int, error) { return migrateDatabase(ctx, db, dialect, opts) }
	run.open = func() (*Auth, error) { return New(db, dialect, masterKey, opts...) } //nolint:contextcheck
	code := run.execute(args)
	if run.a != nil {
		_ = run.a.Shutdown(ctx)
	}
	return code
}

// RunCommandInput is RunCommand with the input that the password is read from
// given by the caller. When stdin is a terminal, that is an *os.File that is one,
// the password is asked for in it without echo. Any other reader is read as a
// pipe.
func (a *Auth) RunCommandInput(ctx context.Context, stdin io.Reader, args []string, stdout, stderr io.Writer) int {
	run := newCommandRun(ctx, stdin, stdout, stderr)
	run.a = a
	run.migrator = func(ctx context.Context) (int, error) {
		if err := a.Migrate(ctx); err != nil {
			return 0, err
		}
		return a.store.SchemaVersion(ctx)
	}
	return run.execute(args)
}

func newCommandRun(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer) *commandRun {
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	return &commandRun{ctx: ctx, stdin: stdin, stdout: stdout, stderr: stderr}
}

func (r *commandRun) execute(args []string) int {
	err := r.dispatch(args)
	switch {
	case err == nil:
		return exitDone
	case errors.Is(err, errUsage):
		_, _ = fmt.Fprintf(r.stderr, "limb: %s\n\n%s", strings.TrimPrefix(err.Error(), "usage: "), commandUsage)
		return exitUsage
	}
	_, _ = fmt.Fprintf(r.stderr, "limb: %s\n", commandMessage(err, r.login))
	return exitFailure
}

type commandRun struct {
	ctx           context.Context
	a             *Auth
	open          func() (*Auth, error)
	migrator      func(ctx context.Context) (int, error)
	stdin         io.Reader
	stdout        io.Writer
	stderr        io.Writer
	login         string
	passwordStdin bool
}

func (r *commandRun) service() (*Auth, error) {
	if r.a == nil {
		a, err := r.open()
		if err != nil {
			return nil, err
		}
		r.a = a
	}
	return r.a, nil
}

func usageError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errUsage, fmt.Sprintf(format, args...))
}

func (r *commandRun) dispatch(args []string) error {
	if len(args) == 0 {
		return usageError("no command is given")
	}
	switch args[0] {
	case "help", "-h", "--help", "-help":
		_, err := io.WriteString(r.stdout, commandUsage)
		return err
	case "migrate":
		return r.noArguments(args[1:], r.migrate)
	case "cleanup":
		return r.noArguments(args[1:], r.cleanup)
	case "admin":
		return r.admin(args[1:])
	}
	return usageError("%q is not a command", args[0])
}

func (r *commandRun) noArguments(args []string, do func() error) error {
	if len(args) > 0 {
		return usageError("%q takes no arguments", args[0])
	}
	return do()
}

func (r *commandRun) admin(args []string) error {
	if len(args) == 0 {
		return usageError("admin needs a command")
	}
	name, rest := args[0], args[1:]
	switch name {
	case "list":
		return r.noArguments(rest, r.listAdmins)
	case "create":
		return r.withLogin(rest, true, r.createAdmin)
	case "reset-password":
		return r.withLogin(rest, true, r.resetAdminPassword)
	case "delete":
		return r.withLogin(rest, false, r.deleteAdmin)
	case "disable":
		return r.withLogin(rest, false, r.disableAdmin)
	case "enable":
		return r.withLogin(rest, false, r.enableAdmin)
	case "reset-totp":
		return r.withLogin(rest, false, r.resetAdminTOTP)
	}
	return usageError("%q is not a command of admin", name)
}

func (r *commandRun) withLogin(args []string, takesPassword bool, do func() error) error {
	var positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			positional = append(positional, args[i+1:]...)
			i = len(args)
		case arg == "--password-stdin" || arg == "-password-stdin":
			if !takesPassword {
				return usageError("this command reads no password")
			}
			r.passwordStdin = true
		case arg == "--login" || arg == "-login":
			if i+1 >= len(args) {
				return usageError("--login needs a value")
			}
			i++
			if err := r.setLogin(args[i]); err != nil {
				return err
			}
		case strings.HasPrefix(arg, "--login=") || strings.HasPrefix(arg, "-login="):
			if err := r.setLogin(arg[strings.IndexByte(arg, '=')+1:]); err != nil {
				return err
			}
		case strings.HasPrefix(arg, "-") && len(arg) > 1:
			return usageError("%q is not an option of this command", arg)
		default:
			positional = append(positional, arg)
		}
	}
	if len(positional) > 1 || (len(positional) == 1 && r.login != "") {
		return usageError("the login is given twice or there are arguments that are not understood")
	}
	if len(positional) == 1 {
		r.login = positional[0]
	}
	if r.login == "" {
		return usageError("the login is missing: give it as --login LOGIN")
	}
	return do()
}

func (r *commandRun) setLogin(login string) error {
	if r.login != "" {
		return usageError("the login is given twice")
	}
	r.login = login
	return nil
}

func (r *commandRun) createAdmin() error {
	a, err := r.service()
	if err != nil {
		return err
	}
	secret, err := r.readPassword()
	if err != nil {
		return err
	}
	account, err := a.admins.Create(r.ctx, audit.CLI, r.login, secret)
	if err != nil {
		return adminError(err)
	}
	_, err = fmt.Fprintf(r.stdout, "the administrator %s is created: the authenticator is bound at the first sign-in to the administration\n", account.Login)
	return err
}

func (r *commandRun) resetAdminPassword() error {
	a, err := r.service()
	if err != nil {
		return err
	}
	secret, err := r.readPassword()
	if err != nil {
		return err
	}
	if err = a.admins.ResetPassword(r.ctx, audit.CLI, r.login, secret); err != nil {
		return adminError(err)
	}
	_, err = fmt.Fprintf(r.stdout, "the password of the administrator %s is changed and their sessions are ended\n", r.login)
	return err
}

func (r *commandRun) deleteAdmin() error {
	a, err := r.service()
	if err != nil {
		return err
	}
	if err = a.admins.Delete(r.ctx, audit.CLI, r.login); err != nil {
		return adminError(err)
	}
	_, err = fmt.Fprintf(r.stdout, "the administrator %s is deleted\n", r.login)
	return err
}

func (r *commandRun) disableAdmin() error {
	a, err := r.service()
	if err != nil {
		return err
	}
	if err = a.admins.Disable(r.ctx, audit.CLI, r.login); err != nil {
		return adminError(err)
	}
	_, err = fmt.Fprintf(r.stdout, "the administrator %s cannot sign in and has no sessions\n", r.login)
	return err
}

func (r *commandRun) enableAdmin() error {
	a, err := r.service()
	if err != nil {
		return err
	}
	if err = a.admins.Enable(r.ctx, audit.CLI, r.login); err != nil {
		return adminError(err)
	}
	_, err = fmt.Fprintf(r.stdout, "the administrator %s can sign in\n", r.login)
	return err
}

func (r *commandRun) resetAdminTOTP() error {
	a, err := r.service()
	if err != nil {
		return err
	}
	if err = a.admins.ResetTOTP(r.ctx, audit.CLI, r.login); err != nil {
		return adminError(err)
	}
	_, err = fmt.Fprintf(r.stdout, "the authenticator of the administrator %s is removed: they bind a new one at the next sign-in\n", r.login)
	return err
}

func (r *commandRun) listAdmins() error {
	a, err := r.service()
	if err != nil {
		return err
	}
	accounts, err := a.admins.List(r.ctx)
	if err != nil {
		return adminError(err)
	}
	if len(accounts) == 0 {
		_, err = io.WriteString(r.stdout, "there are no administrators\n")
		return err
	}
	table := tabwriter.NewWriter(r.stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(table, "LOGIN\tSTATUS\tAUTHENTICATOR\tRECOVERY CODES\tLAST SIGN-IN\tCREATED")
	for _, account := range accounts {
		status, authenticator, lastLogin := "active", "not bound", "never"
		if account.Disabled {
			status = "disabled"
		}
		if account.TOTPBound {
			authenticator = "bound"
		}
		if !account.LastLoginAt.IsZero() {
			lastLogin = account.LastLoginAt.UTC().Format(commandTimeFmt)
		}
		_, _ = fmt.Fprintf(table, "%s\t%s\t%s\t%d\t%s\t%s\n", account.Login, status, authenticator, account.RecoveryCodes, lastLogin, account.CreatedAt.UTC().Format(commandTimeFmt))
	}
	return table.Flush()
}

func (r *commandRun) migrate() error {
	version, err := r.migrator(r.ctx)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(r.stdout, "the schema of the database is at version %d\n", version)
	return err
}

func (r *commandRun) cleanup() error {
	a, err := r.service()
	if err != nil {
		return err
	}
	if err = a.Cleanup(r.ctx); err != nil {
		return err
	}
	_, err = io.WriteString(r.stdout, "old data is removed\n")
	return err
}

var (
	errNoPassword      = errors.New("the password is empty")
	errPasswordsDiffer = errors.New("the passwords differ")
	errNeedStdin       = errors.New("the standard input is not a terminal: give the password as the first line of it and add --password-stdin")
	errLongPassword    = errors.New("the password line is too long")
)

func (r *commandRun) readPassword() (string, error) {
	if file, isFile := r.stdin.(*os.File); isFile {
		fd := int(file.Fd())
		if terminal.isTerminal(fd) {
			return r.askPassword(fd)
		}
	}
	if !r.passwordStdin {
		return "", errNeedStdin
	}
	line, err := bufio.NewReader(io.LimitReader(r.stdin, maxPasswordInput+2)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read the password: %w", err)
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	switch {
	case len(line) > maxPasswordInput:
		return "", errLongPassword
	case line == "":
		return "", errNoPassword
	}
	return line, nil
}

func (r *commandRun) askPassword(fd int) (string, error) {
	first, err := r.prompt(fd, "Password: ")
	if err != nil {
		return "", err
	}
	second, err := r.prompt(fd, "Repeat the password: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errPasswordsDiffer
	}
	return first, nil
}

func (r *commandRun) prompt(fd int, text string) (string, error) {
	_, _ = io.WriteString(r.stderr, text)
	typed, err := terminal.readPassword(fd)
	_, _ = io.WriteString(r.stderr, "\n")
	if err != nil {
		return "", fmt.Errorf("read the password: %w", err)
	}
	if len(typed) == 0 {
		return "", errNoPassword
	}
	if len(typed) > maxPasswordInput {
		return "", errLongPassword
	}
	return string(typed), nil
}

func commandMessage(err error, login string) string {
	var validation *ValidationError
	var policy *PolicyError
	switch {
	case errors.Is(err, ErrAdminNotFound):
		return "there is no administrator with the login " + login
	case errors.Is(err, ErrAdminLoginTaken):
		return "the login " + login + " is taken"
	case errors.As(err, &validation):
		return "the " + validation.Field + " is not valid: it must satisfy this: " + validation.Reason
	case errors.As(err, &policy):
		return "the password does not meet the policy: " + describeRules(policy.Rules)
	}
	return strings.TrimPrefix(err.Error(), "limb: ")
}

func describeRules(rules []string) string {
	known := map[string]string{
		password.RuleMinLength: "it is too short",
		password.RuleMaxLength: "it is too long",
		password.RuleCommon:    "it is a common password",
		password.RuleLogin:     "it is the login",
	}
	described := make([]string, 0, len(rules))
	for _, rule := range rules {
		if text, ok := known[rule]; ok {
			described = append(described, text)
			continue
		}
		described = append(described, rule)
	}
	return strings.Join(described, "; ")
}
