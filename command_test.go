package limb

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

const typedPassword = "another correct horse battery"

func runCommand(t *testing.T, a *Auth, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := a.RunCommandInput(t.Context(), strings.NewReader(stdin), args, &stdout, &stderr)
	given := strings.TrimSpace(strings.SplitN(stdin, "\n", 2)[0])
	if len(given) >= 12 && strings.Contains(stdout.String()+stderr.String(), given) {
		t.Fatalf("the output holds the password that was given:\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
	}
	return code, stdout.String(), stderr.String()
}

type typedLine struct {
	text string
	err  error
}

func attachTerminal(t *testing.T, typed ...typedLine) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "terminal")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	savedIs, savedRead := terminal.isTerminal, terminal.readPassword
	t.Cleanup(func() { terminal.isTerminal, terminal.readPassword = savedIs, savedRead })
	terminal.isTerminal = func(int) bool { return true }
	terminal.readPassword = func(int) ([]byte, error) {
		if len(typed) == 0 {
			return nil, errors.New("nothing is typed")
		}
		next := typed[0]
		typed = typed[1:]
		return []byte(next.text), next.err
	}
	return file
}

func TestTheCommandLineAnswersToHelpAndToWhatItDoesNotUnderstand(t *testing.T) {
	a := newTestAuth(t)
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}} {
		code, stdout, stderr := runCommand(t, a, "", args...)
		if code != 0 || stderr != "" || !strings.Contains(stdout, "admin create --login LOGIN") || !strings.Contains(stdout, "never an argument") {
			t.Errorf("%v: code %d, stdout %q, stderr %q", args, code, stdout, stderr)
		}
	}
	for name, args := range map[string][]string{
		"no command":                nil,
		"an unknown command":        {"bogus"},
		"admin alone":               {"admin"},
		"an unknown admin command":  {"admin", "bogus"},
		"arguments of migrate":      {"migrate", "now"},
		"arguments of cleanup":      {"cleanup", "now"},
		"arguments of list":         {"admin", "list", "root"},
		"no login":                  {"admin", "delete"},
		"no value of the login":     {"admin", "delete", "--login"},
		"two logins":                {"admin", "delete", "--login", "a", "b"},
		"the login twice":           {"admin", "delete", "--login", "abc", "--login=abd"},
		"an unknown option":         {"admin", "delete", "--force", "abc"},
		"a password for delete":     {"admin", "delete", "abc", "--password-stdin"},
		"a password for reset-totp": {"admin", "reset-totp", "abc", "--password-stdin"},
		"an empty login":            {"admin", "enable", "--login="},
		"the login in two forms":    {"admin", "disable", "abc", "--login=abc"},
		"an empty login on its own": {"admin", "disable", "--login", ""},
	} {
		code, stdout, stderr := runCommand(t, a, "", args...)
		if code != 2 || stdout != "" || !strings.HasPrefix(stderr, "limb: ") || !strings.Contains(stderr, "commands:") {
			t.Errorf("%s: code %d, stdout %q, stderr %q; want 2 and the usage", name, code, stdout, stderr)
		}
	}
	_, _, stderr := runCommand(t, a, "", "admin", "delete")
	if !strings.Contains(stderr, "the login is missing: give it as --login LOGIN") {
		t.Errorf("the message does not say what is missing: %q", stderr)
	}
}

func TestAnAdministratorIsCreatedFromTheCommandLine(t *testing.T) {
	forms := map[string][]string{
		"the option":            {"admin", "create", "--login", "root", "--password-stdin"},
		"the option with equal": {"admin", "create", "--login=root", "--password-stdin"},
		"one dash":              {"admin", "create", "-login", "root", "-password-stdin"},
		"the argument":          {"admin", "create", "root", "--password-stdin"},
		"flags first":           {"admin", "create", "--password-stdin", "root"},
		"after the dashes":      {"admin", "create", "--password-stdin", "--", "root"},
	}
	for name, args := range forms {
		t.Run(name, func(t *testing.T) {
			a := newTestAuth(t)
			code, stdout, stderr := runCommand(t, a, typedPassword+"\n", args...)
			if code != 0 || stderr != "" || stdout != "the administrator root is created: the authenticator is bound at the first sign-in to the administration\n" {
				t.Fatalf("code %d, stdout %q, stderr %q", code, stdout, stderr)
			}
			list, err := a.Admin().ListAdmins(t.Context())
			if err != nil || len(list) != 1 || list[0].Login != "root" || list[0].TOTPBound {
				t.Fatalf("the administrators are %+v, %v", list, err)
			}
			records := auditRecords(t, a)
			if len(records) != 1 || records[0].Action != "admin.created" || records[0].ActorKind != store.ActorSystem || records[0].ActorID != "cli" {
				t.Fatalf("the audit log holds %+v: the command line is the system actor cli", records)
			}
		})
	}
}

func TestThePasswordOfTheCommandLineIsTheFirstLineOfThePipe(t *testing.T) {
	cases := map[string]string{
		"a line":                typedPassword + "\n",
		"a line without an end": typedPassword,
		"a line of a terminal":  typedPassword + "\r\n",
		"more lines":            typedPassword + "\nthe second line is not the password\n",
		"spaces that are kept":  typedPassword + "\n",
	}
	for name, stdin := range cases {
		a := newTestAuth(t)
		if code, _, stderr := runCommand(t, a, stdin, "admin", "create", "root", "--password-stdin"); code != 0 {
			t.Fatalf("%s: code %d, stderr %q", name, code, stderr)
		}
		hash := rootHash(t, a)
		if ok, _, err := a.hasher.Verify(t.Context(), typedPassword, hash); err != nil || !ok {
			t.Errorf("%s: the stored hash does not verify the first line: %v", name, err)
		}
	}
	a := newTestAuth(t)
	if code, _, stderr := runCommand(t, a, "  "+typedPassword+"  \n", "admin", "create", "root", "--password-stdin"); code != 0 {
		t.Fatalf("a password with spaces around it: code %d, stderr %q", code, stderr)
	}
	if ok, _, err := a.hasher.Verify(t.Context(), "  "+typedPassword+"  ", rootHash(t, a)); err != nil || !ok {
		t.Errorf("the spaces around a password are part of it: %v", err)
	}
}

func rootHash(t *testing.T, a *Auth) string {
	t.Helper()
	admin, err := a.store.Admins().FindByLogin(t.Context(), a.tenant, "root")
	if err != nil {
		t.Fatal(err)
	}
	return admin.PasswordHash
}

func TestWithoutATerminalThePasswordNeedsTheOptionThatSaysSo(t *testing.T) {
	a := newTestAuth(t)
	code, stdout, stderr := runCommand(t, a, typedPassword+"\n", "admin", "create", "root")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "--password-stdin") || !strings.Contains(stderr, "not a terminal") {
		t.Fatalf("code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	for name, stdin := range map[string]string{"nothing": "", "an empty line": "\n", "a line of a terminal": "\r\n"} {
		code, _, stderr = runCommand(t, a, stdin, "admin", "create", "root", "--password-stdin")
		if code != 1 || !strings.Contains(stderr, "the password is empty") {
			t.Errorf("%s: code %d, stderr %q", name, code, stderr)
		}
	}
	long := strings.Repeat("x", maxPasswordInput+1)
	if code, _, stderr = runCommand(t, a, long+"\n", "admin", "create", "root", "--password-stdin"); code != 1 || !strings.Contains(stderr, "too long") {
		t.Errorf("a line over the limit: code %d, stderr %q", code, stderr)
	}
	if code, _, stderr = runCommand(t, a, strings.Repeat("x", maxPasswordInput)+"\n", "admin", "create", "root", "--password-stdin"); code != 1 || !strings.Contains(stderr, "too long") && !strings.Contains(stderr, "does not meet the policy") {
		t.Errorf("the longest line: code %d, stderr %q", code, stderr)
	}
	if list, err := a.Admin().ListAdmins(t.Context()); err != nil || len(list) != 0 {
		t.Fatalf("a command that failed made an administrator: %v, %v", list, err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("the pipe is broken") }

func TestAPipeThatFailsIsReported(t *testing.T) {
	a := newTestAuth(t)
	var stdout, stderr bytes.Buffer
	code := a.RunCommandInput(t.Context(), failingReader{}, []string{"admin", "create", "root", "--password-stdin"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "read the password: the pipe is broken") {
		t.Fatalf("code %d, stderr %q", code, stderr.String())
	}
}

func TestThePasswordIsAskedForTwiceInATerminalWithoutEcho(t *testing.T) {
	a := newTestAuth(t)
	file := attachTerminal(t, typedLine{text: typedPassword}, typedLine{text: typedPassword})
	var stdout, stderr bytes.Buffer
	code := a.RunCommandInput(t.Context(), file, []string{"admin", "create", "--login", "root"}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "the administrator root is created") {
		t.Fatalf("code %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	if stderr.String() != "Password: \nRepeat the password: \n" {
		t.Fatalf("the prompts are %q", stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), typedPassword) {
		t.Fatal("the password was echoed")
	}
	if ok, _, err := a.hasher.Verify(t.Context(), typedPassword, rootHash(t, a)); err != nil || !ok {
		t.Fatalf("the stored hash does not verify the typed password: %v", err)
	}

	file = attachTerminal(t, typedLine{text: typedPassword + " 2"}, typedLine{text: typedPassword + " 2"})
	if code = a.RunCommandInput(t.Context(), file, []string{"admin", "reset-password", "root", "--password-stdin"}, &stdout, &stderr); code != 0 {
		t.Fatalf("the option --password-stdin must not stop the terminal from being asked: code %d, stderr %q", code, stderr.String())
	}
	if ok, _, err := a.hasher.Verify(t.Context(), typedPassword+" 2", rootHash(t, a)); err != nil || !ok {
		t.Fatalf("the password was not changed: %v", err)
	}
}

func TestAPasswordThatIsTypedWrongInATerminalIsNotUsed(t *testing.T) {
	cases := map[string]struct {
		typed []typedLine
		want  string
	}{
		"the passwords differ":    {[]typedLine{{text: typedPassword}, {text: typedPassword + "x"}}, "the passwords differ"},
		"nothing is typed":        {[]typedLine{{text: ""}}, "the password is empty"},
		"nothing is repeated":     {[]typedLine{{text: typedPassword}, {text: ""}}, "the password is empty"},
		"the terminal fails":      {[]typedLine{{err: errors.New("no terminal")}}, "read the password: no terminal"},
		"the repetition fails":    {[]typedLine{{text: typedPassword}, {err: errors.New("no terminal")}}, "read the password: no terminal"},
		"a line that is too long": {[]typedLine{{text: strings.Repeat("x", maxPasswordInput+1)}}, "too long"},
	}
	for name, c := range cases {
		a := newTestAuth(t)
		file := attachTerminal(t, c.typed...)
		var stdout, stderr bytes.Buffer
		code := a.RunCommandInput(t.Context(), file, []string{"admin", "create", "root"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stderr.String(), c.want) {
			t.Errorf("%s: code %d, stderr %q; want %q", name, code, stderr.String(), c.want)
		}
		if list, err := a.Admin().ListAdmins(t.Context()); err != nil || len(list) != 0 {
			t.Errorf("%s: an administrator was made: %v, %v", name, list, err)
		}
	}
}

func TestAnOrdinaryFileIsNotATerminal(t *testing.T) {
	a := newTestAuth(t)
	file, err := os.CreateTemp(t.TempDir(), "input")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if _, err = file.WriteString(typedPassword + "\n"); err != nil {
		t.Fatal(err)
	}
	if _, err = file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := a.RunCommandInput(t.Context(), file, []string{"admin", "create", "root", "--password-stdin"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code %d, stderr %q", code, stderr.String())
	}
	if stderr.String() != "" {
		t.Fatalf("a file is not asked for a password: %q", stderr.String())
	}
}

func TestTheCommandLineReadsTheStandardInputOfTheProcess(t *testing.T) {
	a := newTestAuth(t)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.WriteString(typedPassword + "\n"); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	saved := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() { os.Stdin = saved; _ = reader.Close() })
	var stdout, stderr bytes.Buffer
	if code := a.RunCommand(t.Context(), []string{"admin", "create", "root", "--password-stdin"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code %d, stderr %q", code, stderr.String())
	}
	if _, err = a.store.Admins().FindByLogin(t.Context(), a.tenant, "root"); err != nil {
		t.Fatalf("the administrator was not made: %v", err)
	}
}

func TestTheCommandLineNeedsNoStreams(t *testing.T) {
	a := newTestAuth(t)
	if code := a.RunCommandInput(t.Context(), nil, []string{"help"}, nil, nil); code != 0 {
		t.Fatalf("help = %d", code)
	}
	if code := a.RunCommandInput(t.Context(), nil, []string{"admin", "create", "root", "--password-stdin"}, nil, nil); code != 1 {
		t.Fatalf("a password without an input = %d, want 1", code)
	}
	if code := a.RunCommandInput(t.Context(), nil, []string{"bogus"}, nil, nil); code != 2 {
		t.Fatalf("a command that is not understood = %d, want 2", code)
	}
}

func TestTheAdministratorsAreListedAsATable(t *testing.T) {
	a, clock := newLimitedAuth(t)
	code, stdout, stderr := runCommand(t, a, "", "admin", "list")
	if code != 0 || stdout != "there are no administrators\n" || stderr != "" {
		t.Fatalf("an empty list: code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	for _, login := range []string{"zed", "ann"} {
		if _, err := a.Admin().CreateAdmin(t.Context(), login, adminPassword); err != nil {
			t.Fatal(err)
		}
		clock.advance(time.Hour)
	}
	ann, err := a.store.Admins().FindByLogin(t.Context(), a.tenant, "ann")
	if err != nil {
		t.Fatal(err)
	}
	ann.TOTPSecret = []byte("sealed")
	ann.TOTPConfirmedAt = clock.now()
	if _, err = a.store.Admins().Update(t.Context(), ann); err != nil {
		t.Fatal(err)
	}
	if err = a.store.Admins().ReplaceRecoveryCodes(t.Context(), a.tenant, ann.ID, [][]byte{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)}); err != nil {
		t.Fatal(err)
	}
	if err = a.store.Admins().RecordLogin(t.Context(), a.tenant, ann.ID, 2, clock.now()); err != nil {
		t.Fatal(err)
	}
	if err = a.Admin().DisableAdmin(t.Context(), "zed"); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runCommand(t, a, "", "admin", "list")
	if code != 0 || stderr != "" {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 3 {
		t.Fatalf("the table has %d lines:\n%s", len(lines), stdout)
	}
	for _, header := range []string{"LOGIN", "STATUS", "AUTHENTICATOR", "RECOVERY CODES", "LAST SIGN-IN", "CREATED"} {
		if !strings.Contains(lines[0], header) {
			t.Errorf("the header %q is missing: %s", header, lines[0])
		}
	}
	annFields, zedFields := strings.Fields(lines[1]), strings.Fields(lines[2])
	if annFields[0] != "ann" || annFields[1] != "active" || annFields[2] != "bound" || annFields[3] != "2" || annFields[4] != "2026-09-10T13:12:13Z" {
		t.Errorf("the line of ann is %v", annFields)
	}
	if zedFields[0] != "zed" || zedFields[1] != "disabled" || zedFields[2] != "not" || zedFields[3] != "bound" || zedFields[4] != "0" || zedFields[5] != "never" {
		t.Errorf("the line of zed is %v", zedFields)
	}
}

func TestTheAdministratorsAreChangedFromTheCommandLine(t *testing.T) {
	a := newTestAuth(t)
	if code, _, stderr := runCommand(t, a, typedPassword+"\n", "admin", "create", "root", "--password-stdin"); code != 0 {
		t.Fatalf("create: code %d, stderr %q", code, stderr)
	}
	steps := []struct {
		args   []string
		stdin  string
		stdout string
	}{
		{[]string{"admin", "disable", "--login", "ROOT"}, "", "the administrator ROOT cannot sign in and has no sessions\n"},
		{[]string{"admin", "enable", "root"}, "", "the administrator root can sign in\n"},
		{[]string{"admin", "reset-totp", "root"}, "", "the authenticator of the administrator root is removed: they bind a new one at the next sign-in\n"},
		{[]string{"admin", "reset-password", "root", "--password-stdin"}, "the new password is good enough\n", "the password of the administrator root is changed and their sessions are ended\n"},
		{[]string{"admin", "delete", "root"}, "", "the administrator root is deleted\n"},
	}
	for _, s := range steps {
		code, stdout, stderr := runCommand(t, a, s.stdin, s.args...)
		if code != 0 || stdout != s.stdout || stderr != "" {
			t.Fatalf("%v: code %d, stdout %q, stderr %q", s.args, code, stdout, stderr)
		}
	}
	var actions []string
	for _, r := range auditRecords(t, a) {
		if r.ActorID != "cli" || r.ActorKind != store.ActorSystem {
			t.Fatalf("the command line is the system actor cli: %+v", r)
		}
		actions = append(actions, r.Action)
	}
	if strings.Join(actions, " ") != "admin.deleted admin.password_reset admin.totp_reset admin.enabled admin.disabled admin.created" {
		t.Fatalf("the actions are %v", actions)
	}
}

func TestACommandOnAnAdministratorThatIsNotThereFails(t *testing.T) {
	a := newTestAuth(t)
	for _, args := range [][]string{
		{"admin", "delete", "nobody"}, {"admin", "disable", "nobody"}, {"admin", "enable", "nobody"}, {"admin", "reset-totp", "nobody"},
		{"admin", "reset-password", "nobody", "--password-stdin"}, {"admin", "delete", "-"},
	} {
		code, stdout, stderr := runCommand(t, a, typedPassword+"\n", args...)
		if code != 1 || stdout != "" || !strings.HasPrefix(stderr, "limb: there is no administrator with the login ") || strings.Contains(stderr, "commands:") {
			t.Errorf("%v: code %d, stdout %q, stderr %q", args, code, stdout, stderr)
		}
	}
}

func TestTheReasonsAFailureIsToldInWords(t *testing.T) {
	a := newTestAuth(t, WithPasswordPolicy(PasswordPolicy{Checks: []func(context.Context, string) error{
		func(_ context.Context, password string) error {
			if strings.Contains(password, "forbidden") {
				return errors.New("forbidden_word")
			}
			return nil
		},
	}}))
	if code, _, stderr := runCommand(t, a, typedPassword+"\n", "admin", "create", "root", "--password-stdin"); code != 0 {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
	cases := []struct {
		args  []string
		stdin string
		want  string
	}{
		{[]string{"admin", "create", "root", "--password-stdin"}, typedPassword + "\n", "the login root is taken"},
		{[]string{"admin", "create", "--login", "-bad", "--password-stdin"}, typedPassword + "\n", "the login is not valid: it must satisfy this: it begins with a letter or a digit"},
		{[]string{"admin", "create", "second", "--password-stdin"}, "short\n", "the password does not meet the policy: it is too short"},
		{[]string{"admin", "create", "second", "--password-stdin"}, "password1234\n", "it is a common password"},
		{[]string{"admin", "create", "second-admin", "--password-stdin"}, "SECOND-ADMIN\n", "it is the login"},
		{[]string{"admin", "create", "second", "--password-stdin"}, strings.Repeat("x", 200) + "\n", "it is too long"},
		{[]string{"admin", "create", "second", "--password-stdin"}, "a forbidden password here\n", "forbidden_word"},
	}
	for _, c := range cases {
		code, stdout, stderr := runCommand(t, a, c.stdin, c.args...)
		if code != 1 || stdout != "" || !strings.Contains(stderr, c.want) || strings.Contains(stderr, "commands:") {
			t.Errorf("%v: code %d, stdout %q, stderr %q; want %q", c.args, code, stdout, stderr, c.want)
		}
	}
}

func TestTheCommandsOfTheDatabaseDoTheirWork(t *testing.T) {
	a := newTestAuth(t)
	code, stdout, stderr := runCommand(t, a, "", "migrate")
	if code != 0 || stdout != "the schema of the database is at version 4\n" || stderr != "" {
		t.Fatalf("migrate: code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if code, stdout, stderr = runCommand(t, a, "", "cleanup"); code != 0 || stdout != "old data is removed\n" || stderr != "" {
		t.Fatalf("cleanup: code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var out, errs bytes.Buffer
	if code = a.RunCommandInput(ctx, strings.NewReader(""), []string{"cleanup"}, &out, &errs); code != 1 || !strings.Contains(errs.String(), "context canceled") {
		t.Fatalf("cleanup with a canceled context: code %d, stderr %q", code, errs.String())
	}
	out.Reset()
	errs.Reset()
	if code = a.RunCommandInput(ctx, strings.NewReader(""), []string{"migrate"}, &out, &errs); code != 1 || !strings.Contains(errs.String(), "context canceled") {
		t.Fatalf("migrate with a canceled context: code %d, stderr %q", code, errs.String())
	}
}
