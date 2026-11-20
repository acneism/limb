# limb

limb is an authentication library for Go with a built-in web admin panel.
It works with PostgreSQL, MySQL/MariaDB and Oracle through `database/sql`.

**Status:** early development, not ready for use.

## Registration, confirmation and password reset

limb sends no e-mail and no SMS itself. The application gives `limb.WithSender` an implementation of `limb.Sender`, and limb calls it in the background with a `limb.Message`: the kind of the message, the recipient, the language, the link, the code and a text made from the built-in templates in Russian and English. `limb.WithMessageTemplate` replaces a template, `limb.WithServiceName` names the service in the texts, and `Auth.Shutdown` waits for the messages and the events that are still waiting when the application stops.

```go
auth, err := limb.New(db, limb.Postgres, masterKey,
	limb.WithIdentifiers(identifier.Email(identifier.Required()), identifier.Username()),
	limb.WithSender(mailer),
	limb.WithSignup(),
	limb.WithVerifyURL("https://app.example.com/confirm"),
	limb.WithResetURL("https://app.example.com/reset"),
	limb.WithServiceName("Acme"),
	limb.WithHooks(limb.Hooks{BeforeRegister: checkInvitation}),
)
```

The routes of `auth.Handler()` for these scenarios are below. They need no session and set no cookie. `/verify` and `/password/reset` answer the same for a login that has an account and one that has not.

| Route | Body | Answer |
| --- | --- | --- |
| `POST /register`, with `WithSignup` | `{"identifiers": {"email": "...", "username": "..."}, "password": "...", "extra": {...}}` | `202` with `{"verification_required": true}` |
| `POST /verify` | `{"login": "..."}` | `202` |
| `POST /verify/confirm` | `{"token": "..."}`, or `{"login": "...", "code": "..."}`, or `{"channel": "...", "code": "..."}` | `204` |
| `POST /password/reset` | `{"login": "..."}` | `202` |
| `POST /password/reset/confirm` | the same as `/verify/confirm` and `{"password": "..."}` | `204` |

The link in a message is the address given with `WithVerifyURL` or `WithResetURL` with the secret in its fragment, for example `https://app.example.com/reset#token=...`. A browser does not send the fragment to a server, so it does not reach the logs: the page of the application reads it with a script and sends it in the body of the request. Without these options the messages carry a code only.

- A registration whose e-mail address or phone number belongs to someone else is answered like any other, creates nothing and sends the owner a notice. A taken nickname is reported with `422 validation_failed`, because it has to be chosen.
- With `WithSignup`, and when an identifier type is a delivery channel, a user signs in only after confirming an address or a phone number: until then `/login` and `/token` answer `403 verification_required`, after the right password only. `WithoutVerificationRequired` turns this off, and `Registration.Verified` lets the code of the application confirm values when it makes a user with `Auth.Register`.
- `Hooks.BeforeRegister` can refuse a registration, for example for an invitation code that the client sends in `extra`: a `*limb.ValidationError` becomes `422` with its field and reason, any other error or a panic becomes `403 registration_refused`.
- A link that resets a password works for 30 minutes and one that confirms an address for 24 hours. A code of six digits works for ten minutes and survives five guesses. A link or a code works once, and using one ends the other. The database keeps only hashes.
- A password is reset only through a channel that is confirmed, and by default it ends every session of the user. The user gets a message about every change of the password. A message of a kind goes to one user at most five times in an hour.
- The limits count registrations and requests for messages by the address of the client and by the address, the phone number or the login that they name, and wrong links and codes by the address of the client. They answer `429` with `Retry-After`, see `limb.WithRecoveryLimits`. A queue of messages that is full answers `503 busy`.
- `Hooks.OnEvent` hears about every registration, sign-in, change and reset of a password, confirmed channel and message that failed, after the operation was committed, and never gets a password, a link or a code. It runs in the request, except for the user that `Signup` created: that event is delivered in the background, so that a slow hook cannot show whether an address was taken.

## Users, the audit log and the maintenance

`auth.Admin()` returns the operations that the administration does, for the code of the application. What they change is written to the audit log as done by the actor `api` of the system, in the transaction of the change, so a change without its record does not happen. The operations that change a user return `limb.ErrUserNotFound` for a user that does not exist and `limb.ErrUserDeleted` for one that is deleted, except `RestoreUser`, which asks for a deleted one. A call that lost a race with other changes of the same user eight times in a row returns `limb.ErrConcurrentChange` and changed nothing.

| Operation | What it does |
| --- | --- |
| `ListUsers(ctx, limb.UserFilter{...})` | A page of users, 50 by default and 200 at most, with their identifiers and the way they came to be (`api`, `signup`, `admin`, `invite`). It filters by status, confirmation, the periods of creation and of the last sign-in, and searches. A text of three characters or more finds the users that have a value of any type that starts with it, as an e-mail address in lower case or a phone number as it is typed; a shorter one finds an exact value. It is ordered by creation, last sign-in or status and read page by page with `UserPage.Next`, which is a cursor bound to the order and the direction |
| `User`, `UserSessions` | The card of a user whatever the status is, and the sessions that are in use |
| `BlockUser`, `UnblockUser` | A block has a reason and may have an end. It ends every session and refresh token of the user at once. A block that has run out is shown as active, and the maintenance lifts it |
| `EndUserSession`, `EndUserSessions` | Ends one session, or all, with the refresh tokens |
| `SendPasswordReset` | Sends the link that resets the password to the channels of the user that are confirmed |
| `SetTemporaryPassword` | Sets a password that follows the policy and returns it once. The user has to change it at the next sign-in |
| `CreateUser`, `InviteUser`, `ResendInvitation` | A user with a password, which they have to change at the first sign-in unless `NewUser.KeepPassword` is set, or one invited by an address or a phone number only: the holder gets a link that works for seven days and only while the account has no password, and the channel is confirmed when they choose one |
| `SetUserIdentifier`, `RemoveUserIdentifier`, `VerifyUserIdentifier` | Changes the values that a user signs in with, which the owners of the confirmed channels are told about, and confirms an address or a phone number on the word of the administrator |
| `DeleteUser`, `RestoreUser` | A deleted user cannot sign in, their sessions and secrets end, and their values stay taken; they are kept for 30 days, `limb.WithDeletedUserRetention`, and can be restored until then. With `limb.WithImmediateDeletion` the user is erased at once together with what belongs to them |
| `ListAudit` | The audit log, the newest record first, filtered by user, administrator, actions and period |
| `PasswordToEndSessions`, `SetPasswordToEndSessions` | The setting that asks for the password to end the sessions of a user. What an administrator sets wins over `limb.WithPasswordToEndSessions`, and every instance sees it within 15 seconds |

`Hooks.BeforeDelete` can refuse the deletion that an administrator asks for, for example while the user owns something: the deletion then returns `limb.ErrDeletionRefused`, which wraps the error of the hook, and a panic of the hook refuses it too. `Hooks.OnEvent` hears `EventUserBlocked`, `EventUserUnblocked`, `EventUserChanged`, `EventUserDeleted`, `EventUserRestored` and `EventUserPurged` besides the events of the users themselves.

The audit log holds what the users did, as `auth.login`, `auth.login_failed`, `auth.password_changed` and the like, and what the administrators and the code did, as `user.blocked`, `user.deleted`, `setting.changed`, `admin.created` and the like. A record has the time, the actor (an administrator, a user or a part of the system: `cli`, `api` or `maintenance`), the action, the user it was done to, the address and the details, which hold the old and the new value and never a password, a code, a token or a secret; the details are at most 4000 bytes, and one that is longer is cut and says so. The records of the failed sign-ins and of the accounts that `Signup` made are written in the background through a queue of 256 records: a record that does not fit is dropped and logged as lost, so that a flood of wrong passwords cannot slow the sign-in down. The records are kept for a year, `limb.WithAuditRetention`.

`auth.Cleanup(ctx)` removes what is no longer of use: old sessions and tokens, counters and secrets, the signing keys that are retired, the sessions of the administrators that ended, the records of the audit log that are past their retention, the deleted users whose retention has ended and the accounts that a visitor made with `Signup` and nobody confirmed for seven days, `limb.WithUnconfirmedAccountLifetime`, and it lifts the blocks that ran out. A user that is removed is removed in one transaction with its record in the audit log, so of several instances exactly one does it. `auth.RunMaintenance(ctx, interval)` calls it at once and then every interval, with a spread of ten percent, and changes the signing key when it is due. It blocks until the context ends, so it runs in a goroutine of its own, and a second call in a process returns `limb.ErrMaintenanceRunning`. Every step has a limit of time, and a failure or a panic of a step is logged and does not stop the loop. The command `cleanup` calls `Cleanup` once.

```go
go func() {
	if err := auth.RunMaintenance(ctx, time.Hour); err != nil {
		log.Print(err)
	}
}()
```

## The web administration

`auth.AdminHandler()` is the web administration: pages for the administrators of the service. The application mounts it under a path of its own and tells limb the path with `limb.WithAdminMountPath`, because the cookies of the administration are scoped to it and its pages link to it:

```go
auth, err := limb.New(db, limb.Postgres, masterKey, limb.WithAdminMountPath("/admin"))
if err != nil {
	log.Fatal(err)
}
mux.Handle("/admin/", http.StripPrefix("/admin", auth.AdminHandler()))
```

`AdminHandler` panics without the mount path, so that a mistake shows when the application starts. The administrators are made by the command line or by `auth.Admin().CreateAdmin`, never from the web. The pages are HTML made on the server. They run no script and ask nothing of another site, so every answer carries a `Content-Security-Policy` that allows only the stylesheet of the administration and the forms of the page and forbids framing, and the headers that tell a browser to keep nothing, to guess no type and to send no referrer. The stylesheet is part of the library.

**Signing in.** The password is the first step. The second is a one-time password of an authenticator app (RFC 6238) or a recovery code. At the first sign-in the administrator binds an authenticator: the page shows a QR code that the server draws and the key to type by hand, the first one-time password confirms it, and ten recovery codes are shown once and kept only as hashes. A one-time password works once, and so does a recovery code. A sign-in that passed the password and not the second step gives no access, ends in five minutes and takes three guesses. A wrong password, one-time password or recovery code counts against limits that are stricter than those of the users, see `limb.WithAdminLoginLimits`: five failures of one login from one address, or twenty from one address, within 15 minutes pause it for 30 minutes, and the failures of one login from anywhere make every attempt wait, up to a minute, so that nobody can lock an administrator out of their account. The audit log holds every sign-in, sign-out and failure with the address, and a failure holds the reason and never the password.

**Sessions.** A session ends after 12 hours and after 30 minutes without a request, see `limb.WithAdminSessionTTL`, when the administrator signs out, when the password or the authenticator of the account is changed or reset, and when the account is disabled or deleted. The cookie is `HttpOnly` and `SameSite=Strict`, scoped to the mount path, `Secure` and named `__Secure-limb_admin`; with `limb.WithDevelopmentMode` it is not `Secure` and has no prefix, so that it works over plain HTTP on a development machine. A form must come from the application, which the browser says in `Sec-Fetch-Site` or `Origin`, and the form of a signed-in administrator carries the token of its session, which is made for the administration alone.

**The account.** At `/account` an administrator changes their password, makes new recovery codes, binds another authenticator and sees and ends their sessions. The first three ask for the current password again, and a wrong one counts against the limits of the sign-in. A change of the password or of the authenticator ends the other sessions and keeps the one that made it. The other authenticator is stored only when its one-time password confirms it, and until then the one that works stays.

**Users.** At `/users` an administrator finds the users: the list shows what each signs in with and which of those values are confirmed, the status and when a block ends, when the account was made and how, and when the user signed in last. It is searched by what the users sign in with, filtered by status, by a confirmed address or phone number, by how the account was made, by the days of creation and of the last sign-in and by users who never signed in, ordered by the heads of the columns and read page by page with the cursor of `ListUsers`. The query holds everything that was asked for, so a page of the list can be kept as a link, and a value that cannot be applied is answered with `400` and the form again. The card of a user, `/users/<id>`, shows the account, the values with the time each was confirmed, the sessions in use, the last sign-ins and the last changes, and has a form for each thing that an administrator does:

- block with a reason, which is required, and the day on which the block ends at 00:00 UTC, or none; lift a block; end one session of the user or all of them;
- give the user a way back: a link to choose a new password, sent to the confirmed address or phone number in the language that is asked for, which needs `limb.WithSender`, or a temporary password, which the page shows once and which the user has to change;
- change, add, remove and confirm the values the user signs in with, with the checks of the API, and send the invitation again to a user who has not chosen a password;
- delete the user, which asks to type a value that the user signs in with, and restore a deleted user until the time of keeping ends.

`/users/new` makes a user either with a password, which the user has to change at the first sign-in unless a box says they need not, or by an invitation, which needs `limb.WithSender` and `limb.WithResetURL`; an address or a phone number can be marked as confirmed there on the word of the administrator. Each of these is the operation of `auth.Admin()` of the same name, so the checks, the hooks and the events are the same, and the change is written to the audit log in the name of the signed-in administrator and from their address. A form that cannot be applied is answered with the card or the form again and the reason in words: `422` for a value that is wrong, `409` for a user who is deleted, who changed meanwhile, whose deletion `Hooks.BeforeDelete` refused or who has no confirmed channel, and `503` for a queue of messages that is full. What the hook said is logged and not shown.

**The audit log.** `/audit` lists the records, the newest first, with when, what, who, to which user, from where and what changed, and filters them by the ID of a user, by an administrator, by an action and by the days of a period, both ends included. The card of a user links to the records of that user. The log can be read and nothing else: no page changes or removes a record. An action that this version does not know, which an older one wrote, is shown by its name.

**Where from.** `limb.WithAdminIPs(prefixes...)` lets only some networks in, and a request from any other address gets the answer for a page that does not exist. The address is the one that `limb.WithTrustedProxies` tells, and behind a proxy that ends TLS the scheme comes from `X-Forwarded-Proto` the same way.

**Languages.** The pages are in English and in Russian, in the language of the `Accept-Language` header or the one that the administrator chose with the links at the foot of every page, which is kept in a cookie. `limb.WithAdminTexts` replaces texts and adds languages, and [docs/admin-texts.md](docs/admin-texts.md) lists the keys:

```go
limb.WithAdminTexts("de", map[string]string{"login.title": "Anmelden", "login.password": "Passwort"})
```

| Option | What it does |
| --- | --- |
| `WithAdminMountPath(path)` | The path that the handler is mounted at, as the browser sees it. Required |
| `WithAdminIPs(prefixes...)` | The networks that may use the administration. Without it every address may, and the limits stand in the way |
| `WithAdminLoginLimits(limits)` | The limits on failed sign-ins and failed second steps. A field that is zero keeps its default |
| `WithAdminSessionTTL(absolute, idle)` | How long a session lasts, 12 hours and 30 minutes by default |
| `WithAdminTexts(language, texts)` | Replaces texts or gives the administration another language |
| `WithoutAdminTOTP()` | Lets an administrator in with the password alone. It needs `WithDevelopmentMode`, and `New` fails without it |

## Databases

The application opens the `*sql.DB` with the driver it prefers and gives `limb.New` the dialect of the database. limb imports no driver. The tests use the drivers in the table.

| Database | Dialect | Versions | Driver |
| --- | --- | --- | --- |
| PostgreSQL | `limb.Postgres` | 15 and newer | `github.com/jackc/pgx/v5/stdlib` |
| MySQL | `limb.MySQL` | 8.4 and newer | `github.com/go-sql-driver/mysql` |
| MariaDB | `limb.MariaDB` | 10.11 and newer | `github.com/go-sql-driver/mysql` |
| Oracle | `limb.Oracle` | 19c and newer | `github.com/sijms/go-ora/v2` |

limb creates its tables itself: with `limb.WithAutoMigrate`, with the function `limb.Migrate(ctx, db, dialect, opts...)`, which needs no service and is meant for the step of a deployment that runs before the new version starts, or with the command `migrate`, see below. Their names start with a prefix, `limb_` by default and `limb.WithTablePrefix` changes it. Every database has the same tables and columns. Migrations are written for each database in `sqlstore/migrations`, and several processes can migrate at once: one of them takes a lease on the schema and the others wait.

`limb.New` checks how the connection is set up before it writes anything and says what to change when it is wrong. Texts are compared byte by byte, and every text has a longest length in bytes, so a value that one database accepts is accepted by all of them.

The user who migrates needs the right to create tables, the user who only runs the application needs the rights to read and write them. One user can do both.

### PostgreSQL

Any DSN of the driver works. The user who migrates needs `CREATE` on the schema, and the others need `SELECT`, `INSERT`, `UPDATE` and `DELETE` on the tables.

### MySQL and MariaDB

The DSN of `github.com/go-sql-driver/mysql` has to contain `parseTime=true&loc=UTC`, for example `user:password@tcp(localhost:3306)/limb?parseTime=true&loc=UTC`. It must not contain `clientFoundRows=true`, and the connection must use the character set `utf8mb4`, which is the default of the driver.

The user needs `CREATE`, `REFERENCES`, `SELECT`, `INSERT`, `UPDATE` and `DELETE` on the database.

MySQL and MariaDB have a dialect each, because their collations differ: the tables of MySQL use `utf8mb4_0900_bin`, those of MariaDB use `utf8mb4_nopad_bin`. Both tell `a` from `a ` and from `A`, which `utf8mb4_bin` does not.

### Oracle

The DSN of `github.com/sijms/go-ora/v2` looks like `oracle://user:password@localhost:1521/service`. The tables go to the schema of the user who connects. The user needs `CREATE SESSION`, `CREATE TABLE` and a quota on a tablespace. The session has to compare strings by their bytes, which is the default (`NLS_COMP=BINARY`), and `New` refuses one that does not.

Oracle starts a server process for every connection, and its listener turns new connections away with ORA-12516, ORA-12519 or ORA-12520 when the processes of the instance are used up, which a pool that opens and closes connections in bursts can bring about. Set `db.SetMaxOpenConns` to what the application needs and `db.SetMaxIdleConns` to the same number, so that connections are kept and reused. limb does not repeat a statement after these errors: they are about the capacity of the server, and repeating would only add to the load.

The driver does not interrupt a running statement when its context ends: a canceled request returns after the statement has finished, so limit long statements in the database if that matters to you. limb never stores an empty string, which Oracle takes for NULL.

Every time column of Oracle is `TIMESTAMP(6) WITH TIME ZONE`, because a plain `TIMESTAMP` is compared through the time zone of the session and the expiry times would drift by the offset of the machine. Oracle does not accept a primary key, a unique key or a unique index on such a column (ORA-02329), so no migration may make one. A test fails when one does.

## Command line

`limb.RunCommand` runs the commands of the command line of the application, which connects it in its `main` function, for example when the first argument is `limb`:

```go
if len(os.Args) > 1 && os.Args[1] == "limb" {
	os.Exit(limb.RunCommand(ctx, db, limb.Postgres, masterKey, os.Args[2:], os.Stdout, os.Stderr, options...))
}
```

It makes the service itself for the commands that need one and stops it, and the commands `migrate` and `help` need none, so `migrate` creates the schema of an empty database without `WithAutoMigrate`. It is for the process that runs a command and ends. A service that exists has the method `auth.RunCommand(ctx, args, stdout, stderr)`.

The commands are `admin create --login LOGIN`, `admin delete`, `admin list`, `admin disable`, `admin enable`, `admin reset-password` and `admin reset-totp`, and `migrate` and `cleanup`; `help` lists them. The administrators of the web administration are made only here and with `Auth.Admin()`, never from the web. The password is never an argument of the command line: in a terminal the command asks for it twice without echo, and without a terminal it is the first line of the standard input, which `--password-stdin` has to say is meant, as in `echo "$PASSWORD" | ./app limb admin create --login root --password-stdin`. What the commands change is written to the audit log as done by the command line.

## Dependencies

The library links these packages, all with licenses that are compatible with Apache 2.0. The drivers of the databases are not among them: the application chooses its own.

| Package | What it is for | License |
| --- | --- | --- |
| `golang.org/x/crypto` | Argon2id for passwords | BSD-3-Clause |
| `golang.org/x/text` | Unicode NFKC for nicknames, logins and passwords | BSD-3-Clause |
| `golang.org/x/net` | punycode for the domains of e-mail addresses | BSD-3-Clause |
| `golang.org/x/term` | reading a password in the terminal without echo, in the command line | BSD-3-Clause |
| `github.com/golang-jwt/jwt/v5` | signing and checking JWT | MIT |
| `github.com/google/uuid` | UUIDv7 | BSD-3-Clause |
| `rsc.io/qr` | the QR code that binds an authenticator, drawn on the server as an inline SVG | BSD-3-Clause |
| `github.com/nyaruka/phonenumbers` | normalizing phone numbers, only in `identifier/phone` | MIT |

## License

Apache 2.0, see [LICENSE](LICENSE).

## Development

Requirements: Go 1.26 or newer, golangci-lint v2 and govulncheck on `PATH`.

Run every check (lint, tests with the race detector, vulnerability scan) with:

```sh
make check
```

The stylesheet of the administration, `internal/adminui/static/admin.css`, is built from `internal/adminui/styles/input.css` and the templates by the standalone command line of [Tailwind CSS](https://tailwindcss.com), which is not part of the library and needs neither Node.js nor any file of npm. After a template or the input changes, build it again with `make css TAILWIND=/path/to/tailwindcss`. CI downloads version 4.3.3 from its release, checks the SHA-256 that `.github/workflows/ci.yml` pins, builds the stylesheet and fails when it is not the committed one, so the file in the library is always what the pinned tool makes of the sources.

The tests of the SQL store and the end-to-end tests of the library need a database. Every database engine has a variable of its own, and the tests run on each engine whose variable holds a DSN, as a subtest named after the engine; they are skipped when no variable is set. The variables are `LIMB_TEST_POSTGRES_DSN`, for example `postgres://user:password@localhost:5432/limb_test?sslmode=disable`, `LIMB_TEST_MYSQL_DSN` and `LIMB_TEST_MARIADB_DSN`, for example `user:password@tcp(localhost:3306)/limb_test?parseTime=true&loc=UTC`, and `LIMB_TEST_ORACLE_DSN`, for example `oracle://user:password@localhost:1521/FREEPDB1`. The user must be allowed to create and drop tables; every test works in tables with a prefix of its own and removes them afterwards. CI runs these tests against PostgreSQL 15 and 18, MySQL 8.4 and 9, MariaDB 10.11 and 11.8, and Oracle Database XE 21c and Free 23, one database in every job, and fails a job in which a test is skipped. The tests keep at most 16 connections open to Oracle, and the Oracle jobs run the packages one after another (`go test -p 1`), because a test binary per package would add up to more processes than a small Oracle instance accepts.

Comment policy: code carries no comments except godoc on exported identifiers, tool directives (`//go:...` and `//nolint:<linter>` without explanation) and `// Output:` blocks in test examples. Inline, trailing and block comments, commented-out code, license headers and TODOs are not used, and the same rule applies to YAML, Makefile and `.gitignore` files. Names and small functions are the documentation.
