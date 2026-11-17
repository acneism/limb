# limb

limb is an authentication library for Go with a built-in web admin panel.
It works with PostgreSQL, MySQL/MariaDB and Oracle through `database/sql`.

**Status:** early development, not ready for use.

## Registration, confirmation and password reset

limb sends no e-mail and no SMS itself. The application gives `limb.WithSender` an implementation of `limb.Sender`, and limb calls it in the background with a `limb.Message`: the kind of the message, the recipient, the language, the link, the code and a text made from the built-in templates in Russian and English. `limb.WithMessageTemplate` replaces a template, `limb.WithServiceName` names the service in the texts, and `Auth.Shutdown` waits for the messages that are still waiting when the application stops.

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
- `Hooks.OnEvent` hears about every registration, sign-in, change and reset of a password, confirmed channel and message that failed, after the operation was committed, and never gets a password, a link or a code.

## Databases

The application opens the `*sql.DB` with the driver it prefers and gives `limb.New` the dialect of the database. limb imports no driver. The tests use the drivers in the table.

| Database | Dialect | Versions | Driver |
| --- | --- | --- | --- |
| PostgreSQL | `limb.Postgres` | 15 and newer | `github.com/jackc/pgx/v5/stdlib` |
| MySQL | `limb.MySQL` | 8.4 and newer | `github.com/go-sql-driver/mysql` |
| MariaDB | `limb.MariaDB` | 10.11 and newer | `github.com/go-sql-driver/mysql` |
| Oracle | `limb.Oracle` | 19c and newer | `github.com/sijms/go-ora/v2` |

limb creates its tables itself, with `limb.WithAutoMigrate` or `Auth.Migrate`. Their names start with a prefix, `limb_` by default and `limb.WithTablePrefix` changes it. Every database has the same tables and columns. Migrations are written for each database in `sqlstore/migrations`, and several processes can migrate at once: one of them takes a lease on the schema and the others wait.

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

## License

Apache 2.0, see [LICENSE](LICENSE).

## Development

Requirements: Go 1.26 or newer, golangci-lint v2 and govulncheck on `PATH`.

Run every check (lint, tests with the race detector, vulnerability scan) with:

```sh
make check
```

The tests of the SQL store and the end-to-end tests of the library need a database. Every database engine has a variable of its own, and the tests run on each engine whose variable holds a DSN, as a subtest named after the engine; they are skipped when no variable is set. The variables are `LIMB_TEST_POSTGRES_DSN`, for example `postgres://user:password@localhost:5432/limb_test?sslmode=disable`, `LIMB_TEST_MYSQL_DSN` and `LIMB_TEST_MARIADB_DSN`, for example `user:password@tcp(localhost:3306)/limb_test?parseTime=true&loc=UTC`, and `LIMB_TEST_ORACLE_DSN`, for example `oracle://user:password@localhost:1521/FREEPDB1`. The user must be allowed to create and drop tables; every test works in tables with a prefix of its own and removes them afterwards. CI runs these tests against PostgreSQL 15 and 18, MySQL 8.4 and 9, MariaDB 10.11 and 11.8, and Oracle Database XE 21c and Free 23, one database in every job, and fails a job in which a test is skipped. The tests keep at most 16 connections open to Oracle, and the Oracle jobs run the packages one after another (`go test -p 1`), because a test binary per package would add up to more processes than a small Oracle instance accepts.

Comment policy: code carries no comments except godoc on exported identifiers, tool directives (`//go:...` and `//nolint:<linter>` without explanation) and `// Output:` blocks in test examples. Inline, trailing and block comments, commented-out code, license headers and TODOs are not used, and the same rule applies to YAML, Makefile and `.gitignore` files. Names and small functions are the documentation.
