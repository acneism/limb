package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	mysqlDuplicateEntry      = 1062
	mysqlParentRowReferenced = 1451
	mysqlParentRowMissing    = 1452
	mysqlNoSuchTable         = 1146
	mysqlTableExists         = 1050
	mysqlDuplicateColumn     = 1060
	mysqlDuplicateKeyName    = 1061
	mysqlDuplicateConstraint = 1826
	mysqlDuplicateCheck      = 3822
	mysqlDeadlock            = 1213

	mysqlTimeLayout = "2006-01-02 15:04:05.999999"
	mysqlProbeRunes = "\U0001F600 \u00e9"
)

var mysqlProbeMoment = time.Date(2001, 2, 3, 4, 5, 6, 789000000, time.UTC)

// MySQL is the dialect of MySQL 8.4 and newer. It is made for the driver
// github.com/go-sql-driver/mysql, whose DSN has to contain parseTime=true and
// loc=UTC and must not contain clientFoundRows=true.
var MySQL Dialect = mysqlDialect{name: "mysql", migrations: mysqlMigrations}

// MariaDB is the dialect of MariaDB 10.11 and newer. It is made for the driver
// github.com/go-sql-driver/mysql, whose DSN has to contain parseTime=true and
// loc=UTC and must not contain clientFoundRows=true.
var MariaDB Dialect = mysqlDialect{name: "mariadb", migrations: mariadbMigrations}

type mysqlDialect struct {
	name       string
	migrations fs.FS
}

func (d mysqlDialect) Name() string {
	return d.name
}

func (mysqlDialect) Placeholder(int) string {
	return "?"
}

func mysqlNumber(err error) int64 {
	number, _ := driverCode(err, "MySQLError", "Number")
	return number
}

func (mysqlDialect) IsUniqueViolation(err error) bool {
	return mysqlNumber(err) == mysqlDuplicateEntry
}

func (mysqlDialect) IsForeignKeyViolation(err error) bool {
	switch mysqlNumber(err) {
	case mysqlParentRowMissing, mysqlParentRowReferenced:
		return true
	}
	return false
}

func (mysqlDialect) IsMissingTable(err error) bool {
	return mysqlNumber(err) == mysqlNoSuchTable
}

func (mysqlDialect) IsAlreadyExists(err error) bool {
	switch mysqlNumber(err) {
	case mysqlTableExists, mysqlDuplicateColumn, mysqlDuplicateKeyName, mysqlDuplicateConstraint, mysqlDuplicateCheck:
		return true
	}
	return false
}

func (mysqlDialect) IsRetryable(err error) bool {
	return mysqlNumber(err) == mysqlDeadlock
}

func (mysqlDialect) TxOptions() *sql.TxOptions {
	return &sql.TxOptions{Isolation: sql.LevelReadCommitted}
}

func (mysqlDialect) InsertIgnoring(table string, columns, values, key []string) string {
	return "INSERT INTO " + table + " (" + strings.Join(columns, ", ") + ") VALUES (" + strings.Join(values, ", ") +
		") ON DUPLICATE KEY UPDATE " + key[0] + " = " + key[0]
}

func (d mysqlDialect) Check(ctx context.Context, db *sql.DB) error {
	var received string
	var read any
	var counted int
	err := db.QueryRowContext(ctx, "SELECT CAST(? AS CHAR), CAST(? AS DATETIME(6)), CHAR_LENGTH(?)",
		mysqlProbeMoment, mysqlProbeMoment, mysqlProbeRunes).Scan(&received, &read, &counted)
	if err != nil {
		return fmt.Errorf("check the %s connection: %w", d.name, err)
	}
	readTime, isTime := read.(time.Time)
	if !isTime {
		return fmt.Errorf("the DSN of the %s driver lacks parseTime=true: without it times are read as text", d.name)
	}
	if arrived, parseErr := time.Parse(mysqlTimeLayout, received); parseErr != nil || !arrived.Equal(mysqlProbeMoment) {
		return fmt.Errorf("the DSN of the %s driver lacks loc=UTC: a time sent as %s UTC reached the server as %s",
			d.name, mysqlProbeMoment.Format(mysqlTimeLayout), received)
	}
	if !readTime.Equal(mysqlProbeMoment) {
		return fmt.Errorf("a time sent as %s UTC to %s was read back as %s: check parseTime=true and loc=UTC in the DSN",
			mysqlProbeMoment.Format(mysqlTimeLayout), d.name, readTime.Format(mysqlTimeLayout))
	}
	if counted != utf8.RuneCountInString(mysqlProbeRunes) {
		return fmt.Errorf("the connection to %s does not carry four byte characters: use the character set utf8mb4, "+
			"which is the default of the driver", d.name)
	}
	return nil
}

func (d mysqlDialect) CheckUpdateCount(reported int64) error {
	if reported != 0 {
		return errors.New("the DSN of the " + d.name + " driver contains clientFoundRows=true: remove it, " +
			"limb needs the number of rows that an UPDATE changed")
	}
	return nil
}

func (d mysqlDialect) Migrations() fs.FS {
	return d.migrations
}
