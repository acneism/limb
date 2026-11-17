package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"
)

const (
	oracleUniqueViolation     = 1
	oracleDeadlock            = 60
	oracleNoSuchTable         = 942
	oracleNameInUse           = 955
	oracleColumnExists        = 1430
	oracleConstraintExists    = 2275
	oracleParentKeyMissing    = 2291
	oracleChildRecordFound    = 2292
	oracleProbeTimeLayout     = "2006-01-02 15:04:05.000000"
	oracleProbeTimeConversion = "YYYY-MM-DD HH24:MI:SS.FF6"
)

var (
	oracleProbeMoment = time.Date(2001, 2, 3, 4, 5, 6, 789000000, time.UTC)
	oracleProbeBytes  = []byte{0, 1, 2, 0, 255, 0}
)

// Oracle is the dialect of Oracle Database 19c and newer. It is made for the
// driver github.com/sijms/go-ora/v2.
var Oracle Dialect = oracleDialect{}

type oracleDialect struct{}

func (oracleDialect) Name() string {
	return "oracle"
}

func (oracleDialect) Placeholder(n int) string {
	return ":" + strconv.Itoa(n)
}

func oracleCode(err error) int64 {
	code, _ := driverCode(err, "OracleError", "ErrCode")
	return code
}

func (oracleDialect) IsUniqueViolation(err error) bool {
	return oracleCode(err) == oracleUniqueViolation
}

func (oracleDialect) IsForeignKeyViolation(err error) bool {
	switch oracleCode(err) {
	case oracleParentKeyMissing, oracleChildRecordFound:
		return true
	}
	return false
}

func (oracleDialect) IsMissingTable(err error) bool {
	return oracleCode(err) == oracleNoSuchTable
}

func (oracleDialect) IsAlreadyExists(err error) bool {
	switch oracleCode(err) {
	case oracleNameInUse, oracleColumnExists, oracleConstraintExists:
		return true
	}
	return false
}

func (oracleDialect) IsRetryable(err error) bool {
	return oracleCode(err) == oracleDeadlock
}

func (oracleDialect) TxOptions() *sql.TxOptions {
	return nil
}

func (oracleDialect) InsertIgnoring(table string, columns, values, key []string) string {
	selected := make([]string, len(columns))
	inserted := make([]string, len(columns))
	for i, column := range columns {
		selected[i] = values[i] + " " + column
		inserted[i] = "s." + column
	}
	matched := make([]string, len(key))
	for i, column := range key {
		matched[i] = "t." + column + " = s." + column
	}
	return "MERGE INTO " + table + " t USING (SELECT " + strings.Join(selected, ", ") + " FROM dual) s ON (" +
		strings.Join(matched, " AND ") + ") WHEN NOT MATCHED THEN INSERT (" + strings.Join(columns, ", ") +
		") VALUES (" + strings.Join(inserted, ", ") + ")"
}

func (oracleDialect) Check(ctx context.Context, db *sql.DB) error {
	var read time.Time
	var received string
	var echoed []byte
	var sameCase int
	err := db.QueryRowContext(ctx, "SELECT :1, TO_CHAR(:2 AT TIME ZONE 'UTC', '"+oracleProbeTimeConversion+"'), :3, "+
		"CASE WHEN 'a' = 'A' THEN 1 ELSE 0 END FROM dual",
		oracleProbeMoment, oracleProbeMoment, oracleProbeBytes).Scan(&read, &received, &echoed, &sameCase)
	if err != nil {
		return fmt.Errorf("check the oracle connection: %w", err)
	}
	if want := oracleProbeMoment.Format(oracleProbeTimeLayout); received != want || !read.Equal(oracleProbeMoment) {
		return fmt.Errorf("a time sent as %s UTC reached oracle as %s and came back as %s: times must travel with "+
			"their time zone, which the driver takes from the location of the time", want, received, read.UTC().Format(oracleProbeTimeLayout))
	}
	if string(echoed) != string(oracleProbeBytes) {
		return fmt.Errorf("bytes sent to oracle as % x came back as % x", oracleProbeBytes, echoed)
	}
	if sameCase != 0 {
		return errors.New("oracle compares strings without regard to case: set NLS_COMP and NLS_SORT of the session to BINARY")
	}
	return nil
}

func (oracleDialect) CheckUpdateCount(int64) error {
	return nil
}

func (oracleDialect) Limit(n int) string {
	return " FETCH FIRST " + strconv.Itoa(n) + " ROWS ONLY"
}

func (oracleDialect) Migrations() fs.FS {
	return oracleMigrations
}
