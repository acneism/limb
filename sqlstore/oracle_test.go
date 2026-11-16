package sqlstore

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type OracleError struct {
	ErrCode int
	Message string
}

func (e OracleError) Error() string {
	return fmt.Sprintf("ORA-%05d: %s", e.ErrCode, e.Message)
}

func TestOracleDialectRecognizesTheErrorsOfTheDriver(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want verdict
	}{
		{"a duplicate key", &OracleError{ErrCode: 1}, verdict{unique: true}},
		{"a parent key that is missing", &OracleError{ErrCode: 2291}, verdict{foreignKey: true}},
		{"a child record that is found", &OracleError{ErrCode: 2292}, verdict{foreignKey: true}},
		{"a table that is missing", &OracleError{ErrCode: 942}, verdict{missingTable: true}},
		{"a name that is in use", &OracleError{ErrCode: 955}, verdict{exists: true}},
		{"a constraint that exists", &OracleError{ErrCode: 2275}, verdict{exists: true}},
		{"a deadlock", &OracleError{ErrCode: 60}, verdict{retryable: true}},
		{"a value that is too long", &OracleError{ErrCode: 12899}, verdict{}},
		{"a check constraint", &OracleError{ErrCode: 2290}, verdict{}},
		{"an error by value", OracleError{ErrCode: 1}, verdict{unique: true}},
		{"a wrapped error", fmt.Errorf("insert: %w", fmt.Errorf("driver: %w", &OracleError{ErrCode: 60})), verdict{retryable: true}},
		{"a joined error", errors.Join(errors.New("first"), &OracleError{ErrCode: 942}), verdict{missingTable: true}},
		{"a plain error", errors.New("ORA-00001"), verdict{}},
		{"no error", nil, verdict{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := verdict{
				unique: Oracle.IsUniqueViolation(tc.err), foreignKey: Oracle.IsForeignKeyViolation(tc.err),
				missingTable: Oracle.IsMissingTable(tc.err), exists: Oracle.IsAlreadyExists(tc.err), retryable: Oracle.IsRetryable(tc.err),
			}
			if got != tc.want {
				t.Fatalf("the dialect recognized %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestOracleDialectIsDescribed(t *testing.T) {
	if Oracle.Name() != "oracle" || Oracle.Placeholder(1) != ":1" || Oracle.Placeholder(12) != ":12" {
		t.Fatalf("the dialect is %q with the placeholders %q and %q", Oracle.Name(), Oracle.Placeholder(1), Oracle.Placeholder(12))
	}
	if options := Oracle.TxOptions(); options != nil {
		t.Fatalf("the options of a transaction are %+v: the driver accepts only its default, which is READ COMMITTED", options)
	}
	insert := Oracle.InsertIgnoring("t", []string{"a", "b", "c"}, []string{"?", "?", "1"}, []string{"a", "b"})
	want := "MERGE INTO t t USING (SELECT ? a, ? b, 1 c FROM dual) s ON (t.a = s.a AND t.b = s.b) " +
		"WHEN NOT MATCHED THEN INSERT (a, b, c) VALUES (s.a, s.b, s.c)"
	if insert != want {
		t.Fatalf("InsertIgnoring = %q, want %q", insert, want)
	}
	if err := Oracle.CheckUpdateCount(0); err != nil {
		t.Fatalf("CheckUpdateCount = %v: Oracle reports the rows that an UPDATE matched", err)
	}
	if err := Oracle.CheckUpdateCount(1); err != nil {
		t.Fatalf("CheckUpdateCount = %v: Oracle reports the rows that an UPDATE matched", err)
	}
}

func TestTheInsertThatIgnoresAConflictTakesItsParametersInOrder(t *testing.T) {
	_, db := newStub(t, nil)
	s, err := New(db, Oracle)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(s.q.insertAttempt, ":"); got != 2 {
		t.Fatalf("the statement %q has %d parameters, want 2", s.q.insertAttempt, got)
	}
	if !strings.Contains(s.q.insertAttempt, "SELECT :1 attempt_key, :2 window_start, 1 hit_count FROM dual") {
		t.Fatalf("the parameters are not in the order of the columns: %q", s.q.insertAttempt)
	}
}

func checkOracleWithProbe(t *testing.T, row []driver.Value, queryErr error) error {
	t.Helper()
	probe, db := newStub(t, func(string, int) error { return queryErr })
	probe.rows = func(string, int) ([]string, [][]driver.Value) {
		return []string{"read", "received", "echoed", "same"}, [][]driver.Value{row}
	}
	return Oracle.Check(t.Context(), db)
}

func TestOracleCheckReadsTheProbe(t *testing.T) {
	moment := time.Date(2001, 2, 3, 4, 5, 6, 789000000, time.UTC)
	text := "2001-02-03 04:05:06.789000"
	bytes := []byte{0, 1, 2, 0, 255, 0}
	cases := []struct {
		name string
		row  []driver.Value
		want string
	}{
		{"a connection that is set up well", []driver.Value{moment, text, bytes, int64(0)}, ""},
		{"the same instant in another zone", []driver.Value{moment.In(time.FixedZone("UTC+9", 9*60*60)), text, bytes, int64(0)}, ""},
		{"a time that reached the server shifted", []driver.Value{moment, "2001-02-03 13:05:06.789000", bytes, int64(0)}, "time zone"},
		{"a time that came back shifted", []driver.Value{moment.Add(time.Hour), text, bytes, int64(0)}, "time zone"},
		{"bytes that came back changed", []driver.Value{moment, text, []byte{0, 1, 2}, int64(0)}, "bytes"},
		{"a session that ignores case", []driver.Value{moment, text, bytes, int64(1)}, "NLS_COMP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkOracleWithProbe(t, tc.row, nil)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("Check = %v, want nil", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("Check = %v, want an error that mentions %q", err, tc.want)
			}
		})
	}
}

func TestOracleCheckReportsAFailureOfTheProbe(t *testing.T) {
	broken := errors.New("the listener is gone")
	err := checkOracleWithProbe(t, nil, broken)
	if !errors.Is(err, broken) || !strings.Contains(err.Error(), "check the oracle connection") {
		t.Fatalf("Check = %v, want the error of the probe", err)
	}
}
