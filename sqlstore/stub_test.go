package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"sync"
	"testing"
)

type stub struct {
	mu        sync.Mutex
	options   []driver.TxOptions
	begins    int
	commits   int
	rollbacks int
	queries   []string
	script    func(query string, n int) error
	affect    func(query string, n int) int64
	rows      func(query string, n int) ([]string, [][]driver.Value)
	counts    map[string]int
}

func newStub(t *testing.T, script func(query string, n int) error) (*stub, *sql.DB) {
	t.Helper()
	s := &stub{script: script, counts: map[string]int{}}
	db := sql.OpenDB(s)
	t.Cleanup(func() { _ = db.Close() })
	return s, db
}

func (s *stub) Connect(context.Context) (driver.Conn, error) {
	return &stubConn{s: s}, nil
}

func (s *stub) Driver() driver.Driver {
	return stubDriver{s: s}
}

type stubDriver struct{ s *stub }

func (d stubDriver) Open(string) (driver.Conn, error) {
	return &stubConn{s: d.s}, nil
}

type stubConn struct{ s *stub }

func (c *stubConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("the stub runs statements without preparing them")
}

func (c *stubConn) Close() error {
	return nil
}

func (c *stubConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *stubConn) BeginTx(_ context.Context, opts driver.TxOptions) (driver.Tx, error) {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	c.s.options = append(c.s.options, opts)
	c.s.begins++
	return &stubTx{s: c.s}, nil
}

func (c *stubConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.s.mu.Lock()
	c.s.queries = append(c.s.queries, query)
	c.s.counts[query]++
	n := c.s.counts[query]
	script, affect := c.s.script, c.s.affect
	c.s.mu.Unlock()
	if script != nil {
		if err := script(query, n); err != nil {
			return nil, err
		}
	}
	if affect != nil {
		return driver.RowsAffected(affect(query, n)), nil
	}
	return driver.RowsAffected(1), nil
}

func (c *stubConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.s.mu.Lock()
	c.s.queries = append(c.s.queries, query)
	c.s.counts[query]++
	n := c.s.counts[query]
	script, rows := c.s.script, c.s.rows
	c.s.mu.Unlock()
	if script != nil {
		if err := script(query, n); err != nil {
			return nil, err
		}
	}
	if rows == nil {
		return &stubRows{}, nil
	}
	columns, data := rows(query, n)
	return &stubRows{columns: columns, data: data}, nil
}

type stubRows struct {
	columns []string
	data    [][]driver.Value
	next    int
}

func (r *stubRows) Columns() []string {
	return r.columns
}

func (r *stubRows) Close() error {
	return nil
}

func (r *stubRows) Next(dest []driver.Value) error {
	if r.next >= len(r.data) {
		return io.EOF
	}
	copy(dest, r.data[r.next])
	r.next++
	return nil
}

type stubTx struct{ s *stub }

func (t *stubTx) Commit() error {
	t.s.mu.Lock()
	defer t.s.mu.Unlock()
	t.s.commits++
	return nil
}

func (t *stubTx) Rollback() error {
	t.s.mu.Lock()
	defer t.s.mu.Unlock()
	t.s.rollbacks++
	return nil
}

type stubError struct{ state string }

func (e stubError) Error() string {
	return "stub error " + e.state
}

func (e stubError) SQLState() string {
	return e.state
}

var (
	errDeadlock = stubError{state: "40P01"}
	errOther    = stubError{state: "23505"}
)
