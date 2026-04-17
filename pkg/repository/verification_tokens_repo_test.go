package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/pkg/domain"
)

type mockVerificationQuerier struct {
	execQuery string
	execArgs  []interface{}
	execErr   error
}

func (m *mockVerificationQuerier) ExecContext(_ context.Context, query string, args ...interface{}) (sql.Result, error) {
	m.execQuery = query
	m.execArgs = args
	if m.execErr != nil {
		return nil, m.execErr
	}
	return mockSQLResult(1), nil
}

func (m *mockVerificationQuerier) QueryContext(_ context.Context, _ string, _ ...interface{}) (*sql.Rows, error) {
	return nil, errors.New("not implemented")
}

func (m *mockVerificationQuerier) QueryRowContext(_ context.Context, _ string, _ ...interface{}) *sql.Row {
	return nil
}

type mockSQLResult int64

func (m mockSQLResult) LastInsertId() (int64, error) {
	return 0, nil
}

func (m mockSQLResult) RowsAffected() (int64, error) {
	return int64(m), nil
}

func TestVerificationTokensRepository_RevokeActiveTokensTx_RevokesAllUnconsumed(t *testing.T) {
	repo := NewVerificationTokensRepository(nil)
	q := &mockVerificationQuerier{}
	userID := uuid.New()
	kind := domain.TokenKindPasswordReset

	err := repo.RevokeActiveTokensTx(context.Background(), q, userID, kind)
	if err != nil {
		t.Fatalf("RevokeActiveTokensTx() error = %v", err)
	}

	compactQuery := strings.Join(strings.Fields(q.execQuery), " ")
	if !strings.Contains(compactQuery, "consumed_at IS NULL") {
		t.Fatalf("query should filter unconsumed tokens, got: %q", compactQuery)
	}
	if strings.Contains(compactQuery, "expires_at > NOW()") {
		t.Fatalf("query should not filter by expiry, got: %q", compactQuery)
	}

	if len(q.execArgs) != 2 {
		t.Fatalf("expected 2 args, got %d", len(q.execArgs))
	}
	if got, ok := q.execArgs[0].(uuid.UUID); !ok || got != userID {
		t.Fatalf("arg[0] = %#v, want userID %s", q.execArgs[0], userID)
	}
	if got, ok := q.execArgs[1].(domain.VerificationTokenKind); !ok || got != kind {
		t.Fatalf("arg[1] = %#v, want kind %s", q.execArgs[1], kind)
	}
}

func TestVerificationTokensRepository_RevokeActiveTokensTx_PropagatesExecError(t *testing.T) {
	repo := NewVerificationTokensRepository(nil)
	expectedErr := errors.New("exec failed")
	q := &mockVerificationQuerier{execErr: expectedErr}

	err := repo.RevokeActiveTokensTx(context.Background(), q, uuid.New(), domain.TokenKindPasswordReset)
	if !errors.Is(err, expectedErr) {
		t.Fatalf("RevokeActiveTokensTx() error = %v, want %v", err, expectedErr)
	}
}
