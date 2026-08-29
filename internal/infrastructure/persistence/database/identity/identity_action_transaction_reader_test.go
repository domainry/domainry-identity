package identity

import (
	"context"
	"database/sql"
	"testing"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
)

type recordingActionExecutor struct {
	inner   *sql.DB
	queries int
}

func (r *recordingActionExecutor) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return r.inner.ExecContext(ctx, query, args...)
}

func (r *recordingActionExecutor) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	r.queries++
	return r.inner.QueryContext(ctx, query, args...)
}

func (r *recordingActionExecutor) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	r.queries++
	return r.inner.QueryRowContext(ctx, query, args...)
}

// TestIdentityReadsUseActionExecutionTransaction guards against the SQLite
// single-connection deadlock: identity reads issued inside a Runtime Action
// execution must reuse the transaction executor from the context instead of
// requesting a new pooled connection (which the Action transaction already
// holds exclusively when SetMaxOpenConns(1) applies).
func TestIdentityReadsUseActionExecutionTransaction(t *testing.T) {
	poolState := &identitySQLState{}
	store, cleanup := scriptedSQLIdentity(poolState)
	defer cleanup()

	executorState := &identitySQLState{}
	executorDB := sql.OpenDB(identitySQLConnector{state: executorState})
	defer executorDB.Close()
	executor := &recordingActionExecutor{inner: executorDB}

	ctx := transaction.WithExecutor(context.Background(), executor)

	if got := store.reader(ctx); got != identityReadExecutor(executor) {
		t.Fatalf("reader must return the ctx action execution executor, got %T", got)
	}
	if got := store.reader(context.Background()); got != identityReadExecutor(store.db) {
		t.Fatalf("reader without action transaction must return the pooled db, got %T", got)
	}

	if _, _, err := store.GetIdentityUser(ctx, "ws", "user-1"); err != nil {
		t.Fatalf("GetIdentityUser inside action transaction: %v", err)
	}
	if executor.queries == 0 {
		t.Fatal("GetIdentityUser inside an action transaction must query through the transaction executor")
	}
	if poolState.queryCount != 0 {
		t.Fatalf("GetIdentityUser inside an action transaction must not touch the pooled db, saw %d pooled queries", poolState.queryCount)
	}
}
