package transaction

import (
	"context"
	"database/sql"
)

type actionExecutionContextKey struct{}

// Executor is the adapter-private SQL surface shared by
// persistence collaborators inside one Runtime Action transaction. It omits
// lifecycle methods so callers cannot commit or roll back the transaction.
type Executor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func WithExecutor(
	ctx context.Context,
	executor Executor,
) context.Context {
	if ctx == nil || executor == nil {
		return ctx
	}
	return context.WithValue(ctx, actionExecutionContextKey{}, executor)
}

func ExecutorFromContext(ctx context.Context) Executor {
	if ctx == nil {
		return nil
	}
	executor, _ := ctx.Value(actionExecutionContextKey{}).(Executor)
	return executor
}
