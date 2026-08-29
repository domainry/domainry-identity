package transaction

import (
	"database/sql"
	"testing"
)

func TestExecutorContextEdges(t *testing.T) {
	var executor *sql.DB
	if WithExecutor(nil, executor) != nil {
		t.Fatal("nil context changed")
	}
	if got := WithExecutor(t.Context(), nil); got != t.Context() {
		t.Fatal("nil executor changed context")
	}
	if ExecutorFromContext(nil) != nil {
		t.Fatal("nil context returned executor")
	}
	ctx := WithExecutor(t.Context(), executor)
	if ExecutorFromContext(ctx) != executor {
		t.Fatal("executor was not preserved")
	}
	if ExecutorFromContext(t.Context()) != nil {
		t.Fatal("plain context returned executor")
	}
}
