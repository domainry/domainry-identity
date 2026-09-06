package moduleassembly

import (
	"context"
	"database/sql"
	"reflect"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitytransaction "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
)

type contextManagedTransaction interface {
	identitytransaction.Executor
	Commit(context.Context) error
	Rollback(context.Context) error
}

// embeddedTransactionExecutor narrows the SDK carrier to the private SQL
// executor used by Identity persistence. A pool or bare connection is not a
// transaction and is rejected even though it implements the same DBTX calls.
func embeddedTransactionExecutor(transaction identitysdk.EmbeddedTransaction) (identitytransaction.Executor, bool) {
	executor := transaction.Executor
	if executor == nil || nilInterfaceValue(executor) {
		return nil, false
	}
	switch value := executor.(type) {
	case *sql.DB:
		return nil, false
	case *sql.Tx:
		if value == nil {
			return nil, false
		}
		return value, true
	case contextManagedTransaction:
		if nilInterfaceValue(value) {
			return nil, false
		}
		return value, true
	default:
		return nil, false
	}
}

func nilInterfaceValue(value any) bool {
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
