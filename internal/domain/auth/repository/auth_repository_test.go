package repository

import (
	"reflect"
	"testing"
)

func TestAuthRepositoryMethodBudget(t *testing.T) {
	t.Parallel()
	const budget = 15
	if methods := reflect.TypeOf((*AuthRepository)(nil)).Elem().NumMethod(); methods > budget {
		t.Fatalf("auth AuthRepository grew to %d methods; budget is %d", methods, budget)
	}
}
