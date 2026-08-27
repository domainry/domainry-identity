package authoring

import "testing"

func TestTrustedBuilderTaskIDContext(t *testing.T) {
	if WithTrustedBuilderTaskID(nil, "task") != nil || TrustedBuilderTaskID(nil) != "" {
		t.Fatal("nil context contract changed")
	}
	ctx := WithTrustedBuilderTaskID(t.Context(), " task-1 ")
	if got := TrustedBuilderTaskID(ctx); got != "task-1" {
		t.Fatalf("trusted builder task id = %q", got)
	}
	if got := TrustedBuilderTaskID(WithTrustedBuilderTaskID(ctx, " ")); got != "task-1" {
		t.Fatalf("blank value replaced trusted builder task id: %q", got)
	}
}
