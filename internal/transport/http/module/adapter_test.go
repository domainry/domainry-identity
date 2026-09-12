package module

import (
	"context"
	"net/http"
	"testing"

	"github.com/domainry/domainry-foundation/modulehttp"
)

type auditRecorderStub struct{ calls int }

func (recorder *auditRecorderStub) Record(context.Context, modulehttp.AuditEvent) error {
	recorder.calls++
	return nil
}

func TestAdapterExposesSourceOwnedAuditRecorder(t *testing.T) {
	recorder := &auditRecorderStub{}
	adapter := NewAdapter("management", http.NotFoundHandler(), nil, recorder)
	if err := adapter.Record(t.Context(), modulehttp.AuditEvent{Event: "auth_api_denied"}); err != nil || recorder.calls != 1 {
		t.Fatalf("record calls=%d err=%v", recorder.calls, err)
	}
}
