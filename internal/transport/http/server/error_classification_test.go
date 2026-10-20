package httpserver

import (
	"net/http/httptest"
	"testing"
)

type classificationCapture struct {
	*httptest.ResponseRecorder
	kind, code string
}

func (capture *classificationCapture) RecordError(kind, code string) {
	capture.kind, capture.code = kind, code
}

func TestIdentityErrorClassificationMatrix(t *testing.T) {
	tests := []struct {
		status int
		kind   string
		code   string
	}{
		{503, "unavailable", "identity.database_unavailable"},
		{409, "conflict", "identity.write_fence_rejected"},
		{400, "bad_request", "identity.validation_failed"},
		{403, "forbidden", "identity.permission_denied"},
	}
	for _, test := range tests {
		capture := &classificationCapture{ResponseRecorder: httptest.NewRecorder()}
		new(httpSupport).writeError(capture, nil, test.status, test.code)
		if capture.kind != test.kind || capture.code != test.code {
			t.Fatalf("status=%d kind=%q code=%q", test.status, capture.kind, capture.code)
		}
	}
}
