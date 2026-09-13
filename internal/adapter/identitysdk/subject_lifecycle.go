package identitysdkadapter

import (
	"context"
	"encoding/json"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	privacy "github.com/domainry/domainry-identity/internal/domain/privacy"
	"net/http"
	"strings"
)

type SubjectLifecycle interface {
	PreviewSubject(context.Context, string, string) (json.RawMessage, error)
	ExportSubject(context.Context, string, string) (json.RawMessage, error)
	EraseSubjectForRequest(context.Context, string, string, string, []privacy.LegalHold) (json.RawMessage, error)
}

func (binding *sdkBinding) SystemSubjects() identitysdk.SystemSubjects {
	return sdkSystemSubjects{binding}
}

type sdkSystemSubjects struct{ binding *sdkBinding }

func (adapter sdkSystemSubjects) validate(ctx context.Context, workspaceID, subjectID string) error {
	if adapter.binding.subjects == nil {
		return &identitysdk.Error{StatusCode: http.StatusNotImplemented, Code: "identity.subject_lifecycle_unavailable"}
	}
	if !identitysdk.WorkspaceID(workspaceID).Valid() || workspaceID != requestcontext.WorkspaceID(ctx) {
		return &identitysdk.Error{StatusCode: http.StatusForbidden, Code: "auth.workspace_mismatch"}
	}
	if strings.TrimSpace(subjectID) == "" {
		return &identitysdk.Error{StatusCode: http.StatusBadRequest, Code: "identity.subject_id_invalid"}
	}
	return nil
}
func (adapter sdkSystemSubjects) PreviewSubject(ctx context.Context, workspaceID, subjectID string) (json.RawMessage, error) {
	if err := adapter.validate(ctx, workspaceID, subjectID); err != nil {
		return nil, err
	}
	return adapter.binding.subjects.PreviewSubject(ctx, workspaceID, subjectID)
}
func (adapter sdkSystemSubjects) ExportSubject(ctx context.Context, workspaceID, subjectID string) (json.RawMessage, error) {
	if err := adapter.validate(ctx, workspaceID, subjectID); err != nil {
		return nil, err
	}
	return adapter.binding.subjects.ExportSubject(ctx, workspaceID, subjectID)
}
func (adapter sdkSystemSubjects) EraseSubjectForRequest(ctx context.Context, request identitysdk.SubjectErasureRequest) (json.RawMessage, error) {
	if err := adapter.validate(ctx, request.WorkspaceID, request.SubjectID); err != nil {
		return nil, err
	}
	var holds []privacy.LegalHold
	if len(request.LegalHolds) > 0 {
		if err := json.Unmarshal(request.LegalHolds, &holds); err != nil {
			return nil, &identitysdk.Error{StatusCode: http.StatusBadRequest, Code: "identity.subject_legal_holds_invalid"}
		}
	}
	if len(holds) > 0 {
		return nil, &identitysdk.Error{StatusCode: http.StatusConflict, Code: "identity.subject_legal_hold"}
	}
	return adapter.binding.subjects.EraseSubjectForRequest(ctx, request.RequestID, request.WorkspaceID, request.SubjectID, holds)
}
