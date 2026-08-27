package changeplan

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	auditmodel "github.com/domainry/domainry-identity/internal/domain/audit/model"
	auditrepository "github.com/domainry/domainry-identity/internal/domain/audit/repository"
	changeplanpolicy "github.com/domainry/domainry-identity/internal/domain/changeplan/policy"
	changeplanrepository "github.com/domainry/domainry-identity/internal/domain/changeplan/repository"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatarepository "github.com/domainry/domainry-identity/internal/domain/metadata/repository"
)

func businessReferenceResourceType(resourceType string) string {
	return changeplanpolicy.ChangePlanCanonicalResourceType(resourceType)
}

type Runtime interface {
	CanonicalizeMetadataCandidate(context.Context, []metadatamodel.MetadataDefinitionMutation) ([]metadatamodel.MetadataDefinitionMutation, error)
	ReloadMetadata(context.Context, identitymodel.Principal) (string, error)
}

// ChangePlanApplicationService owns reviewed, idempotent Identity metadata
// publication. It does not execute business workflows or integration actions.
type ChangePlanApplicationService struct {
	repository changeplanrepository.ChangePlanRepository
	operations changeplanrepository.ChangePlanOperationRepository
	metadata   metadatarepository.DefinitionMutationRepository
	audit      auditrepository.AuditEventWriterRepository
	runtime    Runtime
}

func NewChangePlanApplicationService(repository changeplanrepository.ChangePlanRepository, metadataRepository metadatarepository.DefinitionMutationRepository, auditRepository auditrepository.AuditEventWriterRepository, runtime Runtime) *ChangePlanApplicationService {
	operations, _ := repository.(changeplanrepository.ChangePlanOperationRepository)
	return &ChangePlanApplicationService{repository: repository, operations: operations, metadata: metadataRepository, audit: auditRepository, runtime: runtime}
}

func changePlanAuthorizeQuery(principal identitymodel.Principal) error {
	if _, err := identitymodel.NewWorkspaceQueryScope(principal.WorkspaceID); !principal.Known || err != nil {
		return changePlanError(apperror.KindForbidden, "backend.workspace_scope_required", err)
	}
	return nil
}

func changePlanAuthorizeCommand(principal identitymodel.Principal) error {
	if _, err := identitymodel.NewWorkspaceCommandScope(principal.WorkspaceID); !principal.Known || err != nil {
		return changePlanError(apperror.KindForbidden, "backend.workspace_scope_required", err)
	}
	return nil
}

func badRequest(code string, params ...string) error {
	return changePlanError(apperror.KindBadRequest, code, nil, params...)
}

func forbidden(code string, params ...string) error {
	return changePlanError(apperror.KindForbidden, code, nil, params...)
}

func notFound(code string, params ...string) error {
	return changePlanError(apperror.KindNotFound, code, nil, params...)
}

func conflict(code string, params ...string) error {
	return changePlanError(apperror.KindConflict, code, nil, params...)
}

func internalError(operation string, err error) error {
	return changePlanError(apperror.KindInternal, "backend.internal", err, "operation", operation)
}

func changePlanError(kind apperror.ErrorKind, code string, err error, params ...string) error {
	values := map[string]string{}
	for index := 0; index+1 < len(params); index += 2 {
		if key := strings.TrimSpace(params[index]); key != "" {
			values[key] = params[index+1]
		}
	}
	if len(values) == 0 {
		values = nil
	}
	return &apperror.AppError{Kind: kind, Code: code, Params: values, Err: err}
}

func ErrorCodeOf(err error) string {
	var appErr *apperror.AppError
	if errors.As(err, &appErr) {
		return appErr.ErrorCode()
	}
	return "backend.internal"
}

func wrapMetadataError(err error) error {
	if err == nil {
		return nil
	}
	var appErr *apperror.AppError
	if errors.As(err, &appErr) {
		return err
	}
	var versionConflict *metadatamodel.MetadataDefinitionConflictError
	if errors.As(err, &versionConflict) {
		return conflict("backend.metadata.definition_version_conflict", "resource_type", versionConflict.ResourceType, "resource_key", versionConflict.ResourceKey, "expected_hash", versionConflict.ExpectedHash, "current_hash", versionConflict.CurrentHash)
	}
	return internalError("apply Identity metadata mutations", err)
}

func buildAuditEvent(event, objectKey, recordID string, principal identitymodel.Principal, summary string, before, after, metadataValues map[string]any) auditmodel.AuditEvent {
	metadataValues = cloneChangeMap(metadataValues)
	metadataValues["request_id"] = principal.RequestID
	metadataValues["actor_id"] = principal.UserID
	metadataValues["role_key"] = principal.Role.Key
	metadataValues["workspace_id"] = strings.TrimSpace(principal.WorkspaceID)
	now := time.Now().UTC()
	actorID := strings.TrimSpace(principal.UserID)
	if actorID == "" {
		actorID = "system"
	}
	return auditmodel.AuditEvent{ID: auditmodel.NewEventID(now), WorkspaceID: principal.WorkspaceID, Event: event, ObjectKey: objectKey, RecordID: recordID, ActorID: actorID, RoleKey: principal.Role.Key, Summary: summary, Before: cloneChangeMap(before), After: cloneChangeMap(after), Metadata: metadataValues, CreatedAt: now.Format(time.RFC3339)}
}

func cloneChangeMap(source map[string]any) map[string]any {
	if source == nil {
		return map[string]any{}
	}
	raw, _ := json.Marshal(source)
	result := map[string]any{}
	_ = json.Unmarshal(raw, &result)
	return result
}
