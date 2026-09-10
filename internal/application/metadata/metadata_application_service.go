package metadata

import (
	"bytes"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	metadatacontract "github.com/domainry/domainry-identity/internal/domain/metadata/contract"
	metadatarepository "github.com/domainry/domainry-identity/internal/domain/metadata/repository"
	metadatavalidation "github.com/domainry/domainry-identity/internal/domain/metadata/validation"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	"context"
	"encoding/json"

	auditmodel "github.com/domainry/domainry-audit-sdk/contract"
	auditcontract "github.com/domainry/domainry-identity/internal/application/auditbinding"

	"strings"
	"sync"

	"github.com/domainry/domainry-foundation/idempotency"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

// MetadataApplicationService owns metadata authoring, lifecycle, dictionary and
// localization entrypoints. Cross-domain behavior is exposed through narrow
// runtime ports; the service does not retain the aggregate RuntimeServices.
// MetadataApplicationService owns metadata lifecycle behavior.
type MetadataApplicationService struct {
	repository        metadatarepository.MetadataRepository
	permissions       MetadataPermissionSelectionValidator
	runtime           LifecycleRuntime
	audit             auditcontract.AuditEventFactory
	templateID        string
	version           string
	name              string
	auditAppender     MetadataAuditAppender
	reloadObserversMu sync.RWMutex
	reloadObservers   []MetadataReloadObserver
	reloadMu          sync.Mutex
}

// MetadataReloadCommit publishes one already-prepared dependent snapshot. It
// cannot fail: every validation and external reconciliation step must finish
// before the observer returns it.
type MetadataReloadCommit func()

// MetadataReloadObserver prepares a dependent snapshot without publishing it.
// Returning an error aborts activation and leaves both the runtime snapshot and
// every previously prepared dependent snapshot unchanged.
type MetadataReloadObserver func(context.Context, metadatamodel.MetadataSchemaSnapshot) (MetadataReloadCommit, error)

func (s *MetadataApplicationService) AddReloadObserver(observer MetadataReloadObserver) {
	if s == nil || observer == nil {
		return
	}
	s.reloadObserversMu.Lock()
	defer s.reloadObserversMu.Unlock()
	s.reloadObservers = append(s.reloadObservers, observer)
}

func (s *MetadataApplicationService) prepareReloadObservers(ctx context.Context, snapshot metadatamodel.MetadataSchemaSnapshot) ([]MetadataReloadCommit, error) {
	s.reloadObserversMu.RLock()
	observers := append([]MetadataReloadObserver(nil), s.reloadObservers...)
	s.reloadObserversMu.RUnlock()
	commits := make([]MetadataReloadCommit, 0, len(observers))
	for _, observer := range observers {
		commit, err := observer(ctx, snapshot)
		if err != nil {
			return nil, err
		}
		if commit != nil {
			commits = append(commits, commit)
		}
	}
	return commits, nil
}

type MetadataAuditAppender func(context.Context, string, string, string, identitymodel.Principal, string, map[string]any, map[string]any, map[string]any)

type LifecycleRuntime interface {
	ActivateMetadata(metadatamodel.MetadataSchemaSnapshot)
	Schema() metadatamodel.MetadataSchemaSnapshot
}

type MetadataApplicationDependencies struct {
	Repository    metadatarepository.MetadataRepository
	Permissions   MetadataPermissionSelectionValidator
	Runtime       LifecycleRuntime
	Audit         auditcontract.AuditEventFactory
	TemplateID    string
	Version       string
	Name          string
	AuditAppender MetadataAuditAppender
}

func NewMetadataApplicationService(dependencies MetadataApplicationDependencies) *MetadataApplicationService {
	return &MetadataApplicationService{
		repository: dependencies.Repository, permissions: dependencies.Permissions, runtime: dependencies.Runtime,
		audit: dependencies.Audit, templateID: dependencies.TemplateID,
		version: dependencies.Version, name: dependencies.Name,
		auditAppender: dependencies.AuditAppender,
	}
}

func (s *MetadataApplicationService) RollbackMetadataDefinition(ctx context.Context, resourceType, resourceKey string, request metadatamodel.MetadataDefinitionRollbackRequest, principal identitymodel.Principal) (metadatamodel.MetadataDefinition, metadatamodel.MetadataSchemaSnapshot, error) {
	if err := metadataAuthorizeCommand(principal); err != nil {
		return metadatamodel.MetadataDefinition{}, metadatamodel.MetadataSchemaSnapshot{}, err
	}
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, metadatacontract.MetadataActionDefinitionRollback) {
		return metadatamodel.MetadataDefinition{}, metadatamodel.MetadataSchemaSnapshot{}, forbidden("auth.permission_denied")
	}
	resourceType, resourceKey = strings.TrimSpace(resourceType), strings.TrimSpace(resourceKey)
	if code := metadatavalidation.MetadataRollbackRequestErrorCode(request); code != "" {
		return metadatamodel.MetadataDefinition{}, metadatamodel.MetadataSchemaSnapshot{}, badRequest(code)
	}
	current, found, err := s.repository.GetDefinition(ctx, metadataInstallationScope("load metadata definition for rollback"), resourceType, resourceKey)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, metadatamodel.MetadataSchemaSnapshot{}, wrapMetadataError(err)
	}
	if !found {
		return metadatamodel.MetadataDefinition{}, metadatamodel.MetadataSchemaSnapshot{}, notFound("backend.metadata.definition_not_found")
	}
	versions, err := s.repository.ListDefinitionVersions(ctx, metadataInstallationScope("list metadata rollback versions"), resourceType, resourceKey)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, metadatamodel.MetadataSchemaSnapshot{}, wrapMetadataError(err)
	}
	var target metadatamodel.MetadataDefinitionVersion
	for _, version := range versions {
		if version.SchemaVersion == request.TargetVersion {
			target = version
			break
		}
	}
	if target.SchemaVersion == "" {
		return metadatamodel.MetadataDefinition{}, metadatamodel.MetadataSchemaSnapshot{}, notFound("backend.metadata.rollback_target_not_found")
	}
	canonical, err := s.CanonicalizeMetadataCandidate(ctx, []metadatamodel.MetadataDefinitionMutation{{Operation: "update", ResourceType: resourceType, ResourceKey: resourceKey, Request: metadatamodel.MetadataDefinitionUpsertRequest{ObjectKey: current.ObjectKey, Payload: target.Payload}}})
	if err != nil {
		return metadatamodel.MetadataDefinition{}, metadatamodel.MetadataSchemaSnapshot{}, err
	}
	if len(canonical) == 1 {
		target.Payload = canonical[0].Request.Payload
	}
	if s.audit == nil {
		return metadatamodel.MetadataDefinition{}, metadatamodel.MetadataSchemaSnapshot{}, metadataInternalError("build metadata rollback audit")
	}
	audit := buildRollbackAudit(ctx, s.audit, resourceType, resourceKey, current, target, request, principal)
	definition, err := s.repository.RollbackDefinition(ctx, metadataInstallationScope("rollback metadata definition"), resourceType, resourceKey, request, audit, metadataPublicationForPrincipal(principal))
	if err != nil {
		return metadatamodel.MetadataDefinition{}, metadatamodel.MetadataSchemaSnapshot{}, wrapMetadataError(err)
	}
	snapshot, err := s.ReloadMetadata(ctx, principal)
	return definition, snapshot, err
}

func buildRollbackAudit(ctx context.Context, factory auditcontract.AuditEventFactory, resourceType, resourceKey string, current metadatamodel.MetadataDefinition, target metadatamodel.MetadataDefinitionVersion, request metadatamodel.MetadataDefinitionRollbackRequest, principal identitymodel.Principal) auditmodel.AuditEvent {
	metadata := map[string]any{
		"business_reason": request.BusinessReason, "source_id": request.SourceID, "builder_task_id": request.BuilderTaskID,
		"from_version": current.SchemaVersion, "from_hash": current.SchemaHash, "target_version": target.SchemaVersion, "target_hash": target.SchemaHash,
	}
	return factory.NewAuditEvent(ctx, auditcontract.AuditAppendRequest{
		Event: "metadata_definition.rolled_back", ObjectKey: resourceType, RecordID: resourceKey, Principal: principal,
		Summary: "Rolled back " + resourceType + " " + resourceKey + " to version " + target.SchemaVersion,
		Before:  rollbackJSONMap(current.Payload), After: rollbackJSONMap(target.Payload), Metadata: metadata,
	})
}

func rollbackJSONMap(payload json.RawMessage) map[string]any {
	value := map[string]any{}
	_ = json.Unmarshal(payload, &value)
	return value
}

func (s *MetadataApplicationService) DisableMetadataDefinition(ctx context.Context, resourceType, resourceKey, expectedSchemaHash string, principal identitymodel.Principal) error {
	if err := metadataAuthorizeCommand(principal); err != nil {
		return err
	}
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, metadatacontract.MetadataActionDefinitionDisable) {
		return forbidden("auth.permission_denied")
	}
	resourceType, resourceKey = strings.TrimSpace(resourceType), strings.TrimSpace(resourceKey)
	expectedSchemaHash = strings.TrimSpace(expectedSchemaHash)
	if expectedSchemaHash == "" {
		return badRequest("backend.metadata.expected_schema_hash_required")
	}
	request := metadatamodel.MetadataDefinitionUpsertRequest{ExpectedSchemaHash: &expectedSchemaHash}
	if err := s.ValidateMetadataCandidate(ctx, []metadatamodel.MetadataDefinitionMutation{{Operation: "archive", ResourceType: resourceType, ResourceKey: resourceKey, Request: request}}); err != nil {
		return err
	}
	before, found, err := s.repository.GetDefinition(ctx, metadataInstallationScope("load metadata definition for disable"), resourceType, resourceKey)
	if err != nil {
		return wrapMetadataError(err)
	}
	if !found {
		return notFound("backend.metadata.definition_not_found")
	}
	if s.audit == nil {
		return metadataInternalError("build metadata disable audit")
	}
	audit := s.audit.NewAuditEvent(ctx, auditcontract.AuditAppendRequest{
		Event: "metadata_definition.disabled", ObjectKey: resourceType, RecordID: resourceKey, Principal: principal,
		Summary: "Disabled " + resourceType + " " + resourceKey, Before: DefinitionAuditValue(before, true),
		After: map[string]any{"resource_type": resourceType, "resource_key": resourceKey, "schema_hash": before.SchemaHash, "disabled": true},
	})
	if err := s.repository.DisableDefinition(ctx, metadataInstallationScope("disable metadata definition"), resourceType, resourceKey, expectedSchemaHash, audit, metadataPublicationForPrincipal(principal)); err != nil {
		return wrapMetadataError(err)
	}
	if _, err := s.ReloadMetadata(ctx, principal); err != nil {
		return err
	}
	return nil
}

func (s *MetadataApplicationService) UpsertMetadataDefinition(ctx context.Context, resourceType, resourceKey string, request metadatamodel.MetadataDefinitionUpsertRequest, principal identitymodel.Principal) (metadatamodel.MetadataDefinition, metadatamodel.MetadataSchemaSnapshot, error) {
	if err := metadataAuthorizeCommand(principal); err != nil {
		return metadatamodel.MetadataDefinition{}, metadatamodel.MetadataSchemaSnapshot{}, err
	}
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, metadatacontract.MetadataActionDefinitionUpsert) {
		return metadatamodel.MetadataDefinition{}, metadatamodel.MetadataSchemaSnapshot{}, forbidden("auth.permission_denied")
	}
	return s.upsertMetadataDefinition(ctx, resourceType, resourceKey, request, principal, metadataDefinitionPublicationOptions{})
}

type metadataDefinitionPublicationOptions struct {
	event    string
	summary  string
	metadata map[string]any
}

func (s *MetadataApplicationService) upsertMetadataDefinition(ctx context.Context, resourceType, resourceKey string, request metadatamodel.MetadataDefinitionUpsertRequest, principal identitymodel.Principal, options metadataDefinitionPublicationOptions) (metadatamodel.MetadataDefinition, metadatamodel.MetadataSchemaSnapshot, error) {
	resourceType, resourceKey = strings.TrimSpace(resourceType), strings.TrimSpace(resourceKey)
	normalizedPayload, issues, err := s.ValidateMetadataDefinitionRequestPayload(ctx, resourceType, resourceKey, request)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, metadatamodel.MetadataSchemaSnapshot{}, err
	}
	if err := firstMetadataDefinitionIssueError(issues); err != nil {
		return metadatamodel.MetadataDefinition{}, metadatamodel.MetadataSchemaSnapshot{}, err
	}
	request.Payload = normalizedPayload
	canonical, err := s.CanonicalizeMetadataCandidate(ctx, []metadatamodel.MetadataDefinitionMutation{{Operation: "update", ResourceType: resourceType, ResourceKey: resourceKey, Request: request}})
	if err != nil {
		return metadatamodel.MetadataDefinition{}, metadatamodel.MetadataSchemaSnapshot{}, err
	}
	normalized := canonical[0].Request
	before, beforeFound, err := s.repository.GetDefinition(ctx, metadataInstallationScope("load metadata definition for publish"), resourceType, resourceKey)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, metadatamodel.MetadataSchemaSnapshot{}, wrapMetadataError(err)
	}
	if err := metadataBuilderIdempotencyConflict(before, beforeFound, normalized); err != nil {
		return metadatamodel.MetadataDefinition{}, metadatamodel.MetadataSchemaSnapshot{}, err
	}
	if s.audit == nil {
		return metadatamodel.MetadataDefinition{}, metadatamodel.MetadataSchemaSnapshot{}, metadataInternalError("build metadata publication audit")
	}
	auditMetadata := map[string]any{"source_kind": normalized.SourceKind, "source_id": normalized.SourceID}
	for key, value := range options.metadata {
		auditMetadata[key] = value
	}
	event := valueOrDefault(options.event, "metadata_definition.saved")
	summary := valueOrDefault(options.summary, "Saved "+resourceType+" "+resourceKey)
	audit := s.audit.NewAuditEvent(ctx, auditcontract.AuditAppendRequest{
		Event: event, ObjectKey: resourceType, RecordID: resourceKey, Principal: principal,
		Summary: summary, Before: DefinitionAuditValue(before, beforeFound), Metadata: auditMetadata,
	})
	definition, err := s.repository.PublishDefinition(ctx, metadataInstallationScope("publish metadata definition"), resourceType, resourceKey, normalized, audit, metadataPublicationForPrincipal(principal))
	if err != nil {
		return metadatamodel.MetadataDefinition{}, metadatamodel.MetadataSchemaSnapshot{}, wrapMetadataError(err)
	}
	replayed := beforeFound && before.SchemaVersion == definition.SchemaVersion && before.SchemaHash == definition.SchemaHash
	snapshot, reloadErr := s.ReloadMetadata(ctx, principal)
	if !replayed {
		errorText := ""
		if reloadErr != nil {
			errorText = reloadErr.Error()
		}
		if completeErr := s.repository.CompleteDefinitionRefresh(ctx, metadataInstallationScope("complete metadata definition refresh"), resourceType, resourceKey, definition.SchemaVersion, definition.SchemaHash, errorText); completeErr != nil {
			return definition, metadatamodel.MetadataSchemaSnapshot{}, metadataInternalErrorWithCause("complete metadata refresh intent", completeErr)
		}
	}
	if reloadErr != nil {
		return definition, metadatamodel.MetadataSchemaSnapshot{}, reloadErr
	}
	return definition, snapshot, nil
}

func metadataPublicationForPrincipal(principal identitymodel.Principal) *metadatamodel.MetadataDefinitionPublication {
	return &metadatamodel.MetadataDefinitionPublication{WorkspaceID: strings.TrimSpace(principal.WorkspaceID)}
}

func metadataBuilderIdempotencyConflict(before metadatamodel.MetadataDefinition, found bool, request metadatamodel.MetadataDefinitionUpsertRequest) error {
	if !found || strings.TrimSpace(request.SourceKind) != "builder_v4" || strings.TrimSpace(request.SourceID) == "" || before.SourceID != request.SourceID {
		return nil
	}
	compact := func(value []byte) []byte {
		var decoded any
		if json.Unmarshal(value, &decoded) != nil {
			return value
		}
		// Generic values decoded by encoding/json are always marshalable.
		canonical, _ := json.Marshal(decoded)
		return canonical
	}
	if bytes.Equal(compact(before.Payload), compact(request.Payload)) {
		return nil
	}
	return conflict(idempotency.ErrorCodeKeyReused, "source_id", request.SourceID)
}

func DefinitionAuditValue(definition metadatamodel.MetadataDefinition, found bool) map[string]any {
	if !found {
		return nil
	}
	value := map[string]any{
		"resource_type": definition.ResourceType, "resource_key": definition.ResourceKey,
		"schema_version": definition.SchemaVersion, "schema_hash": definition.SchemaHash,
		"source_kind": definition.SourceKind, "source_id": definition.SourceID,
	}
	var payload any
	if json.Unmarshal(definition.Payload, &payload) == nil {
		value["payload"] = payload
	}
	return value
}
