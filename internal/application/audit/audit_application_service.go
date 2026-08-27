package audit

import (
	"context"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/secrets"
	auditcontract "github.com/domainry/domainry-identity/internal/domain/audit/contract"
	auditmodel "github.com/domainry/domainry-identity/internal/domain/audit/model"
	auditrepository "github.com/domainry/domainry-identity/internal/domain/audit/repository"
	auditservice "github.com/domainry/domainry-identity/internal/domain/audit/service"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type AuditApplicationService struct {
	*auditservice.AuditDomainService
	projectEvents func(context.Context, []auditmodel.AuditEvent, identitymodel.Principal) ([]auditmodel.AuditEvent, error)
}

func NewAuditApplicationService(repository auditrepository.AuditRepository) *AuditApplicationService {
	return &AuditApplicationService{AuditDomainService: auditservice.NewAuditDomainService(repository)}
}

func (service *AuditApplicationService) Append(ctx context.Context, event, objectKey, recordID string, principal identitymodel.Principal, summary string, before, after map[string]any) {
	service.AppendWithMetadata(ctx, event, objectKey, recordID, principal, summary, before, after, nil)
}

func (service *AuditApplicationService) AppendWithMetadata(ctx context.Context, event, objectKey, recordID string, principal identitymodel.Principal, summary string, before, after, metadata map[string]any) {
	if service == nil || service.AuditDomainService == nil {
		return
	}
	if _, err := identitymodel.CommandScopeForPrincipal(principal); err != nil {
		return
	}
	service.AuditDomainService.AppendWithMetadata(ctx, event, objectKey, recordID, principal, summary, before, after, metadata)
}

func (service *AuditApplicationService) Events(ctx context.Context, query auditmodel.AuditEventQuery, principal identitymodel.Principal) ([]auditmodel.AuditEvent, error) {
	if _, err := identitymodel.QueryScopeForPrincipal(principal); err != nil {
		return nil, &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.workspace_scope_required", Err: err}
	}
	events, err := service.AuditDomainService.Events(ctx, query, principal)
	if err != nil || service.projectEvents == nil {
		return events, err
	}
	return service.projectEvents(ctx, events, principal)
}

func (service *AuditApplicationService) SetEventProjector(projector func(context.Context, []auditmodel.AuditEvent, identitymodel.Principal) ([]auditmodel.AuditEvent, error)) {
	if service != nil {
		service.projectEvents = projector
	}
}

func (service *AuditApplicationService) Options(ctx context.Context, query auditmodel.AuditOptionQuery, principal identitymodel.Principal) ([]auditmodel.AuditOption, error) {
	if _, err := identitymodel.QueryScopeForPrincipal(principal); err != nil {
		return nil, &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.workspace_scope_required", Err: err}
	}
	return service.AuditDomainService.Options(ctx, query, principal)
}

func AuditBuildEvent(ctx context.Context, event, objectKey, recordID string, principal identitymodel.Principal, summary string, before, after, metadata map[string]any) auditmodel.AuditEvent {
	return (auditservice.AuditEventFactory{}).NewAuditEvent(ctx, auditcontract.AuditAppendRequest{
		Event: event, ObjectKey: objectKey, RecordID: recordID, Principal: principal,
		Summary: summary, Before: before, After: after, Metadata: metadata,
	})
}

func AuditRedactSensitiveMap(value map[string]any) map[string]any {
	return secrets.RedactMap(value)
}

func AuditPrincipalWorkspaceID(principal identitymodel.Principal) string {
	if workspaceID := strings.TrimSpace(principal.WorkspaceID); workspaceID != "" {
		return workspaceID
	}
	return "default"
}
