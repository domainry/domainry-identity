package audit

import (
	"context"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	auditmodel "github.com/domainry/domainry-identity/internal/domain/audit/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

const (
	PermissionTenantGovernanceRead   = "audit.governance.read"
	PermissionTenantGovernanceExport = "audit.governance.export"
	governanceAuditRetentionDays     = 2555
)

type TenantGovernanceAuditEventDTO struct {
	ID        string         `json:"id"`
	Event     string         `json:"event"`
	ObjectKey string         `json:"object_key,omitempty"`
	RecordID  string         `json:"record_id,omitempty"`
	ActorID   string         `json:"actor_id"`
	RoleKey   string         `json:"role_key,omitempty"`
	Summary   string         `json:"summary"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	Before    map[string]any `json:"before,omitempty"`
	After     map[string]any `json:"after,omitempty"`
	CreatedAt string         `json:"created_at"`
}

type SurfaceAuditResult[T any] struct {
	Items          []T    `json:"items"`
	Count          int    `json:"count"`
	PageSize       int    `json:"page_size"`
	Truncated      bool   `json:"truncated"`
	NextCursor     string `json:"next_cursor,omitempty"`
	RetentionClass string `json:"retention_class"`
	RetentionDays  int    `json:"retention_days"`
}

func (service *AuditApplicationService) TenantGovernanceEvents(ctx context.Context, query auditmodel.AuditEventQuery, principal identitymodel.Principal) (SurfaceAuditResult[TenantGovernanceAuditEventDTO], error) {
	if err := requireAuditPermission(principal, PermissionTenantGovernanceRead); err != nil {
		return SurfaceAuditResult[TenantGovernanceAuditEventDTO]{}, err
	}
	query = applyAuditRetention(query, governanceAuditRetentionDays)
	query.Class = auditmodel.AuditEventClassGovernance
	events, err := service.surfaceEvents(ctx, query, principal)
	if err != nil {
		return SurfaceAuditResult[TenantGovernanceAuditEventDTO]{}, err
	}
	items := []TenantGovernanceAuditEventDTO{}
	for _, event := range events {
		if auditmodel.ClassifyAuditEvent(event) != auditmodel.AuditEventClassGovernance {
			continue
		}
		items = append(items, TenantGovernanceAuditEventDTO{
			ID: event.ID, Event: event.Event, ObjectKey: event.ObjectKey, RecordID: event.RecordID,
			ActorID: event.ActorID, RoleKey: event.RoleKey, Summary: event.Summary,
			Metadata: AuditRedactSensitiveMap(event.Metadata), Before: AuditRedactSensitiveMap(event.Before),
			After: AuditRedactSensitiveMap(event.After), CreatedAt: event.CreatedAt,
		})
	}
	return SurfaceAuditResult[TenantGovernanceAuditEventDTO]{Items: items, Count: len(items), PageSize: query.Limit, RetentionClass: "tenant_governance", RetentionDays: governanceAuditRetentionDays}, nil
}

func (service *AuditApplicationService) TenantGovernanceExport(ctx context.Context, query auditmodel.AuditEventQuery, principal identitymodel.Principal) (SurfaceAuditResult[TenantGovernanceAuditEventDTO], error) {
	if err := requireAuditPermission(principal, PermissionTenantGovernanceExport); err != nil {
		return SurfaceAuditResult[TenantGovernanceAuditEventDTO]{}, err
	}
	return service.TenantGovernanceEvents(ctx, query, principal)
}

func (service *AuditApplicationService) surfaceEvents(ctx context.Context, query auditmodel.AuditEventQuery, principal identitymodel.Principal) ([]auditmodel.AuditEvent, error) {
	if _, err := identitymodel.QueryScopeForPrincipal(principal); err != nil {
		return nil, &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.workspace_scope_required", Err: err}
	}
	events, err := service.ListAuditEvents(ctx, AuditPrincipalWorkspaceID(principal), query)
	if err != nil || service.projectEvents == nil {
		return events, err
	}
	return service.projectEvents(ctx, events, principal)
}

func requireAuditPermission(principal identitymodel.Principal, permission string) error {
	if !principal.Known || !identitycontract.IdentityRoleHasPermissionKey(principal.Role, permission) {
		return &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.audit.view_permission_required"}
	}
	return nil
}

func applyAuditRetention(query auditmodel.AuditEventQuery, days int) auditmodel.AuditEventQuery {
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	if current, err := time.Parse(time.RFC3339, strings.TrimSpace(query.CreatedFrom)); err != nil || current.Before(cutoff) {
		query.CreatedFrom = cutoff.Format(time.RFC3339)
	}
	if query.Limit <= 0 || query.Limit > 1000 {
		query.Limit = 200
	}
	return query
}
