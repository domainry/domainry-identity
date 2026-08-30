package audit

import (
	"context"
	"time"

	auditmodel "github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-foundation/apperror"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

const (
	PermissionTenantGovernanceRead   = "audit.governance.read"
	PermissionTenantGovernanceExport = "audit.governance.export"
)
const governanceAuditRetentionDays = auditmodel.GovernanceRetentionDays

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

func (s *AuditApplicationService) TenantGovernanceEvents(ctx context.Context, q auditmodel.AuditEventQuery, p identitymodel.Principal) (SurfaceAuditResult[TenantGovernanceAuditEventDTO], error) {
	if err := requireAuditPermission(p, PermissionTenantGovernanceRead); err != nil {
		return SurfaceAuditResult[TenantGovernanceAuditEventDTO]{}, err
	}
	r, err := s.sharedSurface(ctx, q, p)
	if err != nil {
		return SurfaceAuditResult[TenantGovernanceAuditEventDTO]{}, err
	}
	items := make([]TenantGovernanceAuditEventDTO, 0, len(r.Items))
	for _, e := range r.Items {
		items = append(items, TenantGovernanceAuditEventDTO{ID: e.ID, Event: e.Event, ObjectKey: e.ObjectKey, RecordID: e.RecordID, ActorID: e.ActorID, RoleKey: e.RoleKey, Summary: e.Summary, Metadata: e.Metadata, Before: e.Before, After: e.After, CreatedAt: e.CreatedAt})
	}
	return SurfaceAuditResult[TenantGovernanceAuditEventDTO]{Items: items, Count: len(items), PageSize: r.PageSize, Truncated: r.Truncated, NextCursor: r.NextCursor, RetentionClass: r.RetentionClass, RetentionDays: r.RetentionDays}, nil
}
func (s *AuditApplicationService) TenantGovernanceExport(ctx context.Context, q auditmodel.AuditEventQuery, p identitymodel.Principal) (SurfaceAuditResult[TenantGovernanceAuditEventDTO], error) {
	if err := requireAuditPermission(p, PermissionTenantGovernanceExport); err != nil {
		return SurfaceAuditResult[TenantGovernanceAuditEventDTO]{}, err
	}
	return s.TenantGovernanceEvents(ctx, q, p)
}
func (s *AuditApplicationService) sharedSurface(ctx context.Context, q auditmodel.AuditEventQuery, p identitymodel.Principal) (auditmodel.SurfaceResult, error) {
	if _, err := identitymodel.QueryScopeForPrincipal(p); err != nil {
		return auditmodel.SurfaceResult{}, &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.workspace_scope_required", Err: err}
	}
	plan, err := auditmodel.PlanSurface(auditmodel.SurfaceGovernance, q, p.UserID, time.Now())
	if err != nil {
		return auditmodel.SurfaceResult{}, err
	}
	events, err := s.ListAuditEvents(ctx, AuditPrincipalWorkspaceID(p), plan.Query)
	if err != nil {
		return auditmodel.SurfaceResult{}, err
	}
	if s.projectEvents != nil {
		events, err = s.projectEvents(ctx, events, p)
		if err != nil {
			return auditmodel.SurfaceResult{}, err
		}
	}
	return auditmodel.ProjectSurface(events, plan), nil
}
func requireAuditPermission(p identitymodel.Principal, permission string) error {
	if !p.Known || !identitycontract.IdentityRoleHasPermissionKey(p.Role, permission) {
		return &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.audit.view_permission_required"}
	}
	return nil
}
