package auditbinding

import (
	"context"

	auditapplication "github.com/domainry/domainry-audit-sdk/application"
	auditcontract "github.com/domainry/domainry-audit-sdk/contract"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type AuditApplicationService = auditapplication.Service[identitymodel.Principal, identitymodel.SystemScope]
type AuditAppendRequest = auditapplication.AppendRequest[identitymodel.Principal]
type AuditAppender = auditapplication.Appender[identitymodel.Principal]
type AuditTelemetryAppender = auditapplication.TelemetryAppender[identitymodel.Principal]
type AuditEventFactory = auditapplication.EventFactory[identitymodel.Principal]
type AuditReader = auditapplication.Reader[identitymodel.SystemScope]
type AuditRepository = auditapplication.Store[identitymodel.SystemScope]
type AuditEventWriterRepository = auditapplication.EventWriterStore
type AuditEventRepository = auditapplication.EventStore

func NewAuditApplicationService(store AuditRepository) *AuditApplicationService {
	return auditapplication.NewService(store, identityPolicy())
}

func identityPolicy() auditapplication.Policy[identitymodel.Principal, identitymodel.SystemScope] {
	return auditapplication.Policy[identitymodel.Principal, identitymodel.SystemScope]{
		Actor: func(principal identitymodel.Principal) auditcontract.Actor {
			kind := "user"
			if !principal.Known || principal.SystemScope.Valid() {
				kind = "system"
			}
			return auditcontract.Actor{WorkspaceID: principal.WorkspaceID, SubjectID: principal.UserID, RoleKey: principal.Role.Key, Kind: kind, RequestID: principal.RequestID, CorrelationID: principal.CorrelationID, AuthorizationRevision: principal.AuthorizationRevision}
		},
		WorkspaceID: func(principal identitymodel.Principal) string { return principal.WorkspaceID },
		ValidateCommand: func(principal identitymodel.Principal) error {
			_, err := identitymodel.CommandScopeForPrincipal(principal)
			return err
		},
		ValidateQuery: func(principal identitymodel.Principal) error {
			_, err := identitymodel.QueryScopeForPrincipal(principal)
			return err
		},
		ValidateSystemQuery: func(scope identitymodel.SystemScope) error {
			_, err := identitymodel.NewSystemQueryScope(scope)
			return err
		},
		Known: func(principal identitymodel.Principal) bool { return principal.Known },
		CanView: func(principal identitymodel.Principal) bool {
			return identitycontract.IdentityRoleHasPermissionKey(principal.Role, "identity.audit.view") || identitycontract.IdentityRoleAllows(principal.Role, "identity_permission", "read")
		},
	}
}

func AuditBuildEvent(ctx context.Context, event, objectKey, recordID string, principal identitymodel.Principal, summary string, before, after, metadata map[string]any) auditcontract.AuditEvent {
	return auditapplication.NewService[identitymodel.Principal, identitymodel.SystemScope](nil, identityPolicy()).NewAuditEvent(ctx, AuditAppendRequest{Event: event, ObjectKey: objectKey, RecordID: recordID, Principal: principal, Summary: summary, Before: before, After: after, Metadata: metadata})
}
func AuditRedactSensitiveMap(value map[string]any) map[string]any {
	return auditapplication.RedactSensitiveMap(value)
}
func AuditPrincipalWorkspaceID(principal identitymodel.Principal) string {
	if principal.WorkspaceID != "" {
		return principal.WorkspaceID
	}
	return "default"
}
