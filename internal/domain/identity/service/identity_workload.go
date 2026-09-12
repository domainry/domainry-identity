package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

func (s *IdentityDomainService) ApplyWorkflowWorkloadRelease(ctx context.Context, release identitymodel.IdentityWorkflowWorkloadRelease) ([]identitymodel.IdentityWorkflowWorkloadBinding, error) {
	repository, ok := s.repo.(identityrepository.IdentityWorkflowWorkloadRepository)
	if !ok {
		return nil, workloadError(apperror.KindUnavailable, "identity.workflow_workload_unavailable")
	}
	release.WorkspaceID = strings.TrimSpace(release.WorkspaceID)
	release.ApplicationKey = strings.TrimSpace(release.ApplicationKey)
	release.ReleaseID = strings.TrimSpace(release.ReleaseID)
	release.ReleaseDigest = strings.TrimSpace(release.ReleaseDigest)
	if release.WorkspaceID == "" || release.WorkspaceID != s.workspace || release.ApplicationKey == "" || release.ReleaseID == "" || release.ReleaseDigest == "" {
		return nil, workloadError(apperror.KindBadRequest, "identity.workflow_workload_release_invalid")
	}
	roles, err := s.repo.ListIdentityRoles(ctx, s.workspace)
	if err != nil {
		return nil, err
	}
	roleByKey := make(map[string]identitymodel.IdentityRole, len(roles))
	for _, role := range roles {
		roleByKey[strings.TrimSpace(role.Key)] = role
	}
	seen := make(map[string]struct{}, len(release.Bindings))
	for index := range release.Bindings {
		binding := &release.Bindings[index]
		binding.WorkspaceID, binding.ApplicationKey = release.WorkspaceID, release.ApplicationKey
		binding.ReleaseID, binding.ReleaseDigest = release.ReleaseID, release.ReleaseDigest
		binding.SourceKind, binding.SourceID = "deployment_control_plane", release.ApplicationKey
		binding.WorkflowKey = strings.TrimSpace(binding.WorkflowKey)
		binding.SubjectID = "workflow:" + binding.WorkflowKey
		binding.DefinitionVersionID = strings.TrimSpace(binding.DefinitionVersionID)
		binding.RoleKey = strings.TrimSpace(binding.RoleKey)
		if binding.WorkflowKey == "" || binding.DefinitionVersionID == "" || binding.DefinitionVersion <= 0 || binding.RoleKey == "" || len(binding.ActionKeys) == 0 {
			return nil, workloadError(apperror.KindBadRequest, "identity.workflow_workload_binding_invalid")
		}
		if _, duplicate := seen[binding.WorkflowKey]; duplicate {
			return nil, workloadError(apperror.KindBadRequest, "identity.workflow_workload_binding_duplicate")
		}
		seen[binding.WorkflowKey] = struct{}{}
		role, found := roleByKey[binding.RoleKey]
		if !found {
			return nil, workloadError(apperror.KindNotFound, "identity.workflow_workload_role_not_found")
		}
		if role.Status != "" && role.Status != identitymodel.IdentityStatusActive {
			return nil, workloadError(apperror.KindForbidden, "identity.workflow_workload_role_disabled")
		}
		definition, published := s.publishedRoleDefinition(role)
		if !published {
			return nil, workloadError(apperror.KindConflict, "identity.workflow_workload_role_unpublished")
		}
		if definition.Audience != identitymodel.IdentityRoleAudienceService {
			return nil, workloadError(apperror.KindForbidden, "identity.workflow_workload_role_audience_invalid")
		}
		if definition.AssignmentMode != identitymodel.IdentityRoleAssignmentSystemManaged {
			return nil, workloadError(apperror.KindForbidden, "identity.workflow_workload_role_assignment_mode_invalid")
		}
		allowed := make(map[string]struct{}, len(definition.Permissions))
		for _, permission := range definition.Permissions {
			allowed[strings.TrimSpace(permission.PermissionKey)] = struct{}{}
		}
		for _, actionKey := range binding.ActionKeys {
			if _, permitted := allowed[strings.TrimSpace(actionKey)]; !permitted {
				return nil, workloadError(apperror.KindForbidden, "identity.workflow_workload_action_denied")
			}
		}
	}
	return repository.ApplyIdentityWorkflowWorkloadRelease(ctx, release)
}

func (s *IdentityDomainService) WorkflowWorkloadBinding(ctx context.Context, applicationKey, workflowKey string) (identitymodel.IdentityWorkflowWorkloadBinding, bool, error) {
	repository, ok := s.repo.(identityrepository.IdentityWorkflowWorkloadRepository)
	if !ok {
		return identitymodel.IdentityWorkflowWorkloadBinding{}, false, workloadError(apperror.KindUnavailable, "identity.workflow_workload_unavailable")
	}
	return repository.GetIdentityWorkflowWorkloadBinding(ctx, s.workspace, strings.TrimSpace(applicationKey), strings.TrimSpace(workflowKey))
}

func (s *IdentityDomainService) BuildWorkflowWorkloadPrincipal(ctx context.Context, binding identitymodel.IdentityWorkflowWorkloadBinding) (identitymodel.Principal, error) {
	scoped, scopeErr := s.withWorkspacePermissions(ctx)
	if scopeErr != nil {
		return identitymodel.Principal{}, scopeErr
	}
	s = scoped

	if binding.WorkspaceID != s.workspace || binding.Status != "active" || binding.SubjectID != "workflow:"+binding.WorkflowKey {
		return identitymodel.Principal{UserID: binding.SubjectID, Known: false}, nil
	}
	roles, err := s.repo.ListIdentityRoles(ctx, s.workspace)
	if err != nil {
		return identitymodel.Principal{}, err
	}
	for _, role := range roles {
		if role.Key != binding.RoleKey || role.Status != "" && role.Status != identitymodel.IdentityStatusActive {
			continue
		}
		definition, published := s.publishedRoleDefinition(role)
		if !published || definition.Audience != identitymodel.IdentityRoleAudienceService || definition.AssignmentMode != identitymodel.IdentityRoleAssignmentSystemManaged {
			return identitymodel.Principal{UserID: binding.SubjectID, Known: false}, nil
		}
		definition.Key = binding.RoleKey
		identityCanonicalizeEffectiveRole(&definition)
		definition.Permissions = s.identityFilterExecutablePermissions(definition.Permissions)
		definition.Permissions = identityFilterGuardrailDeniedPermissions(definition)
		encoded, _ := json.Marshal(struct {
			Binding               identitymodel.IdentityWorkflowWorkloadBinding
			Role                  identitymodel.RoleSchema
			PermissionFingerprint string
		}{binding, definition, identityPermissionStateFingerprint(s.PermissionDefinitions())})
		digest := sha256.Sum256(encoded)
		return identitymodel.Principal{UserID: binding.SubjectID, WorkspaceID: s.workspace, Role: definition, Known: true, AuthorizationRevision: hex.EncodeToString(digest[:])}, nil
	}
	return identitymodel.Principal{UserID: binding.SubjectID, Known: false}, nil
}

func workloadError(kind apperror.ErrorKind, code string) error {
	return &apperror.AppError{Kind: kind, Code: code}
}
