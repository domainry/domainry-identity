package identity

import (
	"context"
	"strings"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *MemoryIdentityStore) ApplyIdentityWorkflowWorkloadRelease(_ context.Context, release identitymodel.IdentityWorkflowWorkloadRelease) ([]identitymodel.IdentityWorkflowWorkloadBinding, error) {
	if _, err := identityWorkspaceID(release.WorkspaceID); err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	s.mu.Lock()
	defer s.mu.Unlock()
	prefix := release.WorkspaceID + "\x00" + release.ApplicationKey + "\x00"
	for key, existing := range s.workflowWorkloads {
		if strings.HasPrefix(key, prefix) && existing.Status == "active" {
			existing.Status, existing.UpdatedAt, existing.DeactivatedAt = "inactive", now, now
			s.workflowWorkloads[key] = existing
		}
	}
	result := make([]identitymodel.IdentityWorkflowWorkloadBinding, 0, len(release.Bindings))
	for _, binding := range release.Bindings {
		key := prefix + binding.WorkflowKey
		createdAt := now
		if previous, found := s.workflowWorkloads[key]; found && previous.CreatedAt != "" {
			createdAt = previous.CreatedAt
		}
		binding.Status, binding.CreatedAt, binding.UpdatedAt, binding.DeactivatedAt = "active", createdAt, now, ""
		binding.ActionKeys = append([]string(nil), binding.ActionKeys...)
		s.workflowWorkloads[key] = binding
		result = append(result, binding)
	}
	return result, nil
}

func (s *MemoryIdentityStore) GetIdentityWorkflowWorkloadBinding(_ context.Context, workspaceID, applicationKey, workflowKey string) (identitymodel.IdentityWorkflowWorkloadBinding, bool, error) {
	if _, err := identityWorkspaceID(workspaceID); err != nil {
		return identitymodel.IdentityWorkflowWorkloadBinding{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	binding, found := s.workflowWorkloads[workspaceID+"\x00"+applicationKey+"\x00"+workflowKey]
	if found {
		binding.ActionKeys = append([]string(nil), binding.ActionKeys...)
	}
	return binding, found, nil
}
