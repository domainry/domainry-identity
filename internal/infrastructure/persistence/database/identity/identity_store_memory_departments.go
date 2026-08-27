package identity

import (
	"context"
	"fmt"
	"sort"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *MemoryIdentityStore) ListIdentityDepartments(ctx context.Context, workspaceID string) ([]identitymodel.IdentityDepartment, error) {
	prefix, err := identityWorkspacePrefix(workspaceID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]identitymodel.IdentityDepartment, 0, len(s.departments))
	for key, value := range s.departments {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		value.AncestorIDs = append([]string(nil), value.AncestorIDs...)
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		leftParent := identityDepartmentParentID(out[i].ParentID)
		rightParent := identityDepartmentParentID(out[j].ParentID)
		if leftParent == rightParent {
			if out[i].SortOrder == out[j].SortOrder {
				return out[i].ID < out[j].ID
			}
			return out[i].SortOrder < out[j].SortOrder
		}
		if out[i].Depth == out[j].Depth {
			return leftParent < rightParent
		}
		return out[i].Depth < out[j].Depth
	})
	return out, nil
}

func identityDepartmentParentID(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (s *MemoryIdentityStore) UpsertIdentityDepartment(ctx context.Context, workspaceID string, department identitymodel.IdentityDepartment) error {
	key, err := identityWorkspaceKey(workspaceID, department.ID)
	if err != nil {
		return err
	}
	if department.ID == "" {
		return fmt.Errorf("department id is required")
	}
	if department.Status == "" {
		department.Status = identitymodel.IdentityStatusActive
	}
	department.AncestorIDs = append([]string(nil), department.AncestorIDs...)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.departments[key] = department
	return nil
}
