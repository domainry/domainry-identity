package identity

import (
	"context"
	"fmt"
	"sort"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *MemoryIdentityStore) ListIdentityOrganizationUnits(ctx context.Context, workspaceID string) ([]identitymodel.IdentityOrganizationUnit, error) {
	prefix, err := identityWorkspacePrefix(workspaceID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]identitymodel.IdentityOrganizationUnit, 0, len(s.organizationUnits))
	for key, value := range s.organizationUnits {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		value.AncestorIDs = append([]string(nil), value.AncestorIDs...)
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		leftParent := identityOrganizationUnitParentID(out[i].ParentID)
		rightParent := identityOrganizationUnitParentID(out[j].ParentID)
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

func identityOrganizationUnitParentID(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (s *MemoryIdentityStore) UpsertIdentityOrganizationUnit(ctx context.Context, workspaceID string, organizationUnit identitymodel.IdentityOrganizationUnit) error {
	return s.UpsertIdentityOrganizationUnitsAtomically(ctx, workspaceID, []identitymodel.IdentityOrganizationUnit{organizationUnit})
}

func (s *MemoryIdentityStore) UpsertIdentityOrganizationUnitsAtomically(_ context.Context, workspaceID string, organizationUnits []identitymodel.IdentityOrganizationUnit) error {
	prepared := make(map[string]identitymodel.IdentityOrganizationUnit, len(organizationUnits))
	for _, organizationUnit := range organizationUnits {
		key, err := identityWorkspaceKey(workspaceID, organizationUnit.ID)
		if err != nil {
			return err
		}
		if organizationUnit.ID == "" {
			return fmt.Errorf("organization unit id is required")
		}
		if organizationUnit.Status == "" {
			organizationUnit.Status = identitymodel.IdentityStatusActive
		}
		organizationUnit.AncestorIDs = append([]string(nil), organizationUnit.AncestorIDs...)
		prepared[key] = organizationUnit
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, organizationUnit := range prepared {
		s.organizationUnits[key] = organizationUnit
	}
	return nil
}
