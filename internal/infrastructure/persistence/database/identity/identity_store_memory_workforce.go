package identity

import (
	"context"
	"fmt"
	"sort"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *MemoryIdentityStore) ListIdentityWorkforceProfiles(_ context.Context, workspaceID string) ([]identitymodel.IdentityWorkforceProfile, error) {
	prefix, err := identityWorkspacePrefix(workspaceID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []identitymodel.IdentityWorkforceProfile{}
	for key, profile := range s.workforceProfiles {
		if strings.HasPrefix(key, prefix) {
			out = append(out, profile)
		}
	}
	sort.Slice(out, func(left, right int) bool { return out[left].ID < out[right].ID })
	return out, nil
}

func (s *MemoryIdentityStore) GetIdentityWorkforceProfile(_ context.Context, workspaceID, profileID string) (identitymodel.IdentityWorkforceProfile, bool, error) {
	key, err := identityWorkspaceKey(workspaceID, profileID)
	if err != nil {
		return identitymodel.IdentityWorkforceProfile{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	profile, ok := s.workforceProfiles[key]
	return profile, ok, nil
}

func (s *MemoryIdentityStore) UpsertIdentityWorkforceProfile(_ context.Context, workspaceID string, profile identitymodel.IdentityWorkforceProfile) error {
	key, err := identityWorkspaceKey(workspaceID, profile.ID)
	if err != nil {
		return err
	}
	prefix, _ := identityWorkspacePrefix(workspaceID)
	if profile.ID == "" {
		return fmt.Errorf("workforce profile id is required")
	}
	if profile.Version == 0 {
		profile.Version = 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for existingKey, existing := range s.workforceProfiles {
		if existingKey == key || !strings.HasPrefix(existingKey, prefix) || existing.OrganizationID != profile.OrganizationID {
			continue
		}
		if existing.IdentityUserID == profile.IdentityUserID {
			return fmt.Errorf("workforce profile identity user already exists in organization")
		}
		if existing.WorkerNo == profile.WorkerNo {
			return fmt.Errorf("workforce profile worker number already exists in organization")
		}
	}
	s.workforceProfiles[key] = profile
	return nil
}

func (s *MemoryIdentityStore) ListIdentityWorkforceAssignments(_ context.Context, workspaceID, profileID string) ([]identitymodel.IdentityWorkforceAssignment, error) {
	prefix, err := identityWorkspacePrefix(workspaceID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []identitymodel.IdentityWorkforceAssignment{}
	for key, assignment := range s.workforceAssignments {
		if strings.HasPrefix(key, prefix) && (profileID == "" || assignment.WorkforceProfileID == profileID) {
			out = append(out, assignment)
		}
	}
	sort.Slice(out, func(left, right int) bool { return out[left].ID < out[right].ID })
	return out, nil
}

func (s *MemoryIdentityStore) GetIdentityWorkforceAssignment(_ context.Context, workspaceID, assignmentID string) (identitymodel.IdentityWorkforceAssignment, bool, error) {
	key, err := identityWorkspaceKey(workspaceID, assignmentID)
	if err != nil {
		return identitymodel.IdentityWorkforceAssignment{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	assignment, ok := s.workforceAssignments[key]
	return assignment, ok, nil
}

func (s *MemoryIdentityStore) UpsertIdentityWorkforceAssignment(_ context.Context, workspaceID string, assignment identitymodel.IdentityWorkforceAssignment) error {
	key, err := identityWorkspaceKey(workspaceID, assignment.ID)
	if err != nil {
		return err
	}
	if assignment.ID == "" {
		return fmt.Errorf("workforce assignment id is required")
	}
	if assignment.Version == 0 {
		assignment.Version = 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workforceAssignments[key] = assignment
	return nil
}
