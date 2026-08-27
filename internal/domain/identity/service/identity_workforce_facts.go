package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

type identityWorkforceFacts struct {
	ProfileID        string
	DepartmentID     string
	DepartmentPath   string
	ReportingPath    string
	ReportingUserIDs []string
	Revision         string
}

type identityWorkforceSnapshot struct {
	profiles         map[string]identitymodel.IdentityWorkforceProfile
	activeProfileIDs map[string]bool
	primary          map[string]identitymodel.IdentityWorkforceAssignment
	departmentPaths  map[string]string
}

func (s *IdentityDomainService) workforceRepository() identityrepository.IdentityWorkforceRepository {
	repository, _ := s.repo.(identityrepository.IdentityWorkforceRepository)
	return repository
}

func (s *IdentityDomainService) resolveWorkforceFacts(ctx context.Context, userID string, now time.Time) (identityWorkforceFacts, map[string]bool, error) {
	snapshot, err := s.loadWorkforceSnapshot(ctx, now)
	if err != nil {
		return identityWorkforceFacts{}, nil, err
	}
	activeProfiles := snapshot.profiles
	userActiveProfileIDs := map[string]bool{}
	primaryByProfile := snapshot.primary
	userProfiles := make([]identitymodel.IdentityWorkforceProfile, 0)
	for _, candidate := range activeProfiles {
		if candidate.IdentityUserID != userID {
			continue
		}
		userActiveProfileIDs[candidate.ID] = true
		userProfiles = append(userProfiles, candidate)
	}
	if len(userProfiles) == 0 {
		return identityWorkforceFacts{}, userActiveProfileIDs, nil
	}
	sort.Slice(userProfiles, func(left, right int) bool { return userProfiles[left].ID < userProfiles[right].ID })
	profile := userProfiles[0]
	facts := identityWorkforceFacts{ProfileID: profile.ID}
	if assignment, exists := primaryByProfile[profile.ID]; exists {
		facts.DepartmentID = assignment.OrganizationUnitID
		facts.DepartmentPath = snapshot.departmentPaths[facts.DepartmentID]
		facts.ReportingPath = identityWorkforceReportingPath(profile.ID, activeProfiles, primaryByProfile)
	}
	facts.ReportingUserIDs = identityWorkforceReportingUsers(profile.ID, activeProfiles, primaryByProfile)
	facts.Revision = identityWorkforceSnapshotRevision(snapshot)
	return facts, userActiveProfileIDs, nil
}

func identityWorkforceSnapshotRevision(snapshot identityWorkforceSnapshot) string {
	profiles := make([]identitymodel.IdentityWorkforceProfile, 0, len(snapshot.profiles))
	for _, profile := range snapshot.profiles {
		profiles = append(profiles, profile)
	}
	sort.Slice(profiles, func(left, right int) bool { return profiles[left].ID < profiles[right].ID })
	assignments := make([]identitymodel.IdentityWorkforceAssignment, 0, len(snapshot.primary))
	for _, assignment := range snapshot.primary {
		assignments = append(assignments, assignment)
	}
	sort.Slice(assignments, func(left, right int) bool { return assignments[left].ID < assignments[right].ID })
	departments := make([][2]string, 0, len(snapshot.departmentPaths))
	for id, path := range snapshot.departmentPaths {
		departments = append(departments, [2]string{id, path})
	}
	sort.Slice(departments, func(left, right int) bool { return departments[left][0] < departments[right][0] })
	encoded, _ := json.Marshal(struct {
		Profiles    []identitymodel.IdentityWorkforceProfile    `json:"profiles"`
		Assignments []identitymodel.IdentityWorkforceAssignment `json:"assignments"`
		Departments [][2]string                                 `json:"departments"`
	}{profiles, assignments, departments})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func (s *IdentityDomainService) loadWorkforceSnapshot(ctx context.Context, now time.Time) (identityWorkforceSnapshot, error) {
	snapshot := identityWorkforceSnapshot{
		profiles: map[string]identitymodel.IdentityWorkforceProfile{}, activeProfileIDs: map[string]bool{},
		primary: map[string]identitymodel.IdentityWorkforceAssignment{}, departmentPaths: map[string]string{},
	}
	repository := s.workforceRepository()
	if repository == nil {
		return snapshot, nil
	}
	profiles, err := repository.ListIdentityWorkforceProfiles(ctx, s.workspace)
	if err != nil {
		return identityWorkforceSnapshot{}, err
	}
	for _, profile := range profiles {
		if profile.WorkStatus == identitymodel.IdentityWorkActive && identityWorkforcePeriodActive(profile.StartDate, profile.EndDate, now) {
			snapshot.profiles[profile.ID] = profile
			snapshot.activeProfileIDs[profile.ID] = true
		}
	}
	assignments, err := repository.ListIdentityWorkforceAssignments(ctx, s.workspace, "")
	if err != nil {
		return identityWorkforceSnapshot{}, err
	}
	snapshot.primary = identityActivePrimaryAssignments(assignments, snapshot.profiles, now)
	departments, err := s.repo.ListIdentityDepartments(ctx, s.workspace)
	if err != nil {
		return identityWorkforceSnapshot{}, err
	}
	for _, department := range departments {
		snapshot.departmentPaths[department.ID] = department.Path
	}
	return snapshot, nil
}

func (s *IdentityDomainService) ListDirectoryWorkforce(ctx context.Context) ([]identitymodel.IdentityWorkforceDirectoryEntry, error) {
	snapshot, err := s.loadWorkforceSnapshot(ctx, time.Now())
	if err != nil {
		return nil, err
	}
	out := make([]identitymodel.IdentityWorkforceDirectoryEntry, 0, len(snapshot.profiles))
	for profileID, profile := range snapshot.profiles {
		entry := identitymodel.IdentityWorkforceDirectoryEntry{
			WorkforceProfileID: profileID, IdentityUserID: profile.IdentityUserID,
			ReportingPath: identityWorkforceReportingPath(profileID, snapshot.profiles, snapshot.primary),
		}
		if assignment, exists := snapshot.primary[profileID]; exists {
			entry.OrganizationUnitID = assignment.OrganizationUnitID
			entry.OrganizationPath = snapshot.departmentPaths[assignment.OrganizationUnitID]
			if manager, exists := snapshot.profiles[assignment.ManagerWorkforceProfileID]; exists {
				entry.ManagerIdentityUserID = manager.IdentityUserID
			}
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(left, right int) bool { return out[left].IdentityUserID < out[right].IdentityUserID })
	return out, nil
}

func identityActivePrimaryAssignments(assignments []identitymodel.IdentityWorkforceAssignment, profiles map[string]identitymodel.IdentityWorkforceProfile, now time.Time) map[string]identitymodel.IdentityWorkforceAssignment {
	candidates := map[string][]identitymodel.IdentityWorkforceAssignment{}
	for _, assignment := range assignments {
		if _, exists := profiles[assignment.WorkforceProfileID]; !exists || assignment.Status != identitymodel.IdentityStatusActive ||
			assignment.AssignmentType != identitymodel.IdentityWorkforceAssignmentPrimary ||
			!identityWorkforcePeriodActive(assignment.EffectiveFrom, assignment.EffectiveTo, now) {
			continue
		}
		candidates[assignment.WorkforceProfileID] = append(candidates[assignment.WorkforceProfileID], assignment)
	}
	out := map[string]identitymodel.IdentityWorkforceAssignment{}
	for profileID, values := range candidates {
		sort.Slice(values, func(left, right int) bool { return values[left].ID < values[right].ID })
		preferredID := profiles[profileID].PrimaryAssignmentID
		out[profileID] = values[0]
		for _, value := range values {
			if value.ID == preferredID {
				out[profileID] = value
				break
			}
		}
	}
	return out
}

func identityWorkforceReportingPath(profileID string, profiles map[string]identitymodel.IdentityWorkforceProfile, assignments map[string]identitymodel.IdentityWorkforceAssignment) string {
	path := []string{}
	visited := map[string]bool{}
	currentID := profileID
	for currentID != "" && !visited[currentID] {
		visited[currentID] = true
		profile, exists := profiles[currentID]
		if !exists {
			break
		}
		path = append(path, profile.IdentityUserID)
		currentID = assignments[currentID].ManagerWorkforceProfileID
	}
	for left, right := 0, len(path)-1; left < right; left, right = left+1, right-1 {
		path[left], path[right] = path[right], path[left]
	}
	if len(path) == 0 {
		return ""
	}
	return "/" + strings.Join(path, "/")
}

func identityWorkforceReportingUsers(managerProfileID string, profiles map[string]identitymodel.IdentityWorkforceProfile, assignments map[string]identitymodel.IdentityWorkforceAssignment) []string {
	users := []string{}
	for profileID, profile := range profiles {
		if profileID == managerProfileID {
			continue
		}
		visited := map[string]bool{}
		currentID := assignments[profileID].ManagerWorkforceProfileID
		for currentID != "" && !visited[currentID] {
			if currentID == managerProfileID {
				users = append(users, profile.IdentityUserID)
				break
			}
			visited[currentID] = true
			currentID = assignments[currentID].ManagerWorkforceProfileID
		}
	}
	sort.Strings(users)
	return users
}

func identityWorkforcePeriodActive(from, to string, now time.Time) bool {
	if strings.TrimSpace(from) != "" {
		start, ok := identityWorkforceTime(from, false)
		if !ok || now.Before(start) {
			return false
		}
	}
	if strings.TrimSpace(to) != "" {
		end, ok := identityWorkforceTime(to, true)
		if !ok || now.After(end) {
			return false
		}
	}
	return true
}

func identityWorkforceTime(value string, endOfDate bool) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed, true
	}
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		return time.Time{}, false
	}
	if endOfDate {
		parsed = parsed.Add(24*time.Hour - time.Nanosecond)
	}
	return parsed, true
}

func identityRoleAssignmentActiveForWorkforce(assignment identitymodel.IdentityUserRoleAssignment, activeProfileIDs map[string]bool, now time.Time) bool {
	if !identityAssignmentActive(assignment, now) {
		return false
	}
	profileID := strings.TrimSpace(assignment.WorkforceProfileID)
	return profileID == "" || activeProfileIDs[profileID]
}
