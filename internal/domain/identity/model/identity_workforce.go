package identitymodel

type IdentityWorkerType string

const (
	IdentityWorkerEmployee     IdentityWorkerType = "employee"
	IdentityWorkerContractor   IdentityWorkerType = "contractor"
	IdentityWorkerPartnerStaff IdentityWorkerType = "partner_staff"
	IdentityWorkerTemporary    IdentityWorkerType = "temporary"
)

type IdentityWorkStatus string

const (
	IdentityWorkPending    IdentityWorkStatus = "pending"
	IdentityWorkActive     IdentityWorkStatus = "active"
	IdentityWorkSuspended  IdentityWorkStatus = "suspended"
	IdentityWorkTerminated IdentityWorkStatus = "terminated"
)

type IdentityWorkforceProfile struct {
	ID                  string             `json:"id"`
	OrganizationID      string             `json:"organization_id"`
	IdentityUserID      string             `json:"identity_user_id"`
	WorkerNo            string             `json:"worker_no"`
	WorkerType          IdentityWorkerType `json:"worker_type"`
	WorkStatus          IdentityWorkStatus `json:"work_status"`
	StartDate           string             `json:"start_date,omitempty"`
	EndDate             string             `json:"end_date,omitempty"`
	PrimaryAssignmentID string             `json:"primary_assignment_id,omitempty"`
	Version             int64              `json:"version"`
}

type IdentityWorkforceProfilePage struct {
	Items    []IdentityWorkforceProfile `json:"items"`
	Page     int                        `json:"page"`
	PageSize int                        `json:"page_size"`
	Total    int                        `json:"total"`
	HasNext  bool                       `json:"has_next"`
}

// IdentityWorkforceProjectionItem is the stable read projection consumed by
// source-owned business applications. It composes Identity-owned account,
// workforce, organization, and reporting facts without exposing account
// security details or pretending Foundation records are business Objects.
type IdentityWorkforceProjectionItem struct {
	Profile           IdentityWorkforceProfile     `json:"profile"`
	DisplayName       string                       `json:"display_name"`
	Roles             []IdentityWorkforceRole      `json:"roles"`
	Email             string                       `json:"email,omitempty"`
	Phone             string                       `json:"phone,omitempty"`
	UpdatedAt         string                       `json:"updated_at,omitempty"`
	PrimaryAssignment *IdentityWorkforceAssignment `json:"primary_assignment,omitempty"`
	Department        *IdentityDepartment          `json:"department,omitempty"`
	Position          *IdentityWorkforcePosition   `json:"position,omitempty"`
	Manager           *IdentityWorkforceManager    `json:"manager,omitempty"`
}

// IdentityWorkforceRole is the least-privilege role summary published to
// business applications. The projection includes only roles that currently
// contribute to the person's effective Runtime authorization.
type IdentityWorkforceRole struct {
	ID    string `json:"id"`
	Key   string `json:"key"`
	Label string `json:"label"`
}

type IdentityWorkforcePosition struct {
	ID   string `json:"id"`
	Code string `json:"code"`
	Name string `json:"name"`
}

type IdentityWorkforceManager struct {
	WorkforceProfileID string `json:"workforce_profile_id"`
	IdentityUserID     string `json:"identity_user_id"`
	DisplayName        string `json:"display_name"`
}

type IdentityWorkforceProjectionPage struct {
	Items    []IdentityWorkforceProjectionItem `json:"items"`
	Page     int                               `json:"page"`
	PageSize int                               `json:"page_size"`
	Total    int                               `json:"total"`
	HasNext  bool                              `json:"has_next"`
}

type IdentityWorkforceProjectionQuery struct {
	Page         int
	PageSize     int
	Search       string
	DepartmentID string
	WorkStatus   IdentityWorkStatus
}

type IdentityWorkforceAssignmentType string

const (
	IdentityWorkforceAssignmentPrimary   IdentityWorkforceAssignmentType = "primary"
	IdentityWorkforceAssignmentSecondary IdentityWorkforceAssignmentType = "secondary"
	IdentityWorkforceAssignmentTemporary IdentityWorkforceAssignmentType = "temporary"
	IdentityWorkforceAssignmentActing    IdentityWorkforceAssignmentType = "acting"
)

type IdentityWorkforceAssignment struct {
	ID                        string                          `json:"id"`
	WorkforceProfileID        string                          `json:"workforce_profile_id"`
	OrganizationUnitID        string                          `json:"organization_unit_id"`
	PositionID                string                          `json:"position_id,omitempty"`
	ManagerWorkforceProfileID string                          `json:"manager_workforce_profile_id,omitempty"`
	AssignmentType            IdentityWorkforceAssignmentType `json:"assignment_type"`
	EffectiveFrom             string                          `json:"effective_from,omitempty"`
	EffectiveTo               string                          `json:"effective_to,omitempty"`
	Status                    IdentityStatus                  `json:"status"`
	Version                   int64                           `json:"version"`
}

type IdentityWorkforceDirectoryEntry struct {
	WorkforceProfileID    string `json:"workforce_profile_id"`
	IdentityUserID        string `json:"identity_user_id"`
	OrganizationUnitID    string `json:"organization_unit_id,omitempty"`
	OrganizationPath      string `json:"organization_path,omitempty"`
	ManagerIdentityUserID string `json:"manager_identity_user_id,omitempty"`
	ReportingPath         string `json:"reporting_path,omitempty"`
}

type IdentityWorkforceDetail struct {
	Profile          IdentityWorkforceProfile      `json:"profile"`
	Assignments      []IdentityWorkforceAssignment `json:"assignments"`
	Account          IdentityUser                  `json:"account"`
	BusinessProfiles []IdentityProfileBinding      `json:"business_profiles"`
}

type IdentityWorkforceTerminationOptions struct {
	ActorID string `json:"actor_id,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

type IdentityWorkforceTerminationMutation struct {
	WorkspaceID string                   `json:"workspace_id"`
	Profile     IdentityWorkforceProfile `json:"profile"`
	EffectiveAt string                   `json:"effective_at"`
	ActorID     string                   `json:"actor_id"`
	Reason      string                   `json:"reason,omitempty"`
}

type IdentityWorkforceTerminationResult struct {
	Profile                  IdentityWorkforceProfile `json:"profile"`
	EndedAssignmentCount     int64                    `json:"ended_assignment_count"`
	RevokedEntitlementCount  int64                    `json:"revoked_entitlement_count"`
	PreservedProfileBindings int64                    `json:"preserved_profile_bindings"`
}

type IdentityWorkforceAssignmentEnd struct {
	AssignmentID string `json:"assignment_id"`
	EffectiveTo  string `json:"effective_to"`
}

type IdentityWorkforceLifecycleMutation struct {
	WorkspaceID        string                           `json:"workspace_id"`
	Profile            *IdentityWorkforceProfile        `json:"profile,omitempty"`
	EndAssignments     []IdentityWorkforceAssignmentEnd `json:"end_assignments,omitempty"`
	UpsertAssignments  []IdentityWorkforceAssignment    `json:"upsert_assignments,omitempty"`
	RevokeEntitlements bool                             `json:"revoke_entitlements,omitempty"`
	ActorID            string                           `json:"actor_id"`
	Reason             string                           `json:"reason,omitempty"`
}

type IdentityWorkforceLifecycleResult struct {
	Profile                 *IdentityWorkforceProfile     `json:"profile,omitempty"`
	Assignments             []IdentityWorkforceAssignment `json:"assignments,omitempty"`
	EndedAssignmentCount    int64                         `json:"ended_assignment_count"`
	RevokedEntitlementCount int64                         `json:"revoked_entitlement_count"`
}

type IdentityWorkforceOnboardingMutation struct {
	WorkspaceID     string                       `json:"workspace_id"`
	User            IdentityUser                 `json:"user"`
	Profile         IdentityWorkforceProfile     `json:"profile"`
	Assignment      IdentityWorkforceAssignment  `json:"assignment"`
	RoleAssignments []IdentityUserRoleAssignment `json:"role_assignments"`
	ActorID         string                       `json:"actor_id"`
	Reason          string                       `json:"reason,omitempty"`
}

type IdentityWorkforceOnboardingResult struct {
	User            IdentityUser                 `json:"user"`
	Profile         IdentityWorkforceProfile     `json:"profile"`
	Assignment      IdentityWorkforceAssignment  `json:"assignment"`
	RoleAssignments []IdentityUserRoleAssignment `json:"role_assignments"`
}
