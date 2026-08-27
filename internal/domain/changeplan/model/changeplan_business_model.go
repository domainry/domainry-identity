package changeplanmodel

import (
	"encoding/json"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

const (
	BusinessSystemChangePlanVersion         = "domain-system-change-plan-v1"
	RuntimeAuthoringCoverageLedgerVersion   = "runtime-authoring-coverage-v1"
	RuntimeAuthoringScenarioEvidenceVersion = "runtime-authoring-scenario-evidence-v1"
	RuntimeAuthoringDeliveryEvidenceVersion = "runtime-authoring-delivery-evidence-v1"
)

var RuntimeAuthoringRequiredScenarioCategories = []string{
	"success", "permission_denied", "precondition_rejected", "atomic_rollback",
	"idempotent_replay", "audit", "event", "outbox",
}

type RuntimeAuthoringCoverageLedger struct {
	Version      string                                `json:"version"`
	Requirements []RuntimeAuthoringCoverageRequirement `json:"requirements"`
}

type RuntimeAuthoringCoverageRequirement struct {
	RequirementID  string                             `json:"requirement_id"`
	CapabilityKeys []string                           `json:"capability_keys"`
	Resources      []RuntimeAuthoringCoverageResource `json:"resources"`
	ScenarioIDs    []string                           `json:"scenario_ids"`
}

type RuntimeAuthoringCoverageResource struct {
	ResourceType string `json:"resource_type"`
	ResourceKey  string `json:"resource_key"`
}

type RuntimeAuthoringCoverageReport struct {
	Version              string                                      `json:"version"`
	Status               string                                      `json:"status"`
	RequirementCount     int                                         `json:"requirement_count"`
	CoveredCount         int                                         `json:"covered_count"`
	Issues               []string                                    `json:"issues"`
	Entries              []RuntimeAuthoringCoverageRequirementReport `json:"entries"`
	SourcelessResources  []RuntimeAuthoringCoverageResource          `json:"sourceless_resources"`
	UnreachableResources []RuntimeAuthoringCoverageResource          `json:"unreachable_resources"`
}

type RuntimeAuthoringCoverageRequirementReport struct {
	RequirementID string   `json:"requirement_id"`
	Status        string   `json:"status"`
	Issues        []string `json:"issues"`
}

type RuntimeAuthoringEvidenceBinding struct {
	RuntimeVersion string            `json:"runtime_version"`
	ContractHash   string            `json:"contract_hash"`
	InstanceHash   string            `json:"instance_hash"`
	SnapshotHash   string            `json:"snapshot_hash"`
	CoverageHash   string            `json:"coverage_hash"`
	ResourceHashes map[string]string `json:"resource_hashes"`
}

type RuntimeAuthoringScenarioEvidence struct {
	Version         string                                 `json:"version"`
	ScenarioID      string                                 `json:"scenario_id"`
	Categories      []string                               `json:"categories"`
	Passed          bool                                   `json:"passed"`
	BeforeStateHash string                                 `json:"before_state_hash,omitempty"`
	AfterStateHash  string                                 `json:"after_state_hash,omitempty"`
	Steps           []RuntimeAuthoringScenarioStepEvidence `json:"steps"`
}

type RuntimeAuthoringScenarioStepEvidence struct {
	Label               string `json:"label"`
	Method              string `json:"method"`
	Path                string `json:"path"`
	ExpectedStatus      []int  `json:"expected_status"`
	ActualStatus        int    `json:"actual_status"`
	RequestHash         string `json:"request_hash"`
	ResponseHash        string `json:"response_hash"`
	IdempotencyKey      string `json:"idempotency_key,omitempty"`
	IdempotencyReplayed bool   `json:"idempotency_replayed,omitempty"`
	Passed              bool   `json:"passed"`
}

type RuntimeAuthoringDeliveryEvidence struct {
	Version   string                             `json:"version"`
	Binding   RuntimeAuthoringEvidenceBinding    `json:"binding"`
	Coverage  RuntimeAuthoringCoverageLedger     `json:"coverage"`
	Scenarios []RuntimeAuthoringScenarioEvidence `json:"scenarios"`
}

type RuntimeAuthoringDeliveryReport struct {
	Version      string                          `json:"version"`
	Valid        bool                            `json:"valid"`
	Status       string                          `json:"status"`
	EvidenceHash string                          `json:"evidence_hash"`
	Binding      RuntimeAuthoringEvidenceBinding `json:"binding"`
	Checks       map[string]string               `json:"checks"`
	Issues       []string                        `json:"issues"`
}

type BusinessSystemChangePlan struct {
	PlanVersion              string                       `json:"plan_version"`
	PlanID                   string                       `json:"plan_id"`
	DraftRevision            int                          `json:"draft_revision,omitempty"`
	BusinessReason           string                       `json:"business_reason"`
	BuilderTaskID            string                       `json:"builder_task_id,omitempty"`
	SnapshotHash             string                       `json:"snapshot_hash"`
	ReferenceGraphHash       string                       `json:"reference_graph_hash"`
	RuntimeVersion           string                       `json:"runtime_version"`
	AuthoringContractVersion string                       `json:"authoring_contract_version"`
	AuthoringContractHash    string                       `json:"authoring_contract_hash"`
	Reviewed                 bool                         `json:"reviewed"`
	ReviewedBy               string                       `json:"reviewed_by,omitempty"`
	ReleaseOrder             []string                     `json:"release_order"`
	RollbackOrder            []string                     `json:"rollback_order"`
	NonAutomaticRollback     []string                     `json:"non_automatic_rollback,omitempty"`
	AcceptanceScenarios      []BusinessAcceptanceScenario `json:"acceptance_scenarios,omitempty"`
	Items                    []BusinessSystemChangeItem   `json:"items"`
}

const BusinessAcceptanceScenarioKindActionDefinition = "action_definition"

// BusinessAcceptanceScenario is an executable, side-effect-free assertion
// against resources in the composed Change Plan candidate.
type BusinessAcceptanceScenario struct {
	Key         string                                `json:"key"`
	Kind        string                                `json:"kind"`
	ResourceKey string                                `json:"resource_key"`
	Input       map[string]any                        `json:"input,omitempty"`
	Record      map[string]any                        `json:"record,omitempty"`
	Expected    BusinessAcceptanceScenarioExpectation `json:"expected"`
}

type BusinessAcceptanceScenarioExpectation struct {
	Valid      bool     `json:"valid"`
	ErrorCodes []string `json:"error_codes,omitempty"`
}

type BusinessAcceptanceScenarioSimulation struct {
	PlanID         string                             `json:"plan_id"`
	DraftRevision  int                                `json:"draft_revision"`
	SideEffectFree bool                               `json:"side_effect_free"`
	Passed         bool                               `json:"passed"`
	Results        []BusinessAcceptanceScenarioResult `json:"results"`
}

type BusinessAcceptanceScenarioResult struct {
	Key                string          `json:"key"`
	Kind               string          `json:"kind"`
	ResourceKey        string          `json:"resource_key"`
	Passed             bool            `json:"passed"`
	ExpectedValid      bool            `json:"expected_valid"`
	ActualValid        bool            `json:"actual_valid"`
	ExpectedErrorCodes []string        `json:"expected_error_codes"`
	ActualErrorCodes   []string        `json:"actual_error_codes"`
	Simulation         json.RawMessage `json:"simulation"`
}

type BusinessSystemChangeItem struct {
	ItemID               string                       `json:"item_id"`
	Operation            string                       `json:"operation"`
	ChangeKind           string                       `json:"change_kind"`
	RiskLevel            string                       `json:"risk_level"`
	ResourceType         string                       `json:"resource_type"`
	ResourceKey          string                       `json:"resource_key"`
	ResourceOwner        string                       `json:"resource_owner"`
	ExpectedResourceHash string                       `json:"expected_resource_hash,omitempty"`
	OwnerAuthorized      bool                         `json:"owner_authorized"`
	CapabilityKey        string                       `json:"capability_key"`
	Before               json.RawMessage              `json:"before,omitempty"`
	After                json.RawMessage              `json:"after,omitempty"`
	Dependencies         []BusinessChangeTarget       `json:"dependencies,omitempty"`
	Impacts              []BusinessChangeTarget       `json:"impacts,omitempty"`
	Replacement          *BusinessChangeTarget        `json:"replacement,omitempty"`
	ReferenceMigrations  []BusinessReferenceMigration `json:"reference_migrations,omitempty"`
	ValidationMethods    []string                     `json:"validation_methods"`
	RollbackMethod       string                       `json:"rollback_method,omitempty"`
}

type BusinessReferenceMigration struct {
	Consumer     BusinessChangeTarget `json:"consumer"`
	Replacement  BusinessChangeTarget `json:"replacement"`
	Strategy     string               `json:"strategy"`
	ChangeItemID string               `json:"change_item_id,omitempty"`
	Reason       string               `json:"reason"`
}

type BusinessChangeTarget struct {
	ResourceType string `json:"resource_type"`
	ResourceKey  string `json:"resource_key"`
	Reason       string `json:"reason,omitempty"`
}

type BusinessChangePlanValidation struct {
	Valid               bool                                `json:"valid"`
	ApplyAllowed        bool                                `json:"apply_allowed"`
	CurrentSnapshotHash string                              `json:"current_snapshot_hash"`
	CurrentGraphHash    string                              `json:"current_reference_graph_hash"`
	RiskSummary         map[string]int                      `json:"risk_summary"`
	Diffs               []BusinessChangeDiff                `json:"diffs"`
	Issues              []BusinessChangePlanValidationIssue `json:"issues"`
}

type BusinessChangePlanValidationIssue struct {
	ItemID    string            `json:"item_id,omitempty"`
	FieldPath string            `json:"field_path"`
	Code      string            `json:"code"`
	Severity  string            `json:"severity"`
	Params    map[string]string `json:"params,omitempty"`
}

type BusinessChangeDiff struct {
	ItemID           string                   `json:"item_id"`
	ResourceType     string                   `json:"resource_type"`
	ResourceKey      string                   `json:"resource_key"`
	Operation        string                   `json:"operation"`
	BusinessSummary  string                   `json:"business_summary"`
	NormalizedBefore json.RawMessage          `json:"normalized_before,omitempty"`
	NormalizedAfter  json.RawMessage          `json:"normalized_after,omitempty"`
	Changes          []BusinessPropertyChange `json:"changes"`
	RiskSignals      []string                 `json:"risk_signals"`
	ReferenceImpact  ReferenceImpact          `json:"reference_impact"`
	AffectedRecords  int                      `json:"affected_records"`
}

type BusinessPropertyChange struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Before any    `json:"before,omitempty"`
	After  any    `json:"after,omitempty"`
}

type Snapshot struct {
	SnapshotHash             string
	RuntimeVersion           string
	AuthoringContractVersion string
	AuthoringContractHash    string
	HiddenResourceCategories []string
	ResourceSources          []ResourceSource
	ObjectRecordCounts       map[string]int
	IdentityGovernance       IdentityGovernance
	CapabilityKeys           []string
}

func (snapshot Snapshot) ChangePlanSnapshot() Snapshot { return snapshot }

type ResourceSource struct {
	ResourceType string
	ResourceKey  string
	SchemaHash   string
	SourceKind   string
	Disabled     bool
}

type IdentityGovernance struct {
	Users               []identitymodel.IdentityUser                 `json:"users"`
	Departments         []identitymodel.IdentityDepartment           `json:"departments"`
	Roles               []identitymodel.IdentityRole                 `json:"roles"`
	RoleDefinitions     []identitymodel.RoleSchema                   `json:"role_definitions"`
	Permissions         []identitymodel.IdentityPermissionDefinition `json:"permissions"`
	Menus               []identitymodel.IdentityMenu                 `json:"menus"`
	UserRoleAssignments []identitymodel.IdentityUserRoleAssignment   `json:"user_role_assignments"`
	RoleMenuAssignments []identitymodel.IdentityRoleMenuAssignment   `json:"role_menu_assignments"`
}
