package projection

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	changeplanmodel "github.com/domainry/domainry-identity/internal/domain/changeplan/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

const BusinessSystemSnapshotVersion = "identity-system-snapshot-v1"

type SystemResourceSource struct {
	ResourceType  string `json:"resource_type"`
	ResourceKey   string `json:"resource_key"`
	ObjectKey     string `json:"object_key,omitempty"`
	Name          string `json:"name,omitempty"`
	SchemaVersion string `json:"schema_version,omitempty"`
	SchemaHash    string `json:"schema_hash,omitempty"`
	SourceKind    string `json:"source_kind,omitempty"`
	SourceID      string `json:"source_id,omitempty"`
	Disabled      bool   `json:"disabled"`
}

// BusinessSystemSnapshot is the immutable Identity authoring baseline used by
// the Admin UI. It contains no workflow, automation or integration state.
type BusinessSystemSnapshot struct {
	SnapshotVersion          string                               `json:"snapshot_version"`
	SnapshotHash             string                               `json:"snapshot_hash"`
	RuntimeVersion           string                               `json:"runtime_version"`
	AuthoringContractVersion string                               `json:"authoring_contract_version"`
	AuthoringContractHash    string                               `json:"authoring_contract_hash"`
	SchemaHash               string                               `json:"schema_hash"`
	Schema                   metadatamodel.MetadataSchemaSnapshot `json:"schema"`
	IdentityGovernance       changeplanmodel.IdentityGovernance   `json:"identity_governance"`
	ResourceSources          []SystemResourceSource               `json:"resource_sources"`
	ObjectRecordCounts       map[string]int                       `json:"object_record_counts"`
	CapabilityKeys           []string                             `json:"-"`
}

func (snapshot BusinessSystemSnapshot) ChangePlanSnapshot() changeplanmodel.Snapshot {
	resources := make([]changeplanmodel.ResourceSource, 0, len(snapshot.ResourceSources))
	for _, source := range snapshot.ResourceSources {
		resources = append(resources, changeplanmodel.ResourceSource{ResourceType: source.ResourceType, ResourceKey: source.ResourceKey, SchemaHash: source.SchemaHash, SourceKind: source.SourceKind, Disabled: source.Disabled})
	}
	return changeplanmodel.Snapshot{
		SnapshotHash: snapshot.SnapshotHash, RuntimeVersion: snapshot.RuntimeVersion,
		AuthoringContractVersion: snapshot.AuthoringContractVersion, AuthoringContractHash: snapshot.AuthoringContractHash,
		ResourceSources:    resources,
		ObjectRecordCounts: snapshot.ObjectRecordCounts, CapabilityKeys: append([]string(nil), snapshot.CapabilityKeys...),
		IdentityGovernance: snapshot.IdentityGovernance,
	}
}

func (snapshot BusinessSystemSnapshot) WithIdentityGovernance(identity changeplanmodel.IdentityGovernance) BusinessSystemSnapshot {
	snapshot.IdentityGovernance = identity
	for _, role := range identity.RoleDefinitions {
		snapshot.addResourceSource("role", role.Key, role.Name, "metadata")
	}
	snapshot.Finalize()
	return snapshot
}

func (snapshot *BusinessSystemSnapshot) addResourceSource(resourceType, resourceKey, name, sourceKind string) {
	for _, source := range snapshot.ResourceSources {
		if source.ResourceType == resourceType && source.ResourceKey == resourceKey {
			return
		}
	}
	snapshot.ResourceSources = append(snapshot.ResourceSources, SystemResourceSource{ResourceType: resourceType, ResourceKey: resourceKey, Name: name, SourceKind: sourceKind, SourceID: sourceKind})
}

func (snapshot *BusinessSystemSnapshot) Finalize() {
	if snapshot.ResourceSources == nil {
		snapshot.ResourceSources = []SystemResourceSource{}
	}
	if snapshot.ObjectRecordCounts == nil {
		snapshot.ObjectRecordCounts = map[string]int{}
	}
	normalizeIdentityGovernance(&snapshot.IdentityGovernance)
	sort.Slice(snapshot.ResourceSources, func(i, j int) bool {
		if snapshot.ResourceSources[i].ResourceType == snapshot.ResourceSources[j].ResourceType {
			return snapshot.ResourceSources[i].ResourceKey < snapshot.ResourceSources[j].ResourceKey
		}
		return snapshot.ResourceSources[i].ResourceType < snapshot.ResourceSources[j].ResourceType
	})
	snapshot.SnapshotHash = ""
	snapshot.SnapshotHash = SystemSnapshotHash(*snapshot)
}

func normalizeIdentityGovernance(snapshot *changeplanmodel.IdentityGovernance) {
	if snapshot.Users == nil {
		snapshot.Users = []identitymodel.IdentityUser{}
	}
	if snapshot.Departments == nil {
		snapshot.Departments = []identitymodel.IdentityDepartment{}
	}
	if snapshot.Roles == nil {
		snapshot.Roles = []identitymodel.IdentityRole{}
	}
	if snapshot.RoleDefinitions == nil {
		snapshot.RoleDefinitions = []identitymodel.RoleSchema{}
	}
	if snapshot.Permissions == nil {
		snapshot.Permissions = []identitymodel.IdentityPermissionDefinition{}
	}
	if snapshot.Menus == nil {
		snapshot.Menus = []identitymodel.IdentityMenu{}
	}
	if snapshot.UserRoleAssignments == nil {
		snapshot.UserRoleAssignments = []identitymodel.IdentityUserRoleAssignment{}
	}
	if snapshot.RoleMenuAssignments == nil {
		snapshot.RoleMenuAssignments = []identitymodel.IdentityRoleMenuAssignment{}
	}
	sort.Slice(snapshot.Users, func(i, j int) bool { return snapshot.Users[i].ID < snapshot.Users[j].ID })
	sort.Slice(snapshot.Departments, func(i, j int) bool { return snapshot.Departments[i].ID < snapshot.Departments[j].ID })
	sort.Slice(snapshot.Roles, func(i, j int) bool { return snapshot.Roles[i].ID < snapshot.Roles[j].ID })
	sort.Slice(snapshot.RoleDefinitions, func(i, j int) bool { return snapshot.RoleDefinitions[i].Key < snapshot.RoleDefinitions[j].Key })
	sort.Slice(snapshot.Permissions, func(i, j int) bool { return snapshot.Permissions[i].Key < snapshot.Permissions[j].Key })
	sort.Slice(snapshot.Menus, func(i, j int) bool { return snapshot.Menus[i].Key < snapshot.Menus[j].Key })
}

func SystemSnapshotHash(snapshot BusinessSystemSnapshot) string {
	snapshot.SnapshotHash = ""
	payload, _ := json.Marshal(snapshot)
	hash := sha256.Sum256(payload)
	return hex.EncodeToString(hash[:])
}
