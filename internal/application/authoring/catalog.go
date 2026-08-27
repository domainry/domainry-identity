package authoring

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

const (
	ContractVersion = "identity-authoring-v1"
	RuntimeVersion  = "identity-v1"
)

type Parameter struct {
	Key      string   `json:"key"`
	Type     string   `json:"type"`
	Required bool     `json:"required,omitempty"`
	Default  any      `json:"default,omitempty"`
	Enum     []string `json:"enum,omitempty"`
	Minimum  *float64 `json:"minimum,omitempty"`
	Maximum  *float64 `json:"maximum,omitempty"`
}

type Definition struct {
	Key         string      `json:"key"`
	Status      string      `json:"status"`
	Lifecycle   string      `json:"lifecycle"`
	Requires    []string    `json:"requires,omitempty"`
	Parameters  []Parameter `json:"parameters,omitempty"`
	Permissions []string    `json:"permissions,omitempty"`
}

type Domain struct {
	Key          string       `json:"key"`
	Capabilities []Definition `json:"capabilities"`
}

type ScopedValues struct {
	Scope  string   `json:"scope"`
	Values []string `json:"values"`
}

type Instance struct {
	SchemaHash     string         `json:"schema_hash,omitempty"`
	ObjectKeys     []string       `json:"object_keys"`
	FieldKeys      []ScopedValues `json:"field_keys,omitempty"`
	ActionKeys     []string       `json:"action_keys"`
	RoleKeys       []string       `json:"role_keys,omitempty"`
	PermissionKeys []string       `json:"permission_keys,omitempty"`
}

type Contract struct {
	ContractVersion string   `json:"contract_version"`
	RuntimeVersion  string   `json:"runtime_version"`
	ContractHash    string   `json:"contract_hash"`
	InstanceHash    string   `json:"instance_hash"`
	Domains         []Domain `json:"domains"`
	Instance        Instance `json:"instance"`
}

// AuthoringCatalog describes the Identity-owned resources that management
// clients may configure. It is discovery metadata, not an authorization
// decision source; every operation still checks dynamically assigned role and
// permission data at its application boundary.
//
// It intentionally contains no Workflow, Automation, Reporting, Integration,
// or general business Runtime capabilities.
type AuthoringCatalog struct {
	domains      []Domain
	contractHash string
}

func NewAuthoringCatalog() *AuthoringCatalog {
	minimumZero, maximumThirtyEight := number(0), number(38)
	domains := []Domain{
		{Key: "schema", Capabilities: []Definition{
			definition("schema.field", "versioned_metadata", []string{"metadata.read", "metadata.write"}, nil,
				Parameter{Key: "type", Type: "string", Required: true, Enum: []string{"boolean", "currency", "date", "datetime", "email", "integer", "long_text", "number", "percent", "phone", "relation", "select", "text", "url", "user"}},
				Parameter{Key: "precision", Type: "integer", Default: 19, Minimum: number(1), Maximum: maximumThirtyEight},
				Parameter{Key: "scale", Type: "integer", Default: 2, Minimum: minimumZero, Maximum: maximumThirtyEight}),
			definition("schema.relation", "versioned_metadata", []string{"metadata.read", "metadata.write"}, []string{"schema.field"},
				Parameter{Key: "cardinality", Type: "string", Default: "many_to_one", Enum: []string{"many_to_one", "one_to_one"}},
				Parameter{Key: "on_delete", Type: "string", Default: "restrict", Enum: []string{"cascade", "restrict", "set_null"}}),
		}},
		{Key: "identity", Capabilities: []Definition{
			definition("identity.user", "immediate_audited_configuration", []string{"identity.users.write"}, nil),
			definition("identity.department", "immediate_audited_configuration", []string{"identity.departments.write"}, nil),
			definition("identity.role", "versioned_metadata", []string{"identity.roles.write"}, nil),
			definition("identity.user_role_assignment", "immediate_audited_configuration", []string{"identity.roles.write"}, []string{"identity.user", "identity.role"}),
			definition("identity.role_permission", "versioned_metadata", []string{"identity.permissions.write"}, []string{"identity.role"}),
			definition("identity.role_data_scope", "versioned_metadata", []string{"identity.data_scopes.write"}, []string{"identity.role", "schema.field"},
				Parameter{Key: "data_scope", Type: "string", Required: true, Enum: []string{"all_records", "custom", "department", "department_and_children", "none", "owned_records", "subordinates", "team"}}),
			definition("identity.role_field_permission", "versioned_metadata", []string{"identity.field_permissions.write"}, []string{"identity.role", "schema.field"}),
			definition("identity.menu", "immediate_audited_configuration", []string{"identity.menus.write"}, nil),
		}},
	}
	for domainIndex := range domains {
		sort.Slice(domains[domainIndex].Capabilities, func(left, right int) bool {
			return domains[domainIndex].Capabilities[left].Key < domains[domainIndex].Capabilities[right].Key
		})
	}
	sort.Slice(domains, func(left, right int) bool { return domains[left].Key < domains[right].Key })
	catalog := &AuthoringCatalog{domains: domains}
	catalog.contractHash = hash(domains)
	return catalog
}

func (c *AuthoringCatalog) Contract(instance Instance) Contract {
	instance = normalizedInstance(instance)
	return Contract{
		ContractVersion: ContractVersion,
		RuntimeVersion:  RuntimeVersion,
		ContractHash:    c.contractHash,
		InstanceHash:    hash(instance),
		Domains:         cloneDomains(c.domains),
		Instance:        instance,
	}
}

func (c *AuthoringCatalog) Definitions() []Definition {
	result := make([]Definition, 0)
	for _, domain := range c.domains {
		result = append(result, domain.Capabilities...)
	}
	return result
}

func (c *AuthoringCatalog) Keys() []string {
	definitions := c.Definitions()
	result := make([]string, 0, len(definitions))
	for _, item := range definitions {
		result = append(result, item.Key)
	}
	sort.Strings(result)
	return result
}

func definition(key, lifecycle string, permissions, requires []string, parameters ...Parameter) Definition {
	return Definition{
		Key: key, Status: "supported", Lifecycle: lifecycle,
		Permissions: append([]string(nil), permissions...),
		Requires:    append([]string(nil), requires...),
		Parameters:  append([]Parameter(nil), parameters...),
	}
}

func normalizedInstance(instance Instance) Instance {
	sort.Strings(instance.ObjectKeys)
	sort.Strings(instance.ActionKeys)
	sort.Strings(instance.RoleKeys)
	sort.Strings(instance.PermissionKeys)
	for index := range instance.FieldKeys {
		sort.Strings(instance.FieldKeys[index].Values)
	}
	sort.Slice(instance.FieldKeys, func(left, right int) bool { return instance.FieldKeys[left].Scope < instance.FieldKeys[right].Scope })
	return instance
}

func cloneDomains(domains []Domain) []Domain {
	raw, _ := json.Marshal(domains)
	var result []Domain
	_ = json.Unmarshal(raw, &result)
	return result
}

func hash(value any) string {
	raw, _ := json.Marshal(value)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func number(value float64) *float64 { return &value }
