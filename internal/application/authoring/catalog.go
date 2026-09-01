package authoring

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"
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

func NewAuthoringCatalog(ownerDomain authoringcontract.CapabilityAuthoringDomain) (*AuthoringCatalog, error) {
	if ownerDomain.Key != "identity" {
		return nil, fmt.Errorf("Identity authoring domain is required")
	}
	domains := []Domain{{Key: ownerDomain.Key, Capabilities: make([]Definition, 0, len(ownerDomain.Capabilities))}}
	for _, capability := range ownerDomain.Capabilities {
		if capability.Execution == nil || capability.Execution.PermissionModel != authoringcontract.CapabilityPermissionModelExactAction || len(capability.Permissions) == 0 {
			return nil, fmt.Errorf("Identity authoring capability %q has not been projected from Actions", capability.Key)
		}
		parameters := make([]Parameter, 0, len(capability.Parameters))
		for _, parameter := range capability.Parameters {
			parameters = append(parameters, legacyAuthoringParameter(parameter))
		}
		domains[0].Capabilities = append(domains[0].Capabilities, Definition{
			Key: capability.Key, Status: capability.Status, Lifecycle: capability.Lifecycle,
			Requires: append([]string(nil), capability.Requires...), Parameters: parameters,
			Permissions: append([]string(nil), capability.Permissions...),
		})
	}
	for domainIndex := range domains {
		sort.Slice(domains[domainIndex].Capabilities, func(left, right int) bool {
			return domains[domainIndex].Capabilities[left].Key < domains[domainIndex].Capabilities[right].Key
		})
	}
	sort.Slice(domains, func(left, right int) bool { return domains[left].Key < domains[right].Key })
	catalog := &AuthoringCatalog{domains: domains}
	catalog.contractHash = hash(domains)
	return catalog, nil
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

func legacyAuthoringParameter(source authoringcontract.CapabilityAuthoringParameter) Parameter {
	return Parameter{
		Key: source.Key, Type: source.Type, Required: source.Required, Default: source.Default,
		Enum: append([]string(nil), source.Enum...), Minimum: source.Minimum, Maximum: source.Maximum,
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
