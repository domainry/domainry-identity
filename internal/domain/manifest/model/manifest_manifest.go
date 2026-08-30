package manifestmodel

import (
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	localizationmodel "github.com/domainry/domainry-identity/internal/domain/localization/model"
)

type ManifestSchema struct {
	SchemaVersion             string                                         `json:"schema_version"`
	TemplateID                string                                         `json:"template_id"`
	Version                   string                                         `json:"version"`
	ManifestHash              string                                         `json:"manifest_hash,omitempty"`
	SourceBlueprintID         string                                         `json:"source_blueprint_id,omitempty"`
	TargetAPIContractVersion  string                                         `json:"target_api_contract_version,omitempty"`
	TargetAPIContractHash     string                                         `json:"target_api_contract_hash,omitempty"`
	AuthoringContractVersion  string                                         `json:"authoring_contract_version,omitempty"`
	AuthoringContractHash     string                                         `json:"authoring_contract_hash,omitempty"`
	GeneratedDomainSDK        *GeneratedDomainSDKIdentity                    `json:"generated_domain_sdk,omitempty"`
	SourceIntentCoverage      *ManifestSourceIntentCoverage                  `json:"source_intent_coverage,omitempty"`
	DefaultLocale             string                                         `json:"default_locale,omitempty"`
	Name                      string                                         `json:"name,omitempty"`
	Description               string                                         `json:"description,omitempty"`
	I18n                      localizationmodel.LocalizedTextMap             `json:"i18n,omitempty"`
	Objects                   []definitionmodel.ObjectSchema                 `json:"objects"`
	Actions                   []definitionmodel.ActionSchema                 `json:"actions,omitempty"`
	IdentityBootstrap         *identitymodel.ManifestIdentityBootstrapSchema `json:"identity_bootstrap,omitempty"`
	IdentityProfileExtensions []identitymodel.IdentityProfileExtension       `json:"identity_profile_extensions,omitempty"`
	ReferencePermissions      []identitymodel.ReferencePermission            `json:"reference_permissions,omitempty"`
	Users                     []identitymodel.ManifestIdentityUserSchema     `json:"users,omitempty"`
	PermissionSets            []identitymodel.IdentityPermissionSet          `json:"permission_sets,omitempty"`
	PermissionSetGroups       []identitymodel.IdentityPermissionSetGroup     `json:"permission_set_groups,omitempty"`
	Guardrails                []identitymodel.IdentityGuardrailPolicy        `json:"guardrails,omitempty"`
	Roles                     []identitymodel.RoleSchema                     `json:"roles"`
}
