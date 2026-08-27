package identitysdkadapter

import (
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type catalogResourcePolicy struct {
	actions    map[identitysdk.Action]struct{}
	fields     map[string]struct{}
	facts      map[string]struct{}
	references map[string]identitysdk.ResourceType
}

// resolveCatalogRoleAccess materializes wildcard and workspace-administrator
// authority against the Runtime-published catalog. The generic Identity
// snapshot cannot enumerate resources that only exist in a remote Runtime, so
// the catalog is the only legitimate source for those concrete resource,
// action, and field keys.
func resolveCatalogRoleAccess(bundle identitysdk.AccessBundle, catalog identitysdk.AuthorizationCatalog, role identitymodel.RoleSchema) identitysdk.AccessBundle {
	functionAllows := make(map[string]struct{}, len(bundle.FunctionGrants))
	dataAllows := make(map[string]struct{}, len(bundle.DataPolicies))
	fieldPolicies := make(map[string]struct{}, len(bundle.FieldPolicies))
	for _, grant := range bundle.FunctionGrants {
		if grant.Effect == identitysdk.EffectAllow {
			functionAllows[catalogActionKey(grant.Resource, grant.Action)] = struct{}{}
		}
	}
	for _, policy := range bundle.DataPolicies {
		if policy.Effect == identitysdk.EffectAllow {
			dataAllows[catalogActionKey(policy.Resource, policy.Action)] = struct{}{}
		}
	}
	for _, policy := range bundle.FieldPolicies {
		fieldPolicies[string(policy.Resource)+"\x00"+strings.TrimSpace(policy.Field)] = struct{}{}
	}
	for _, action := range catalog.Actions {
		key := catalogActionKey(action.Resource, action.Action)
		if identitycontract.IdentityRoleAllows(role, string(action.Resource), string(action.Action)) {
			if _, exists := functionAllows[key]; !exists {
				bundle.FunctionGrants = append(bundle.FunctionGrants, identitysdk.FunctionGrant{
					Resource: action.Resource,
					Action:   action.Action,
					Effect:   identitysdk.EffectAllow,
				})
				functionAllows[key] = struct{}{}
			}
		}
		if identitycontract.IdentityRoleAllowsData(role, string(action.Resource), string(action.Action)) {
			if _, exists := dataAllows[key]; !exists {
				scope := identitycontract.IdentityDataScopeForAction(role, string(action.Resource), string(action.Action))
				if scope != "" && scope != "none" && scope != "custom" {
					bundle.DataPolicies = append(bundle.DataPolicies, identitysdk.DataPolicy{
						Key:       "catalog-role:" + string(action.Resource) + ":" + string(action.Action),
						Resource:  action.Resource,
						Action:    action.Action,
						Effect:    identitysdk.EffectAllow,
						Predicate: sdkScopePredicate(scope),
					})
					dataAllows[key] = struct{}{}
				}
			}
		}
	}
	for _, resource := range catalog.Resources {
		for _, rawField := range resource.Fields {
			field := strings.TrimSpace(rawField)
			key := string(resource.Key) + "\x00" + field
			if _, exists := fieldPolicies[key]; exists {
				continue
			}
			bundle.FieldPolicies = append(bundle.FieldPolicies, identitysdk.FieldPolicy{
				Resource: resource.Key,
				Field:    field,
				Read:     identitycontract.IdentityCanReadField(role, string(resource.Key), field),
				Write:    identitycontract.IdentityCanWriteField(role, string(resource.Key), field),
				Export:   identitycontract.IdentityCanExportField(role, string(resource.Key), field),
				Masked:   identitycontract.IdentityFieldReadMasked(role, string(resource.Key), field),
			})
			fieldPolicies[key] = struct{}{}
		}
	}
	return bundle
}

func catalogActionKey(resource identitysdk.ResourceType, action identitysdk.Action) string {
	return string(resource) + "\x00" + string(action)
}

func accessBundleForCatalog(bundle identitysdk.AccessBundle, catalog identitysdk.AuthorizationCatalog) (identitysdk.AccessBundle, error) {
	resources := make(map[identitysdk.ResourceType]catalogResourcePolicy, len(catalog.Resources))
	for _, resource := range catalog.Resources {
		policy := catalogResourcePolicy{actions: map[identitysdk.Action]struct{}{}, fields: map[string]struct{}{}, facts: map[string]struct{}{}, references: map[string]identitysdk.ResourceType{}}
		for _, field := range resource.Fields {
			policy.fields[strings.TrimSpace(field)] = struct{}{}
		}
		for _, fact := range resource.SupportedFacts {
			policy.facts[strings.TrimSpace(fact)] = struct{}{}
		}
		for _, reference := range resource.References {
			policy.references[strings.TrimSpace(reference.Key)] = reference.TargetResource
		}
		resources[resource.Key] = policy
	}
	for _, action := range catalog.Actions {
		policy := resources[action.Resource]
		policy.actions[action.Action] = struct{}{}
		resources[action.Resource] = policy
	}
	hasAction := func(resource identitysdk.ResourceType, action identitysdk.Action) bool {
		policy, found := resources[resource]
		if !found {
			return false
		}
		_, found = policy.actions[action]
		return found
	}
	functionGrants := make([]identitysdk.FunctionGrant, 0, len(bundle.FunctionGrants))
	for _, grant := range bundle.FunctionGrants {
		if hasAction(grant.Resource, grant.Action) {
			functionGrants = append(functionGrants, grant)
		}
	}
	dataPolicies := make([]identitysdk.DataPolicy, 0, len(bundle.DataPolicies))
	for _, policy := range bundle.DataPolicies {
		resource, found := resources[policy.Resource]
		if !found || !hasAction(policy.Resource, policy.Action) {
			continue
		}
		if !catalogPredicateSupported(policy.Predicate, resource.facts) {
			return identitysdk.AccessBundle{}, &identitysdk.Error{Code: "identity.catalog_policy_fact_unsupported", Message: policy.Key}
		}
		dataPolicies = append(dataPolicies, policy)
	}
	fieldPolicies := make([]identitysdk.FieldPolicy, 0, len(bundle.FieldPolicies))
	for _, policy := range bundle.FieldPolicies {
		resource, found := resources[policy.Resource]
		if _, declared := resource.fields[strings.TrimSpace(policy.Field)]; found && declared {
			fieldPolicies = append(fieldPolicies, policy)
		}
	}
	referencePolicies := make([]identitysdk.ReferencePolicy, 0, len(bundle.ReferencePolicies))
	for _, policy := range bundle.ReferencePolicies {
		resource, found := resources[policy.SourceResource]
		target, declared := resource.references[strings.TrimSpace(policy.Reference)]
		targetPolicy, targetFound := resources[policy.TargetResource]
		displayFieldsDeclared := targetFound
		for _, field := range policy.DisplayFields {
			if _, fieldFound := targetPolicy.fields[strings.TrimSpace(field)]; !fieldFound {
				displayFieldsDeclared = false
				break
			}
		}
		if found && declared && target == policy.TargetResource && displayFieldsDeclared {
			referencePolicies = append(referencePolicies, policy)
		}
	}
	exportPolicies := make([]identitysdk.ExportPolicy, 0, len(bundle.ExportPolicies))
	for _, policy := range bundle.ExportPolicies {
		resource, found := resources[policy.Resource]
		if !found {
			continue
		}
		valid := true
		for _, field := range policy.Fields {
			if _, declared := resource.fields[strings.TrimSpace(field)]; !declared {
				valid = false
				break
			}
		}
		if valid {
			exportPolicies = append(exportPolicies, policy)
		}
	}
	guardrails := make([]identitysdk.Guardrail, 0, len(bundle.Guardrails))
	for _, guardrail := range bundle.Guardrails {
		if guardrail.Resource == "" && guardrail.Action == "" && guardrail.Predicate == nil {
			guardrails = append(guardrails, guardrail)
			continue
		}
		resource, found := resources[guardrail.Resource]
		if !found || guardrail.Action != "" && !hasAction(guardrail.Resource, guardrail.Action) {
			continue
		}
		if guardrail.Predicate != nil && !catalogPredicateSupported(*guardrail.Predicate, resource.facts) {
			return identitysdk.AccessBundle{}, &identitysdk.Error{Code: "identity.catalog_policy_fact_unsupported", Message: guardrail.Key}
		}
		guardrails = append(guardrails, guardrail)
	}
	bundle.FunctionGrants = functionGrants
	bundle.DataPolicies = dataPolicies
	bundle.FieldPolicies = fieldPolicies
	bundle.ReferencePolicies = referencePolicies
	bundle.ExportPolicies = exportPolicies
	bundle.Guardrails = guardrails
	return bundle, nil
}

func catalogPredicateSupported(predicate identitysdk.Predicate, facts map[string]struct{}) bool {
	if len(predicate.All) > 0 {
		for _, child := range predicate.All {
			if !catalogPredicateSupported(child, facts) {
				return false
			}
		}
		return true
	}
	if len(predicate.Any) > 0 {
		for _, child := range predicate.Any {
			if !catalogPredicateSupported(child, facts) {
				return false
			}
		}
		return true
	}
	if predicate.Not != nil {
		return catalogPredicateSupported(*predicate.Not, facts)
	}
	_, found := facts[strings.TrimSpace(predicate.Fact)]
	return found
}
