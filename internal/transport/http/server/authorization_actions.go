package httpserver

import (
	"fmt"
	"net/http"

	actioncontract "github.com/domainry/domainry-foundation/action"
	"github.com/domainry/domainry-foundation/modulecapability"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type standaloneProtocolActionSpec struct {
	key, owner, sourceKind              string
	capabilityKey, capabilityLabel      string
	operationKey, operationLabel, label string
	method, route                       string
	exposure                            actioncontract.Exposure
	authorization                       actioncontract.Authorization
	risk                                actioncontract.RiskLevel
	effect                              actioncontract.EffectClass
}

func standaloneProtocolAuthorizationActions() ([]identitymodel.IdentityActionDefinition, error) {
	anonymous := actioncontract.Authorization{Strategy: actioncontract.AuthorizationAnonymous}
	principal := actioncontract.Authorization{Strategy: actioncontract.AuthorizationAuthenticated}
	service := func(policy string) actioncontract.Authorization {
		// The credential registry resolves the exact workspace/application scope
		// named by the request. This audience names that source-owned credential
		// class; it is not a RoleSchema grant or a wildcard permission.
		return actioncontract.Authorization{Strategy: actioncontract.AuthorizationSigned, PolicyKey: policy, Audiences: []string{"registered_identity_application"}}
	}
	operations := func(policy string) actioncontract.Authorization {
		return actioncontract.Authorization{Strategy: actioncontract.AuthorizationSigned, PolicyKey: policy}
	}
	specs := []standaloneProtocolActionSpec{
		{key: "identity.health.live", owner: "identity:standalone", sourceKind: "health_probe", capabilityKey: "identity.health", capabilityLabel: "Identity health", operationKey: "live", operationLabel: "Liveness", label: "Read Identity liveness", method: http.MethodGet, route: "/live", exposure: actioncontract.ExposurePublic, authorization: anonymous, risk: actioncontract.RiskLow},
		{key: "identity.health.ready", owner: "identity:standalone", sourceKind: "health_probe", capabilityKey: "identity.health", capabilityLabel: "Identity health", operationKey: "ready", operationLabel: "Readiness", label: "Read Identity readiness", method: http.MethodGet, route: "/ready", exposure: actioncontract.ExposurePublic, authorization: anonymous, risk: actioncontract.RiskLow},
		{key: "identity.health.get", owner: "identity:standalone", sourceKind: "health_probe", capabilityKey: "identity.health", capabilityLabel: "Identity health", operationKey: "get", operationLabel: "Health", label: "Read Identity health", method: http.MethodGet, route: "/health", exposure: actioncontract.ExposurePublic, authorization: anonymous, risk: actioncontract.RiskLow},

		{key: "identity.portability.write_fences.freeze", owner: "identity:portability", sourceKind: "operations_http", capabilityKey: "identity.portability.write_fences", capabilityLabel: "Identity portability write fences", operationKey: "freeze", operationLabel: "Freeze", label: "Freeze workspace writes for portability", method: http.MethodPost, route: "/identity/portability/write-fences", exposure: actioncontract.ExposureOps, authorization: operations("identity.portability.operations_token"), risk: actioncontract.RiskCritical},
		{key: "identity.portability.write_fences.release", owner: "identity:portability", sourceKind: "operations_http", capabilityKey: "identity.portability.write_fences", capabilityLabel: "Identity portability write fences", operationKey: "release", operationLabel: "Release", label: "Release a workspace portability write fence", method: http.MethodPost, route: "/identity/portability/write-fences/{workspaceID}/release", exposure: actioncontract.ExposureOps, authorization: operations("identity.portability.operations_token"), risk: actioncontract.RiskCritical},

		{key: "identity.remote.discovery.get", owner: "identity:remote-sdk", sourceKind: "remote_sdk_http", capabilityKey: "identity.remote.discovery", capabilityLabel: "Identity Remote SDK discovery", operationKey: "get", operationLabel: "Discover", label: "Read the Identity Remote SDK descriptor", method: http.MethodGet, route: "/identity/discovery", exposure: actioncontract.ExposurePublic, authorization: anonymous, risk: actioncontract.RiskLow},
		{key: "identity.remote.application_service.token", owner: "identity:remote-sdk", sourceKind: "remote_sdk_http", capabilityKey: "identity.remote.application_service", capabilityLabel: "Identity application service", operationKey: "token", operationLabel: "Issue token", label: "Issue an application service token", method: http.MethodPost, route: "/identity/application-service/token", exposure: actioncontract.ExposurePublic, authorization: service("identity.application_service.static_credential"), risk: actioncontract.RiskHigh},
		{key: "identity.remote.application_service.verify", owner: "identity:remote-sdk", sourceKind: "remote_sdk_http", capabilityKey: "identity.remote.application_service", capabilityLabel: "Identity application service", operationKey: "verify", operationLabel: "Verify token", label: "Verify an application service token", method: http.MethodPost, route: "/identity/application-service/verify", exposure: actioncontract.ExposurePublic, authorization: service("identity.application_service.verifier_credential"), risk: actioncontract.RiskHigh},
		{key: "identity.remote.access_bundle.resolve", owner: "identity:remote-sdk", sourceKind: "remote_sdk_http", capabilityKey: "identity.remote.authorization", capabilityLabel: "Identity Remote SDK authorization", operationKey: "access_bundle", operationLabel: "Resolve access", label: "Resolve an access bundle for the authenticated subject", method: http.MethodPost, route: "/identity/access-bundle", exposure: actioncontract.ExposurePublic, authorization: principal, risk: actioncontract.RiskMedium},
		{key: "identity.remote.authorization.reauthorize", owner: "identity:remote-sdk", sourceKind: "remote_sdk_http", capabilityKey: "identity.remote.authorization", capabilityLabel: "Identity Remote SDK authorization", operationKey: "reauthorize", operationLabel: "Reauthorize", label: "Reauthorize an authenticated subject", method: http.MethodPost, route: "/identity/reauthorize", exposure: actioncontract.ExposurePublic, authorization: principal, risk: actioncontract.RiskMedium},
		{key: "identity.remote.action_assurance.begin", owner: "identity:remote-sdk", sourceKind: "remote_sdk_http", capabilityKey: "identity.remote.action_assurance", capabilityLabel: "Identity Action assurance", operationKey: "begin", operationLabel: "Begin", label: "Begin an authenticated Action assurance challenge", method: http.MethodPost, route: "/auth/action-assurance/challenges", exposure: actioncontract.ExposurePublic, authorization: principal, risk: actioncontract.RiskHigh},
		{key: "identity.remote.action_assurance.verify", owner: "identity:remote-sdk", sourceKind: "remote_sdk_http", capabilityKey: "identity.remote.action_assurance", capabilityLabel: "Identity Action assurance", operationKey: "verify", operationLabel: "Verify", label: "Verify an authenticated Action assurance challenge", method: http.MethodPost, route: "/auth/action-assurance/challenges/verify", exposure: actioncontract.ExposurePublic, authorization: principal, risk: actioncontract.RiskHigh},
		{key: "identity.remote.action_assurance.receipt_validate", owner: "identity:remote-sdk", sourceKind: "remote_sdk_http", capabilityKey: "identity.remote.action_assurance", capabilityLabel: "Identity Action assurance", operationKey: "receipt_validate", operationLabel: "Validate receipt", label: "Validate an Identity-signed Action assurance receipt", method: http.MethodPost, route: "/auth/action-assurance/receipts/validate", exposure: actioncontract.ExposurePublic, authorization: principal, risk: actioncontract.RiskHigh},
		{key: "identity.remote.applications.register", owner: "identity:remote-sdk", sourceKind: "remote_sdk_http", capabilityKey: "identity.remote.applications", capabilityLabel: "Identity application registry", operationKey: "register", operationLabel: "Register", label: "Register the calling application", method: http.MethodPut, route: "/identity/applications/current", exposure: actioncontract.ExposurePublic, authorization: service("identity.applications.application_credential"), risk: actioncontract.RiskHigh},
		{key: "identity.remote.permissions.reconcile", owner: "identity:remote-sdk", sourceKind: "remote_sdk_http", capabilityKey: "identity.remote.permissions", capabilityLabel: "Identity PermissionDefinition reconcile", operationKey: "reconcile", operationLabel: "Reconcile", label: "Reconcile source-owned PermissionDefinitions", method: http.MethodPut, route: "/identity/permissions/reconcile", exposure: actioncontract.ExposurePublic, authorization: service("identity.permissions.application_credential"), risk: actioncontract.RiskHigh},
		{key: "identity.remote.permissions.source_snapshot", owner: "identity:remote-sdk", sourceKind: "remote_sdk_http", capabilityKey: "identity.remote.permissions", capabilityLabel: "Identity PermissionDefinition reconcile", operationKey: "source_snapshot", operationLabel: "Read source snapshot", label: "Read the current source-owned PermissionDefinition snapshot hash", method: http.MethodPost, route: "/identity/permissions/source-snapshot", exposure: actioncontract.ExposurePublic, authorization: service("identity.permissions.application_credential"), risk: actioncontract.RiskLow, effect: actioncontract.EffectRead},

		{key: "identity.remote.projection.user.get", owner: "identity:remote-sdk", sourceKind: "remote_sdk_http", capabilityKey: "identity.remote.projection", capabilityLabel: "Identity projection projection", operationKey: "user_get", operationLabel: "Get user", label: "Read one user projection", method: http.MethodPost, route: "/identity/users/lookup", exposure: actioncontract.ExposurePublic, authorization: service("identity.projection.application_credential"), risk: actioncontract.RiskLow},
		{key: "identity.remote.projection.organization_unit.get", owner: "identity:remote-sdk", sourceKind: "remote_sdk_http", capabilityKey: "identity.remote.projection", capabilityLabel: "Identity projection projection", operationKey: "organization_unit_get", operationLabel: "Get organization unit", label: "Read one organization unit projection", method: http.MethodPost, route: "/identity/organization-units/lookup", exposure: actioncontract.ExposurePublic, authorization: service("identity.projection.application_credential"), risk: actioncontract.RiskLow},
		{key: "identity.remote.projection.users.list", owner: "identity:remote-sdk", sourceKind: "remote_sdk_http", capabilityKey: "identity.remote.projection", capabilityLabel: "Identity projection projection", operationKey: "users_list", operationLabel: "List users", label: "List user projections", method: http.MethodPost, route: "/identity/users/query", exposure: actioncontract.ExposurePublic, authorization: service("identity.projection.application_credential"), risk: actioncontract.RiskLow},
		{key: "identity.remote.projection.roles.list", owner: "identity:remote-sdk", sourceKind: "remote_sdk_http", capabilityKey: "identity.remote.projection", capabilityLabel: "Identity projection projection", operationKey: "roles_list", operationLabel: "List roles", label: "List role projections", method: http.MethodPost, route: "/identity/roles/query", exposure: actioncontract.ExposurePublic, authorization: service("identity.projection.application_credential"), risk: actioncontract.RiskLow},
		{key: "identity.remote.projection.role_assignments.list", owner: "identity:remote-sdk", sourceKind: "remote_sdk_http", capabilityKey: "identity.remote.projection", capabilityLabel: "Identity projection projection", operationKey: "role_assignments_list", operationLabel: "List role assignments", label: "List user-role assignment projections", method: http.MethodPost, route: "/identity/user-role-assignments/query", exposure: actioncontract.ExposurePublic, authorization: service("identity.projection.application_credential"), risk: actioncontract.RiskLow},
		{key: "identity.remote.principal.resolve", owner: "identity:remote-sdk", sourceKind: "remote_sdk_http", capabilityKey: "identity.remote.principal", capabilityLabel: "Identity principal projection", operationKey: "resolve", operationLabel: "Resolve", label: "Resolve a principal for a trusted Runtime", method: http.MethodPost, route: "/identity/principal/resolve", exposure: actioncontract.ExposurePublic, authorization: service("identity.principal.application_credential"), risk: actioncontract.RiskMedium},

		{key: "identity.remote.module_capability.summary", owner: "identity:remote-sdk", sourceKind: "module_capability_protocol", capabilityKey: "identity.remote.module_capability", capabilityLabel: "Identity module capability protocol", operationKey: "summary", operationLabel: "Read summary", label: "Read the Identity module capability summary", method: http.MethodGet, route: modulecapability.SummaryPath, exposure: actioncontract.ExposurePublic, authorization: service("identity.module_capability.application_credential"), risk: actioncontract.RiskLow},
		{key: "identity.remote.module_capability.category", owner: "identity:remote-sdk", sourceKind: "module_capability_protocol", capabilityKey: "identity.remote.module_capability", capabilityLabel: "Identity module capability protocol", operationKey: "category", operationLabel: "Read category", label: "Read one Identity module capability category", method: http.MethodGet, route: modulecapability.CategoriesPath + "{key}", exposure: actioncontract.ExposurePublic, authorization: service("identity.module_capability.application_credential"), risk: actioncontract.RiskLow},
		{key: "identity.remote.module_capability.validate", owner: "identity:remote-sdk", sourceKind: "module_capability_protocol", capabilityKey: "identity.remote.module_capability", capabilityLabel: "Identity module capability protocol", operationKey: "validate", operationLabel: "Validate", label: "Validate an Identity module capability candidate", method: http.MethodPost, route: modulecapability.ValidationPath, exposure: actioncontract.ExposurePublic, authorization: service("identity.module_capability.application_credential"), risk: actioncontract.RiskMedium},
	}
	definitions := make([]identitymodel.IdentityActionDefinition, 0, len(specs))
	for _, spec := range specs {
		effect, idempotency := actioncontract.EffectRead, "not_applicable"
		if spec.method != http.MethodGet && spec.method != http.MethodHead {
			effect, idempotency = actioncontract.EffectWrite, "protocol_or_application_receipt"
		}
		if spec.effect != "" {
			effect = spec.effect
			if effect == actioncontract.EffectRead {
				idempotency = "not_applicable"
			}
		}
		definition, err := actioncontract.NormalizeDefinition(actioncontract.ActionDefinition{
			Key: spec.key, Owner: spec.owner, SourceKind: spec.sourceKind,
			CapabilityKey: spec.capabilityKey, CapabilityLabel: spec.capabilityLabel,
			OperationKey: spec.operationKey, OperationLabel: spec.operationLabel, Label: spec.label,
			Exposures: []actioncontract.Exposure{spec.exposure}, Authorization: spec.authorization,
			HTTP:        &actioncontract.HTTPBinding{Method: spec.method, RouteTemplate: spec.route, DisplayRouteTemplate: spec.route},
			EffectClass: effect, RiskLevel: spec.risk, IdempotencyDecision: idempotency,
			AuditClass: "identity_protocol", LifecycleStatus: actioncontract.LifecycleActive,
		})
		if err != nil {
			return nil, fmt.Errorf("standalone protocol action %q: %w", spec.key, err)
		}
		definitions = append(definitions, definition)
	}
	return definitions, nil
}
