package identitysdkadapter

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityevaluator "github.com/domainry/domainry-identity-sdk/authorization/evaluator"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestSDKBoundaryNormalizesDomainErrors(t *testing.T) {
	domainError := apperror.New(apperror.KindForbidden, "auth.invalid_credentials", errors.New("credential mismatch"), map[string]string{"attempt": "login"})
	var sdkError *identitysdk.Error
	if err := sdkBoundaryError(domainError); !errors.As(err, &sdkError) {
		t.Fatalf("boundary error type=%T value=%v", err, err)
	}
	if sdkError.StatusCode != http.StatusForbidden || sdkError.Code != "auth.invalid_credentials" || sdkError.Params["attempt"] != "login" || !errors.Is(sdkError, domainError) {
		t.Fatalf("sdk error=%#v", sdkError)
	}
	contractError := &identitysdk.Error{Code: "identity.catalog_invalid"}
	if err := sdkBoundaryError(contractError); !errors.As(err, &sdkError) || sdkError.StatusCode != http.StatusBadRequest || sdkError == contractError {
		t.Fatalf("contract error=%#v original=%#v", sdkError, contractError)
	}
	if sdkBoundaryError(nil) != nil {
		t.Fatal("nil error was not preserved")
	}
}

func TestNewBindingRejectsIncompleteNamedDependencies(t *testing.T) {
	if binding, err := NewBinding(BindingDependencies{}); err == nil || binding != nil {
		t.Fatalf("binding=%T err=%v", binding, err)
	}
}

func TestSDKScopePredicateCoversPublishedIdentityScopes(t *testing.T) {
	tests := map[string]identitysdk.Predicate{
		"all_records":             {Fact: "id", Operator: identitysdk.OperatorExists, Value: true},
		"owned_records":           {Fact: "owner_id", Operator: identitysdk.OperatorEqual, Value: "$subject.id"},
		"department":              {Fact: "department_id", Operator: identitysdk.OperatorEqual, Value: "$subject.department_id"},
		"department_and_children": {Fact: "department_path", Operator: identitysdk.OperatorPrefix, Value: "$subject.department_path"},
		"subordinates":            {Fact: "owner_id", Operator: identitysdk.OperatorIn, Value: "$subject.reporting_subject_ids"},
		"team":                    {Fact: "team_id", Operator: identitysdk.OperatorIn, Value: "$subject.organization_scopes.team_ids"},
	}
	for scope, want := range tests {
		if got := sdkScopePredicate(scope); got.Fact != want.Fact || got.Operator != want.Operator || got.Value != want.Value {
			t.Fatalf("scope %s predicate=%#v want=%#v", scope, got, want)
		}
	}
}

func TestSDKAccessBundleDoesNotInventDataAccessFromFunctionGrant(t *testing.T) {
	bundle := sdkAccessBundle(identitymodel.IdentityEffectiveAccessSnapshot{
		AuthorizationRevision: "revision-1",
		Permissions:           []identitymodel.IdentityEffectivePermissionGrant{{ObjectKey: "order", Action: "read"}},
	}, identitymodel.Principal{WorkspaceID: "default", UserID: "user-1"}, "catalog-1", time.Now())
	if len(bundle.FunctionGrants) != 1 || len(bundle.DataPolicies) != 0 {
		t.Fatalf("bundle=%#v", bundle)
	}

	bundle = sdkAccessBundle(identitymodel.IdentityEffectiveAccessSnapshot{
		AuthorizationRevision: "revision-1",
		DataAccess:            []identitymodel.IdentityEffectiveDataAccess{{ObjectKey: "order", Action: "read", Allowed: true, Scope: "all_records"}},
	}, identitymodel.Principal{WorkspaceID: "default", UserID: "user-1"}, "catalog-1", time.Now())
	if len(bundle.DataPolicies) != 1 || bundle.DataPolicies[0].Predicate.Operator != identitysdk.OperatorExists {
		t.Fatalf("all-records policy=%#v", bundle.DataPolicies)
	}
}

func TestSDKAccessBundlePreservesCompleteV2PolicySemantics(t *testing.T) {
	relation := &identitymodel.IdentityPolicyExpression{
		Operator: "eq", FieldKey: "owner_id", ValueSource: "actor_claim", ClaimKey: "business_profile_id",
		Path: []identitymodel.IdentityPolicyRelationSegment{{Direction: "forward", RelationFieldKey: "account_id", TargetObjectKey: "account"}},
	}
	bundle := sdkAccessBundle(identitymodel.IdentityEffectiveAccessSnapshot{
		AuthorizationRevision: "revision-2",
		DataAccess:            []identitymodel.IdentityEffectiveDataAccess{{ObjectKey: "invoice", Action: "read", Allowed: true, Scope: "custom", Predicate: relation, AuditDenial: true}},
		FieldAccess: []identitymodel.IdentityEffectiveFieldAccess{{
			ObjectKey: "invoice", FieldKey: "phone", Read: true, Masked: true, Reason: "personal data",
			Policies: []identitymodel.ContextualFieldPolicyRule{{Key: "owner-clear", Priority: 100, Actions: []string{"read"}, Effect: "allow", Predicate: relation}},
		}},
		ReferencePermissions: []identitymodel.ReferencePermission{{SourceObjectKey: "invoice", RelationFieldKey: "account_id", TargetObjectKey: "account", Mode: "deny", Reason: "restricted"}},
		GuardrailKeys:        []string{"regulated"},
	}, identitymodel.Principal{
		WorkspaceID: "default", UserID: "user-1",
		Role: identitymodel.RoleSchema{Guardrails: []identitymodel.IdentityGuardrailPolicy{{Key: "regulated", FieldRestrictions: []identitymodel.IdentityFieldRestriction{{ObjectKey: "invoice", FieldKey: "phone", Actions: []string{"export"}, Reason: "legal hold"}}}}},
	}, "catalog-2", time.Now())
	if bundle.ContractVersion != identitysdk.CurrentPolicyBundleVersion || len(bundle.DataPolicies) != 1 || !bundle.DataPolicies[0].AuditDenial || len(bundle.DataPolicies[0].Predicate.Path) != 1 || bundle.DataPolicies[0].Predicate.Value != "$context.business_profile_id" {
		t.Fatalf("data policy lost V2 semantics: %#v", bundle.DataPolicies)
	}
	if len(bundle.FieldPolicies) != 1 || bundle.FieldPolicies[0].Reason != "personal data" || len(bundle.FieldPolicies[0].Rules) != 1 || len(bundle.FieldPolicies[0].Rules[0].Predicate.Path) != 1 {
		t.Fatalf("field policy lost contextual semantics: %#v", bundle.FieldPolicies)
	}
	if len(bundle.ReferencePolicies) != 1 || bundle.ReferencePolicies[0].Allowed || bundle.ReferencePolicies[0].Reason != "restricted" {
		t.Fatalf("reference policy lost reason/mode: %#v", bundle.ReferencePolicies)
	}
	if len(bundle.Guardrails) != 1 || bundle.Guardrails[0].Field != "phone" || bundle.Guardrails[0].Reason != "legal hold" {
		t.Fatalf("field guardrail lost restriction: %#v", bundle.Guardrails)
	}
}

func TestAccessBundleIsConstrainedByPublishedCatalog(t *testing.T) {
	catalog := identitysdk.AuthorizationCatalog{
		ContractVersion: identitysdk.CatalogVersionV1,
		Application:     identitysdk.ApplicationRef{WorkspaceID: "default", ApplicationKey: "runtime-app"},
		Resources: []identitysdk.ResourceDefinition{
			{Key: "customer", Fields: []string{"id"}, SupportedFacts: []string{"owner_id"}},
		},
		Actions: []identitysdk.ActionDefinition{{Resource: "customer", Action: "read"}},
	}
	bundle := identitysdk.AccessBundle{
		FunctionGrants: []identitysdk.FunctionGrant{
			{Resource: "customer", Action: "read", Effect: identitysdk.EffectAllow},
			{Resource: "internal_admin", Action: "read", Effect: identitysdk.EffectAllow},
		},
		DataPolicies: []identitysdk.DataPolicy{{Key: "owned", Resource: "customer", Action: "read", Effect: identitysdk.EffectAllow, Predicate: identitysdk.Predicate{Fact: "owner_id", Operator: identitysdk.OperatorEqual, Value: "$subject.id"}}},
		FieldPolicies: []identitysdk.FieldPolicy{
			{Resource: "customer", Field: "id", Read: true},
			{Resource: "customer", Field: "secret", Read: true},
		},
	}
	constrained, err := accessBundleForCatalog(bundle, catalog)
	if err != nil {
		t.Fatal(err)
	}
	if len(constrained.FunctionGrants) != 1 || constrained.FunctionGrants[0].Resource != "customer" || len(constrained.FieldPolicies) != 1 || constrained.FieldPolicies[0].Field != "id" {
		t.Fatalf("constrained bundle=%#v", constrained)
	}
	bundle.DataPolicies[0].Predicate.Fact = "undeclared_fact"
	if _, err := accessBundleForCatalog(bundle, catalog); err == nil {
		t.Fatal("policy using undeclared Runtime fact was accepted")
	}
}

func TestGymOnboardingWritePolicySurvivesCatalogAndAuthorizesExactMutations(t *testing.T) {
	now := time.Now().UTC()
	catalog := identitysdk.AuthorizationCatalog{
		ContractVersion: identitysdk.CatalogVersionV1,
		Application:     identitysdk.ApplicationRef{WorkspaceID: "default", ApplicationKey: "runtime-app"},
		Resources: []identitysdk.ResourceDefinition{
			{Key: "course_favorite", Fields: []string{"id", "identity_user_id", "course_template_id"}, SupportedFacts: []string{"id", "identity_user_id"}},
			{Key: "member", Fields: []string{"id", "identity_user_id"}, SupportedFacts: []string{"id", "identity_user_id"}},
		},
		Actions: []identitysdk.ActionDefinition{
			{Resource: "course_favorite", Action: "create"}, {Resource: "course_favorite", Action: "read"}, {Resource: "course_favorite", Action: "delete"},
			{Resource: "member", Action: "read"}, {Resource: "member", Action: "self_enroll"},
		},
	}
	predicate := identitymodel.IdentityPolicyExpression{Operator: "eq", FieldKey: "identity_user_id", ValueSource: "actor_claim", ClaimKey: "user_id"}
	snapshot := identitymodel.IdentityEffectiveAccessSnapshot{
		AuthorizationRevision: "authz",
		Permissions: []identitymodel.IdentityEffectivePermissionGrant{
			{Key: "course_favorite.create", ObjectKey: "course_favorite", Action: "create"},
			{Key: "member.self_enroll", ObjectKey: "member", Action: "self_enroll"},
		},
		DataAccess: []identitymodel.IdentityEffectiveDataAccess{
			{ObjectKey: "course_favorite", Action: "write", Allowed: true, Scope: "custom", Predicate: &predicate},
			{ObjectKey: "member", Action: "write", Allowed: true, Scope: "custom", Predicate: &predicate},
		},
	}
	principal := identitymodel.Principal{Known: true, WorkspaceID: "default", UserID: "wechat-user"}
	bundle := sdkAccessBundle(snapshot, principal, "catalog", now)
	bundle = resolveCatalogRoleAccess(bundle, catalog, identitymodel.RoleSchema{Permissions: []string{"course_favorite.create", "member.self_enroll"}})
	bundle, err := accessBundleForCatalog(bundle, catalog)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.DataPolicies) != 2 {
		t.Fatalf("write policies were removed by catalog constraint: %+v", bundle.DataPolicies)
	}
	for _, request := range []identitysdk.AccessRequest{{ObjectKey: "course_favorite", Action: "create"}, {ObjectKey: "member", Action: "self_enroll"}} {
		decision, err := identityevaluator.Evaluate(bundle, request, identitysdk.ResourceFacts{"identity_user_id": "wechat-user"}, now)
		if err != nil || !decision.Allowed {
			t.Fatalf("request=%+v decision=%+v err=%v bundle=%+v", request, decision, err, bundle)
		}
	}
	readOnlyCatalog := catalog
	readOnlyCatalog.Actions = []identitysdk.ActionDefinition{{Resource: "course_favorite", Action: "read"}, {Resource: "member", Action: "read"}}
	readOnlyBundle, err := accessBundleForCatalog(sdkAccessBundle(snapshot, principal, "catalog", now), readOnlyCatalog)
	if err != nil {
		t.Fatal(err)
	}
	if len(readOnlyBundle.DataPolicies) != 0 {
		t.Fatalf("write policy survived a read-only catalog: %+v", readOnlyBundle.DataPolicies)
	}
}

func TestCatalogAcceptsDeclaredRelationshipPredicatesAndRejectsDrift(t *testing.T) {
	catalog := identitysdk.AuthorizationCatalog{
		ContractVersion: identitysdk.CatalogVersionV1,
		Application:     identitysdk.ApplicationRef{WorkspaceID: "default", ApplicationKey: "runtime-app"},
		Resources: []identitysdk.ResourceDefinition{
			{Key: "invoice", Fields: []string{"id", "account_id", "phone"}, SupportedFacts: []string{"id"}, References: []identitysdk.ReferenceDefinition{{Key: "account_id", TargetResource: "account"}}},
			{Key: "account", Fields: []string{"id", "owner_id"}, SupportedFacts: []string{"owner_id"}},
		},
		Actions: []identitysdk.ActionDefinition{{Resource: "invoice", Action: "read"}},
	}
	predicate := identitysdk.Predicate{Fact: "owner_id", Operator: identitysdk.OperatorEqual, Value: "$subject.id", Path: []identitysdk.RelationSegment{{Direction: identitysdk.RelationForward, Reference: "account_id", TargetResource: "account"}}}
	bundle := identitysdk.AccessBundle{
		DataPolicies:  []identitysdk.DataPolicy{{Key: "account-owner", Resource: "invoice", Action: "read", Effect: identitysdk.EffectAllow, Predicate: predicate}},
		FieldPolicies: []identitysdk.FieldPolicy{{Resource: "invoice", Field: "phone", Read: true, Rules: []identitysdk.FieldRule{{Key: "owner-clear", Priority: 10, Actions: []identitysdk.Action{"read"}, Effect: identitysdk.FieldEffectAllow, Predicate: &predicate}}}},
	}
	if _, err := accessBundleForCatalog(bundle, catalog); err != nil {
		t.Fatalf("declared relationship predicate rejected: %v", err)
	}
	bundle.DataPolicies[0].Predicate.Path[0].Reference = "missing"
	if _, err := accessBundleForCatalog(bundle, catalog); err == nil {
		t.Fatal("drifted relationship predicate was accepted")
	}
}

func TestPublishedCatalogMaterializesWorkspaceAdministratorAuthority(t *testing.T) {
	catalog := identitysdk.AuthorizationCatalog{
		ContractVersion: identitysdk.CatalogVersionV1,
		Application:     identitysdk.ApplicationRef{WorkspaceID: "default", ApplicationKey: "runtime-app"},
		Resources:       []identitysdk.ResourceDefinition{{Key: "customer", Fields: []string{"id", "secret"}, SupportedFacts: []string{"id"}}},
		Actions:         []identitysdk.ActionDefinition{{Resource: "customer", Action: "read"}},
	}
	bundle := identitysdk.AccessBundle{
		ContractVersion:       identitysdk.CurrentPolicyBundleVersion,
		CatalogRevision:       "catalog-revision",
		AuthorizationRevision: "authorization-revision",
		ExpiresAt:             time.Now().Add(time.Minute),
		Subject:               identitysdk.Subject{WorkspaceID: "default", SubjectID: "admin"},
	}
	bundle = resolveCatalogRoleAccess(bundle, catalog, identitymodel.RoleSchema{Permissions: []string{"workspace.admin"}})
	bundle, err := accessBundleForCatalog(bundle, catalog)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := identityevaluator.Evaluate(bundle, identitysdk.AccessRequest{ObjectKey: "customer", Action: "read", FieldKey: "secret"}, identitysdk.ResourceFacts{"id": "customer-1"}, time.Now())
	if err != nil || !decision.Allowed {
		t.Fatalf("workspace administrator decision=%+v err=%v bundle=%+v", decision, err, bundle)
	}
}

func TestPublishedCatalogDoesNotInventDataAuthority(t *testing.T) {
	catalog := identitysdk.AuthorizationCatalog{
		ContractVersion: identitysdk.CatalogVersionV1,
		Application:     identitysdk.ApplicationRef{WorkspaceID: "default", ApplicationKey: "runtime-app"},
		Resources:       []identitysdk.ResourceDefinition{{Key: "customer", Fields: []string{"id"}, SupportedFacts: []string{"id"}}},
		Actions:         []identitysdk.ActionDefinition{{Resource: "customer", Action: "read"}},
	}
	bundle := resolveCatalogRoleAccess(identitysdk.AccessBundle{}, catalog, identitymodel.RoleSchema{Permissions: []string{"customer.read"}})
	if len(bundle.FunctionGrants) != 1 || len(bundle.DataPolicies) != 0 {
		t.Fatalf("catalog authority=%+v", bundle)
	}
}
