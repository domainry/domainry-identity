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
	contractError := &identitysdk.Error{Code: "identity.permission_definition_invalid"}
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
	}, identitymodel.Principal{WorkspaceID: "workspace-primary", UserID: "user-1"}, time.Now())
	if len(bundle.FunctionGrants) != 1 || len(bundle.DataPolicies) != 0 {
		t.Fatalf("bundle=%#v", bundle)
	}
	bundle = sdkAccessBundle(identitymodel.IdentityEffectiveAccessSnapshot{
		AuthorizationRevision: "revision-1",
		DataAccess:            []identitymodel.IdentityEffectiveDataAccess{{ObjectKey: "order", Action: "read", Allowed: true, Scope: "all_records"}},
	}, identitymodel.Principal{WorkspaceID: "workspace-primary", UserID: "user-1"}, time.Now())
	if len(bundle.DataPolicies) != 1 || bundle.DataPolicies[0].Predicate.Operator != identitysdk.OperatorExists {
		t.Fatalf("all-records policy=%#v", bundle.DataPolicies)
	}
}

func TestSDKAccessBundlePreservesCompleteV4PolicySemantics(t *testing.T) {
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
		WorkspaceID: "workspace-primary", UserID: "user-1",
		Role: identitymodel.RoleSchema{Guardrails: []identitymodel.IdentityGuardrailPolicy{{Key: "regulated", FieldRestrictions: []identitymodel.IdentityFieldRestriction{{ObjectKey: "invoice", FieldKey: "phone", Actions: []string{"export"}, Reason: "legal hold"}}}}},
	}, time.Now())
	if bundle.ContractVersion != identitysdk.CurrentPolicyBundleVersion || len(bundle.DataPolicies) != 1 || !bundle.DataPolicies[0].AuditDenial || len(bundle.DataPolicies[0].Predicate.Path) != 1 || bundle.DataPolicies[0].Predicate.Value != "$context.business_profile_id" {
		t.Fatalf("data policy lost V3 semantics: %#v", bundle.DataPolicies)
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

func TestSDKAccessBundleAuthorizesOnlyExactPermissionGrant(t *testing.T) {
	now := time.Now().UTC()
	predicate := identitymodel.IdentityPolicyExpression{Operator: "eq", FieldKey: "identity_user_id", ValueSource: "actor_claim", ClaimKey: "user_id"}
	bundle := sdkAccessBundle(identitymodel.IdentityEffectiveAccessSnapshot{
		AuthorizationRevision: "authz",
		Permissions:           []identitymodel.IdentityEffectivePermissionGrant{{Key: "course_favorite.create", ObjectKey: "course_favorite", Action: "create"}},
		DataAccess:            []identitymodel.IdentityEffectiveDataAccess{{ObjectKey: "course_favorite", Action: "write", Allowed: true, Scope: "custom", Predicate: &predicate}},
	}, identitymodel.Principal{Known: true, WorkspaceID: "workspace-primary", UserID: "wechat-user"}, now)
	allowed, err := identityevaluator.Evaluate(bundle, identitysdk.AccessRequest{ObjectKey: "course_favorite", Action: "create", DataAction: identitysdk.DataActionWrite}, identitysdk.ResourceFacts{"identity_user_id": "wechat-user"}, now)
	if err != nil || !allowed.Allowed {
		t.Fatalf("exact action decision=%+v err=%v bundle=%+v", allowed, err, bundle)
	}
	denied, err := identityevaluator.Evaluate(bundle, identitysdk.AccessRequest{ObjectKey: "course_favorite", Action: "read", DataAction: identitysdk.DataActionRead}, identitysdk.ResourceFacts{"identity_user_id": "wechat-user"}, now)
	if err != nil || denied.Allowed {
		t.Fatalf("undeclared action decision=%+v err=%v bundle=%+v", denied, err, bundle)
	}
}

func TestFunctionGrantRemainsExact(t *testing.T) {
	bundle := sdkAccessBundle(identitymodel.IdentityEffectiveAccessSnapshot{
		AuthorizationRevision: "authz",
		Permissions:           []identitymodel.IdentityEffectivePermissionGrant{{Key: "identity.roles.list", ObjectKey: "identity.roles", Action: "list"}},
	}, identitymodel.Principal{Known: true, WorkspaceID: "workspace-primary", UserID: "admin"}, time.Now())
	if len(bundle.FunctionGrants) != 1 || bundle.FunctionGrants[0].Resource != "identity.roles" || bundle.FunctionGrants[0].Action != "list" {
		t.Fatalf("function grant changed unexpectedly: %+v", bundle.FunctionGrants)
	}
}
