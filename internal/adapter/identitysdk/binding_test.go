package identitysdkadapter

import (
	"errors"
	"net/http"
	"reflect"
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
	tests := map[identitymodel.IdentityDataScope]identitysdk.Predicate{
		"all":        {},
		"owner":      {Fact: "owner_user_id", Operator: identitysdk.OperatorEqual, Value: "$subject.id"},
		"org":        {Fact: "owner_org_id", Operator: identitysdk.OperatorEqual, Value: "$subject.org_id"},
		"org_child":  {Fact: "owner_org_id", Operator: identitysdk.OperatorIn, Value: "$subject.org_scope_ids"},
		"target_org": {Fact: "owner_org_id", Operator: identitysdk.OperatorIn, Value: "$subject.support_org_scope_ids"},
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
	}, identitymodel.Principal{
		WorkspaceID: "workspace-primary", UserID: "user-1", OrgID: "region",
		OrgScopeIDs: []string{"region", "store"}, SupportOrgID: "support", SupportOrgScopeIDs: []string{"support", "support-child"}, ReportingScopeUserIDs: []string{"manager", "seller"},
	}, time.Now())
	if len(bundle.FunctionGrants) != 1 || len(bundle.DataPolicies) != 0 {
		t.Fatalf("bundle=%#v", bundle)
	}
	if bundle.Subject.OrgID != "region" || len(bundle.Subject.OrgScopeIDs) != 2 || bundle.Subject.SupportOrgID != "support" || len(bundle.Subject.SupportOrgScopeIDs) != 2 || len(bundle.Subject.ReportingScopeUserIDs) != 2 {
		t.Fatalf("bundle subject lost current hierarchy IDs: %#v", bundle.Subject)
	}
	bundle = sdkAccessBundle(identitymodel.IdentityEffectiveAccessSnapshot{
		AuthorizationRevision: "revision-1",
		DataAccess:            []identitymodel.IdentityEffectiveDataAccess{{PermissionKey: "order.read", Resource: "order", Action: "read", Allowed: true, Scopes: []identitymodel.IdentityDataScope{identitymodel.IdentityDataScopeAll}}},
	}, identitymodel.Principal{WorkspaceID: "workspace-primary", UserID: "user-1"}, time.Now())
	if len(bundle.DataPolicies) != 1 || bundle.DataPolicies[0].Action != "read" || !bundle.DataPolicies[0].Predicate.IsZero() || len(bundle.DataPolicies[0].DataScopes) != 1 || bundle.DataPolicies[0].DataScopes[0] != identitysdk.DataScopeAll {
		t.Fatalf("all data-scope policy=%#v", bundle.DataPolicies)
	}
}

func TestSDKAccessBundlePreservesTenantScope(t *testing.T) {
	now := time.Now().UTC()
	bundle := sdkAccessBundle(identitymodel.IdentityEffectiveAccessSnapshot{
		AuthorizationRevision: "revision-tenant",
	}, identitymodel.Principal{
		TenantID: "tenant-primary", WorkspaceID: "workspace-primary", UserID: "user-1",
	}, now)
	if bundle.Subject.TenantID != "tenant-primary" || bundle.Subject.WorkspaceID != "workspace-primary" {
		t.Fatalf("bundle subject scope=%#v", bundle.Subject)
	}
}

func TestSDKAccessBundlePreservesCompleteV4PolicySemantics(t *testing.T) {
	relation := &identitymodel.IdentityPolicyExpression{
		Operator: "eq", FieldKey: "owner_id", ValueSource: "actor_claim", ClaimKey: "business_profile_id",
		Path: []identitymodel.IdentityPolicyRelationSegment{{Direction: "forward", RelationFieldKey: "account_id", TargetObjectKey: "account"}},
	}
	bundle := sdkAccessBundle(identitymodel.IdentityEffectiveAccessSnapshot{
		AuthorizationRevision: "revision-2",
		DataAccess:            []identitymodel.IdentityEffectiveDataAccess{{PermissionKey: "invoice.read", Resource: "invoice", Action: "read", Allowed: true, Scopes: []identitymodel.IdentityDataScope{identitymodel.IdentityDataScopeTargetOrg}, AuditDenial: true}},
		FieldAccess: []identitymodel.IdentityEffectiveFieldAccess{{
			ObjectKey: "invoice", FieldKey: "phone", Read: true, Masked: true, Reason: "personal data", AuditDenial: true,
			Policies: []identitymodel.ContextualFieldPolicyRule{{Key: "owner-clear", Priority: 100, Actions: []string{"read"}, Effect: "allow", Predicate: relation}},
		}},
		ReferencePermissions: []identitymodel.ReferencePermission{{SourceObjectKey: "invoice", RelationFieldKey: "account_id", TargetObjectKey: "account", Mode: "deny", Reason: "restricted"}},
		GuardrailKeys:        []string{"regulated"},
	}, identitymodel.Principal{
		WorkspaceID: "workspace-primary", UserID: "user-1", SupportOrgScopeIDs: []string{"sales"},
		Role: identitymodel.RoleSchema{Guardrails: []identitymodel.IdentityGuardrailPolicy{{Key: "regulated", FieldRestrictions: []identitymodel.IdentityFieldRestriction{{ObjectKey: "invoice", FieldKey: "phone", Actions: []string{"export"}, Reason: "legal hold"}}}}},
	}, time.Now())
	if bundle.ContractVersion != identitysdk.CurrentPolicyBundleVersion || len(bundle.DataPolicies) != 1 || !bundle.DataPolicies[0].AuditDenial || bundle.DataPolicies[0].Predicate.Value != "$subject.support_org_scope_ids" || len(bundle.DataPolicies[0].DataScopes) != 1 || bundle.DataPolicies[0].DataScopes[0] != identitysdk.DataScopeTargetOrg {
		t.Fatalf("data policy lost canonical scope semantics: %#v", bundle.DataPolicies)
	}
	if len(bundle.FieldPolicies) != 1 || bundle.FieldPolicies[0].Reason != "personal data" || !bundle.FieldPolicies[0].AuditDenial || len(bundle.FieldPolicies[0].Rules) != 1 || len(bundle.FieldPolicies[0].Rules[0].Predicate.Path) != 1 {
		t.Fatalf("field policy lost contextual semantics: %#v", bundle.FieldPolicies)
	}
	if len(bundle.ReferencePolicies) != 1 || bundle.ReferencePolicies[0].Allowed || bundle.ReferencePolicies[0].Reason != "restricted" {
		t.Fatalf("reference policy lost reason/mode: %#v", bundle.ReferencePolicies)
	}
	if len(bundle.Guardrails) != 1 || bundle.Guardrails[0].Field != "phone" || bundle.Guardrails[0].Reason != "legal hold" {
		t.Fatalf("field guardrail lost restriction: %#v", bundle.Guardrails)
	}
}

func TestSDKAccessBundleOmitsUnrestrictedAllFieldsExportRule(t *testing.T) {
	bundle := sdkAccessBundle(identitymodel.IdentityEffectiveAccessSnapshot{
		AuthorizationRevision: "revision-export",
		ExportRules: []identitymodel.ExportRule{
			{ObjectKey: "customer", Mode: "all_fields"},
			{ObjectKey: "invoice", Mode: "selected_fields", Fields: []string{"id", "amount"}},
			{ObjectKey: "secret", Mode: "deny"},
		},
	}, identitymodel.Principal{WorkspaceID: "workspace-primary", UserID: "user-1"}, time.Now())

	if len(bundle.ExportPolicies) != 2 {
		t.Fatalf("unrestricted all_fields export rule must not become an SDK restriction: %#v", bundle.ExportPolicies)
	}
	if bundle.ExportPolicies[0].Resource != "invoice" || bundle.ExportPolicies[0].Mode != identitysdk.ExportModeAllowList || !reflect.DeepEqual(bundle.ExportPolicies[0].Fields, []string{"id", "amount"}) {
		t.Fatalf("allow-list export policy changed unexpectedly: %#v", bundle.ExportPolicies[0])
	}
	if bundle.ExportPolicies[1].Resource != "secret" || bundle.ExportPolicies[1].Mode != identitysdk.ExportModeDeny || len(bundle.ExportPolicies[1].Fields) != 0 {
		t.Fatalf("deny export policy changed unexpectedly: %#v", bundle.ExportPolicies[1])
	}
	if err := bundle.Validate(time.Now()); err != nil {
		t.Fatalf("normalized SDK access bundle is invalid: %v", err)
	}
}

func TestSDKAccessBundleFreezesSupportOrganizationScopeAndFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	snapshot := identitymodel.IdentityEffectiveAccessSnapshot{
		AuthorizationRevision: "support-scope-revision",
		Permissions:           []identitymodel.IdentityEffectivePermissionGrant{{Key: "customer.read", ObjectKey: "customer", Action: "read"}},
		DataAccess:            []identitymodel.IdentityEffectiveDataAccess{{PermissionKey: "customer.read", Resource: "customer", Action: "read", Allowed: true, Scopes: []identitymodel.IdentityDataScope{identitymodel.IdentityDataScopeTargetOrg}}},
	}
	principal := identitymodel.Principal{Known: true, WorkspaceID: "workspace-primary", UserID: "support-agent", SupportOrgID: "sales", SupportOrgScopeIDs: []string{"sales", "sales-east"}}
	bundle := sdkAccessBundle(snapshot, principal, now)
	if len(bundle.DataPolicies) != 1 || bundle.DataPolicies[0].Predicate.Value != "$subject.support_org_scope_ids" || !reflect.DeepEqual(bundle.Subject.SupportOrgScopeIDs, []string{"sales", "sales-east"}) {
		t.Fatalf("support scope was not published as a trusted subject fact: bundle=%#v", bundle)
	}
	allowed, err := identityevaluator.Evaluate(bundle, identitysdk.AccessRequest{ObjectKey: "customer", Action: "read"}, identitysdk.ResourceFacts{"owner_org_id": "sales-east"}, now)
	if err != nil || !allowed.Allowed {
		t.Fatalf("supported sales customer decision=%+v err=%v", allowed, err)
	}
	denied, err := identityevaluator.Evaluate(bundle, identitysdk.AccessRequest{ObjectKey: "customer", Action: "read"}, identitysdk.ResourceFacts{"owner_org_id": "other-sales"}, now)
	if err != nil || denied.Allowed {
		t.Fatalf("customer outside support scope decision=%+v err=%v", denied, err)
	}
	writeDenied, err := identityevaluator.Evaluate(bundle, identitysdk.AccessRequest{ObjectKey: "customer", Action: "update"}, identitysdk.ResourceFacts{"owner_org_id": "sales-east"}, now)
	if err != nil || writeDenied.Allowed {
		t.Fatalf("support scope granted an undeclared customer update Action: decision=%+v err=%v", writeDenied, err)
	}

	emptyBundle := sdkAccessBundle(snapshot, identitymodel.Principal{Known: true, WorkspaceID: "workspace-primary", UserID: "support-agent"}, now)
	denied, err = identityevaluator.Evaluate(emptyBundle, identitysdk.AccessRequest{ObjectKey: "customer", Action: "read"}, identitysdk.ResourceFacts{"owner_org_id": "sales"}, now)
	if err != nil || denied.Allowed {
		t.Fatalf("empty support scope did not fail closed: decision=%+v err=%v", denied, err)
	}
}

func TestSDKAccessBundleUnionsPrimaryAndSupportOrganizationScopes(t *testing.T) {
	now := time.Now().UTC()
	bundle := sdkAccessBundle(identitymodel.IdentityEffectiveAccessSnapshot{
		AuthorizationRevision: "combined-org-scope",
		Permissions:           []identitymodel.IdentityEffectivePermissionGrant{{Key: "customer.read", ObjectKey: "customer", Action: "read"}},
		DataAccess:            []identitymodel.IdentityEffectiveDataAccess{{PermissionKey: "customer.read", Resource: "customer", Action: "read", Allowed: true, Scopes: []identitymodel.IdentityDataScope{identitymodel.IdentityDataScopeOrg, identitymodel.IdentityDataScopeTargetOrg}}},
	}, identitymodel.Principal{Known: true, WorkspaceID: "workspace-primary", UserID: "support-agent", OrgID: "support-team", SupportOrgID: "sales", SupportOrgScopeIDs: []string{"sales", "sales-east"}}, now)

	for _, organizationID := range []string{"support-team", "sales", "sales-east"} {
		decision, err := identityevaluator.Evaluate(bundle, identitysdk.AccessRequest{ObjectKey: "customer", Action: "read"}, identitysdk.ResourceFacts{"owner_org_id": organizationID}, now)
		if err != nil || !decision.Allowed {
			t.Fatalf("combined scope denied organization %q: decision=%+v err=%v", organizationID, decision, err)
		}
	}
	decision, err := identityevaluator.Evaluate(bundle, identitysdk.AccessRequest{ObjectKey: "customer", Action: "read"}, identitysdk.ResourceFacts{"owner_org_id": "other"}, now)
	if err != nil || decision.Allowed {
		t.Fatalf("combined scope allowed unrelated organization: decision=%+v err=%v", decision, err)
	}
}

func TestSDKAccessBundleAuthorizesOnlyExactPermissionGrant(t *testing.T) {
	now := time.Now().UTC()
	bundle := sdkAccessBundle(identitymodel.IdentityEffectiveAccessSnapshot{
		AuthorizationRevision: "authz",
		Permissions:           []identitymodel.IdentityEffectivePermissionGrant{{Key: "course_favorite.create", ObjectKey: "course_favorite", Action: "create"}},
		DataAccess:            []identitymodel.IdentityEffectiveDataAccess{{PermissionKey: "course_favorite.create", Resource: "course_favorite", Action: "create", Allowed: true, Scopes: []identitymodel.IdentityDataScope{identitymodel.IdentityDataScopeOwner}}},
	}, identitymodel.Principal{Known: true, WorkspaceID: "workspace-primary", UserID: "wechat-user"}, now)
	allowed, err := identityevaluator.Evaluate(bundle, identitysdk.AccessRequest{ObjectKey: "course_favorite", Action: "create"}, identitysdk.ResourceFacts{"owner_user_id": "wechat-user"}, now)
	if err != nil || !allowed.Allowed {
		t.Fatalf("exact action decision=%+v err=%v bundle=%+v", allowed, err, bundle)
	}
	denied, err := identityevaluator.Evaluate(bundle, identitysdk.AccessRequest{ObjectKey: "course_favorite", Action: "read"}, identitysdk.ResourceFacts{"owner_user_id": "wechat-user"}, now)
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
