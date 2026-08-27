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

func TestPublishedCatalogMaterializesWorkspaceAdministratorAuthority(t *testing.T) {
	catalog := identitysdk.AuthorizationCatalog{
		ContractVersion: identitysdk.CatalogVersionV1,
		Application:     identitysdk.ApplicationRef{WorkspaceID: "default", ApplicationKey: "runtime-app"},
		Resources:       []identitysdk.ResourceDefinition{{Key: "customer", Fields: []string{"id", "secret"}, SupportedFacts: []string{"id"}}},
		Actions:         []identitysdk.ActionDefinition{{Resource: "customer", Action: "read"}},
	}
	bundle := identitysdk.AccessBundle{
		ContractVersion:       identitysdk.PolicyBundleVersionV1,
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
