package projection

import (
	"testing"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityBuildEffectiveAccessSnapshotEdges(t *testing.T) {
	expiresAt := "2030-01-01T00:00:00Z"
	input := IdentityEffectiveAccessProjectionInput{
		Principal: identitymodel.Principal{
			UserID: "user", Known: true,
			Role: identitymodel.RoleSchema{
				Permissions: []identitymodel.RolePermission{
					{PermissionKey: "order.read", DataScope: identitymodel.IdentityDataScopeOrg, AuditDenial: true},
					{PermissionKey: "order.update", DataScope: identitymodel.IdentityDataScopeAll},
					{PermissionKey: "domain.order.update", DataScope: identitymodel.IdentityDataScopeAll},
				},
				FieldPermissions: []identitymodel.FieldPermission{{ObjectKey: "order", FieldKey: "plain", Read: true, Reason: "sensitive", AuditDenial: true, Policies: []identitymodel.ContextualFieldPolicyRule{{Key: "owner", Priority: 10, Actions: []string{"read"}, Effect: "allow", Predicate: &identitymodel.IdentityPolicyExpression{Operator: "eq", FieldKey: "owner_id", ValueSource: "actor_claim", ClaimKey: "user_id"}}}}},
			},
		},
		Assignments: []identitymodel.IdentityUserRoleAssignment{
			{UserID: "user", RoleID: "role-2"},
			{UserID: "user", RoleID: "role-1", ExpiresAt: &expiresAt},
		},
		ProjectionRoles: []identitymodel.IdentityRole{
			{ID: "role-1", Key: "manager"},
			{ID: "role-2"},
		},
		RoleDefinitions: []identitymodel.RoleSchema{
			{Key: "manager", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "order.read"), PermissionSetKeys: []string{"direct"}, PermissionSetGroups: []string{"group"}, GuardrailKeys: []string{"guardrail"}},
			{Key: "role-2", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "domain.order.update")},
		},
		PermissionSets: []identitymodel.IdentityPermissionSet{
			{Key: "direct"},
			{Key: "grouped", FieldPermissions: []identitymodel.FieldPermission{{ObjectKey: "order", FieldKey: "plain", Read: true}}},
		},
		PermissionSetGroups: []identitymodel.IdentityPermissionSetGroup{{Key: "group", PermissionSetKeys: []string{"grouped"}}},
		RoleMenus: []identitymodel.IdentityRoleMenuAssignment{
			{RoleID: "role-1", MenuID: "blank"},
			{RoleID: "role-1", MenuID: "active"},
			{RoleID: "role-1", MenuID: "disabled"},
			{RoleID: "missing", MenuID: "unassigned"},
		},
		Menus: []identitymodel.IdentityMenu{
			{ID: "blank", Key: "b"},
			{ID: "active", Key: "a", Status: identitymodel.IdentityStatusActive},
			{ID: "disabled", Key: "d", Status: identitymodel.IdentityStatusDisabled},
			{ID: "unassigned", Key: "u"},
		},
		Objects: []definitionmodel.ObjectSchema{{
			Key: "order",
			Fields: []definitionmodel.FieldSchema{
				{Key: "plain"},
				{Key: "second"},
				{Key: "disabled", DisabledAt: "now"},
			},
		}},
		FieldDecision: func(identitymodel.RoleSchema, definitionmodel.ObjectSchema, definitionmodel.FieldSchema) (bool, bool, bool, bool) {
			return true, true, true, false
		},
	}
	snapshot := IdentityBuildEffectiveAccessSnapshot(input)
	if len(snapshot.RoleKeys) != 2 || len(snapshot.PermissionSetKeys) != 2 || len(snapshot.PermissionSetGroups) != 1 {
		t.Fatalf("governance keys = %#v %#v %#v", snapshot.RoleKeys, snapshot.PermissionSetKeys, snapshot.PermissionSetGroups)
	}
	if len(snapshot.Menus) != 2 || snapshot.Menus[0].Key != "a" || len(snapshot.FieldAccess) != 2 {
		t.Fatalf("menus/fields = %#v %#v", snapshot.Menus, snapshot.FieldAccess)
	}
	if len(snapshot.DataAccess) != 3 || len(snapshot.Permissions) != 3 {
		t.Fatalf("data/permissions = %#v %#v", snapshot.DataAccess, snapshot.Permissions)
	}
	for _, permission := range snapshot.Permissions {
		for _, source := range permission.Sources {
			if source.PermissionSetKey != "" || source.PermissionSetGroup != "" {
				t.Fatalf("functional permission %q was attributed to non-functional policy source: %#v", permission.Key, permission.Sources)
			}
		}
	}
	readData, readFound := identityProjectionData(snapshot.DataAccess, "order", "read")
	if !readFound || !readData.AuditDenial {
		t.Fatalf("data denial-audit intent was lost: %#v", snapshot.DataAccess)
	}
	if snapshot.FieldAccess[0].Reason != "sensitive" || !snapshot.FieldAccess[0].AuditDenial || len(snapshot.FieldAccess[0].Policies) != 1 {
		t.Fatalf("contextual field policy was lost: %#v", snapshot.FieldAccess[0])
	}

	withoutDecision := IdentityBuildEffectiveAccessSnapshot(IdentityEffectiveAccessProjectionInput{})
	if len(withoutDecision.FieldAccess) != 0 {
		t.Fatalf("field access without decision = %#v", withoutDecision.FieldAccess)
	}
}

func TestIdentityExplainEffectiveAccessEdges(t *testing.T) {
	base := identitymodel.IdentityEffectiveAccessSnapshot{
		Known: true,
		Permissions: []identitymodel.IdentityEffectivePermissionGrant{{
			Key: "order.read", ObjectKey: "order", Action: "read",
		}},
		DataAccess: []identitymodel.IdentityEffectiveDataAccess{{
			PermissionKey: "order.read", Resource: "order", Action: "read", Allowed: true, Scopes: []identitymodel.IdentityDataScope{identitymodel.IdentityDataScopeAll},
		}},
		FieldAccess: []identitymodel.IdentityEffectiveFieldAccess{{
			ObjectKey: "order", FieldKey: "secret", Read: true, Write: false, Export: true,
		}},
	}
	request := identitymodel.IdentityAccessExplainRequest{UserID: "user", ObjectKey: "order", Action: "read"}
	assertReason := func(name, want string, snapshot identitymodel.IdentityEffectiveAccessSnapshot, role identitymodel.RoleSchema, request identitymodel.IdentityAccessExplainRequest) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			if got := IdentityExplainEffectiveAccess(snapshot, role, request).Reason.Code; got != want {
				t.Fatalf("reason = %q, want %q", got, want)
			}
		})
	}

	assertReason("unknown identity", "identity_unknown", identitymodel.IdentityEffectiveAccessSnapshot{}, identitymodel.RoleSchema{}, request)
	assertReason("missing object", "object_and_action_required", base, identitymodel.RoleSchema{}, identitymodel.IdentityAccessExplainRequest{})
	assertReason("missing action", "object_and_action_required", base, identitymodel.RoleSchema{}, identitymodel.IdentityAccessExplainRequest{ObjectKey: "order"})
	assertReason("direct permission guardrail", "guardrail_permission_denied", base, identitymodel.RoleSchema{Guardrails: []identitymodel.IdentityGuardrailPolicy{{DeniedPermissionKeys: []string{"order.read"}}}}, request)

	aliased := base
	aliased.Permissions = []identitymodel.IdentityEffectivePermissionGrant{{Key: "domain.order.read", ObjectKey: "order", Action: "read"}}
	assertReason("grant key guardrail", "guardrail_permission_denied", aliased, identitymodel.RoleSchema{Guardrails: []identitymodel.IdentityGuardrailPolicy{{DeniedPermissionKeys: []string{"domain.order.read"}}}}, request)
	assertReason("functional permission missing", "functional_permission_missing", identitymodel.IdentityEffectiveAccessSnapshot{Known: true}, identitymodel.RoleSchema{}, request)
	assertReason("role fallback permission", "effective_access_allowed", identitymodel.IdentityEffectiveAccessSnapshot{Known: true, DataAccess: base.DataAccess}, identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "order.read")}, request)
	assertReason("data guardrail", "guardrail_data_denied", base, identitymodel.RoleSchema{Guardrails: []identitymodel.IdentityGuardrailPolicy{{DataRestrictions: []identitymodel.IdentityDataRestriction{{ObjectKey: "order", Actions: []string{"read"}}}}}}, request)
	assertReason("data missing", "data_scope_missing", identitymodel.IdentityEffectiveAccessSnapshot{Known: true, Permissions: base.Permissions}, identitymodel.RoleSchema{}, request)

	fieldRequest := request
	fieldRequest.FieldKey = "secret"
	assertReason("field guardrail", "guardrail_field_denied", base, identitymodel.RoleSchema{Guardrails: []identitymodel.IdentityGuardrailPolicy{{FieldRestrictions: []identitymodel.IdentityFieldRestriction{{ObjectKey: "order", FieldKey: "secret", Actions: []string{"read"}}}}}}, fieldRequest)
	fieldDenied := base
	fieldDenied.FieldAccess = append([]identitymodel.IdentityEffectiveFieldAccess(nil), base.FieldAccess...)
	fieldDenied.FieldAccess[0].Read = false
	assertReason("field missing", "field_permission_denied", fieldDenied, identitymodel.RoleSchema{}, fieldRequest)
	assertReason("allowed", "effective_access_allowed", base, identitymodel.RoleSchema{}, fieldRequest)
}

func TestIdentityEffectiveAccessProjectionHelpers(t *testing.T) {
	role := identitymodel.RoleSchema{Permissions: []identitymodel.RolePermission{
		{PermissionKey: "one.read", DataScope: identitymodel.IdentityDataScopeOrg},
		{PermissionKey: "one.update", DataScope: identitymodel.IdentityDataScopeOwner},
		{PermissionKey: "two.update", DataScope: identitymodel.IdentityDataScopeAll},
		{PermissionKey: "three.read", DataScope: identitymodel.IdentityDataScopeTargetOrg},
	}}
	data := identityProjectionDataAccess(role, map[string][]identitymodel.IdentityGrantSource{
		"role": {{Type: "role", Key: "role"}},
	})
	if len(data) != 4 {
		t.Fatalf("data access = %#v", data)
	}

	grant := identitymodel.IdentityEffectivePermissionGrant{Key: "order.read", ObjectKey: "order", Action: "read"}
	if _, ok := identityProjectionPermission([]identitymodel.IdentityEffectivePermissionGrant{grant}, "order.read"); !ok {
		t.Fatal("exact permission not found")
	}
	if _, ok := identityProjectionPermissionForAction([]identitymodel.IdentityEffectivePermissionGrant{{Key: "order.read"}}, "order", "read"); !ok {
		t.Fatal("fallback permission not found")
	}
	if _, ok := identityProjectionPermissionForAction([]identitymodel.IdentityEffectivePermissionGrant{{Key: "order.write", ObjectKey: "order", Action: "write"}, grant}, "order", "read"); !ok {
		t.Fatal("permission after different action not found")
	}
	if _, ok := identityProjectionPermissionForAction([]identitymodel.IdentityEffectivePermissionGrant{grant}, "other", "read"); ok {
		t.Fatal("unexpected permission")
	}

	dataValues := []identitymodel.IdentityEffectiveDataAccess{
		{PermissionKey: "order.read", Resource: "order", Action: "read", Allowed: false},
		{PermissionKey: "order.read", Resource: "order", Action: "read", Allowed: true},
		{PermissionKey: "order.export", Resource: "order", Action: "export", Allowed: true},
		{PermissionKey: "order.update", Resource: "order", Action: "update", Allowed: true},
	}
	for _, action := range []string{"read", "export", "update"} {
		if _, ok := identityProjectionData(dataValues, "order", action); !ok {
			t.Fatalf("data action %q not found", action)
		}
	}
	if _, ok := identityProjectionData(dataValues, "missing", "read"); ok {
		t.Fatal("unexpected data permission")
	}

	fieldValues := []identitymodel.IdentityEffectiveFieldAccess{
		{ObjectKey: "other", FieldKey: "field"},
		{ObjectKey: "order", FieldKey: "other"},
		{ObjectKey: "order", FieldKey: "field", Read: true, Write: true, Export: true},
	}
	for _, action := range []string{"read", "export", "update", "write", "create"} {
		if _, ok := identityProjectionField(fieldValues, "order", "field", action); !ok {
			t.Fatalf("field action %q not found", action)
		}
	}
	if _, ok := identityProjectionField(fieldValues, "missing", "field", "read"); ok {
		t.Fatal("unexpected field permission")
	}

	for input, wantObject := range map[string]string{"read": "", "order.read": "order", "domain.order.read": "domain.order", "domain.nested.order.read": "domain.nested.order"} {
		if object, _ := identityProjectionPermissionParts(input); object != wantObject {
			t.Fatalf("permission parts %q object = %q", input, object)
		}
	}
	if scopes := identityProjectionUniqueDataScopes([]identitymodel.IdentityDataScope{"", identitymodel.IdentityDataScopeOrg, identitymodel.IdentityDataScopeOrg, identitymodel.IdentityDataScopeAll}); len(scopes) != 2 || scopes[0] != identitymodel.IdentityDataScopeAll {
		t.Fatalf("unique scopes=%#v", scopes)
	}
	if identityProjectionContains([]string{" other ", " target "}, "target") == false || identityProjectionContains([]string{"other"}, "target") {
		t.Fatal("contains")
	}
	if got := identityProjectionUniqueStrings([]string{"", " one ", "one", "two"}); len(got) != 2 {
		t.Fatalf("unique strings = %#v", got)
	}
	sources := identityProjectionUniqueSources([]identitymodel.IdentityGrantSource{{Type: "role", Key: "one"}, {Type: "role", Key: "one"}, {Type: "role", Key: "two"}})
	if len(sources) != 2 {
		t.Fatalf("unique sources = %#v", sources)
	}

	if !identityProjectionSensitiveField(definitionmodel.ObjectSchema{Config: map[string]any{"field_access_mode": "default_deny"}}, definitionmodel.FieldSchema{}) {
		t.Fatal("default deny field not sensitive")
	}
	for _, field := range []definitionmodel.FieldSchema{
		{Config: map[string]any{"sensitive": true}},
		{Config: map[string]any{"sensitive": false}},
		{Config: map[string]any{"sensitivity": "secret"}},
		{},
	} {
		_ = identityProjectionSensitiveField(definitionmodel.ObjectSchema{}, field)
	}
}

func TestIdentityProjectionDataPolicyCannotInventFunctionalActions(t *testing.T) {
	role := identitymodel.RoleSchema{
		Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeTargetOrg, "customer.read"),
	}
	data := identityProjectionDataAccess(role, nil)
	if len(data) != 1 || data[0].PermissionKey != "customer.read" || data[0].Action != "read" {
		t.Fatalf("data policy did not stay attached to its exact permission: %#v", data)
	}
	role.Permissions = nil
	if data = identityProjectionDataAccess(role, nil); len(data) != 0 {
		t.Fatalf("data policy invented functional authority: %#v", data)
	}
}

func TestTargetOrganizationScopeRequiresTrustedDerivedClaim(t *testing.T) {
	role := identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeTargetOrg, "customer.read")}
	facts := identitycontract.IdentityResourceFacts{RecordID: "customer", OwnerOrgID: "sales-east"}

	if identitycontract.IdentityPermissionDataScopeAllows(identitymodel.Principal{Known: true, UserID: "user", Role: role}, "customer.read", facts) {
		t.Fatal("target organization scope allowed without a trusted support organization set")
	}

	if !identitycontract.IdentityPermissionDataScopeAllows(identitymodel.Principal{Known: true, UserID: "user", Role: role, SupportOrgID: "sales", SupportOrgScopeIDs: []string{"sales", "sales-east"}}, "customer.read", facts) {
		t.Fatal("target organization scope rejected a trusted derived support organization")
	}
}
