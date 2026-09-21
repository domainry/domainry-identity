package validation

import (
	"strings"
	"testing"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
)

func TestMetadataIdentityAuthorizationValidatesStructureWithoutMirroringRuntimeObjects(t *testing.T) {
	valid := func() manifestmodel.ManifestSchema {
		return manifestmodel.ManifestSchema{
			Objects: []definitionmodel.ObjectSchema{{
				Key: "identity_owned", Fields: []definitionmodel.FieldSchema{
					{Key: "account_id", Type: "relation", Validation: definitionmodel.FieldValidation{Target: "identity_user"}},
					{Key: "label", Type: "text"},
				},
			}},
			Roles: []identitymodel.RoleSchema{{
				Key:              "operator",
				Permissions:      identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeTargetOrg, "runtime_booking.read"),
				FieldPermissions: []identitymodel.FieldPermission{{ObjectKey: "runtime_booking", FieldKey: "amount", Read: true}},
				ReferencePermissions: []identitymodel.ReferencePermission{{
					SourceObjectKey: "runtime_booking", RelationFieldKey: "member_id", TargetObjectKey: "runtime_member", DisplayFields: []string{"name"},
				}},
				ExportRules: []identitymodel.ExportRule{{ObjectKey: "runtime_booking", Mode: "allow_list", Fields: []string{"id", "amount"}}},
			}},
		}
	}
	if err := MetadataValidateIdentitySchema(valid()); err != nil {
		t.Fatalf("opaque Runtime policy references rejected: %v", err)
	}

	tests := []struct {
		name string
		edit func(*manifestmodel.ManifestSchema)
		want string
	}{
		{name: "permission key", edit: func(value *manifestmodel.ManifestSchema) { value.Roles[0].Permissions[0].PermissionKey = "" }, want: "permissions[0].permission_key: is required"},
		{name: "data scope", edit: func(value *manifestmodel.ManifestSchema) { value.Roles[0].Permissions[0].DataScope = "unbounded" }, want: `unsupported scope "unbounded"`},
		{name: "field key", edit: func(value *manifestmodel.ManifestSchema) { value.Roles[0].FieldPermissions[0].FieldKey = "" }, want: "field_permissions[0].field_key: is required"},
		{name: "reference target", edit: func(value *manifestmodel.ManifestSchema) { value.Roles[0].ReferencePermissions[0].TargetObjectKey = "" }, want: "reference_permissions[0].target_object_key: is required"},
		{name: "reference display", edit: func(value *manifestmodel.ManifestSchema) {
			value.Roles[0].ReferencePermissions[0].DisplayFields = []string{""}
		}, want: "display_fields[0]: is required"},
		{name: "export field", edit: func(value *manifestmodel.ManifestSchema) { value.Roles[0].ExportRules[0].Fields = []string{""} }, want: "export_rules[0].fields[0]: is required"},
		{name: "local field", edit: func(value *manifestmodel.ManifestSchema) {
			value.Roles[0].FieldPermissions[0] = identitymodel.FieldPermission{ObjectKey: "identity_owned", FieldKey: "missing", Read: true}
		}, want: "references unknown field identity_owned.missing"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schema := valid()
			test.edit(&schema)
			if err := MetadataValidateIdentitySchema(schema); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestMetadataIdentityAuthorizationValidatesRelationalPolicyAgainstObjectGraph(t *testing.T) {
	policy := identitysdk.ProjectDataPolicy{
		Operator: identitysdk.ProjectDataPolicyIn,
		Path:     []identitysdk.ProjectDataPolicyRelationSegment{{Direction: identitysdk.RelationForward, RelationFieldKey: "customer_id", TargetObjectKey: "customer"}},
		FieldKey: "organization_id", SubjectClaim: identitysdk.ProjectSubjectClaimOrgScopeIDs,
	}
	schema := manifestmodel.ManifestSchema{
		Objects: []definitionmodel.ObjectSchema{
			{Key: "order", Fields: []definitionmodel.FieldSchema{{Key: "customer_id", Type: "relation", Validation: definitionmodel.FieldValidation{Target: "customer"}}}},
			{Key: "customer", Fields: []definitionmodel.FieldSchema{{Key: "organization_id", Type: "text"}}},
		},
		Roles: []identitymodel.RoleSchema{{Key: "operator", Permissions: []identitymodel.RolePermission{{PermissionKey: "order.read", DataPolicy: &policy}}}},
	}
	if err := MetadataValidateIdentitySchema(schema); err != nil {
		t.Fatalf("valid relational data policy rejected: %v", err)
	}
	policy.Path[0].RelationFieldKey = "missing"
	if err := MetadataValidateIdentitySchema(schema); err == nil || !strings.Contains(err.Error(), "must reference a relation field") {
		t.Fatalf("invalid relation path error=%v", err)
	}
}
