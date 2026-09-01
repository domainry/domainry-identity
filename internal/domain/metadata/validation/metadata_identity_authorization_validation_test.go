package validation

import (
	"strings"
	"testing"

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
				Key: "operator", RecordScope: "custom",
				DataPermissions: []identitymodel.DataPermission{{
					ObjectKey: "runtime_booking", Scope: "custom", Read: true,
					Predicate: &identitymodel.IdentityPolicyExpression{
						Operator: "eq", Path: []identitymodel.IdentityPolicyRelationSegment{{Direction: "forward", RelationFieldKey: "member_id", TargetObjectKey: "runtime_member"}},
						FieldKey: "name", ValueSource: "actor_claim", ClaimKey: "member_name",
					},
				}},
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
		{name: "data object", edit: func(value *manifestmodel.ManifestSchema) { value.Roles[0].DataPermissions[0].ObjectKey = "" }, want: "data_permissions[0].object_key: is required"},
		{name: "data scope", edit: func(value *manifestmodel.ManifestSchema) { value.Roles[0].DataPermissions[0].Scope = "unbounded" }, want: `unsupported scope "unbounded"`},
		{name: "custom predicate", edit: func(value *manifestmodel.ManifestSchema) { value.Roles[0].DataPermissions[0].Predicate = nil }, want: "predicate: is required for custom scope"},
		{name: "predicate direction", edit: func(value *manifestmodel.ManifestSchema) {
			value.Roles[0].DataPermissions[0].Predicate.Path[0].Direction = "sideways"
		}, want: "direction: must be forward or reverse"},
		{name: "predicate value source", edit: func(value *manifestmodel.ManifestSchema) {
			value.Roles[0].DataPermissions[0].Predicate.ValueSource = "request"
		}, want: "value_source: must be literal or actor_claim"},
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
