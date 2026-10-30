package scim

import (
	"errors"
	"testing"

	scimmodel "github.com/domainry/domainry-identity/internal/domain/scim/model"
)

func TestUserFilterSupportsBooleanLogicalAndMultiValueComparisons(t *testing.T) {
	active := true
	user := scimmodel.User{
		Schemas: []string{scimmodel.SchemaUser}, ID: "user-1", UserName: "Admin@Example.com", Active: &active,
		Name:   scimmodel.Name{GivenName: "Ada", FamilyName: "Lovelace"},
		Emails: []scimmodel.MultiValue{{Value: "admin@example.com", Type: "work", Primary: true}},
		Meta:   scimmodel.Meta{ResourceType: "User", LastModified: "2026-01-02T03:04:05Z"},
	}
	values := UserAttributeValues(user)
	for _, filter := range []string{
		`userName eq "admin@example.com"`,
		`active eq true and emails.value co "@example.com"`,
		`emails.primary eq true`,
		`not (name.familyName sw "hopper")`,
		`(name.givenName eq "Ada" and active eq true) or id eq "missing"`,
		`emails[type eq "work" and value co "@example.com"]`,
		`urn:ietf:params:scim:schemas:core:2.0:User:userName sw "admin"`,
		`schemas eq "urn:ietf:params:scim:schemas:core:2.0:User" and meta.lastModified gt "2026-01-01T00:00:00Z"`,
	} {
		matched, err := MatchFilter(filter, values)
		if err != nil || !matched {
			t.Errorf("filter %q matched=%v err=%v", filter, matched, err)
		}
	}
	matched, err := MatchFilter(`active eq false or emails.value ew "invalid.test"`, values)
	if err != nil || matched {
		t.Fatalf("negative filter matched=%v err=%v", matched, err)
	}
	_, err = MatchFilter(`unknown eq "value"`, values)
	var scimErr *Error
	if !errors.As(err, &scimErr) || scimErr.SCIMType != "invalidFilter" {
		t.Fatalf("unsupported attribute error=%v", err)
	}
	for _, filter := range []string{
		`phoneNumbers pr`,
		`emails[type eq "home"]`,
		`externalId eq ""`,
		`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department pr`,
	} {
		matched, err = MatchFilter(filter, values)
		if err != nil || matched {
			t.Errorf("absent known attribute filter %q matched=%v err=%v", filter, matched, err)
		}
	}
}

func TestGroupFilterTreatsAbsentMembersAsKnown(t *testing.T) {
	group := scimmodel.Group{Schemas: []string{scimmodel.SchemaGroup}, ID: "group-1", DisplayName: "Engineering"}
	for _, filter := range []string{`members pr`, `members[value eq "user-1"]`} {
		matched, err := MatchFilter(filter, GroupAttributeValues(group))
		if err != nil || matched {
			t.Errorf("filter %q matched=%v err=%v", filter, matched, err)
		}
	}
}

func TestPatchOperationsApplySCIMPathsAndSelectors(t *testing.T) {
	active := true
	user := scimmodel.User{
		Schemas: []string{scimmodel.SchemaUser}, UserName: "old@example.com", Active: &active,
		Emails: []scimmodel.MultiValue{{Value: "old@example.com", Type: "work", Primary: true}, {Value: "home@example.com", Type: "home"}},
	}
	updated, err := ApplyUserPatch(user, scimmodel.PatchRequest{
		Schemas: []string{scimmodel.SchemaPatch},
		Operations: []scimmodel.PatchOperation{
			{Op: "replace", Path: "userName", Value: "new@example.com"},
			{Op: "replace", Path: `emails[type eq "work"].value`, Value: "new@example.com"},
			{Op: "remove", Path: `emails[value eq "home@example.com"]`},
			{Op: "replace", Path: scimmodel.SchemaEnterpriseUser + ":employeeNumber", Value: "E-42"},
			{Op: "replace", Path: scimmodel.SchemaEnterpriseUser + ":department", Value: "Research"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.UserName != "new@example.com" || len(updated.Emails) != 1 || updated.Emails[0].Value != "new@example.com" || updated.EnterpriseUser == nil || updated.EnterpriseUser.EmployeeNumber != "E-42" || updated.EnterpriseUser.Department != "Research" {
		t.Fatalf("patched user=%+v", updated)
	}

	group := scimmodel.Group{Schemas: []string{scimmodel.SchemaGroup}, DisplayName: "Engineering", Members: []scimmodel.Member{{Value: "user-1"}, {Value: "user-2"}}}
	group, err = ApplyGroupPatch(group, scimmodel.PatchRequest{
		Schemas: []string{scimmodel.SchemaPatch},
		Operations: []scimmodel.PatchOperation{
			{Op: "remove", Path: `members[value eq "user-1"]`},
			{Op: "add", Path: "members", Value: []any{map[string]any{"value": "user-3"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(group.Members) != 2 || group.Members[0].Value != "user-2" || group.Members[1].Value != "user-3" {
		t.Fatalf("patched group=%+v", group)
	}
}

func TestPatchRejectsMissingTargetAndPatchSchema(t *testing.T) {
	group := scimmodel.Group{Members: []scimmodel.Member{{Value: "user-1"}}}
	_, err := ApplyGroupPatch(group, scimmodel.PatchRequest{Schemas: []string{scimmodel.SchemaPatch}, Operations: []scimmodel.PatchOperation{{Op: "remove", Path: `members[value eq "missing"]`}}})
	var scimErr *Error
	if !errors.As(err, &scimErr) || scimErr.SCIMType != "noTarget" {
		t.Fatalf("missing member error=%v", err)
	}
	_, err = ApplyUserPatch(scimmodel.User{}, scimmodel.PatchRequest{Operations: []scimmodel.PatchOperation{{Op: "replace", Path: "active", Value: true}}})
	if !errors.As(err, &scimErr) || scimErr.SCIMType != "invalidValue" {
		t.Fatalf("missing PatchOp schema error=%v", err)
	}
}

func TestPatchAddExistingMultiValueIsANoOp(t *testing.T) {
	user := scimmodel.User{Emails: []scimmodel.MultiValue{{Value: "ada@example.com", Type: "work"}}}
	updated, err := ApplyUserPatch(user, scimmodel.PatchRequest{
		Schemas:    []string{scimmodel.SchemaPatch},
		Operations: []scimmodel.PatchOperation{{Op: "add", Path: "emails", Value: []any{map[string]any{"value": "ADA@EXAMPLE.COM", "type": "WORK"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Emails) != 1 {
		t.Fatalf("duplicate email was appended: %+v", updated.Emails)
	}
}

func TestResourceSchemaValidationRequiresBaseAndDeclaredExtension(t *testing.T) {
	if err := validateResourceSchemas(nil, scimmodel.SchemaUser, false); err == nil {
		t.Fatal("User without core schema was accepted")
	}
	if err := validateResourceSchemas([]string{scimmodel.SchemaUser}, scimmodel.SchemaUser, true); err == nil {
		t.Fatal("enterprise attributes without extension schema were accepted")
	}
	if err := validateResourceSchemas([]string{scimmodel.SchemaGroup, scimmodel.SchemaEnterpriseUser}, scimmodel.SchemaGroup, false); err == nil {
		t.Fatal("enterprise User extension was accepted on Group")
	}
}

func TestRequireETagAcceptsHTTPLists(t *testing.T) {
	if err := requireETag(`W/"1", W/"2"`, `W/"2"`); err != nil {
		t.Fatal(err)
	}
	if err := requireETag(`W/"1"`, `W/"2"`); err == nil {
		t.Fatal("mismatched If-Match was accepted")
	}
}
