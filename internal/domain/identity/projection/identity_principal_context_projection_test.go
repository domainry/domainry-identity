package projection

import (
	"encoding/json"
	"strings"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityBuildPrincipalContextPublishesCanonicalNonSecretSelectors(t *testing.T) {
	principal := identitymodel.Principal{
		Known: true, WorkspaceID: " workspace ", UserID: "user-1",
		OrgID: "sales", OrganizationPath: "/company/sales",
		Role: identitymodel.RoleSchema{Key: "seller"}, AuthorizationRevision: "revision-1",
		BusinessProfiles: []identitymodel.BusinessProfileReference{{
			BindingKey: "member", ObjectKey: "member_profile", RecordID: "member-1",
			Claims: map[string]identitymodel.BusinessClaimValue{"api_secret": {Type: "string", Value: "must-not-leak"}},
		}},
	}
	principal.ActiveBusinessProfile = &principal.BusinessProfiles[0]

	context := IdentityBuildPrincipalContext(principal)
	if context.ContractVersion != identitymodel.IdentityPrincipalContextContractV1 || context.WorkspaceID != "workspace" || context.OrgID != "sales" || context.OrganizationPath != "/company/sales" {
		t.Fatalf("principal context identity=%+v", context)
	}
	if len(context.BusinessProfiles) != 1 || !context.BusinessProfiles[0].Active || len(context.RequestContexts) != 2 {
		t.Fatalf("principal contexts=%+v", context)
	}
	profile := context.RequestContexts[1]
	if profile.SubjectKind != "business_profile" || profile.CanonicalRequestHeader["X-Workspace-ID"] != "workspace" ||
		profile.CanonicalRequestHeader["X-Business-Profile-Key"] != "member" ||
		profile.CanonicalRequestHeader["X-Business-Profile-ID"] != "member-1" {
		t.Fatalf("business profile selector=%+v", profile)
	}
	encoded, err := json.Marshal(context)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "must-not-leak") || strings.Contains(string(encoded), "Authorization") {
		t.Fatalf("principal context leaked a secret-bearing value: %s", encoded)
	}
}

func TestIdentityBuildPrincipalContextFailsClosedForUnknownPrincipal(t *testing.T) {
	context := IdentityBuildPrincipalContext(identitymodel.Principal{WorkspaceID: "workspace", UserID: "unknown"})
	if context.Known || len(context.RequestContexts) != 0 || len(context.BusinessProfiles) != 0 {
		t.Fatalf("unknown principal context=%+v", context)
	}
}
