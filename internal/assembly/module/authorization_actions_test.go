package moduleassembly

import (
	"testing"

	actioncontract "github.com/domainry/domainry-foundation/action"
)

func TestModuleBindingPublishesCompleteIdentityAuthorizationActions(t *testing.T) {
	var provider actioncontract.Provider = (*moduleBinding)(nil)
	definitions, err := provider.AuthorizationActions()
	if err != nil {
		t.Fatal(err)
	}
	foundMetadataPermission := false
	for _, definition := range definitions {
		if definition.Key == "identity.metadata.migration_plan.get" && definition.Permission != nil {
			foundMetadataPermission = true
			break
		}
	}
	if !foundMetadataPermission {
		t.Fatal("complete Identity Action manifest omitted the non-HTTP metadata migration permission")
	}
}
