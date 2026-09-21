package capability

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/domainry/domainry-foundation/modulecapability"
)

func TestOpenAttachesSourceOwnedAdapterProfilesToIdentity(t *testing.T) {
	category := modulecapability.CategoryDocument{
		Category: modulecapability.CategorySummary{Key: "identity.external", Name: "External identity", Description: "External identity adapter.", AssemblyChains: []string{"identity_before_authorization_and_application_publication"}},
		OpenAPI:  modulecapability.OpenAPIFragment{OpenAPI: "3.1.0", Paths: map[string]map[string]json.RawMessage{}},
		Projections: []modulecapability.SourceProjection{{
			Kind: "identity.adapter_profile", Key: "identity.external",
			Payload: json.RawMessage(`{"type":"object","x-domainry-assembly":{"deployment_mode":"external"}}`),
		}},
	}
	binding, err := Open(Inputs{AdapterCategories: []modulecapability.CategoryDocument{category}})
	if err != nil {
		t.Fatal(err)
	}
	document, err := binding.CapabilityCategory(context.Background(), "identity.external")
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Projections) != 1 || document.Projections[0].Kind != category.Projections[0].Kind || document.Projections[0].Key != category.Projections[0].Key {
		t.Fatalf("adapter projections = %+v", document.Projections)
	}
	summary, err := binding.CapabilitySummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, key := range summary.Composition.ProvidedCapabilities {
		found = found || key == category.Projections[0].Key
	}
	if !found {
		t.Fatalf("provided capabilities omit %q: %+v", category.Projections[0].Key, summary.Composition.ProvidedCapabilities)
	}
}

func TestOpenRejectsNonIdentityAdapterProjection(t *testing.T) {
	_, err := Open(Inputs{AdapterCategories: []modulecapability.CategoryDocument{{
		Category:    modulecapability.CategorySummary{Key: "identity.external", Name: "External identity", Description: "External identity adapter."},
		Projections: []modulecapability.SourceProjection{{Kind: "other.profile", Key: "identity.external", Payload: json.RawMessage(`{}`)}},
	}}})
	if err == nil {
		t.Fatal("non-Identity adapter profile was accepted")
	}
}
