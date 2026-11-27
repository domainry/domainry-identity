package identitymodel

import "testing"

func TestIdentityOrganizationUnitTypeIsGenericProductVocabulary(t *testing.T) {
	for _, value := range []IdentityOrganizationUnitType{IdentityOrganizationUnitCompany, "store", "venue_zone", "floor_2"} {
		if !value.Valid() {
			t.Fatalf("organization node type %q was rejected", value)
		}
	}
	for _, value := range []IdentityOrganizationUnitType{"", "Venue", "venue-zone", "venue_", " venue"} {
		if value.Valid() {
			t.Fatalf("invalid organization node type %q was accepted", value)
		}
	}
}
