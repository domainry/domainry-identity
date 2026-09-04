package manifestmodel

import (
	"strings"
	"testing"
)

func TestDecodeManifestRejectsRetiredIdentityProfileDirectory(t *testing.T) {
	_, err := DecodeManifest([]byte(`{
		"schema_version":"2",
		"template_id":"test",
		"version":"1",
		"objects":[],
		"roles":[],
		"identity_profile_extensions":[{
			"contract_version":"identity-profile-extension",
			"min_reader_version":"identity-profile-extension-reader",
			"object_key":"employee",
			"identity_relation_field":"identity_user_id",
			"cardinality":"one_to_one",
			"business_identity":{"key":"employee"},
			"directory":{"enabled":true},
			"default_visibility":"when_readable"
		}]
	}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field \"directory\"") {
		t.Fatalf("retired identity profile directory was accepted: %v", err)
	}
}
