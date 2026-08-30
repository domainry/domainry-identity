package portability

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBundleRejectsNestedProviderSecretsAndDuplicateRecords(t *testing.T) {
	base := Bundle{
		WorkspaceID:          "workspace-a",
		SchemaVersion:        "schema-v1",
		MetadataSchemaSHA256: strings.Repeat("a", 64),
		SourceMode:           "module",
		ExportedAt:           time.Date(2026, time.August, 27, 12, 0, 0, 0, time.UTC),
		Datasets: []Dataset{{
			Name:    "users",
			Records: []Record{{"id": json.RawMessage(`"user-1"`)}},
		}},
	}
	nestedSecret := base
	nestedSecret.ProviderReferences = []ProviderReference{{
		ProviderKey: "oidc", SecretRequired: true,
		Configuration:     json.RawMessage(`{"type":"oidc","credentials":{"client_secret":"must-not-export"}}`),
		ConfigurationHash: strings.Repeat("b", 64),
	}}
	if err := nestedSecret.Finalize(); err == nil || !strings.Contains(err.Error(), "provider_secret_forbidden") {
		t.Fatalf("nested provider secret accepted: %v", err)
	}

	duplicates := base
	duplicates.Datasets[0].Records = append(duplicates.Datasets[0].Records, duplicates.Datasets[0].Records[0])
	if err := duplicates.Finalize(); err == nil || !strings.Contains(err.Error(), "record_order_invalid") {
		t.Fatalf("duplicate record accepted: %v", err)
	}
}

func TestAuthorizationStateDigestIgnoresInputOrderingWithoutMutatingCaller(t *testing.T) {
	datasets := []Dataset{
		{Name: "users", Records: []Record{{"id": json.RawMessage(`"user-2"`)}, {"id": json.RawMessage(`"user-1"`)}}},
		{Name: "roles", Records: []Record{{"id": json.RawMessage(`"role-1"`)}}},
	}
	wantFirst := string(datasets[0].Records[0]["id"])
	left, err := AuthorizationStateDigest(datasets)
	if err != nil {
		t.Fatal(err)
	}
	right, err := AuthorizationStateDigest([]Dataset{datasets[1], datasets[0]})
	if err != nil {
		t.Fatal(err)
	}
	if left != right || string(datasets[0].Records[0]["id"]) != wantFirst {
		t.Fatalf("digest left=%s right=%s caller=%s", left, right, datasets[0].Records[0]["id"])
	}
}
