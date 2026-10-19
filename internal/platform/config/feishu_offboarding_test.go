package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFeishuEventCredentialsAreRedactedInConfigurationSnapshot(t *testing.T) {
	t.Setenv("AUTH_FEISHU_EVENT_VERIFICATION_TOKEN", "fixture-verification-secret")
	t.Setenv("AUTH_FEISHU_EVENT_ENCRYPT_KEY", "fixture-encryption-secret")
	_, snapshot, err := LoadContract()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "fixture-verification-secret") || strings.Contains(string(raw), "fixture-encryption-secret") {
		t.Fatal("Feishu webhook secrets leaked in configuration snapshot")
	}
	for _, name := range []string{"AUTH_FEISHU_EVENT_VERIFICATION_TOKEN", "AUTH_FEISHU_EVENT_ENCRYPT_KEY"} {
		found := false
		for _, d := range Definitions() {
			if d.Name == name {
				found = true
				if !d.Secret || d.Default != "[REDACTED]" {
					t.Fatalf("unsafe definition: %s", name)
				}
			}
		}
		if !found {
			t.Fatalf("missing definition: %s", name)
		}
	}
}
