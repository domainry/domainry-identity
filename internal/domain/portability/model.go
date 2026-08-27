// Package portability defines the versioned, secret-free contract used to
// move one Identity workspace from an embedded deployment to SaaS.
package portability

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

const ContractVersionV1 = "domainry-identity-portability-v1"

type Record map[string]json.RawMessage

type Dataset struct {
	Name    string   `json:"name"`
	Records []Record `json:"records"`
}

type ProviderReference struct {
	ProviderKey       string          `json:"provider_key"`
	Configuration     json.RawMessage `json:"configuration"`
	ConfigurationHash string          `json:"configuration_sha256"`
	SecretRequired    bool            `json:"secret_required"`
}

type SecurityDisposition struct {
	PasswordCredentials string `json:"password_credentials"`
	RefreshSessions     string `json:"refresh_sessions"`
	MFAFactors          string `json:"mfa_factors"`
	ProviderSecrets     string `json:"provider_secrets"`
}

func SecureCutoverDisposition() SecurityDisposition {
	return SecurityDisposition{
		PasswordCredentials: "reset_required",
		RefreshSessions:     "revoke_all",
		MFAFactors:          "reenrollment_required",
		ProviderSecrets:     "reconfigure_out_of_band",
	}
}

type Bundle struct {
	ContractVersion          string              `json:"contract_version"`
	ExportID                 string              `json:"export_id"`
	WorkspaceID              string              `json:"workspace_id"`
	SchemaVersion            string              `json:"schema_version"`
	MetadataSchemaSHA256     string              `json:"metadata_schema_sha256"`
	AuthorizationStateSHA256 string              `json:"authorization_state_sha256"`
	SourceMode               string              `json:"source_mode"`
	ExportedAt               time.Time           `json:"exported_at"`
	FreezeEvidence           string              `json:"freeze_evidence"`
	Datasets                 []Dataset           `json:"datasets"`
	ProviderReferences       []ProviderReference `json:"provider_references"`
	ExcludedCounts           map[string]int64    `json:"excluded_counts"`
	Security                 SecurityDisposition `json:"security_disposition"`
	ContentSHA256            string              `json:"content_sha256"`
}

type Inventory struct {
	WorkspaceID    string           `json:"workspace_id"`
	DatasetCounts  map[string]int64 `json:"dataset_counts"`
	ExcludedCounts map[string]int64 `json:"excluded_counts"`
	ProviderKeys   []string         `json:"provider_keys"`
}

type ImportReceipt struct {
	ReceiptID        string           `json:"receipt_id"`
	WorkspaceID      string           `json:"workspace_id"`
	ContentSHA256    string           `json:"content_sha256"`
	IdempotencyKey   string           `json:"idempotency_key"`
	ImportedCounts   map[string]int64 `json:"imported_counts"`
	AuthorizationOK  bool             `json:"authorization_parity_verified"`
	SessionsRevoked  bool             `json:"sessions_revoked"`
	CredentialsReset bool             `json:"credentials_reset_required"`
	MFAReenrollment  bool             `json:"mfa_reenrollment_required"`
	ImportedAt       time.Time        `json:"imported_at"`
	Replayed         bool             `json:"replayed"`
}

type WriteFence struct {
	WorkspaceID    string     `json:"workspace_id"`
	State          string     `json:"state"`
	EvidenceSHA256 string     `json:"evidence_sha256"`
	FrozenBy       string     `json:"frozen_by"`
	FrozenAt       time.Time  `json:"frozen_at"`
	ReleasedBy     string     `json:"released_by,omitempty"`
	ReleasedAt     *time.Time `json:"released_at,omitempty"`
}

func (bundle *Bundle) Finalize() error {
	if bundle == nil {
		return fmt.Errorf("identity portability bundle is required")
	}
	canonicalize(bundle)
	bundle.ContractVersion = ContractVersionV1
	bundle.Security = SecureCutoverDisposition()
	authorizationDigest, err := AuthorizationStateDigest(bundle.Datasets)
	if err != nil {
		return err
	}
	bundle.AuthorizationStateSHA256 = authorizationDigest
	digest, err := bundle.contentDigest()
	if err != nil {
		return err
	}
	bundle.ContentSHA256 = digest
	bundle.ExportID = "identity-export:" + digest[:24]
	return bundle.Validate()
}

func (bundle Bundle) Validate() error {
	if bundle.ContractVersion != ContractVersionV1 {
		return fmt.Errorf("identity.portability_contract_unsupported")
	}
	if _, err := identitymodel.NewWorkspaceID(bundle.WorkspaceID); err != nil {
		return fmt.Errorf("identity.portability_workspace_invalid: %w", err)
	}
	if strings.TrimSpace(bundle.SchemaVersion) == "" || len(strings.TrimSpace(bundle.MetadataSchemaSHA256)) != 64 || strings.TrimSpace(bundle.SourceMode) == "" || bundle.ExportedAt.IsZero() || strings.TrimSpace(bundle.FreezeEvidence) == "" {
		return fmt.Errorf("identity.portability_export_evidence_required")
	}
	if bundle.Security != SecureCutoverDisposition() {
		return fmt.Errorf("identity.portability_security_disposition_invalid")
	}
	if err := validateDatasets(bundle.Datasets); err != nil {
		return err
	}
	if err := validateProviderReferences(bundle.ProviderReferences); err != nil {
		return err
	}
	authorizationDigest, err := AuthorizationStateDigest(bundle.Datasets)
	if err != nil || bundle.AuthorizationStateSHA256 != authorizationDigest {
		return fmt.Errorf("identity.portability_authorization_checksum_invalid")
	}
	digest, err := bundle.contentDigest()
	if err != nil {
		return err
	}
	if len(bundle.ContentSHA256) != 64 || bundle.ContentSHA256 != digest || bundle.ExportID != "identity-export:"+digest[:24] {
		return fmt.Errorf("identity.portability_checksum_invalid")
	}
	return nil
}

// AuthorizationStateDigest is the deterministic source/target reconciliation
// hash. It covers every portable workspace record because users, workforce and
// departments are authorization facts as much as roles and Catalog grants are.
func AuthorizationStateDigest(datasets []Dataset) (string, error) {
	copy := append([]Dataset(nil), datasets...)
	for index := range copy {
		copy[index].Records = append([]Record(nil), copy[index].Records...)
	}
	sort.Slice(copy, func(left, right int) bool { return copy[left].Name < copy[right].Name })
	for index := range copy {
		sort.Slice(copy[index].Records, func(left, right int) bool {
			leftJSON, _ := json.Marshal(copy[index].Records[left])
			rightJSON, _ := json.Marshal(copy[index].Records[right])
			return string(leftJSON) < string(rightJSON)
		})
	}
	raw, err := json.Marshal(copy)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (bundle Bundle) contentDigest() (string, error) {
	copy := bundle
	copy.ExportID = ""
	copy.ContentSHA256 = ""
	copy.ExportedAt = time.Time{}
	copy.FreezeEvidence = ""
	canonicalize(&copy)
	raw, err := json.Marshal(copy)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalize(bundle *Bundle) {
	sort.Slice(bundle.Datasets, func(left, right int) bool { return bundle.Datasets[left].Name < bundle.Datasets[right].Name })
	for index := range bundle.Datasets {
		sort.Slice(bundle.Datasets[index].Records, func(left, right int) bool {
			leftJSON, _ := json.Marshal(bundle.Datasets[index].Records[left])
			rightJSON, _ := json.Marshal(bundle.Datasets[index].Records[right])
			return string(leftJSON) < string(rightJSON)
		})
	}
	sort.Slice(bundle.ProviderReferences, func(left, right int) bool {
		return bundle.ProviderReferences[left].ProviderKey < bundle.ProviderReferences[right].ProviderKey
	})
}

func validateDatasets(datasets []Dataset) error {
	previous := ""
	for _, dataset := range datasets {
		if strings.TrimSpace(dataset.Name) == "" || dataset.Name <= previous {
			return fmt.Errorf("identity.portability_dataset_order_invalid")
		}
		previous = dataset.Name
		previousRecord := ""
		for _, record := range dataset.Records {
			raw, err := json.Marshal(record)
			if err != nil || previousRecord != "" && string(raw) <= previousRecord {
				return fmt.Errorf("identity.portability_record_order_invalid")
			}
			previousRecord = string(raw)
			for column := range record {
				if forbiddenPortableColumn(column) {
					return fmt.Errorf("identity.portability_secret_column_forbidden: %s", column)
				}
			}
		}
	}
	return nil
}

func validateProviderReferences(references []ProviderReference) error {
	previous := ""
	for _, reference := range references {
		if strings.TrimSpace(reference.ProviderKey) == "" || reference.ProviderKey <= previous || !reference.SecretRequired || len(reference.ConfigurationHash) != 64 {
			return fmt.Errorf("identity.portability_provider_reference_invalid")
		}
		var value any
		if json.Unmarshal(reference.Configuration, &value) != nil {
			return fmt.Errorf("identity.portability_provider_configuration_invalid")
		}
		if containsForbiddenProviderSecret(value) {
			return fmt.Errorf("identity.portability_provider_secret_forbidden")
		}
		sum := sha256.Sum256(reference.Configuration)
		if reference.ConfigurationHash != hex.EncodeToString(sum[:]) {
			return fmt.Errorf("identity.portability_provider_checksum_invalid")
		}
		previous = reference.ProviderKey
	}
	return nil
}

func containsForbiddenProviderSecret(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if forbiddenPortableColumn(key) || containsForbiddenProviderSecret(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsForbiddenProviderSecret(child) {
				return true
			}
		}
	}
	return false
}

func forbiddenPortableColumn(column string) bool {
	column = strings.ToLower(strings.TrimSpace(column))
	for _, marker := range []string{"password", "refresh_token", "token_hash", "secret", "mfa_secret", "session_json", "state_hash", "authorization_code", "provider_ref"} {
		if strings.Contains(column, marker) {
			return true
		}
	}
	return false
}
