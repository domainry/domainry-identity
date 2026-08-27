package portability

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	portabilityapplication "github.com/domainry/domainry-identity/internal/application/portability"
	portabilitymodel "github.com/domainry/domainry-identity/internal/domain/portability"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
)

type SQLRepository struct {
	store *database.IdentityStore
}

type datasetQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func NewSQLRepository(store *database.IdentityStore) (*SQLRepository, error) {
	if store == nil || store.DB() == nil {
		return nil, fmt.Errorf("Identity portability database is required")
	}
	return &SQLRepository{store: store}, nil
}

func (repository *SQLRepository) Inventory(ctx context.Context, workspaceID string) (portabilitymodel.Inventory, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return portabilitymodel.Inventory{}, fmt.Errorf("Identity portability workspace is required")
	}
	inventory := portabilitymodel.Inventory{
		WorkspaceID:    workspaceID,
		DatasetCounts:  map[string]int64{},
		ExcludedCounts: map[string]int64{},
		ProviderKeys:   []string{},
	}
	for _, spec := range portableDatasetSpecs {
		count, err := repository.workspaceCount(ctx, repository.store.DB(), spec.table, spec.workspace, workspaceID)
		if err != nil {
			return portabilitymodel.Inventory{}, err
		}
		inventory.DatasetCounts[spec.name] = count
	}
	for name, table := range excludedWorkspaceTables {
		count, err := repository.workspaceCount(ctx, repository.store.DB(), table, "workspace_id", workspaceID)
		if err != nil {
			return portabilitymodel.Inventory{}, err
		}
		inventory.ExcludedCounts[name] = count
	}
	rows, err := repository.store.DB().QueryContext(ctx,
		"SELECT "+repository.store.Identifier("provider_key")+" FROM "+repository.store.TableIdentifier("auth_provider_credentials")+
			" WHERE "+repository.store.Identifier("workspace_id")+" = "+repository.store.Placeholder(1)+" ORDER BY "+repository.store.Identifier("provider_key"),
		workspaceID,
	)
	if err != nil {
		return portabilitymodel.Inventory{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var provider string
		if err := rows.Scan(&provider); err != nil {
			return portabilitymodel.Inventory{}, err
		}
		inventory.ProviderKeys = append(inventory.ProviderKeys, provider)
	}
	return inventory, rows.Err()
}

func (repository *SQLRepository) MetadataSchemaSHA256(ctx context.Context) (string, error) {
	var digest string
	query := "SELECT " + repository.store.Identifier("value") + " FROM " + repository.store.TableIdentifier("metadata_catalog") + " WHERE " + repository.store.Identifier("key") + " = " + repository.store.Placeholder(1)
	if err := repository.store.DB().QueryRowContext(ctx, query, "schema_hash").Scan(&digest); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("identity.portability_metadata_schema_hash_missing")
		}
		return "", err
	}
	digest = strings.ToLower(strings.TrimSpace(digest))
	if len(digest) != 64 {
		return "", fmt.Errorf("identity.portability_metadata_schema_hash_invalid")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", fmt.Errorf("identity.portability_metadata_schema_hash_invalid")
	}
	return digest, nil
}

func (repository *SQLRepository) Export(ctx context.Context, workspaceID string) ([]portabilitymodel.Dataset, []portabilitymodel.ProviderReference, map[string]int64, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	datasets := make([]portabilitymodel.Dataset, 0, len(portableDatasetSpecs))
	for _, spec := range portableDatasetSpecs {
		dataset, err := repository.exportDataset(ctx, spec, workspaceID)
		if err != nil {
			return nil, nil, nil, err
		}
		datasets = append(datasets, dataset)
	}
	providers, err := repository.providerReferences(ctx, workspaceID)
	if err != nil {
		return nil, nil, nil, err
	}
	inventory, err := repository.Inventory(ctx, workspaceID)
	if err != nil {
		return nil, nil, nil, err
	}
	return datasets, providers, inventory.ExcludedCounts, nil
}

func (repository *SQLRepository) RecordExport(ctx context.Context, bundle portabilitymodel.Bundle) error {
	counts := map[string]int64{}
	for _, dataset := range bundle.Datasets {
		counts[dataset.Name] = int64(len(dataset.Records))
	}
	countsJSON, err := json.Marshal(counts)
	if err != nil {
		return err
	}
	freezeHash := sha256.Sum256([]byte(bundle.FreezeEvidence))
	columns := []string{"export_id", "workspace_id", "content_sha256", "freeze_evidence_sha256", "dataset_counts_json", "source_mode", "exported_at"}
	query := "INSERT INTO " + repository.store.TableIdentifier("identity_portability_export_receipts") + " (" + strings.Join(database.QuotedColumns(repository.store, columns), ", ") + ") VALUES (" + strings.Join(repository.placeholders(len(columns)), ", ") + ")"
	_, err = repository.store.DB().ExecContext(ctx, query, bundle.ExportID, bundle.WorkspaceID, bundle.ContentSHA256, hex.EncodeToString(freezeHash[:]), string(countsJSON), bundle.SourceMode, bundle.ExportedAt.UTC().Format(time.RFC3339Nano))
	if err == nil {
		return nil
	}
	var existing string
	lookup := "SELECT " + repository.store.Identifier("content_sha256") + " FROM " + repository.store.TableIdentifier("identity_portability_export_receipts") + " WHERE " + repository.store.Identifier("export_id") + " = " + repository.store.Placeholder(1)
	if lookupErr := repository.store.DB().QueryRowContext(ctx, lookup, bundle.ExportID).Scan(&existing); lookupErr == nil && existing == bundle.ContentSHA256 {
		return nil
	}
	return fmt.Errorf("record Identity portability export: %w", err)
}

func (repository *SQLRepository) FreezeWrites(ctx context.Context, workspaceID, evidence, operator string, now time.Time) (portabilitymodel.WriteFence, error) {
	return repository.store.FreezeIdentityWrites(ctx, workspaceID, evidence, operator, now)
}

func (repository *SQLRepository) ReleaseWriteFence(ctx context.Context, workspaceID, operator string, now time.Time) (portabilitymodel.WriteFence, error) {
	return repository.store.ReleaseIdentityWriteFence(ctx, workspaceID, operator, now)
}

func (repository *SQLRepository) VerifyWriteFreeze(ctx context.Context, workspaceID, evidence string) error {
	return repository.store.VerifyIdentityWriteFreeze(ctx, workspaceID, evidence)
}

func (repository *SQLRepository) VerifyProviderReadiness(ctx context.Context, workspaceID string, references []portabilitymodel.ProviderReference) error {
	for _, reference := range references {
		query := "SELECT " + strings.Join(database.QuotedColumns(repository.store, []string{"configuration_json", "secret_envelope"}), ", ") + " FROM " + repository.store.TableIdentifier("auth_provider_credentials") + " WHERE " + repository.store.Identifier("workspace_id") + " = " + repository.store.Placeholder(1) + " AND " + repository.store.Identifier("provider_key") + " = " + repository.store.Placeholder(2)
		var configuration, secretEnvelope string
		if err := repository.store.DB().QueryRowContext(ctx, query, workspaceID, reference.ProviderKey).Scan(&configuration, &secretEnvelope); err != nil {
			if err == sql.ErrNoRows {
				return fmt.Errorf("identity.portability_provider_not_ready: %s", reference.ProviderKey)
			}
			return err
		}
		if strings.TrimSpace(secretEnvelope) == "" {
			return fmt.Errorf("identity.portability_provider_secret_not_ready: %s", reference.ProviderKey)
		}
		var source, target map[string]any
		if json.Unmarshal(reference.Configuration, &source) != nil || json.Unmarshal([]byte(configuration), &target) != nil {
			return fmt.Errorf("identity.portability_provider_configuration_invalid: %s", reference.ProviderKey)
		}
		for _, field := range []string{"type", "issuer"} {
			if strings.TrimSpace(fmt.Sprint(source[field])) != strings.TrimSpace(fmt.Sprint(target[field])) {
				return fmt.Errorf("identity.portability_provider_configuration_mismatch: %s.%s", reference.ProviderKey, field)
			}
		}
	}
	return nil
}

func (repository *SQLRepository) Import(ctx context.Context, bundle portabilitymodel.Bundle, idempotencyKey string, importedAt time.Time) (portabilitymodel.ImportReceipt, error) {
	if err := bundle.Validate(); err != nil {
		return portabilitymodel.ImportReceipt{}, err
	}
	if err := validateImportDatasets(bundle); err != nil {
		return portabilitymodel.ImportReceipt{}, err
	}
	metadataSchemaSHA256, err := repository.MetadataSchemaSHA256(ctx)
	if err != nil {
		return portabilitymodel.ImportReceipt{}, err
	}
	if metadataSchemaSHA256 != bundle.MetadataSchemaSHA256 {
		return portabilitymodel.ImportReceipt{}, fmt.Errorf("identity.portability_metadata_schema_mismatch")
	}
	if receipt, found, err := repository.importReceipt(ctx, bundle.WorkspaceID, idempotencyKey); err != nil {
		return portabilitymodel.ImportReceipt{}, err
	} else if found {
		if receipt.ContentSHA256 != bundle.ContentSHA256 {
			return portabilitymodel.ImportReceipt{}, fmt.Errorf("identity.portability_idempotency_conflict")
		}
		if err := repository.verifyAuthorizationState(ctx, repository.store.DB(), bundle); err != nil {
			return portabilitymodel.ImportReceipt{}, err
		}
		receipt.Replayed = true
		return receipt, nil
	}

	tx, err := repository.store.DB().BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return portabilitymodel.ImportReceipt{}, err
	}
	defer tx.Rollback()
	for _, spec := range portableDatasetSpecs {
		count, countErr := repository.workspaceCount(ctx, tx, spec.table, spec.workspace, bundle.WorkspaceID)
		if countErr != nil {
			return portabilitymodel.ImportReceipt{}, countErr
		}
		if count != 0 {
			return portabilitymodel.ImportReceipt{}, fmt.Errorf("identity.portability_target_not_empty: %s", spec.name)
		}
	}

	counts := map[string]int64{}
	for _, dataset := range bundle.Datasets {
		spec, _ := datasetSpecNamed(dataset.Name)
		for _, record := range dataset.Records {
			values, valuesErr := importValues(spec, record, bundle.WorkspaceID)
			if valuesErr != nil {
				return portabilitymodel.ImportReceipt{}, valuesErr
			}
			query := "INSERT INTO " + repository.store.TableIdentifier(spec.table) + " (" + strings.Join(database.QuotedColumns(repository.store, spec.columns), ", ") + ") VALUES (" + strings.Join(repository.placeholders(len(spec.columns)), ", ") + ")"
			if _, insertErr := tx.ExecContext(ctx, query, values...); insertErr != nil {
				return portabilitymodel.ImportReceipt{}, fmt.Errorf("import Identity dataset %s: %w", dataset.Name, insertErr)
			}
			counts[dataset.Name]++
		}
	}
	if err := repository.verifyAuthorizationState(ctx, tx, bundle); err != nil {
		return portabilitymodel.ImportReceipt{}, err
	}
	receipt := portabilitymodel.ImportReceipt{
		ReceiptID:      importReceiptID(bundle.WorkspaceID, bundle.ContentSHA256, idempotencyKey),
		WorkspaceID:    bundle.WorkspaceID,
		ContentSHA256:  bundle.ContentSHA256,
		IdempotencyKey: idempotencyKey,
		ImportedCounts: counts,
		ImportedAt:     importedAt.UTC(),
	}
	countsJSON, err := json.Marshal(counts)
	if err != nil {
		return portabilitymodel.ImportReceipt{}, err
	}
	columns := []string{"receipt_id", "workspace_id", "content_sha256", "idempotency_key", "imported_counts_json", "imported_at"}
	query := "INSERT INTO " + repository.store.TableIdentifier("identity_portability_import_receipts") + " (" + strings.Join(database.QuotedColumns(repository.store, columns), ", ") + ") VALUES (" + strings.Join(repository.placeholders(len(columns)), ", ") + ")"
	if _, err := tx.ExecContext(ctx, query, receipt.ReceiptID, receipt.WorkspaceID, receipt.ContentSHA256, receipt.IdempotencyKey, string(countsJSON), receipt.ImportedAt.Format(time.RFC3339Nano)); err != nil {
		return portabilitymodel.ImportReceipt{}, fmt.Errorf("record Identity portability import: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return portabilitymodel.ImportReceipt{}, err
	}
	return receipt, nil
}

func (repository *SQLRepository) exportDataset(ctx context.Context, spec datasetSpec, workspaceID string) (portabilitymodel.Dataset, error) {
	return repository.exportDatasetFrom(ctx, repository.store.DB(), spec, workspaceID)
}

func (repository *SQLRepository) exportDatasetFrom(ctx context.Context, queryer datasetQueryer, spec datasetSpec, workspaceID string) (portabilitymodel.Dataset, error) {
	query := "SELECT " + strings.Join(database.QuotedColumns(repository.store, spec.columns), ", ") + " FROM " + repository.store.TableIdentifier(spec.table) + " WHERE " + repository.store.Identifier(spec.workspace) + " = " + repository.store.Placeholder(1)
	if len(spec.orderBy) > 0 {
		query += " ORDER BY " + strings.Join(database.QuotedColumns(repository.store, spec.orderBy), ", ")
	}
	rows, err := queryer.QueryContext(ctx, query, workspaceID)
	if err != nil {
		return portabilitymodel.Dataset{}, fmt.Errorf("export Identity dataset %s: %w", spec.name, err)
	}
	defer rows.Close()
	dataset := portabilitymodel.Dataset{Name: spec.name, Records: []portabilitymodel.Record{}}
	for rows.Next() {
		values := make([]any, len(spec.columns))
		destinations := make([]any, len(values))
		for index := range values {
			destinations[index] = &values[index]
		}
		if err := rows.Scan(destinations...); err != nil {
			return portabilitymodel.Dataset{}, err
		}
		record := portabilitymodel.Record{}
		for index, column := range spec.columns {
			raw, encodeErr := portableValue(values[index])
			if encodeErr != nil {
				return portabilitymodel.Dataset{}, fmt.Errorf("encode %s.%s: %w", spec.name, column, encodeErr)
			}
			record[column] = raw
		}
		dataset.Records = append(dataset.Records, record)
	}
	return dataset, rows.Err()
}

func (repository *SQLRepository) verifyAuthorizationState(ctx context.Context, queryer datasetQueryer, bundle portabilitymodel.Bundle) error {
	datasets := make([]portabilitymodel.Dataset, 0, len(portableDatasetSpecs))
	for _, spec := range portableDatasetSpecs {
		dataset, err := repository.exportDatasetFrom(ctx, queryer, spec, bundle.WorkspaceID)
		if err != nil {
			return err
		}
		datasets = append(datasets, dataset)
	}
	digest, err := portabilitymodel.AuthorizationStateDigest(datasets)
	if err != nil {
		return err
	}
	if digest != bundle.AuthorizationStateSHA256 {
		return fmt.Errorf("identity.portability_authorization_parity_failed")
	}
	return nil
}

func (repository *SQLRepository) providerReferences(ctx context.Context, workspaceID string) ([]portabilitymodel.ProviderReference, error) {
	query := "SELECT " + strings.Join(database.QuotedColumns(repository.store, []string{"provider_key", "configuration_json"}), ", ") + " FROM " + repository.store.TableIdentifier("auth_provider_credentials") + " WHERE " + repository.store.Identifier("workspace_id") + " = " + repository.store.Placeholder(1) + " ORDER BY " + repository.store.Identifier("provider_key")
	rows, err := repository.store.DB().QueryContext(ctx, query, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	references := []portabilitymodel.ProviderReference{}
	for rows.Next() {
		var key, configuration string
		if err := rows.Scan(&key, &configuration); err != nil {
			return nil, err
		}
		var document any
		if err := json.Unmarshal([]byte(configuration), &document); err != nil {
			return nil, fmt.Errorf("decode provider reference %s: %w", key, err)
		}
		canonical, err := json.Marshal(document)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(canonical)
		references = append(references, portabilitymodel.ProviderReference{ProviderKey: key, Configuration: canonical, ConfigurationHash: hex.EncodeToString(digest[:]), SecretRequired: true})
	}
	return references, rows.Err()
}

func (repository *SQLRepository) workspaceCount(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, table, workspaceColumn, workspaceID string) (int64, error) {
	var count int64
	query := "SELECT COUNT(*) FROM " + repository.store.TableIdentifier(table) + " WHERE " + repository.store.Identifier(workspaceColumn) + " = " + repository.store.Placeholder(1)
	if err := queryer.QueryRowContext(ctx, query, workspaceID).Scan(&count); err != nil {
		return 0, fmt.Errorf("inventory Identity table %s: %w", table, err)
	}
	return count, nil
}

func (repository *SQLRepository) placeholders(count int) []string {
	result := make([]string, 0, count)
	for position := 1; position <= count; position++ {
		result = append(result, repository.store.Placeholder(position))
	}
	return result
}

func (repository *SQLRepository) importReceipt(ctx context.Context, workspaceID, idempotencyKey string) (portabilitymodel.ImportReceipt, bool, error) {
	query := "SELECT " + strings.Join(database.QuotedColumns(repository.store, []string{"receipt_id", "content_sha256", "imported_counts_json", "imported_at"}), ", ") + " FROM " + repository.store.TableIdentifier("identity_portability_import_receipts") + " WHERE " + repository.store.Identifier("workspace_id") + " = " + repository.store.Placeholder(1) + " AND " + repository.store.Identifier("idempotency_key") + " = " + repository.store.Placeholder(2)
	var receipt portabilitymodel.ImportReceipt
	var countsJSON, importedAt string
	err := repository.store.DB().QueryRowContext(ctx, query, workspaceID, idempotencyKey).Scan(&receipt.ReceiptID, &receipt.ContentSHA256, &countsJSON, &importedAt)
	if err == sql.ErrNoRows {
		return portabilitymodel.ImportReceipt{}, false, nil
	}
	if err != nil {
		return portabilitymodel.ImportReceipt{}, false, err
	}
	receipt.WorkspaceID, receipt.IdempotencyKey = workspaceID, idempotencyKey
	if err := json.Unmarshal([]byte(countsJSON), &receipt.ImportedCounts); err != nil {
		return portabilitymodel.ImportReceipt{}, false, err
	}
	receipt.ImportedAt, err = time.Parse(time.RFC3339Nano, importedAt)
	return receipt, true, err
}

func validateImportDatasets(bundle portabilitymodel.Bundle) error {
	if len(bundle.Datasets) != len(portableDatasetSpecs) {
		return fmt.Errorf("identity.portability_dataset_set_invalid")
	}
	for _, dataset := range bundle.Datasets {
		spec, found := datasetSpecNamed(dataset.Name)
		if !found {
			return fmt.Errorf("identity.portability_dataset_unsupported: %s", dataset.Name)
		}
		for _, record := range dataset.Records {
			if len(record) != len(spec.columns) {
				return fmt.Errorf("identity.portability_record_shape_invalid: %s", dataset.Name)
			}
			for _, column := range spec.columns {
				if _, exists := record[column]; !exists {
					return fmt.Errorf("identity.portability_record_column_missing: %s.%s", dataset.Name, column)
				}
			}
		}
	}
	return nil
}

func portableValue(value any) (json.RawMessage, error) {
	switch typed := value.(type) {
	case nil:
		return json.RawMessage("null"), nil
	case []byte:
		return json.Marshal(string(typed))
	case time.Time:
		return json.Marshal(typed.UTC().Format(time.RFC3339Nano))
	default:
		return json.Marshal(typed)
	}
}

func importValues(spec datasetSpec, record portabilitymodel.Record, workspaceID string) ([]any, error) {
	values := make([]any, 0, len(spec.columns))
	for _, column := range spec.columns {
		value, err := importValue(record[column])
		if err != nil {
			return nil, fmt.Errorf("decode %s.%s: %w", spec.name, column, err)
		}
		if column == spec.workspace && fmt.Sprint(value) != workspaceID {
			return nil, fmt.Errorf("identity.portability_record_workspace_mismatch: %s", spec.name)
		}
		values = append(values, value)
	}
	return values, nil
}

func importValue(raw json.RawMessage) (any, error) {
	if string(raw) == "null" {
		return nil, nil
	}
	var value any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	switch typed := value.(type) {
	case string, bool, nil:
		return typed, nil
	case json.Number:
		if integer, err := strconv.ParseInt(string(typed), 10, 64); err == nil {
			return integer, nil
		}
		return strconv.ParseFloat(string(typed), 64)
	default:
		return nil, fmt.Errorf("composite database value is not supported")
	}
}

func importReceiptID(workspaceID, contentHash, idempotencyKey string) string {
	sum := sha256.Sum256([]byte(workspaceID + "\x00" + contentHash + "\x00" + idempotencyKey))
	return "identity-import:" + hex.EncodeToString(sum[:])[:24]
}

var _ portabilityapplication.Repository = (*SQLRepository)(nil)
