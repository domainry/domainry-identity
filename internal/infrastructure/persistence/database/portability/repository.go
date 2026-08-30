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
	ormbuilder "github.com/domainry/domainry-orm/query"
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
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(repository.store.SQLRenderer, "auth_provider_credentials", workspaceID).
		Columns("provider_key").OrderBy(ormbuilder.Ascending("provider_key")).Build()
	if err != nil {
		return portabilitymodel.Inventory{}, fmt.Errorf("build Identity provider inventory: %w", err)
	}
	rows, err := repository.store.DB().QueryContext(ctx, statement, arguments...)
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
	query, arguments, err := ormbuilder.NewSelectBuilder(repository.store.SQLRenderer, "application_schema_catalog").
		Columns("value").Where(ormbuilder.Equal("key", "schema_hash")).Build()
	if err != nil {
		return "", fmt.Errorf("build Identity metadata schema hash read: %w", err)
	}
	if err := repository.store.DB().QueryRowContext(ctx, query, arguments...).Scan(&digest); err != nil {
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

func (repository *SQLRepository) FreezeWrites(ctx context.Context, workspaceID, evidence, operator string, now time.Time) (portabilitymodel.WriteFence, error) {
	return repository.store.FreezeIdentityWrites(ctx, workspaceID, evidence, operator, now)
}

func (repository *SQLRepository) ReleaseWriteFence(ctx context.Context, workspaceID, operator string, now time.Time) (portabilitymodel.WriteFence, error) {
	return repository.store.ReleaseIdentityWriteFence(ctx, workspaceID, operator, now)
}

func (repository *SQLRepository) VerifyWriteFreeze(ctx context.Context, workspaceID string) error {
	frozen, err := repository.store.IdentityWritesFrozen(ctx, workspaceID)
	if err != nil {
		return err
	}
	if !frozen {
		return fmt.Errorf("identity.portability_write_freeze_not_active")
	}
	return nil
}

func (repository *SQLRepository) VerifyProviderReadiness(ctx context.Context, workspaceID string, references []portabilitymodel.ProviderReference) error {
	for _, reference := range references {
		query, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(repository.store.SQLRenderer, "auth_provider_credentials", workspaceID).
			Columns("configuration_json", "secret_envelope").Where(ormbuilder.Equal("provider_key", reference.ProviderKey)).Build()
		if err != nil {
			return fmt.Errorf("build Identity provider readiness read: %w", err)
		}
		var configuration, secretEnvelope string
		if err := repository.store.DB().QueryRowContext(ctx, query, arguments...).Scan(&configuration, &secretEnvelope); err != nil {
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
	tx, err := repository.store.DB().BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return portabilitymodel.ImportReceipt{}, err
	}
	defer tx.Rollback()
	targetPopulated := false
	for _, spec := range portableDatasetSpecs {
		count, countErr := repository.workspaceCount(ctx, tx, spec.table, spec.workspace, bundle.WorkspaceID)
		if countErr != nil {
			return portabilitymodel.ImportReceipt{}, countErr
		}
		if count != 0 {
			targetPopulated = true
		}
	}
	counts := map[string]int64{}
	for _, dataset := range bundle.Datasets {
		counts[dataset.Name] = int64(len(dataset.Records))
	}
	if targetPopulated {
		if err := repository.verifyAuthorizationState(ctx, tx, bundle); err != nil {
			return portabilitymodel.ImportReceipt{}, fmt.Errorf("identity.portability_target_not_empty: %w", err)
		}
		return portabilitymodel.ImportReceipt{
			ReceiptID: importReceiptID(bundle.WorkspaceID, bundle.ContentSHA256, idempotencyKey), WorkspaceID: bundle.WorkspaceID,
			ContentSHA256: bundle.ContentSHA256, IdempotencyKey: idempotencyKey, ImportedCounts: counts, ImportedAt: importedAt.UTC(), Replayed: true,
		}, nil
	}

	counts = map[string]int64{}
	for _, dataset := range bundle.Datasets {
		spec, _ := datasetSpecNamed(dataset.Name)
		for _, record := range dataset.Records {
			values, valuesErr := importValues(spec, record, bundle.WorkspaceID)
			if valuesErr != nil {
				return portabilitymodel.ImportReceipt{}, valuesErr
			}
			columns, workspaceValues, fieldsErr := workspaceDatasetFields(spec, values)
			if fieldsErr != nil {
				return portabilitymodel.ImportReceipt{}, fieldsErr
			}
			query, arguments, buildErr := ormbuilder.NewWorkspaceInsertBuilder(repository.store.SQLRenderer, spec.table, bundle.WorkspaceID).
				Columns(columns...).Values(workspaceValues...).Build()
			if buildErr != nil {
				return portabilitymodel.ImportReceipt{}, fmt.Errorf("build Identity dataset %s import: %w", dataset.Name, buildErr)
			}
			if _, insertErr := tx.ExecContext(ctx, query, arguments...); insertErr != nil {
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
	if err := tx.Commit(); err != nil {
		return portabilitymodel.ImportReceipt{}, err
	}
	return receipt, nil
}

func (repository *SQLRepository) exportDataset(ctx context.Context, spec datasetSpec, workspaceID string) (portabilitymodel.Dataset, error) {
	return repository.exportDatasetFrom(ctx, repository.store.DB(), spec, workspaceID)
}

func (repository *SQLRepository) exportDatasetFrom(ctx context.Context, queryer datasetQueryer, spec datasetSpec, workspaceID string) (portabilitymodel.Dataset, error) {
	if spec.workspace != ormbuilder.WorkspaceIDColumn {
		return portabilitymodel.Dataset{}, fmt.Errorf("Identity portability dataset %s has unsupported workspace column %s", spec.name, spec.workspace)
	}
	selectBuilder := ormbuilder.NewWorkspaceSelectBuilder(repository.store.SQLRenderer, spec.table, workspaceID).Columns(spec.columns...)
	if len(spec.orderBy) > 0 {
		orders := make([]ormbuilder.Order, 0, len(spec.orderBy))
		for _, column := range spec.orderBy {
			orders = append(orders, ormbuilder.Ascending(column))
		}
		selectBuilder.OrderBy(orders...)
	}
	query, arguments, err := selectBuilder.Build()
	if err != nil {
		return portabilitymodel.Dataset{}, fmt.Errorf("build Identity dataset %s export: %w", spec.name, err)
	}
	rows, err := queryer.QueryContext(ctx, query, arguments...)
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
	query, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(repository.store.SQLRenderer, "auth_provider_credentials", workspaceID).
		Columns("provider_key", "configuration_json").OrderBy(ormbuilder.Ascending("provider_key")).Build()
	if err != nil {
		return nil, fmt.Errorf("build Identity provider reference list: %w", err)
	}
	rows, err := repository.store.DB().QueryContext(ctx, query, arguments...)
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
	if workspaceColumn != ormbuilder.WorkspaceIDColumn {
		return 0, fmt.Errorf("inventory Identity table %s has unsupported workspace column %s", table, workspaceColumn)
	}
	query, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(repository.store.SQLRenderer, table, workspaceID).
		Projections(ormbuilder.Project(ormbuilder.CountAll())).Build()
	if err != nil {
		return 0, fmt.Errorf("build inventory Identity table %s count: %w", table, err)
	}
	var count int64
	if err := queryer.QueryRowContext(ctx, query, arguments...).Scan(&count); err != nil {
		return 0, fmt.Errorf("inventory Identity table %s: %w", table, err)
	}
	return count, nil
}

func workspaceDatasetFields(spec datasetSpec, values []any) ([]string, []any, error) {
	if len(values) != len(spec.columns) {
		return nil, nil, fmt.Errorf("Identity portability dataset %s column/value count mismatch", spec.name)
	}
	columns := make([]string, 0, len(spec.columns)-1)
	workspaceValues := make([]any, 0, len(values)-1)
	workspaceFound := false
	for index, column := range spec.columns {
		if column == spec.workspace {
			workspaceFound = true
			continue
		}
		columns = append(columns, column)
		workspaceValues = append(workspaceValues, values[index])
	}
	if spec.workspace != ormbuilder.WorkspaceIDColumn || !workspaceFound {
		return nil, nil, fmt.Errorf("Identity portability dataset %s must declare workspace_id", spec.name)
	}
	return columns, workspaceValues, nil
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
