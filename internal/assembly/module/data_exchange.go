package moduleassembly

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	dataexchange "github.com/domainry/domainry-data-exchange-sdk"
	"github.com/domainry/domainry-data-exchange-sdk/modulehost"
	portabilityapplication "github.com/domainry/domainry-identity/internal/application/portability"
	portabilitymodel "github.com/domainry/domainry-identity/internal/domain/portability"
)

const IdentityPortabilityProviderKey = "identity-portability"

type identityPortabilityDataExchangeProvider struct {
	service *portabilityapplication.Service
}

type identityPortabilityExportOptions struct {
	SourceMode string `json:"source_mode"`
	DryRun     bool   `json:"dry_run"`
}

func (*identityPortabilityDataExchangeProvider) ValidateImportBatch(context.Context, dataexchange.ImportBatch) (dataexchange.ImportBatchResult, error) {
	return dataexchange.ImportBatchResult{}, fmt.Errorf("Identity portability requires an atomic JSON artifact")
}

func (*identityPortabilityDataExchangeProvider) ApplyImportBatch(context.Context, dataexchange.ImportBatch) (dataexchange.ImportBatchResult, error) {
	return dataexchange.ImportBatchResult{}, fmt.Errorf("Identity portability requires an atomic JSON artifact")
}

func (*identityPortabilityDataExchangeProvider) ReadExportPage(context.Context, dataexchange.ExportPageRequest) (dataexchange.ExportPage, error) {
	return dataexchange.ExportPage{}, fmt.Errorf("Identity portability requires a canonical JSON artifact")
}

func (provider *identityPortabilityDataExchangeProvider) BuildExportArtifact(ctx context.Context, request dataexchange.ExportArtifactRequest) (dataexchange.ExportArtifact, error) {
	var options identityPortabilityExportOptions
	if err := json.Unmarshal(request.Options, &options); err != nil {
		return dataexchange.ExportArtifact{}, fmt.Errorf("decode Identity portability export options: %w", err)
	}
	result, err := provider.service.Export(ctx, portabilityapplication.ExportRequest{
		WorkspaceID: request.Scope.WorkspaceID, SourceMode: strings.TrimSpace(options.SourceMode), DryRun: options.DryRun,
	})
	if err != nil {
		return dataexchange.ExportArtifact{}, err
	}
	if result.Bundle == nil {
		if !options.DryRun {
			return dataexchange.ExportArtifact{}, fmt.Errorf("Identity portability export returned no bundle")
		}
		raw, err := json.Marshal(result.Inventory)
		if err != nil {
			return dataexchange.ExportArtifact{}, err
		}
		return dataexchange.ExportArtifact{
			Filename: "identity-portability-inventory.json", ContentType: "application/json", ExpiresAt: request.CreatedAt.Add(24 * time.Hour),
			Content: io.NopCloser(strings.NewReader(string(raw))),
		}, nil
	}
	raw, err := json.Marshal(result.Bundle)
	if err != nil {
		return dataexchange.ExportArtifact{}, err
	}
	records := 0
	for _, dataset := range result.Bundle.Datasets {
		records += len(dataset.Records)
	}
	return dataexchange.ExportArtifact{
		Filename: result.Bundle.ExportID + ".json", ContentType: "application/json", ExpiresAt: request.CreatedAt.Add(24 * time.Hour),
		Content: io.NopCloser(strings.NewReader(string(raw))), Records: records,
	}, nil
}

func (provider *identityPortabilityDataExchangeProvider) ValidateImportArtifact(ctx context.Context, artifact dataexchange.ImportArtifact) (dataexchange.ImportArtifactResult, error) {
	bundle, records, err := decodeIdentityPortabilityArtifact(artifact)
	if err != nil {
		return dataexchange.ImportArtifactResult{}, err
	}
	_, err = provider.service.Import(ctx, portabilityapplication.ImportRequest{Bundle: bundle, DryRun: true})
	return dataexchange.ImportArtifactResult{Records: records}, err
}

func (provider *identityPortabilityDataExchangeProvider) ApplyImportArtifact(ctx context.Context, artifact dataexchange.ImportArtifact) (dataexchange.ImportArtifactResult, error) {
	bundle, records, err := decodeIdentityPortabilityArtifact(artifact)
	if err != nil {
		return dataexchange.ImportArtifactResult{}, err
	}
	result, err := provider.service.Import(ctx, portabilityapplication.ImportRequest{
		Bundle: bundle, IdempotencyKey: artifact.JobID,
	})
	if err != nil {
		return dataexchange.ImportArtifactResult{}, err
	}
	receipt := ""
	if result.Receipt != nil {
		receipt = result.Receipt.ReceiptID
	}
	return dataexchange.ImportArtifactResult{Records: records, Receipt: receipt}, nil
}

func decodeIdentityPortabilityArtifact(artifact dataexchange.ImportArtifact) (portabilitymodel.Bundle, int, error) {
	if artifact.Content == nil {
		return portabilitymodel.Bundle{}, 0, fmt.Errorf("Identity portability bundle is required")
	}
	var bundle portabilitymodel.Bundle
	if err := json.NewDecoder(artifact.Content).Decode(&bundle); err != nil {
		return portabilitymodel.Bundle{}, 0, fmt.Errorf("decode Identity portability bundle: %w", err)
	}
	records := 0
	for _, dataset := range bundle.Datasets {
		records += len(dataset.Records)
	}
	return bundle, records, nil
}

var _ modulehost.ImportProvider = (*identityPortabilityDataExchangeProvider)(nil)
var _ modulehost.ImportArtifactProvider = (*identityPortabilityDataExchangeProvider)(nil)
var _ modulehost.ExportProvider = (*identityPortabilityDataExchangeProvider)(nil)
var _ modulehost.ExportArtifactProvider = (*identityPortabilityDataExchangeProvider)(nil)
