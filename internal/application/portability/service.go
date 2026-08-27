package portability

import (
	"context"
	"fmt"
	"strings"
	"time"

	portabilitymodel "github.com/domainry/domainry-identity/internal/domain/portability"
)

type Repository interface {
	Inventory(context.Context, string) (portabilitymodel.Inventory, error)
	MetadataSchemaSHA256(context.Context) (string, error)
	Export(context.Context, string) ([]portabilitymodel.Dataset, []portabilitymodel.ProviderReference, map[string]int64, error)
	RecordExport(context.Context, portabilitymodel.Bundle) error
	FreezeWrites(context.Context, string, string, string, time.Time) (portabilitymodel.WriteFence, error)
	ReleaseWriteFence(context.Context, string, string, time.Time) (portabilitymodel.WriteFence, error)
	VerifyWriteFreeze(context.Context, string, string) error
	VerifyProviderReadiness(context.Context, string, []portabilitymodel.ProviderReference) error
	Import(context.Context, portabilitymodel.Bundle, string, time.Time) (portabilitymodel.ImportReceipt, error)
}

type Service struct {
	repository    Repository
	clock         func() time.Time
	schemaVersion string
}

type Options struct {
	Clock         func() time.Time
	SchemaVersion string
}

func NewService(repository Repository, options Options) (*Service, error) {
	if repository == nil {
		return nil, fmt.Errorf("Identity portability repository is required")
	}
	if options.Clock == nil {
		options.Clock = func() time.Time { return time.Now().UTC() }
	}
	if strings.TrimSpace(options.SchemaVersion) == "" {
		return nil, fmt.Errorf("Identity portability schema version is required")
	}
	return &Service{repository: repository, clock: options.Clock, schemaVersion: strings.TrimSpace(options.SchemaVersion)}, nil
}

type ExportRequest struct {
	WorkspaceID    string
	SourceMode     string
	FreezeEvidence string
	DryRun         bool
}

type ExportResult struct {
	Inventory portabilitymodel.Inventory `json:"inventory"`
	Bundle    *portabilitymodel.Bundle   `json:"bundle,omitempty"`
}

func (service *Service) FreezeWrites(ctx context.Context, workspaceID, evidence, operator string) (portabilitymodel.WriteFence, error) {
	return service.repository.FreezeWrites(ctx, strings.TrimSpace(workspaceID), strings.TrimSpace(evidence), strings.TrimSpace(operator), service.clock().UTC())
}

func (service *Service) ReleaseWriteFence(ctx context.Context, workspaceID, operator string) (portabilitymodel.WriteFence, error) {
	return service.repository.ReleaseWriteFence(ctx, strings.TrimSpace(workspaceID), strings.TrimSpace(operator), service.clock().UTC())
}

func (service *Service) Export(ctx context.Context, request ExportRequest) (ExportResult, error) {
	workspaceID := strings.TrimSpace(request.WorkspaceID)
	inventory, err := service.repository.Inventory(ctx, workspaceID)
	if err != nil {
		return ExportResult{}, err
	}
	if request.DryRun {
		return ExportResult{Inventory: inventory}, nil
	}
	if strings.TrimSpace(request.FreezeEvidence) == "" {
		return ExportResult{}, fmt.Errorf("identity.portability_write_freeze_evidence_required")
	}
	if err := service.repository.VerifyWriteFreeze(ctx, workspaceID, request.FreezeEvidence); err != nil {
		return ExportResult{}, err
	}
	datasets, providers, excluded, err := service.repository.Export(ctx, workspaceID)
	if err != nil {
		return ExportResult{}, err
	}
	metadataSchemaSHA256, err := service.repository.MetadataSchemaSHA256(ctx)
	if err != nil {
		return ExportResult{}, err
	}
	bundle := portabilitymodel.Bundle{
		WorkspaceID:          workspaceID,
		SchemaVersion:        service.schemaVersion,
		MetadataSchemaSHA256: metadataSchemaSHA256,
		SourceMode:           strings.TrimSpace(request.SourceMode),
		ExportedAt:           service.clock().UTC(),
		FreezeEvidence:       strings.TrimSpace(request.FreezeEvidence),
		Datasets:             datasets,
		ProviderReferences:   providers,
		ExcludedCounts:       excluded,
	}
	if err := bundle.Finalize(); err != nil {
		return ExportResult{}, err
	}
	if err := service.repository.RecordExport(ctx, bundle); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Inventory: inventory, Bundle: &bundle}, nil
}

type ImportRequest struct {
	Bundle                  portabilitymodel.Bundle
	IdempotencyKey          string
	DryRun                  bool
	ProviderReadiness       map[string]bool
	AcceptSessionRevocation bool
	AcceptCredentialReset   bool
	AcceptMFAReenrollment   bool
}

type ImportResult struct {
	Inventory portabilitymodel.Inventory      `json:"target_inventory"`
	Receipt   *portabilitymodel.ImportReceipt `json:"receipt,omitempty"`
}

func (service *Service) Import(ctx context.Context, request ImportRequest) (ImportResult, error) {
	if err := request.Bundle.Validate(); err != nil {
		return ImportResult{}, err
	}
	if err := validateSecurityAcceptance(request); err != nil {
		return ImportResult{}, err
	}
	for _, provider := range request.Bundle.ProviderReferences {
		if !request.ProviderReadiness[provider.ProviderKey] {
			return ImportResult{}, fmt.Errorf("identity.portability_provider_not_ready: %s", provider.ProviderKey)
		}
	}
	if err := service.repository.VerifyProviderReadiness(ctx, request.Bundle.WorkspaceID, request.Bundle.ProviderReferences); err != nil {
		return ImportResult{}, err
	}
	inventory, err := service.repository.Inventory(ctx, request.Bundle.WorkspaceID)
	if err != nil {
		return ImportResult{}, err
	}
	if request.DryRun {
		for dataset, count := range inventory.DatasetCounts {
			if count > 0 {
				return ImportResult{}, fmt.Errorf("identity.portability_target_not_empty: %s", dataset)
			}
		}
		return ImportResult{Inventory: inventory}, nil
	}
	idempotencyKey := strings.TrimSpace(request.IdempotencyKey)
	if idempotencyKey == "" {
		return ImportResult{}, fmt.Errorf("identity.portability_idempotency_key_required")
	}
	receipt, err := service.repository.Import(ctx, request.Bundle, idempotencyKey, service.clock().UTC())
	if err != nil {
		return ImportResult{}, err
	}
	receipt.AuthorizationOK = true
	receipt.SessionsRevoked = true
	receipt.CredentialsReset = true
	receipt.MFAReenrollment = true
	return ImportResult{Inventory: inventory, Receipt: &receipt}, nil
}

func validateSecurityAcceptance(request ImportRequest) error {
	if !request.AcceptSessionRevocation || !request.AcceptCredentialReset || !request.AcceptMFAReenrollment {
		return fmt.Errorf("identity.portability_security_disposition_not_accepted")
	}
	return nil
}
