package repository

import (
	"context"

	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
)

type ManifestRuntimeMetadataRepository interface {
	EnsureManifestMetadata(context.Context, manifestmodel.ManifestSchema) error
	LoadManifestMetadata(context.Context) (manifestmodel.ManifestSchema, error)
	SyncManifestStorage(context.Context, manifestmodel.ManifestSchema) error
}
