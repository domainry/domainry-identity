package metadata

import (
	"context"
	"errors"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
	metadatacontract "github.com/domainry/domainry-identity/internal/domain/metadata/contract"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatarepository "github.com/domainry/domainry-identity/internal/domain/metadata/repository"
)

type metadataSchemaApplicationProviderStub struct {
	snapshot metadatamodel.MetadataSchemaSnapshot
}

func (s metadataSchemaApplicationProviderStub) SchemaForPrincipal(context.Context, identitymodel.Principal) metadatamodel.MetadataSchemaSnapshot {
	return s.snapshot
}

func TestMetadataSchemaApplicationServiceOwnsFeaturePermissionProjection(t *testing.T) {
	application := NewMetadataSchemaApplicationService(metadataSchemaApplicationProviderStub{snapshot: metadatamodel.MetadataSchemaSnapshot{Objects: []definitionmodel.ObjectSchema{{Key: "customer", Name: "Customer"}}}}, nil)
	admin := identitymodel.Principal{Known: true, WorkspaceID: "workspace-primary", UserID: "admin", Role: identitymodel.RoleSchema{
		Permissions:     []string{"customer.read"},
		DataPermissions: []identitymodel.DataPermission{{ObjectKey: "customer", Scope: "all_records", Read: true}},
	}}
	permissions, err := application.FeaturePermissions(t.Context(), admin)
	if err != nil || len(permissions.Objects) != 1 || !permissions.Objects[0].Actions[0].Allowed {
		t.Fatalf("permissions=%#v err=%v", permissions, err)
	}
	if _, err := application.FeaturePermissions(t.Context(), identitymodel.Principal{}); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("unknown principal error=%v", err)
	}
}

type metadataReloadRepositoryStub struct {
	metadatarepository.MetadataRepository
	manifest  manifestmodel.ManifestSchema
	syncCalls int
}

func (repository *metadataReloadRepositoryStub) LoadManifest(context.Context, identitymodel.SystemScope) (manifestmodel.ManifestSchema, error) {
	return repository.manifest, nil
}

func (repository *metadataReloadRepositoryStub) SyncManifest(context.Context, identitymodel.SystemScope, manifestmodel.ManifestSchema) error {
	repository.syncCalls++
	return nil
}

type metadataLifecycleRuntimeStub struct {
	snapshot    metadatamodel.MetadataSchemaSnapshot
	activations int
}

func (runtime *metadataLifecycleRuntimeStub) ActivateMetadata(snapshot metadatamodel.MetadataSchemaSnapshot) {
	runtime.snapshot = snapshot
	runtime.activations++
}

func (runtime *metadataLifecycleRuntimeStub) Schema() metadatamodel.MetadataSchemaSnapshot {
	return runtime.snapshot
}

func TestReloadMetadataPreparesEveryObserverBeforeActivation(t *testing.T) {
	observerErr := errors.New("permission reconciliation failed")
	repository := &metadataReloadRepositoryStub{manifest: manifestmodel.ManifestSchema{
		TemplateID: "candidate", Objects: []definitionmodel.ObjectSchema{{Key: "candidate"}},
	}}
	runtime := &metadataLifecycleRuntimeStub{snapshot: metadatamodel.MetadataSchemaSnapshot{
		TemplateID: "current", Objects: []definitionmodel.ObjectSchema{{Key: "current"}},
	}}
	service := NewMetadataApplicationService(MetadataApplicationDependencies{Repository: repository, Runtime: runtime})
	firstCommitted := false
	service.AddReloadObserver(func(context.Context, metadatamodel.MetadataSchemaSnapshot) (MetadataReloadCommit, error) {
		return func() { firstCommitted = true }, nil
	})
	service.AddReloadObserver(func(context.Context, metadatamodel.MetadataSchemaSnapshot) (MetadataReloadCommit, error) {
		return nil, observerErr
	})
	principal := identitymodel.Principal{Known: true, WorkspaceID: "workspace", Role: identitymodel.RoleSchema{Permissions: []string{metadatacontract.MetadataActionReload}}}
	snapshot, err := service.ReloadMetadata(t.Context(), principal)
	if !errors.Is(err, observerErr) {
		t.Fatalf("reload error=%v", err)
	}
	if snapshot.TemplateID != "current" || runtime.snapshot.TemplateID != "current" || runtime.activations != 0 || firstCommitted {
		t.Fatalf("failed candidate escaped: result=%#v runtime=%#v activations=%d committed=%t", snapshot, runtime.snapshot, runtime.activations, firstCommitted)
	}
}

func TestReloadMetadataActivatesExactPreparedCandidateOnce(t *testing.T) {
	repository := &metadataReloadRepositoryStub{manifest: manifestmodel.ManifestSchema{
		TemplateID: "candidate", Objects: []definitionmodel.ObjectSchema{{Key: "z"}, {Key: "a"}},
	}}
	runtime := &metadataLifecycleRuntimeStub{snapshot: metadatamodel.MetadataSchemaSnapshot{TemplateID: "current"}}
	service := NewMetadataApplicationService(MetadataApplicationDependencies{Repository: repository, Runtime: runtime})
	preparedHash := ""
	committedHash := ""
	service.AddReloadObserver(func(_ context.Context, candidate metadatamodel.MetadataSchemaSnapshot) (MetadataReloadCommit, error) {
		preparedHash = candidate.SchemaHash
		return func() { committedHash = candidate.SchemaHash }, nil
	})
	principal := identitymodel.Principal{Known: true, WorkspaceID: "workspace", Role: identitymodel.RoleSchema{Permissions: []string{metadatacontract.MetadataActionReload}}}
	snapshot, err := service.ReloadMetadata(t.Context(), principal)
	if err != nil {
		t.Fatal(err)
	}
	if repository.syncCalls != 1 || runtime.activations != 1 || snapshot.TemplateID != "candidate" || snapshot.Objects[0].Key != "a" || preparedHash == "" || preparedHash != snapshot.SchemaHash || committedHash != snapshot.SchemaHash || runtime.snapshot.SchemaHash != snapshot.SchemaHash {
		t.Fatalf("activation mismatch: snapshot=%#v runtime=%#v prepared=%q committed=%q", snapshot, runtime.snapshot, preparedHash, committedHash)
	}
}
