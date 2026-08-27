// Schema domain service tests.
package service

import (
	"context"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	"testing"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

type schemaServiceProviderStub struct {
	snapshot metadatamodel.MetadataSchemaSnapshot
}

func (s schemaServiceProviderStub) SchemaForPrincipal(_ context.Context, principal identitymodel.Principal) metadatamodel.MetadataSchemaSnapshot {
	result := s.snapshot
	if principal.Known && !identitycontract.IdentityRoleAllows(principal.Role, "customer", "read") {
		result.Objects = nil
	}
	return result
}

func TestMetadataSchemaDomainServiceOwnsSnapshotProjection(t *testing.T) {
	service := NewMetadataSchemaDomainService(schemaServiceProviderStub{snapshot: metadatamodel.MetadataSchemaSnapshot{Objects: []definitionmodel.ObjectSchema{{Key: "customer", Name: "Customer"}}}}, nil)
	if snapshot := service.Snapshot(t.Context()); len(snapshot.Objects) != 1 {
		t.Fatalf("snapshot=%#v", snapshot)
	}
}
