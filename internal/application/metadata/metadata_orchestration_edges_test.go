package metadata

import (
	"context"
	"errors"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	changeplanmodel "github.com/domainry/domainry-identity/internal/domain/changeplan/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type metadataReferenceEdgeProvider struct {
	graph changeplanmodel.ReferenceGraph
	err   error
}

func (p metadataReferenceEdgeProvider) Graph(context.Context, identitymodel.Principal) (changeplanmodel.ReferenceGraph, error) {
	return p.graph, p.err
}

func TestMetadataReferenceGraphBoundaries(t *testing.T) {
	admin := identitymodel.Principal{Known: true, UserID: "admin", WorkspaceID: identitymodel.InstallationWorkspaceID}
	service := NewMetadataApplicationService(MetadataApplicationDependencies{})
	if _, err := service.ReferenceGraph(t.Context(), identitymodel.Principal{}); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("authorization error=%v", err)
	}
	if _, err := service.ReferenceGraph(t.Context(), admin); apperror.KindOf(err) != apperror.KindInternal {
		t.Fatalf("missing provider error=%v", err)
	}
	edgeErr := errors.New("graph failed")
	service.references = metadataReferenceEdgeProvider{err: edgeErr}
	if _, err := service.ReferenceGraph(t.Context(), admin); !errors.Is(err, edgeErr) {
		t.Fatalf("provider error=%v", err)
	}
}
