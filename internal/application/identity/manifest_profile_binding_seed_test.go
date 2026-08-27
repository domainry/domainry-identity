package identity

import (
	"context"
	"testing"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
)

type manifestProfileBindingRepositoryStub struct {
	current  identitymodel.IdentityProfileBinding
	found    bool
	mutation identitymodel.IdentityProfileBindingMutation
}

func (s *manifestProfileBindingRepositoryStub) GetIdentityProfileBinding(context.Context, string, string, string) (identitymodel.IdentityProfileBinding, bool, error) {
	return s.current, s.found, nil
}
func (s *manifestProfileBindingRepositoryStub) GetIdentityProfileBindingByKey(context.Context, string, string, string) (identitymodel.IdentityProfileBinding, bool, error) {
	return s.current, s.found, nil
}
func (s *manifestProfileBindingRepositoryStub) GetIdentityProfileBindingReceipt(context.Context, identitymodel.IdentityProfileBindingMutation) (identitymodel.IdentityProfileBindingReceipt, bool, error) {
	return identitymodel.IdentityProfileBindingReceipt{}, false, nil
}
func (s *manifestProfileBindingRepositoryStub) ExecuteIdentityProfileBindingMutation(_ context.Context, mutation identitymodel.IdentityProfileBindingMutation) (identitymodel.IdentityProfileBindingReceipt, error) {
	s.mutation = mutation
	return identitymodel.IdentityProfileBindingReceipt{}, nil
}
func (s *manifestProfileBindingRepositoryStub) ListIdentityProfileBindingEvents(context.Context, string, string, string) ([]identitymodel.IdentityProfileBindingEvent, error) {
	return nil, nil
}

func TestSyncManifestIdentityProfileBindingsCreatesActiveBindingIntent(t *testing.T) {
	repository := &manifestProfileBindingRepositoryStub{}
	manifest := manifestmodel.ManifestSchema{IdentityBootstrap: &identitymodel.ManifestIdentityBootstrapSchema{
		ProfileBindings: []identitymodel.ManifestIdentityProfileBindingSeedSchema{{
			BindingKey: "customer", ObjectKey: "customer_profile", ProfileID: "customer_profile_alpha", IdentityUserID: "customer-user", IdentityField: "identity_user_id",
		}},
	}}
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-a")
	if err := SyncManifestIdentityProfileBindings(ctx, repository, manifest); err != nil {
		t.Fatal(err)
	}
	mutation := repository.mutation
	if mutation.WorkspaceID != "workspace-a" || mutation.Operation != identitymodel.IdentityProfileBindingBind || mutation.ExpectedVersion != 0 || mutation.IdentityUserID != "customer-user" || len(mutation.RequestFingerprint) != 64 {
		t.Fatalf("profile binding mutation=%#v", mutation)
	}
}

func TestSyncManifestIdentityProfileBindingsAcceptsMatchingActiveBinding(t *testing.T) {
	repository := &manifestProfileBindingRepositoryStub{found: true, current: identitymodel.IdentityProfileBinding{
		BindingKey: "customer", ObjectKey: "customer_profile", ProfileID: "customer_profile_alpha", IdentityUserID: "customer-user", Status: identitymodel.IdentityProfileBindingActive,
	}}
	manifest := manifestmodel.ManifestSchema{IdentityBootstrap: &identitymodel.ManifestIdentityBootstrapSchema{ProfileBindings: []identitymodel.ManifestIdentityProfileBindingSeedSchema{{
		BindingKey: "customer", ObjectKey: "customer_profile", ProfileID: "customer_profile_alpha", IdentityUserID: "customer-user", IdentityField: "identity_user_id",
	}}}}
	if err := SyncManifestIdentityProfileBindings(t.Context(), repository, manifest); err != nil {
		t.Fatal(err)
	}
	if repository.mutation.BindingKey != "" {
		t.Fatalf("matching active binding was rewritten: %#v", repository.mutation)
	}
}
