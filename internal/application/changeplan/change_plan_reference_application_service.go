package changeplan

import (
	"context"
	"strconv"

	"github.com/domainry/domainry-foundation/apperror"
	changeplanmodel "github.com/domainry/domainry-identity/internal/domain/changeplan/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitypolicy "github.com/domainry/domainry-identity/internal/domain/identity/policy"
)

// ChangePlanReferenceApplicationService projects dependencies among Identity
// authorization metadata only.
type ChangePlanReferenceApplicationService struct {
	schema func(context.Context, identitymodel.Principal) ReferenceSchema
}

func NewChangePlanReferenceApplicationService(schema func(context.Context, identitymodel.Principal) ReferenceSchema) *ChangePlanReferenceApplicationService {
	return &ChangePlanReferenceApplicationService{schema: schema}
}

func (s *ChangePlanReferenceApplicationService) Graph(ctx context.Context, principal identitymodel.Principal) (changeplanmodel.ReferenceGraph, error) {
	if err := changePlanAuthorizeQuery(principal); err != nil {
		return changeplanmodel.ReferenceGraph{}, err
	}
	if !identitypolicy.IdentityRoleHasPermissionKey(principal.Role, "workspace.admin") {
		return changeplanmodel.ReferenceGraph{}, &apperror.AppError{Kind: apperror.KindForbidden, Code: "auth.permission_denied"}
	}
	builder := newChangePlanReferenceGraphBuilder()
	snapshot := ReferenceSchema{}
	if s.schema != nil {
		snapshot = s.schema(ctx, principal)
	}
	AddSchemaReferences(builder, snapshot)
	AddIdentityReferences(builder, snapshot)
	AddActionReferences(builder, snapshot)
	return builder.Graph(), nil
}

func referenceInternalError(operation string, err error) error {
	return &apperror.AppError{Kind: apperror.KindInternal, Code: "backend.internal", Params: map[string]string{"operation": operation}, Err: err}
}

func stringIndex(index int) string { return strconv.Itoa(index) }
