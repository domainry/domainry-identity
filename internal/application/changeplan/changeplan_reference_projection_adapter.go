package changeplan

import (
	changeplanprojection "github.com/domainry/domainry-identity/internal/domain/changeplan/projection"
)

func newChangePlanReferenceGraphBuilder() *changeplanprojection.ChangePlanReferenceGraphBuilder {
	return changeplanprojection.NewChangePlanReferenceGraphBuilder()
}
