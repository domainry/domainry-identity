// Package module provides Identity's host-mounted HTTP surfaces.
package module

import (
	"net/http"

	actioncontract "github.com/domainry/domainry-foundation/action"
	identityhttpapi "github.com/domainry/domainry-identity-sdk/httpapi"
)

type Surface struct {
	name    string
	handler http.Handler
	routes  []identityhttpapi.Route
}

func NewSurface(name string, handler http.Handler, routes []identityhttpapi.Route) *Surface {
	return &Surface{name: name, handler: handler, routes: cloneRoutes(routes)}
}

func (*Surface) ContractVersion() string { return identityhttpapi.ContractVersion }
func (*Surface) Owner() string           { return "identity" }

func (surface *Surface) Name() string {
	if surface == nil {
		return ""
	}
	return surface.name
}

func (surface *Surface) Routes() []identityhttpapi.Route {
	if surface == nil {
		return nil
	}
	return cloneRoutes(surface.routes)
}

func (surface *Surface) Handler() http.Handler {
	if surface == nil {
		return nil
	}
	return surface.handler
}

func cloneRoutes(routes []identityhttpapi.Route) []identityhttpapi.Route {
	result := make([]identityhttpapi.Route, len(routes))
	for index, route := range routes {
		result[index] = route
		result[index].Action = actioncontract.CloneDefinition(route.Action)
	}
	return result
}

var _ identityhttpapi.Surface = (*Surface)(nil)
