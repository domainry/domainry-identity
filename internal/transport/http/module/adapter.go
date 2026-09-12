// Package module provides Identity's host-mounted HTTP adapters.
package module

import (
	"context"
	"errors"
	"net/http"

	actioncontract "github.com/domainry/domainry-foundation/action"
	"github.com/domainry/domainry-foundation/modulehttp"
	identityhttpapi "github.com/domainry/domainry-identity-sdk/httpapi"
)

type Adapter struct {
	name    string
	handler http.Handler
	routes  []identityhttpapi.Route
	audit   modulehttp.AuditRecorder
}

func NewAdapter(name string, handler http.Handler, routes []identityhttpapi.Route, audit modulehttp.AuditRecorder) *Adapter {
	return &Adapter{name: name, handler: handler, routes: cloneRoutes(routes), audit: audit}
}

func (*Adapter) ContractVersion() string { return identityhttpapi.ContractVersion }
func (*Adapter) Owner() string           { return "identity" }

func (adapter *Adapter) Name() string {
	if adapter == nil {
		return ""
	}
	return adapter.name
}

func (adapter *Adapter) Routes() []identityhttpapi.Route {
	if adapter == nil {
		return nil
	}
	return cloneRoutes(adapter.routes)
}

func (adapter *Adapter) Handler() http.Handler {
	if adapter == nil {
		return nil
	}
	return adapter.handler
}

func (adapter *Adapter) Record(ctx context.Context, event modulehttp.AuditEvent) error {
	if adapter == nil || adapter.audit == nil {
		return errors.New("identity module audit recorder is unavailable")
	}
	return adapter.audit.Record(ctx, event)
}

func cloneRoutes(routes []identityhttpapi.Route) []identityhttpapi.Route {
	result := make([]identityhttpapi.Route, len(routes))
	for index, route := range routes {
		result[index] = route
		result[index].Action = actioncontract.CloneDefinition(route.Action)
	}
	return result
}

var _ identityhttpapi.Adapter = (*Adapter)(nil)
var _ modulehttp.AuditRecorder = (*Adapter)(nil)
