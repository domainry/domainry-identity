package main

import (
	"testing"

	"github.com/domainry/domainry-identity/internal/platform/config"
	httpserver "github.com/domainry/domainry-identity/internal/transport/http/server"
)

func TestIdentityHTTPListenersSeparateProductionSurfaces(t *testing.T) {
	production := config.Config{
		Environment: "production", HTTPPublicAddr: "0.0.0.0:8081",
		HTTPTenantAdminAddr: "127.0.0.1:8082", HTTPOpsAddr: "127.0.0.1:8083",
	}
	listeners := identityHTTPListeners(production, &httpserver.Server{})
	if len(listeners) != 3 {
		t.Fatalf("production listener count=%d", len(listeners))
	}
	want := map[string]string{"public": production.HTTPPublicAddr, "tenant_admin": production.HTTPTenantAdminAddr, "operations": production.HTTPOpsAddr}
	for _, listener := range listeners {
		if listener.server == nil || listener.server.Addr != want[listener.surface] {
			t.Fatalf("listener=%+v", listener)
		}
	}

	development := config.Config{Environment: "development", Port: "9091"}
	listeners = identityHTTPListeners(development, &httpserver.Server{})
	if len(listeners) != 1 || listeners[0].surface != "development" || listeners[0].server.Addr != ":9091" {
		t.Fatalf("development listeners=%+v", listeners)
	}
}
