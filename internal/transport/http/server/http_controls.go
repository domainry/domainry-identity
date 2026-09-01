package httpserver

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

type routeSurface string

const (
	routeSurfacePublic      routeSurface = "public"
	routeSurfaceTenantAdmin routeSurface = "tenant_admin"
	routeSurfaceOperations  routeSurface = "operations"
)

type httpControlConfig struct {
	PublicMaxJSONBodyBytes        int64
	TenantAdminMaxJSONBodyBytes   int64
	OperationsMaxJSONBodyBytes    int64
	PublicRequestTimeout          time.Duration
	TenantAdminRequestTimeout     time.Duration
	OperationsRequestTimeout      time.Duration
	PublicRateLimitPerMinute      int
	TenantAdminRateLimitPerMinute int
	OperationsRateLimitPerMinute  int
}

type httpSurfaceControls struct {
	config     httpControlConfig
	public     *fixedWindowLimiter
	admin      *fixedWindowLimiter
	operations *fixedWindowLimiter
	clock      func() time.Time
}

func newHTTPSurfaceControls(config httpControlConfig) *httpSurfaceControls {
	controls := &httpSurfaceControls{config: config, clock: func() time.Time { return time.Now().UTC() }}
	controls.public = newFixedWindowLimiter(config.PublicRateLimitPerMinute)
	controls.admin = newFixedWindowLimiter(config.TenantAdminRateLimitPerMinute)
	controls.operations = newFixedWindowLimiter(config.OperationsRateLimitPerMinute)
	return controls
}

func (controls *httpSurfaceControls) bodyLimit(surface routeSurface) int64 {
	if controls == nil {
		return 4 << 20
	}
	switch surface {
	case routeSurfaceOperations:
		return positiveInt64(controls.config.OperationsMaxJSONBodyBytes, 1<<20)
	case routeSurfaceTenantAdmin:
		return positiveInt64(controls.config.TenantAdminMaxJSONBodyBytes, 2<<20)
	default:
		return positiveInt64(controls.config.PublicMaxJSONBodyBytes, 2<<20)
	}
}

func (controls *httpSurfaceControls) timeout(surface routeSurface) time.Duration {
	if controls == nil {
		return 0
	}
	switch surface {
	case routeSurfaceOperations:
		return controls.config.OperationsRequestTimeout
	case routeSurfaceTenantAdmin:
		return controls.config.TenantAdminRequestTimeout
	default:
		return controls.config.PublicRequestTimeout
	}
}

func (controls *httpSurfaceControls) allow(surface routeSurface) (bool, int, time.Time) {
	if controls == nil {
		return true, 0, time.Time{}
	}
	limiter := controls.public
	switch surface {
	case routeSurfaceOperations:
		limiter = controls.operations
	case routeSurfaceTenantAdmin:
		limiter = controls.admin
	}
	return limiter.Allow(controls.clock())
}

type fixedWindowLimiter struct {
	mu        sync.Mutex
	limit     int
	used      int
	windowEnd time.Time
}

func newFixedWindowLimiter(limit int) *fixedWindowLimiter {
	return &fixedWindowLimiter{limit: limit}
}

func (limiter *fixedWindowLimiter) Allow(now time.Time) (bool, int, time.Time) {
	if limiter == nil || limiter.limit <= 0 {
		return true, 0, time.Time{}
	}
	now = now.UTC()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if limiter.windowEnd.IsZero() || !now.Before(limiter.windowEnd) || now.Before(limiter.windowEnd.Add(-time.Minute)) {
		limiter.used = 0
		limiter.windowEnd = now.Truncate(time.Minute).Add(time.Minute)
	}
	if limiter.used >= limiter.limit {
		return false, 0, limiter.windowEnd
	}
	limiter.used++
	return true, limiter.limit - limiter.used, limiter.windowEnd
}

func classifyRouteSurface(method, path string) routeSurface {
	path = "/" + strings.TrimLeft(strings.TrimSpace(path), "/")
	if path == "/ops" || strings.HasPrefix(path, "/ops/") || path == "/operations" || strings.HasPrefix(path, "/operations/") {
		return routeSurfaceOperations
	}
	if path == "/auth/reset-password" || strings.HasSuffix(path, "/setup-check") || method == http.MethodPut && strings.HasSuffix(path, "/setup") {
		return routeSurfaceTenantAdmin
	}
	for _, publicIdentityPath := range []string{
		"/identity/discovery", "/identity/access-bundle", "/identity/reauthorize",
		"/identity/application-service/token", "/identity/application-service/verify",
		"/identity/applications/current", "/identity/permissions/reconcile", "/identity/permissions/source-snapshot",
	} {
		if path == publicIdentityPath {
			return routeSurfacePublic
		}
	}
	if strings.HasPrefix(path, "/identity/runtime/") {
		return routeSurfacePublic
	}
	for _, prefix := range []string{
		"/tenant-admin", "/identity", "/metadata", "/audit", "/permissions",
	} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return routeSurfaceTenantAdmin
		}
	}
	return routeSurfacePublic
}

func surfaceOnly(surface routeSurface, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if classifyRouteSurface(request.Method, request.URL.Path) != surface {
			http.NotFound(w, request)
			return
		}
		next.ServeHTTP(w, request)
	})
}

func positiveInt64(value, fallback int64) int64 {
	if value > 0 {
		return value
	}
	return fallback
}
