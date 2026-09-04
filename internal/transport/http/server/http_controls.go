package httpserver

import (
	"net/http"
	"strings"
	"sync"
	"time"

	actioncontract "github.com/domainry/domainry-foundation/action"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
)

type listenerClass string

const (
	listenerClassPublic     listenerClass = "public"
	listenerClassManagement listenerClass = "management"
	listenerClassOperations listenerClass = "operations"
)

type httpControlConfig struct {
	PublicMaxJSONBodyBytes       int64
	ManagementMaxJSONBodyBytes   int64
	OperationsMaxJSONBodyBytes   int64
	PublicRequestTimeout         time.Duration
	ManagementRequestTimeout     time.Duration
	OperationsRequestTimeout     time.Duration
	PublicRateLimitPerMinute     int
	ManagementRateLimitPerMinute int
	OperationsRateLimitPerMinute int
}

type httpListenerControls struct {
	config     httpControlConfig
	public     *fixedWindowLimiter
	management *fixedWindowLimiter
	operations *fixedWindowLimiter
	clock      func() time.Time
}

func newHTTPListenerControls(config httpControlConfig) *httpListenerControls {
	controls := &httpListenerControls{config: config, clock: func() time.Time { return time.Now().UTC() }}
	controls.public = newFixedWindowLimiter(config.PublicRateLimitPerMinute)
	controls.management = newFixedWindowLimiter(config.ManagementRateLimitPerMinute)
	controls.operations = newFixedWindowLimiter(config.OperationsRateLimitPerMinute)
	return controls
}

func (controls *httpListenerControls) bodyLimit(listener listenerClass) int64 {
	if controls == nil {
		return 4 << 20
	}
	switch listener {
	case listenerClassOperations:
		return positiveInt64(controls.config.OperationsMaxJSONBodyBytes, 1<<20)
	case listenerClassManagement:
		return positiveInt64(controls.config.ManagementMaxJSONBodyBytes, 2<<20)
	default:
		return positiveInt64(controls.config.PublicMaxJSONBodyBytes, 2<<20)
	}
}

func (controls *httpListenerControls) timeout(listener listenerClass) time.Duration {
	if controls == nil {
		return 0
	}
	switch listener {
	case listenerClassOperations:
		return controls.config.OperationsRequestTimeout
	case listenerClassManagement:
		return controls.config.ManagementRequestTimeout
	default:
		return controls.config.PublicRequestTimeout
	}
}

func (controls *httpListenerControls) allow(listener listenerClass) (bool, int, time.Time) {
	if controls == nil {
		return true, 0, time.Time{}
	}
	limiter := controls.public
	switch listener {
	case listenerClassOperations:
		limiter = controls.operations
	case listenerClassManagement:
		limiter = controls.management
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

// routeExposureResolver derives the listener class of a request from the
// frozen Action registry (Action.Exposures) and the mux pattern that serves
// it. URL paths carry no audience; the module owns its root and the Action
// declares where it is exposed.
type routeExposureResolver struct {
	mux     *http.ServeMux
	actions *identityapplication.IdentityActionRegistry
}

func newRouteExposureResolver(mux *http.ServeMux, actions *identityapplication.IdentityActionRegistry) *routeExposureResolver {
	return &routeExposureResolver{mux: mux, actions: actions}
}

func listenerClassForExposure(exposure actioncontract.Exposure) (listenerClass, bool) {
	switch exposure {
	case actioncontract.ExposurePublic:
		return listenerClassPublic, true
	case actioncontract.ExposureManagement:
		return listenerClassManagement, true
	case actioncontract.ExposureOps:
		return listenerClassOperations, true
	}
	return "", false
}

// listenerClassesForPattern returns every listener class an Action is exposed on.
// Unknown patterns are exposed nowhere.
func (resolver *routeExposureResolver) listenerClassesForPattern(method, routeTemplate string) []listenerClass {
	if resolver == nil || resolver.actions == nil {
		return nil
	}
	action, found := resolver.actions.ResolveHTTP(strings.TrimSpace(method), strings.TrimSpace(routeTemplate))
	if !found {
		return nil
	}
	classes := make([]listenerClass, 0, len(action.Exposures))
	for _, exposure := range action.Exposures {
		if listener, ok := listenerClassForExposure(exposure); ok {
			classes = append(classes, listener)
		}
	}
	return classes
}

func (resolver *routeExposureResolver) pattern(request *http.Request) (string, string) {
	if request == nil {
		return "", ""
	}
	pattern := strings.TrimSpace(request.Pattern)
	if pattern == "" && resolver != nil && resolver.mux != nil {
		_, pattern = resolver.mux.Handler(request)
	}
	method, routeTemplate, ok := strings.Cut(strings.TrimSpace(pattern), " ")
	if !ok {
		return "", ""
	}
	return method, routeTemplate
}

// exposedOn reports whether the request's Action is exposed on the listener.
func (resolver *routeExposureResolver) exposedOn(request *http.Request, listener listenerClass) bool {
	method, routeTemplate := resolver.pattern(request)
	for _, candidate := range resolver.listenerClassesForPattern(method, routeTemplate) {
		if candidate == listener {
			return true
		}
	}
	return false
}

// controlClass picks the listener class whose transport controls govern a
// request: the least privileged listener the Action is exposed on. Requests
// that match no Action fall back to public controls and are then 404s.
func (resolver *routeExposureResolver) controlClass(request *http.Request) listenerClass {
	method, routeTemplate := resolver.pattern(request)
	return controlClassOf(resolver.listenerClassesForPattern(method, routeTemplate))
}

func controlClassOf(classes []listenerClass) listenerClass {
	rank := map[listenerClass]int{listenerClassPublic: 0, listenerClassManagement: 1, listenerClassOperations: 2}
	result := listenerClassPublic
	for index, listener := range classes {
		if index == 0 || rank[listener] < rank[result] {
			result = listener
		}
	}
	return result
}

func listenerOnly(listener listenerClass, resolver *routeExposureResolver, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !resolver.exposedOn(request, listener) {
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
