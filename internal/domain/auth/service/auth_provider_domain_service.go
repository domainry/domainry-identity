package service

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"context"
	"strings"
	"sync"
)

// AuthProviderDomainService manages authentication-provider configuration and credentials.
type AuthProviderDomainService struct {
	mu                sync.RWMutex
	configs           map[string]authmodel.AuthProviderConfig
	order             []string
	defaultAutoCreate bool
}

func NewAuthProviderDomainService(configs []map[string]any, defaultAutoCreate bool) *AuthProviderDomainService {
	s := &AuthProviderDomainService{configs: map[string]authmodel.AuthProviderConfig{}, defaultAutoCreate: defaultAutoCreate}
	for _, raw := range configs {
		config := authmodel.AuthProviderConfigFromMap(raw)
		key := strings.ToLower(config.Key)
		if key == "" {
			continue
		}
		s.configs[key] = config
		s.order = append(s.order, key)
	}
	return s
}

func (s *AuthProviderDomainService) ListSafe(_ context.Context) []map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.order) == 0 {
		return []map[string]any{{"key": "local", "label": "Password", "enabled": true, "type": "password"}}
	}
	out := make([]map[string]any, 0, len(s.order))
	for _, key := range s.order {
		out = append(out, s.configs[key].SafeMap())
	}
	return out
}
func (s *AuthProviderDomainService) Find(_ context.Context, key string) (authmodel.AuthProviderConfig, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.configs[strings.ToLower(strings.TrimSpace(key))]
	return value.Clone(), ok
}
func (s *AuthProviderDomainService) Enabled(ctx context.Context, key string) (authmodel.AuthProviderConfig, bool) {
	value, ok := s.Find(ctx, key)
	return value, ok && value.Enabled
}
func (s *AuthProviderDomainService) ReplaceConfig(value authmodel.AuthProviderConfig) (authmodel.AuthProviderConfig, bool) {
	key := strings.ToLower(strings.TrimSpace(value.Key))
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.configs[key]
	if !ok {
		return authmodel.AuthProviderConfig{}, false
	}
	value.Key = key
	s.configs[key] = value.Clone()
	return value.Clone(), true
}
func (s *AuthProviderDomainService) AuthExternalLoginPolicy(_ context.Context, config authmodel.AuthProviderConfig) authmodel.AuthExternalLoginPolicy {
	autoCreate := s.defaultAutoCreate
	if config.AutoCreateConfigured {
		autoCreate = config.AutoCreateUsers
	}
	return authmodel.AuthExternalLoginPolicy{AutoCreateUsers: autoCreate, DefaultRoleKey: config.DefaultRoleKey, RoleMappings: append([]authmodel.AuthExternalRoleMapping(nil), config.RoleMappings...)}
}
