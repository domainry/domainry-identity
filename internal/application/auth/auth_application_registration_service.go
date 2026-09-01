package auth

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type AuthApplicationRegistrationService struct {
	repository authrepository.AuthApplicationRepository
	workspace  string
}

func (service *AuthApplicationRegistrationService) WorkspaceID() string {
	if service == nil {
		return ""
	}
	return service.workspace
}

func NewAuthApplicationRegistrationService(repository authrepository.AuthApplicationRepository, workspaceID string) (*AuthApplicationRegistrationService, error) {
	if repository == nil {
		return nil, fmt.Errorf("authentication application repository is required")
	}
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	return &AuthApplicationRegistrationService{repository: repository, workspace: workspace.String()}, nil
}

func (service *AuthApplicationRegistrationService) Register(ctx context.Context, applicationKey string, redirectURLs []string) (authmodel.AuthApplicationRegistration, error) {
	applicationKey = strings.TrimSpace(applicationKey)
	redirectURLs, err := normalizeAuthApplicationRedirectURLs(redirectURLs)
	if applicationKey == "" {
		return authmodel.AuthApplicationRegistration{}, fmt.Errorf("authentication application key is required")
	}
	if err != nil {
		return authmodel.AuthApplicationRegistration{}, err
	}
	registration := authmodel.AuthApplicationRegistration{
		WorkspaceID: service.workspace, ApplicationKey: applicationKey,
		RedirectURLs: redirectURLs, Status: authmodel.AuthApplicationActive,
	}
	if err := service.repository.UpsertAuthApplications(ctx, service.workspace, []authmodel.AuthApplicationRegistration{registration}); err != nil {
		return authmodel.AuthApplicationRegistration{}, err
	}
	registered, found, err := service.repository.GetAuthApplication(ctx, service.workspace, applicationKey)
	if err != nil {
		return authmodel.AuthApplicationRegistration{}, err
	}
	if !found {
		return authmodel.AuthApplicationRegistration{}, fmt.Errorf("registered authentication application %q was not found", applicationKey)
	}
	return registered, nil
}

func (service *AuthApplicationRegistrationService) Registered(ctx context.Context, applicationKey string) (bool, error) {
	registration, found, err := service.repository.GetAuthApplication(ctx, service.workspace, strings.TrimSpace(applicationKey))
	return found && registration.Status == authmodel.AuthApplicationActive, err
}

func (service *AuthApplicationRegistrationService) RedirectAllowed(ctx context.Context, applicationKey, redirectURL string) (bool, error) {
	registration, found, err := service.repository.GetAuthApplication(ctx, service.workspace, strings.TrimSpace(applicationKey))
	if err != nil || !found || registration.Status != authmodel.AuthApplicationActive {
		return false, err
	}
	return slices.Contains(registration.RedirectURLs, strings.TrimSpace(redirectURL)), nil
}

func normalizeAuthApplicationRedirectURLs(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		parsed, err := url.ParseRequestURI(value)
		if err != nil || parsed == nil || !parsed.IsAbs() || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return nil, fmt.Errorf("authentication application redirect URL %q is invalid", value)
		}
		result = append(result, value)
	}
	slices.Sort(result)
	return slices.Compact(result), nil
}
