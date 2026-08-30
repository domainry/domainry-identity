package metadata

import (
	"context"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

const PermissionMetadataOpsRead = "metadata.ops.read"

type PublishedRuntimeSchemaDTO struct {
	TemplateID      string                                       `json:"template_id"`
	TemplateVersion string                                       `json:"template_version"`
	Name            string                                       `json:"name,omitempty"`
	SchemaHash      string                                       `json:"schema_hash"`
	SnapshotVersion string                                       `json:"snapshot_version"`
	Objects         []definitionmodel.ObjectSchema               `json:"objects"`
	Actions         []definitionmodel.ActionSchema               `json:"actions"`
	GuardedWrites   []metadatamodel.MetadataGuardedWriteContract `json:"guarded_writes,omitempty"`
}

type PublishedSurfaceContextDTO struct {
	Surface               string   `json:"surface"`
	UserID                string   `json:"user_id"`
	RoleKey               string   `json:"role_key"`
	Permissions           []string `json:"permissions"`
	ActiveBusinessProfile string   `json:"active_business_profile,omitempty"`
	AuthorizationRevision string   `json:"authorization_revision,omitempty"`
	SchemaHash            string   `json:"schema_hash"`
}

type OpsMetadataDiagnosticsDTO struct {
	RepositoryRevision string `json:"repository_revision"`
	SchemaHash         string `json:"schema_hash"`
	SnapshotVersion    string `json:"snapshot_version"`
	TemplateVersion    string `json:"template_version"`
	ObjectCount        int    `json:"object_count"`
	ActionCount        int    `json:"action_count"`
	Compatible         bool   `json:"compatible"`
}

func (s *MetadataSchemaApplicationService) PublishedRuntimeSchema(ctx context.Context, principal identitymodel.Principal) (PublishedRuntimeSchemaDTO, error) {
	if _, err := identitymodel.QueryScopeForPrincipal(principal); err != nil {
		return PublishedRuntimeSchemaDTO{}, &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.workspace_scope_required", Err: err}
	}
	snapshot := s.ForPrincipal(ctx, principal)
	objects := append([]definitionmodel.ObjectSchema(nil), snapshot.Objects...)
	for index := range objects {
		objects[index].Config = sanitizePublishedMap(objects[index].Config)
		objects[index].UX = sanitizePublishedMap(objects[index].UX)
	}
	return PublishedRuntimeSchemaDTO{
		TemplateID: snapshot.TemplateID, TemplateVersion: snapshot.TemplateVersion, Name: snapshot.Name,
		SchemaHash: snapshot.SchemaHash, SnapshotVersion: snapshot.SnapshotVersion,
		Objects: objects, Actions: append([]definitionmodel.ActionSchema(nil), snapshot.Actions...),
		GuardedWrites: append([]metadatamodel.MetadataGuardedWriteContract(nil), snapshot.GuardedWrites...),
	}, nil
}

func (s *MetadataSchemaApplicationService) PublishedSurfaceContext(ctx context.Context, surface string, principal identitymodel.Principal) (PublishedSurfaceContextDTO, error) {
	if _, err := identitymodel.QueryScopeForPrincipal(principal); err != nil {
		return PublishedSurfaceContextDTO{}, &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.workspace_scope_required", Err: err}
	}
	if strings.TrimSpace(principal.SurfaceKey) != "" && strings.TrimSpace(principal.SurfaceKey) != strings.TrimSpace(surface) {
		return PublishedSurfaceContextDTO{}, &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.surface.audience_required"}
	}
	snapshot := s.ForPrincipal(ctx, principal)
	profile := ""
	if principal.ActiveBusinessProfile != nil {
		profile = principal.ActiveBusinessProfile.BindingKey
	}
	return PublishedSurfaceContextDTO{
		Surface: strings.TrimSpace(surface), UserID: principal.UserID, RoleKey: principal.Role.Key,
		Permissions: append([]string(nil), principal.Role.Permissions...), ActiveBusinessProfile: profile,
		AuthorizationRevision: principal.AuthorizationRevision, SchemaHash: snapshot.SchemaHash,
	}, nil
}

func (s *MetadataApplicationService) OpsMetadataDiagnostics(ctx context.Context, principal identitymodel.Principal) (OpsMetadataDiagnosticsDTO, error) {
	if _, err := identitymodel.QueryScopeForPrincipal(principal); err != nil {
		return OpsMetadataDiagnosticsDTO{}, &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.workspace_scope_required", Err: err}
	}
	if !metadataHasExactPermission(principal, PermissionMetadataOpsRead) {
		return OpsMetadataDiagnosticsDTO{}, forbidden("auth.permission_denied")
	}
	if s == nil || s.repository == nil || s.runtime == nil {
		return OpsMetadataDiagnosticsDTO{}, &apperror.AppError{Kind: apperror.KindUnavailable, Code: "backend.metadata.repository_unavailable"}
	}
	revision, err := s.repository.SnapshotRevision(ctx, metadataInstallationScope("inspect metadata repository revision"))
	if err != nil {
		return OpsMetadataDiagnosticsDTO{}, wrapMetadataError(err)
	}
	snapshot := s.runtime.Schema()
	return OpsMetadataDiagnosticsDTO{
		RepositoryRevision: revision, SchemaHash: snapshot.SchemaHash, SnapshotVersion: snapshot.SnapshotVersion,
		TemplateVersion: snapshot.TemplateVersion, ObjectCount: len(snapshot.Objects), ActionCount: len(snapshot.Actions),
		Compatible: strings.TrimSpace(revision) != "" && strings.TrimSpace(snapshot.SchemaHash) != "",
	}, nil
}

func metadataHasExactPermission(principal identitymodel.Principal, permission string) bool {
	if !principal.Known {
		return false
	}
	for _, candidate := range principal.Role.Permissions {
		if strings.TrimSpace(candidate) == permission {
			return true
		}
	}
	return false
}

func sanitizePublishedMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	out := make(map[string]any, len(input))
	for key, value := range input {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if strings.Contains(normalized, "secret") || strings.Contains(normalized, "password") ||
			strings.Contains(normalized, "token") || strings.Contains(normalized, "sql") ||
			strings.HasPrefix(normalized, "internal_") {
			continue
		}
		switch typed := value.(type) {
		case map[string]any:
			out[key] = sanitizePublishedMap(typed)
		case []any:
			values := make([]any, 0, len(typed))
			for _, item := range typed {
				if nested, ok := item.(map[string]any); ok {
					values = append(values, sanitizePublishedMap(nested))
				} else {
					values = append(values, item)
				}
			}
			out[key] = values
		default:
			out[key] = value
		}
	}
	return out
}
