package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	"github.com/domainry/domainry-orm/batch"
	"github.com/domainry/domainry-orm/query"
)

func (s AuthStore) GetAuthApplication(ctx context.Context, workspaceID, applicationKey string) (authmodel.AuthApplicationRegistration, bool, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return authmodel.AuthApplicationRegistration{}, false, err
	}
	applicationKey = strings.TrimSpace(applicationKey)
	if applicationKey == "" {
		return authmodel.AuthApplicationRegistration{}, false, fmt.Errorf("authentication application key is required")
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_applications", workspaceID).
		Columns("id", "workspace_id", "application_key", "redirect_urls_json", "status", "created_at", "updated_at").
		Where(query.Equal("application_key", applicationKey)).Limit(1).Build()
	if err != nil {
		return authmodel.AuthApplicationRegistration{}, false, fmt.Errorf("build authentication application lookup: %w", err)
	}
	var registration authmodel.AuthApplicationRegistration
	var redirects []byte
	var createdAt, updatedAt int64
	err = s.store.QueryIdentityRowContext(ctx, statement, arguments...).Scan(
		&registration.ID, &registration.WorkspaceID, &registration.ApplicationKey, &redirects,
		&registration.Status, &createdAt, &updatedAt,
	)
	if err == sql.ErrNoRows {
		return authmodel.AuthApplicationRegistration{}, false, nil
	}
	if err != nil {
		return authmodel.AuthApplicationRegistration{}, false, err
	}
	if err := json.Unmarshal(redirects, &registration.RedirectURLs); err != nil {
		return authmodel.AuthApplicationRegistration{}, false, fmt.Errorf("decode authentication application redirects: %w", err)
	}
	registration.CreatedAt = identitypersistence.TimeString(createdAt)
	registration.UpdatedAt = identitypersistence.TimeString(updatedAt)
	return registration, true, nil
}

func (s AuthStore) UpsertAuthApplications(ctx context.Context, workspaceID string, registrations []authmodel.AuthApplicationRegistration) error {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil || len(registrations) == 0 {
		return err
	}
	type applicationRow struct {
		id, applicationKey string
		redirects          []byte
	}
	rows := make([]applicationRow, len(registrations))
	for index, registration := range registrations {
		applicationKey := strings.TrimSpace(registration.ApplicationKey)
		if applicationKey == "" || strings.TrimSpace(registration.WorkspaceID) != workspaceID {
			return fmt.Errorf("authentication application registration does not match workspace scope")
		}
		redirects, marshalErr := json.Marshal(registration.RedirectURLs)
		if marshalErr != nil {
			return fmt.Errorf("encode authentication application redirects: %w", marshalErr)
		}
		rows[index] = applicationRow{id: authApplicationRowID(workspaceID, applicationKey), applicationKey: applicationKey, redirects: redirects}
	}
	const parametersPerRow = 7 // workspace_id plus the six explicit columns below.
	ranges, err := (batch.Parameters{Max: s.store.MaxParameters(), PerItem: parametersPerRow}).Ranges(len(rows))
	if err != nil {
		return fmt.Errorf("plan authentication application upsert batches: %w", err)
	}
	executor := interface {
		ExecContext(context.Context, string, ...any) (sql.Result, error)
	}(s.db)
	if hostExecutor := transaction.ExecutorFromContext(ctx); hostExecutor != nil {
		executor = hostExecutor
	}
	now := identitypersistence.TimeMillis(identitypersistence.NowString())
	for _, batchRange := range ranges {
		insert := query.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "_identity_applications", workspaceID).
			Columns("id", "application_key", "redirect_urls_json", "status", "created_at", "updated_at")
		for _, row := range rows[batchRange.Start:batchRange.End] {
			insert.Values(row.id, row.applicationKey, row.redirects, authmodel.AuthApplicationActive, now, now)
		}
		// Re-registration refreshes source-owned redirects while preserving the
		// administrator-owned status of an existing application.
		s.store.ApplyUpsert(insert, []string{"workspace_id", "application_key"}, "redirect_urls_json", "updated_at")
		statement, arguments, buildErr := insert.Build()
		if buildErr != nil {
			return fmt.Errorf("build authentication application batch upsert: %w", buildErr)
		}
		if _, execErr := executor.ExecContext(ctx, statement, arguments...); execErr != nil {
			return fmt.Errorf("upsert authentication application batch: %w", execErr)
		}
	}
	return nil
}

func (s AuthStore) AuthorizationRedirectRegistered(ctx context.Context, workspaceID, applicationKey, redirectURL string) (bool, error) {
	registration, found, err := s.GetAuthApplication(ctx, workspaceID, applicationKey)
	if err != nil || !found || registration.Status != authmodel.AuthApplicationActive {
		return false, err
	}
	return slices.Contains(registration.RedirectURLs, strings.TrimSpace(redirectURL)), nil
}

func authApplicationRowID(workspaceID, applicationKey string) string {
	sum := sha256.Sum256([]byte(workspaceID + "\x00" + applicationKey))
	return "application-" + hex.EncodeToString(sum[:16])
}
