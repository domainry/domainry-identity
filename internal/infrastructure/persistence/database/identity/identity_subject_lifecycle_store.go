package identity

import (
	"context"
	"database/sql"
	"encoding/json"

	privacy "github.com/domainry/domainry-identity/internal/domain/privacy"
	subjectpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/lifecycle/subject"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

type lifecycleSQLStore interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
	ApplyUpsert(*query.InsertBuilder, []string, ...string) *query.InsertBuilder
}

type IdentitySubjectLifecycleStore struct{ store lifecycleSQLStore }

func NewIdentitySubjectLifecycleStore(store lifecycleSQLStore) *IdentitySubjectLifecycleStore {
	return &IdentitySubjectLifecycleStore{store: store}
}

func (s *IdentitySubjectLifecycleStore) owner() *subjectpersistence.Store {
	return subjectpersistence.New(s.store)
}

func (s *IdentitySubjectLifecycleStore) Owner(ctx context.Context) string {
	return s.owner().Owner(ctx)
}

func (s *IdentitySubjectLifecycleStore) ResolveSubject(ctx context.Context, workspaceID, subjectType, subjectID string) (string, error) {
	return s.owner().ResolveSubject(ctx, workspaceID, subjectType, subjectID)
}

func (s *IdentitySubjectLifecycleStore) PreviewSubject(ctx context.Context, workspaceID, userID string) (json.RawMessage, error) {
	return s.owner().PreviewSubject(ctx, workspaceID, userID)
}

func (s *IdentitySubjectLifecycleStore) ExportSubject(ctx context.Context, workspaceID, userID string) (json.RawMessage, error) {
	return s.owner().ExportSubject(ctx, workspaceID, userID)
}

func (s *IdentitySubjectLifecycleStore) exportSubjectRelationships(ctx context.Context, workspaceID, userID string) (map[string]any, error) {
	return s.owner().ExportRelationships(ctx, workspaceID, userID)
}

func (s *IdentitySubjectLifecycleStore) EraseSubject(ctx context.Context, workspaceID, userID string, holds []privacy.LegalHold) (json.RawMessage, error) {
	return s.owner().EraseSubject(ctx, workspaceID, userID, holds)
}
