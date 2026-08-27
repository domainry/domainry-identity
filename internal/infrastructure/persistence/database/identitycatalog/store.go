// Package identitycatalog persists immutable SDK authorization catalogs using
// the Identity-owned database schema.
package identitycatalog

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

type Store struct {
	identity *identitypersistence.SQLIdentityStore
	db       *sql.DB
}

func NewStore(identity *identitypersistence.SQLIdentityStore) *Store {
	if identity == nil {
		return nil
	}
	return &Store{identity: identity, db: identity.DB()}
}

func (store *Store) Save(ctx context.Context, catalog identitysdk.AuthorizationCatalog, receipt identitysdk.CatalogReceipt) error {
	payload, err := json.Marshal(catalog)
	if err != nil {
		return err
	}
	applicationKey := strings.TrimSpace(string(catalog.Application.ApplicationKey))
	workspaceID := strings.TrimSpace(string(catalog.Application.WorkspaceID))
	if workspaceID == "" || applicationKey == "" {
		return &identitysdk.Error{Code: "identity.application_scope_invalid"}
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	historyID := applicationKey + ":" + string(receipt.Revision)
	var existingPayload []byte
	var existingRevision, existingSHA256, existingPublishedAt string
	historyQuery := "SELECT " + store.identity.IdentityColumns("catalog_json", "revision", "sha256", "published_at") + " FROM " + store.identity.TableIdentifier("identity_authorization_catalog_revisions") + " WHERE " + store.identity.Identifier("workspace_id") + " = " + store.identity.Placeholder(1) + " AND " + store.identity.Identifier("id") + " = " + store.identity.Placeholder(2)
	historyErr := tx.QueryRowContext(ctx, historyQuery, workspaceID, historyID).Scan(&existingPayload, &existingRevision, &existingSHA256, &existingPublishedAt)
	switch {
	case historyErr == sql.ErrNoRows:
		if _, err := tx.ExecContext(ctx, "INSERT INTO "+store.identity.TableIdentifier("identity_authorization_catalog_revisions")+" ("+store.identity.IdentityColumns("id", "workspace_id", "application_key", "catalog_json", "revision", "sha256", "published_at", "created_at")+") VALUES ("+store.identity.Placeholders(8)+")", historyID, workspaceID, applicationKey, payload, string(receipt.Revision), receipt.SHA256, receipt.PublishedAt, receipt.PublishedAt); err != nil {
			return err
		}
	case historyErr != nil:
		return historyErr
	case !bytes.Equal(existingPayload, payload) || existingRevision != string(receipt.Revision) || existingSHA256 != receipt.SHA256 || existingPublishedAt != receipt.PublishedAt:
		return &identitysdk.Error{Code: "identity.catalog_revision_immutable_conflict"}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM "+store.identity.TableIdentifier("identity_authorization_catalogs")+" WHERE "+store.identity.Identifier("workspace_id")+" = "+store.identity.Placeholder(1)+" AND "+store.identity.Identifier("application_key")+" = "+store.identity.Placeholder(2), workspaceID, applicationKey); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO "+store.identity.TableIdentifier("identity_authorization_catalogs")+" ("+store.identity.IdentityColumns("application_key", "workspace_id", "catalog_json", "revision", "sha256", "published_at", "updated_at")+") VALUES ("+store.identity.Placeholders(7)+")", applicationKey, workspaceID, payload, string(receipt.Revision), receipt.SHA256, receipt.PublishedAt, receipt.PublishedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) Load(ctx context.Context, application identitysdk.ApplicationRef) (identitysdk.AuthorizationCatalog, identitysdk.CatalogReceipt, bool, error) {
	workspaceID := strings.TrimSpace(string(application.WorkspaceID))
	applicationKey := strings.TrimSpace(string(application.ApplicationKey))
	if workspaceID == "" || applicationKey == "" {
		return identitysdk.AuthorizationCatalog{}, identitysdk.CatalogReceipt{}, false, &identitysdk.Error{Code: "identity.application_scope_invalid"}
	}
	row := store.db.QueryRowContext(ctx, "SELECT "+store.identity.IdentityColumns("catalog_json", "revision", "sha256", "published_at")+" FROM "+store.identity.TableIdentifier("identity_authorization_catalogs")+" WHERE "+store.identity.Identifier("workspace_id")+" = "+store.identity.Placeholder(1)+" AND "+store.identity.Identifier("application_key")+" = "+store.identity.Placeholder(2), workspaceID, applicationKey)
	var payload []byte
	var revision, sha256Value, publishedAt string
	if err := row.Scan(&payload, &revision, &sha256Value, &publishedAt); err != nil {
		if err == sql.ErrNoRows {
			return identitysdk.AuthorizationCatalog{}, identitysdk.CatalogReceipt{}, false, nil
		}
		return identitysdk.AuthorizationCatalog{}, identitysdk.CatalogReceipt{}, false, err
	}
	var catalog identitysdk.AuthorizationCatalog
	if err := json.Unmarshal(payload, &catalog); err != nil {
		return identitysdk.AuthorizationCatalog{}, identitysdk.CatalogReceipt{}, false, err
	}
	receipt := identitysdk.CatalogReceipt{Revision: identitysdk.CatalogRevision(revision), SHA256: sha256Value, PublishedAt: publishedAt}
	return catalog, receipt, true, nil
}

func (store *Store) LoadRevision(ctx context.Context, application identitysdk.ApplicationRef, revision identitysdk.CatalogRevision) (identitysdk.AuthorizationCatalog, identitysdk.CatalogReceipt, bool, error) {
	workspaceID := strings.TrimSpace(string(application.WorkspaceID))
	applicationKey := strings.TrimSpace(string(application.ApplicationKey))
	if workspaceID == "" || applicationKey == "" || !revision.Valid() {
		return identitysdk.AuthorizationCatalog{}, identitysdk.CatalogReceipt{}, false, &identitysdk.Error{Code: "identity.application_scope_invalid"}
	}
	row := store.db.QueryRowContext(ctx, "SELECT "+store.identity.IdentityColumns("catalog_json", "sha256", "published_at")+" FROM "+store.identity.TableIdentifier("identity_authorization_catalog_revisions")+" WHERE "+store.identity.Identifier("workspace_id")+" = "+store.identity.Placeholder(1)+" AND "+store.identity.Identifier("application_key")+" = "+store.identity.Placeholder(2)+" AND "+store.identity.Identifier("revision")+" = "+store.identity.Placeholder(3), workspaceID, applicationKey, string(revision))
	var payload []byte
	var sha256Value, publishedAt string
	if err := row.Scan(&payload, &sha256Value, &publishedAt); err != nil {
		if err == sql.ErrNoRows {
			return identitysdk.AuthorizationCatalog{}, identitysdk.CatalogReceipt{}, false, nil
		}
		return identitysdk.AuthorizationCatalog{}, identitysdk.CatalogReceipt{}, false, err
	}
	var catalog identitysdk.AuthorizationCatalog
	if err := json.Unmarshal(payload, &catalog); err != nil {
		return identitysdk.AuthorizationCatalog{}, identitysdk.CatalogReceipt{}, false, err
	}
	receipt := identitysdk.CatalogReceipt{Revision: revision, SHA256: sha256Value, PublishedAt: publishedAt}
	return catalog, receipt, true, nil
}
