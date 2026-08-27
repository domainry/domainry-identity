package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
)

func (s AuthStore) AuthorizationRedirectRegistered(ctx context.Context, workspaceID, applicationKey, redirectURL string) (bool, error) {
	var payload []byte
	err := s.db.QueryRowContext(ctx, "SELECT "+s.store.Identifier("catalog_json")+" FROM "+s.store.TableIdentifier("identity_authorization_catalogs")+" WHERE "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(1)+" AND "+s.store.Identifier("application_key")+" = "+s.store.Placeholder(2), strings.TrimSpace(workspaceID), strings.TrimSpace(applicationKey)).Scan(&payload)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	var catalog struct {
		Application struct {
			RedirectURLs []string `json:"redirect_urls"`
		} `json:"application"`
	}
	if err := json.Unmarshal(payload, &catalog); err != nil {
		return false, err
	}
	redirectURL = strings.TrimSpace(redirectURL)
	for _, candidate := range catalog.Application.RedirectURLs {
		if strings.TrimSpace(candidate) == redirectURL {
			return true, nil
		}
	}
	return false, nil
}
