package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/domainry/domainry-orm/query"
)

func (s AuthStore) AuthorizationRedirectRegistered(ctx context.Context, workspaceID, applicationKey, redirectURL string) (bool, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return false, err
	}
	statement, args, buildErr := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_authorization_catalogs", workspaceID).
		Columns("catalog_json").Where(query.Equal("application_key", strings.TrimSpace(applicationKey))).Limit(1).Build()
	if buildErr != nil {
		return false, buildErr
	}
	var payload []byte
	err = s.db.QueryRowContext(ctx, statement, args...).Scan(&payload)
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
