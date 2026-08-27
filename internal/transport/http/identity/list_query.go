package identity

import (
	"encoding/json"
	"net/http"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func identityListQuery(r *http.Request) identitymodel.IdentityListQuery {
	values := r.URL.Query()
	query := identitymodel.IdentityListQuery{
		Page:         intQuery(values.Get("page")),
		PageSize:     intQuery(values.Get("page_size")),
		Search:       strings.TrimSpace(values.Get("search")),
		SearchFields: identityQueryCSV(values.Get("search_fields")),
		Filters:      map[string]any{},
	}
	if encoded := strings.TrimSpace(values.Get("filters")); encoded != "" {
		_ = json.Unmarshal([]byte(encoded), &query.Filters)
	}
	for _, item := range identityQueryCSV(values.Get("sort")) {
		field, direction := item, "asc"
		if parts := strings.SplitN(item, ":", 2); len(parts) == 2 {
			field, direction = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		} else if strings.HasPrefix(field, "-") {
			field, direction = strings.TrimPrefix(field, "-"), "desc"
		}
		query.Sort = append(query.Sort, identitymodel.IdentitySortRule{Field: field, Direction: direction})
	}
	return query
}

func identityQueryCSV(value string) []string {
	result := []string{}
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}
