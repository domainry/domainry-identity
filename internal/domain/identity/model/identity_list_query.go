package identitymodel

// IdentitySortRule describes a stable ordering for Identity directory pages.
type IdentitySortRule struct {
	Field     string `json:"field"`
	Direction string `json:"direction"`
}

// IdentityListQuery is the query contract shared by Identity directory,
// workforce, role, and assignment searches. It is intentionally independent
// from host business-record filtering and transaction semantics.
type IdentityListQuery struct {
	AfterID                   string             `json:"after_id,omitempty"`
	PageSize                  int                `json:"page_size"`
	Search                    string             `json:"search,omitempty"`
	SearchFields              []string           `json:"search_fields,omitempty"`
	Filters                   map[string]any     `json:"filters,omitempty"`
	Sort                      []IdentitySortRule `json:"sort,omitempty"`
	Scope                     string             `json:"-"`
	PrincipalUserID           string             `json:"-"`
	PrincipalDepartmentPath   string             `json:"-"`
	PrincipalReportingUserIDs []string           `json:"-"`
}
