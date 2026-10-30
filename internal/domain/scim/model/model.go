package scimmodel

const (
	SchemaUser           = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup          = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaEnterpriseUser = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	SchemaListResponse   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaPatch          = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaError          = "urn:ietf:params:scim:api:messages:2.0:Error"
)

type Meta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created"`
	LastModified string `json:"lastModified"`
	Version      string `json:"version"`
	Location     string `json:"location"`
}

type Name struct {
	Formatted       string `json:"formatted,omitempty"`
	FamilyName      string `json:"familyName,omitempty"`
	GivenName       string `json:"givenName,omitempty"`
	MiddleName      string `json:"middleName,omitempty"`
	HonorificPrefix string `json:"honorificPrefix,omitempty"`
	HonorificSuffix string `json:"honorificSuffix,omitempty"`
}

type MultiValue struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

type Manager struct {
	Value       string `json:"value,omitempty"`
	Ref         string `json:"$ref,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

type EnterpriseUser struct {
	EmployeeNumber string   `json:"employeeNumber,omitempty"`
	Department     string   `json:"department,omitempty"`
	Manager        *Manager `json:"manager,omitempty"`
}

type User struct {
	Schemas        []string        `json:"schemas"`
	ID             string          `json:"id,omitempty"`
	ExternalID     string          `json:"externalId,omitempty"`
	UserName       string          `json:"userName"`
	Name           Name            `json:"name,omitempty"`
	DisplayName    string          `json:"displayName,omitempty"`
	Active         *bool           `json:"active,omitempty"`
	Emails         []MultiValue    `json:"emails,omitempty"`
	PhoneNumbers   []MultiValue    `json:"phoneNumbers,omitempty"`
	PreferredLang  string          `json:"preferredLanguage,omitempty"`
	Locale         string          `json:"locale,omitempty"`
	Timezone       string          `json:"timezone,omitempty"`
	EnterpriseUser *EnterpriseUser `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
	Meta           Meta            `json:"meta,omitempty"`
}

type Member struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
}

type Group struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	DisplayName string   `json:"displayName"`
	Members     []Member `json:"members,omitempty"`
	Meta        Meta     `json:"meta,omitempty"`
}

type ListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    any      `json:"Resources"`
}

type PatchRequest struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}

type PatchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value,omitempty"`
}

type UserLink struct {
	WorkspaceID string
	UserID      string
	ExternalID  string
	UserName    string
	Department  string
	Version     int64
	CreatedAt   string
	UpdatedAt   string
	DeletedAt   string
}

type DirectoryGroup struct {
	WorkspaceID string
	GroupID     string
	ExternalID  string
	DisplayName string
	MemberIDs   []string
	Version     int64
	CreatedAt   string
	UpdatedAt   string
	DeletedAt   string
}
