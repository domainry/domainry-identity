package authmodel

const (
	AuthApplicationActive   = "active"
	AuthApplicationDisabled = "disabled"
)

// AuthApplicationRegistration is an authentication client registration.
// Authorization Actions, Permissions, and service credential secrets do not
// belong to this record.
type AuthApplicationRegistration struct {
	ID             string   `json:"id"`
	WorkspaceID    string   `json:"workspace_id"`
	ApplicationKey string   `json:"application_key"`
	RedirectURLs   []string `json:"redirect_urls"`
	Status         string   `json:"status"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
}
