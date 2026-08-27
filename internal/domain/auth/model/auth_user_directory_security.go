package authmodel

type UserDirectorySecurityFact struct {
	UserID         string `json:"user_id"`
	MFAEnabled     bool   `json:"mfa_enabled"`
	ActiveSessions int    `json:"active_sessions"`
	LockedUntil    string `json:"locked_until,omitempty"`
	LastLoginAt    string `json:"last_login_at,omitempty"`
}
