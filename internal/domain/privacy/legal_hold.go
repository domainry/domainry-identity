package privacy

import "time"

// LegalHold is the narrow compliance fact supplied by the cross-domain
// privacy orchestrator when Identity evaluates a subject-erasure request.
type LegalHold struct {
	ID            string
	WorkspaceID   string
	Owner         string
	ResourceType  string
	ResourceID    string
	Reason        string
	Authority     string
	StartsAt      time.Time
	EndsAt        *time.Time
	ReviewAt      time.Time
	AuditEvidence string
}
