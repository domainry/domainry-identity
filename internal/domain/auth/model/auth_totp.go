package authmodel

const TOTPProvider = "domainry_totp"
const TOTPEnrollmentPurpose = "totp_enrollment"
const TOTPDisablePurpose = "totp_disable"

type TOTPRequest struct {
	Operation       string `json:"operation"`
	CurrentPassword string `json:"current_password,omitempty"`
	State           string `json:"state,omitempty"`
	Code            string `json:"code,omitempty"`
}

type TOTPResult struct {
	Enabled bool `json:"enabled"`

	State      string `json:"state,omitempty"`
	SetupKey   string `json:"setup_key,omitempty"`
	OTPAuthURL string `json:"otpauth_url,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

// TOTPSecret is internal encrypted factor material, never a user projection.
type TOTPSecret struct {
	Secret string `json:"secret"`
}

type TOTPFactorState struct {
	Enabled bool

	Generation string
}
