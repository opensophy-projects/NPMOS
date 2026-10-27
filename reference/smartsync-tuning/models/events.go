package models

// FirstRequestNotification contains the required data for handling notification of first request in agent
type FirstRequestNotification struct {
	Tenant   string
	Asset    string
	Severity string
}

// CertStatus contains the status of the certification installation
type CertStatus struct {
	Tenant string
	Asset  string
	Data   CertInstallStatus
}

// UpstreamStatus contains the status of the upstream healthcheck
type UpstreamStatus struct {
	Tenant  string
	Asset   string              `json:"assetId"`
	Version string              `json:"version,omitempty"`
	Data    UpstreamHealthcheck `json:"status"`
}

// ProcessAsset defines the data in the event of assets IDs
type ProcessAsset struct {
	MgmtID         string `json:"mgmtId"`
	IntelligenceID string `json:"intelligenceId"`
}

// ProcessTenantNotification defines the IDs for a tenant and it's assets
type ProcessTenantNotification struct {
	TenantID string         `json:"tenantId"`
	Assets   []ProcessAsset `json:"assets"`
}

//RevokeAgent indicates an agent with agent id is revoked
type RevokeAgent struct {
	TenantID string
	AgentID  string
}
