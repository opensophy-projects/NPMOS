package models

import (
	"context"

	"openappsec.io/log"
)

// WaapType represents type of asset protection
type WaapType string

// defines types of assets
const (
	WaapTypeWebApp WaapType = "webApplication"
	WaapTypeWebAPI WaapType = "webApi"
)

// Identifier used to identify a source
type Identifier struct {
	Value string `json:"value"`
}

// TrustedSourcesPolicy defines the trusted sources policy
type TrustedSourcesPolicy struct {
	NumOfSources       int          `json:"minNumOfSources" validate:"required" bson:"numOfSources"`
	SourcesIdentifiers []Identifier `json:"sourcesIdentifiers" validate:"required" bson:"sourcesIdentifiers"`
}

// WaapPolicyShared defines webapi and webapp shared fields
type WaapPolicyShared struct {
	ApplicationUrls string                 `json:"applicationUrls" validate:"required"`
	AssetName       string                 `json:"assetName" validate:"required"`
	TrustedSources  []TrustedSourcesPolicy `json:"trustedSources" validate:"required"`
	AssetID         string                 `json:"assetId" validate:"required"`
	Mode            string                 `json:"webAttackMitigationMode" validate:"required"`
	Severity        string                 `json:"webAttackMitigationSeverity" validate:"required"`
}

// WaapPolicy defines waap policy
type WaapPolicy struct {
	WaapWebAppPolicy []WaapPolicyShared `json:"WebApplicationSecurity"`
	WaapWebAPIPolicy []WaapPolicyShared `json:"WebAPISecurity"`
}

// WaapApp defines waap policy
type WaapApp struct {
	WaapPolicy WaapPolicy `json:"WAAP"`
}

// SecurityApps define security apps
type SecurityApps struct {
	Waap WaapApp `json:"waap" validate:"required"`
}

// PolicyMessageData define policy msg from kafka queue
type PolicyMessageData struct {
	TenantID     string `json:"tenantId" validate:"required"`
	PolicyID     string `json:"id"`
	Version      int64  `json:"version" validate:"required"`
	DownloadPath string `json:"downloadPath" validate:"required"`
}

// PolicyFile defines policy file from s3
type PolicyFile struct {
	TenantID     string
	Version      int64
	SecurityApps SecurityApps `json:"securityApps" validate:"required"`
}

// AssetDetails define the details processed from kafka queue msg
type AssetDetails struct {
	AssetID         string
	TenantID        string
	PolicyVersion   int64
	TrustedSources  TrustedSourcesPolicy
	ApplicationUrls string
	Name            string
	Type            WaapType
	Mode            string
	Level           string
}

//ProcessWaapPolicy extracts assets in policy to assetDetails
func ProcessWaapPolicy(ctx context.Context, policy PolicyFile) []AssetDetails {
	var assetsDetails []AssetDetails

	for _, asset := range policy.SecurityApps.Waap.WaapPolicy.WaapWebAppPolicy {
		var assetDetails AssetDetails
		assetDetails.AssetID = asset.AssetID
		assetDetails.TenantID = policy.TenantID
		assetDetails.PolicyVersion = policy.Version
		assetDetails.ApplicationUrls = asset.ApplicationUrls
		assetDetails.Name = asset.AssetName
		assetDetails.Type = WaapTypeWebApp
		assetDetails.Mode = asset.Mode
		assetDetails.Level = asset.Severity
		if len(asset.TrustedSources) == 0 {
			assetDetails.TrustedSources = TrustedSourcesPolicy{
				NumOfSources:       3,
				SourcesIdentifiers: []Identifier{},
			}
			log.WithContext(ctx).Warnf("policy warning: asset does not contain trusted sources: %s", asset.AssetID)
		} else {
			assetDetails.TrustedSources = asset.TrustedSources[0]
		}
		assetsDetails = append(assetsDetails, assetDetails)
	}

	for _, asset := range policy.SecurityApps.Waap.WaapPolicy.WaapWebAPIPolicy {
		var assetDetails AssetDetails
		assetDetails.AssetID = asset.AssetID
		assetDetails.TenantID = policy.TenantID
		assetDetails.PolicyVersion = policy.Version
		assetDetails.ApplicationUrls = asset.ApplicationUrls
		assetDetails.Name = asset.AssetName
		assetDetails.Type = WaapTypeWebAPI
		assetDetails.Mode = asset.Mode
		assetDetails.Level = asset.Severity
		if len(asset.TrustedSources) == 0 {
			assetDetails.TrustedSources = TrustedSourcesPolicy{
				NumOfSources:       3,
				SourcesIdentifiers: []Identifier{},
			}
			log.WithContext(ctx).Warnf("policy warning: asset does not contain trusted sources: %s", asset.AssetID)
		} else {
			assetDetails.TrustedSources = asset.TrustedSources[0]
		}
		assetsDetails = append(assetsDetails, assetDetails)
	}

	return assetsDetails
}
