package models

// Field names
const (
	FieldNameAssetName            = "asset_name"
	FieldNameSeverity             = "severity"
	FieldNameCountSources         = "number_of_sources"
	FieldNameCountURLs            = "number_of_urls"
	FieldNameCountParameters      = "number_of_parameters"
	FieldNameCountAll             = "number_of_requests"
	FieldNameElapsedTime          = "elapsed_hours"
	FieldNameStartTime            = "start_time"
	FieldNameAttackTypes          = "attack_types"
	FieldNameLogIDs               = "log_ids"
	FieldNameLastHitEvent         = "lastHitEvent"
	FieldNameHitCountPerAsset     = "hitCountPerAsset"
	FieldNameHitCountPerException = "hitCountPerException"
	FieldNameURIs                 = "uris"
	FieldNameParams               = "params"
	FieldNameCountHigh            = "high_severity"
	FieldNameCountCritical        = "critical_severity"
	FieldNameTenantID             = "tenant_id"
	FieldNameAssetID              = "assetid"
	FieldNameExceptionID          = "exceptionId"
)

// GroupedData contains the grouped data returned by the query
type GroupedData interface{}

// GroupedResponse is a slice of grouped data
type GroupedResponse []GroupedData

// TenantResponse contains a map from a hash string to a grouped response data
type TenantResponse map[string]GroupedResponse

// QueryResponse contains a map from a tenant to his assets
type QueryResponse map[string]TenantResponse

// TuningQueryData contains the data extracted from the query
type TuningQueryData struct {
	AssetName       string
	Severity        string
	SourcesCount    int64
	URLsCount       int64
	ParametersCount int64
	Count           int64
	AttackTypes     []string
	LogIDs          []int64
	ExtraFieldName  string
	ExtraFieldValue string
}

// GeneralStatsData contains the data extracted from the query
type GeneralStatsData struct {
	SourcesCount  int64
	URLsCount     int64
	Count         int64
	ElapsedTime   int64
	StartupTime   int64
	TotalRequests int64
}

// SeverityStatsData contains the data extracted from the query
type SeverityStatsData struct {
	TotalRequests            int64
	HighSeverityRequests     int64
	CriticalSeverityRequests int64
}

// ExceptionsData contains exceptions data extracted from the query
type ExceptionsData struct {
	ExceptionID          string
	AssetID              string
	LastHitEvent         string
	HitCountPerAsset     int64
	HitCountPerException int64
}

//UrlsToCollapse contains list of urls to collapse
type UrlsToCollapse struct {
	Urls []string `json:"urls"`
}

//ParamsToCollapse contains list of urls to collapse
type ParamsToCollapse struct {
	Params []string `json:"params"`
}
