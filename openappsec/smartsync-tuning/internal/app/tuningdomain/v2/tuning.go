package tuning

import (
	"context"

	"github.com/google/uuid"

	"openappsec.io/smartsync-tuning/models"
	"openappsec.io/log"
)

const (
	confKeyTuningBase        = "tuning"
	confKeyTuningTenantsList = "TENANTS_LIST"

	confKeyTuningThreshold      = confKeyTuningBase + ".threshold"
	confKeyTuningThresholdCount = confKeyTuningThreshold + ".minEventsCount"
	confKeyTuningThresholdRatio = confKeyTuningThreshold + ".minRatio"

	confKeyElpisLogsTenant = "ELPIS_LOGS_TENANT"
)

// mockgen -destination mocks/mock_queryTuningServiceV2.go -package mocks -source=./internal/app/tuningdomain/v2/tuning.go

// LogRepositoryAdapter defines the interface to query all the dataset tables
type LogRepositoryAdapter interface {
	GeneralLogQuery(ctx context.Context, tableName string) (models.QueryResponse, error)
	SeverityLogQuery(ctx context.Context, tableName string) (models.QueryResponse, error)
	TuneLogQuery(ctx context.Context, tableName string) (models.QueryResponse, error)
	ExceptionsLogQuery(ctx context.Context, tableName string) (models.QueryResponse, error)
	GenerateLogQuery(data models.TuneEvent, assetName string) string
	GetUrlsToCollapse(ctx context.Context, tenants []string) (models.QueryResponse, error)
	GetParamsToCollapse(ctx context.Context, tenants []string) (models.QueryResponse, error)
	InsertLog(ctx context.Context, message *models.AgentMessage) error
	GetTuningLogs(ctx context.Context, asset string, event models.TuneEvent) (models.Logs, error)
}

// Configuration defines the interface to get a configuration data
type Configuration interface {
	GetString(key string) (string, error)
	GetInt(key string) (int, error)
	IsSet(key string) bool
	Get(key string) interface{}
}

// RepositoryV2 defines the interface for storing and getting data
// mockgen -destination mocks/mock_repositoryV2.go -package mocks -mock_names RepositoryV2=MockRepositoryV2 openappsec.io/smartsync-tuning/internal/app/tuningdomain/v2 RepositoryV2
type RepositoryV2 interface {
	ReportAsset(ctx context.Context, reportedType models.ReportedAssetType, tenant string, asset string, data interface{}) error
	GetAssetData(ctx context.Context, reportedType models.ReportedAssetType, tenantID string, assetID string, out interface{}) error
	GetAllAssetsData(ctx context.Context, tenantID string) ([]models.Attributes, error)
	PruneAssets(ctx context.Context, assets []models.AssetDetails, policyVersion int64) error
	DeleteAllAssetsOfTenant(ctx context.Context, tenantID string) error
}

//CacheRepository defines the interface for cache repository
type CacheRepository interface {
	Invalidate(ctx context.Context, tenantID string, attr models.Attributes)
	InitTenantInvalidation(ctx context.Context, tenantID string) error
}

// S3Repo defines the interface for s3 adapter
type S3Repo interface {
	GetDecisions(ctx context.Context, tenantID string, assetID string) (models.Decisions, error)
	AppendDecisions(ctx context.Context, tenantID string, assetID string, decisions []models.TuneEvent) error
	RemoveDecisions(ctx context.Context, tenantID string, assetID string, decisions []models.TuneEvent) error
	PostDecisions(ctx context.Context, tenantID string, assetID string, decisions models.Decisions) error
	GetConfidenceFile(tenant string, asset string) (models.ConfidenceData, error)
	PostPatterns(ctx context.Context, tenantID string, assetID string, patterns models.Tokens) error
	GetPatterns(ctx context.Context, tenantID string, assetID string) (models.Tokens, error)
}

// PolicyFetch defines the interface for s3 adapter to get policy file
type PolicyFetch interface {
	GetPolicyDetails(ctx context.Context, tenantID string, assetID string, policyVersion int64) (models.AssetDetails, error)
	GetPolicy(ctx context.Context, tenantID string, path string, policyVersion int64) ([]models.AssetDetails, error)
}

//mockgen -destination mocks/mock_queryTuningServiceV2.go -package mocks -mock_names PolicyDetails=MockPolicyDetails -source internal/app/tuningdomain/v2/tuning.go

// PolicyDetails defines the interface for the policyDetails adapter
type PolicyDetails interface {
	GetPolicyVersion(ctx context.Context, tenantID string, userID string) (int, error)
	GetTrustedSourcesPolicy(ctx context.Context, tenantID string, assetID string, resourceName string) (models.TrustedSourcesPolicy, error)
}

// MultiplePodsLock defines a distributed lock
type MultiplePodsLock interface {
	LockTenant(ctx context.Context, tenantID string) bool
	UnlockTenant(ctx context.Context, tenantID string) error
	BlockingLockTenant(ctx context.Context, tenantID string) error
}

// StandAlone contains operations supported in standalone mode
type StandAlone struct {
	lr            LogRepositoryAdapter
	config        Configuration
	db            RepositoryV2
	policyDetails PolicyDetails
	policyFetch   PolicyFetch
	s3            S3Repo
	uuid          string
}

// Tuning struct
type Tuning struct {
	StandAlone
	cdb         CacheRepository
	mpl         MultiplePodsLock
	elpisTenant string
}

//NewStandAlone returns a new instance of a standalone service.
func NewStandAlone(
	c Configuration,
	lr LogRepositoryAdapter,
	db RepositoryV2,
	policyDetails PolicyDetails,
	s3 S3Repo,
	policyFetch PolicyFetch,
) *StandAlone {
	return &StandAlone{
		lr:            lr,
		config:        c,
		db:            db,
		policyDetails: policyDetails,
		policyFetch:   policyFetch,
		s3:            s3,
		uuid:          "dummy",
	}
}

// NewTuningService returns a new instance of a tuning service.
func NewTuningService(
	c Configuration,
	qs LogRepositoryAdapter,
	db RepositoryV2,
	policyDetails PolicyDetails,
	s3 S3Repo,
	policyFetch PolicyFetch,
	lock MultiplePodsLock,
	cdb CacheRepository,
) (*Tuning, error) {
	userID, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}
	elpisTenant, err := c.GetString(confKeyElpisLogsTenant)
	if err != nil {
		log.Errorf("failed to load ELPIS tenant to ignore")
		elpisTenant = ""
	}
	return &Tuning{
		StandAlone: StandAlone{
			lr:            qs,
			config:        c,
			db:            db,
			policyDetails: policyDetails,
			policyFetch:   policyFetch,
			s3:            s3,
			uuid:          userID.String(),
		},
		cdb:         cdb,
		mpl:         lock,
		elpisTenant: elpisTenant}, nil
}

func (sa *StandAlone) getDecision(decisions models.Decisions, decided []models.TuneEvent, eventType string,
	eventValue string) string {
	for _, decision := range decisions.Decisions {
		if decision.EventType == eventType && decision.EventTitle == eventValue {
			log.Infof("a decision for %v: %v is already set to %v", eventType, eventValue, decision.Decision)
			return decision.Decision
		}
	}
	for _, tuneEvent := range decided {
		if tuneEvent.EventType == eventType && tuneEvent.EventTitle == eventValue {
			log.Infof("a decision for %v: %v is already set to %v", eventType, eventValue, tuneEvent.Decision)
			return tuneEvent.Decision
		}
	}
	return models.DecisionUnknown
}
