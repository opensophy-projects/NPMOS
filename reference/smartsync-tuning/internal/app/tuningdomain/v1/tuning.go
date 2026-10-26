package v1

import (
	"context"
	"net"

	"openappsec.io/log"
	"openappsec.io/smartsync-tuning/models"
)

// Configuration defines the interface to get a configuration data
type Configuration interface {
	GetString(key string) (string, error)
	GetInt(key string) (int, error)
	IsSet(key string) bool
	Get(key string) interface{}
}

// Repository defines the interface for storing and getting data
type Repository interface {
	ReportAsset(ctx context.Context, reportedType models.ReportedAssetType, tenant string, asset string, data interface{}) error
	GetAssetData(ctx context.Context, reportedType models.ReportedAssetType, tenantID string, assetID string, out interface{}) error
}

// Mgmt defines the interface for the management adapter
type Mgmt interface {
	AppendParameters(tenantID string, assetID string, tuningEvents []models.TuneEvent) error
	RemoveParameters(tenantID string, assetID string, tuningEvents []models.TuneEvent) error
	GetPolicyVersion(tenantID string) (int, error)
}

// Tuning struct
type Tuning struct {
	config Configuration
	db     Repository
	mgmt   Mgmt
}

// NewTuningService returns a new instance of a demo service.
func NewTuningService(c Configuration, db Repository, mgmt Mgmt) (*Tuning, error) {
	return &Tuning{config: c, db: db, mgmt: mgmt}, nil
}

func checkCIDRMatch(ip, cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Debugf("failed to parse cidr: %v", cidr)
		return false
	}
	return network.Contains(net.ParseIP(ip))
}

func (t *Tuning) getDecision(parameters models.TenantsOverrides, decided []models.TuneEvent, eventType string, eventValue string) string {
	for _, overrideData := range parameters.Matches[eventType] {
		paramValue := overrideData.MatchValue
		if (eventType == models.EventTypeSource && checkCIDRMatch(eventValue, paramValue)) || paramValue == eventValue {
			log.Infof("an override for %v: %v is already set to %v", eventType, eventValue, overrideData.Decision)
			return overrideData.Decision
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
