package policy

import (
	"context"
	"encoding/json"
	"openappsec.io/errors"
	"openappsec.io/log"
	"openappsec.io/smartsync-tuning/models"
	"os"
	"time"
)

const policyPath = "policy.path"

type Adapter struct {
	policyPath string
}

type Configuration interface {
	GetString(key string) (string, error)
}

func NewAdapter(conf Configuration) (*Adapter, error) {
	path, err := conf.GetString(policyPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create docker policy adapter")
	}
	return &Adapter{policyPath: path}, nil
}

func (a *Adapter) GetPolicyDetails(ctx context.Context, tenantID string, assetID string,
	policyVersion int64) (models.AssetDetails, error) {
	assets, err := a.GetPolicy(ctx, tenantID, "", policyVersion)
	if err != nil {
		return models.AssetDetails{}, errors.Wrap(err, "failed to get policy")
	}
	for _, asset := range assets {
		if asset.AssetID == assetID {
			return asset, nil
		}
	}
	return models.AssetDetails{}, errors.New("asset not found").SetClass(errors.ClassNotFound)
}

func (a *Adapter) GetPolicy(ctx context.Context, tenantID string, path string,
	_ int64) ([]models.AssetDetails, error) {
	var content models.SecurityApps
	data, err := os.ReadFile(a.policyPath)
	if err != nil {
		return []models.AssetDetails{}, errors.Wrapf(err, "failed to read policy file. path: %v", a.policyPath)
	}

	err = json.Unmarshal(data, &content)
	if err != nil {
		return []models.AssetDetails{}, errors.Wrap(err, "failed to unmarshal policy file")
	}
	log.WithContext(ctx).Infof("unmarshal result: %+v", content)
	return models.ProcessWaapPolicy(ctx, models.PolicyFile{TenantID: tenantID, Version: time.Now().Unix(), SecurityApps: content}), nil
}

func (a *Adapter) GetPolicyVersion(ctx context.Context, tenantID string, userID string) (int, error) {
	return 0, nil
}

func (a *Adapter) GetTrustedSourcesPolicy(ctx context.Context, tenantID string, assetID string,
	resourceName string) (models.TrustedSourcesPolicy, error) {
	asset, err := a.GetPolicyDetails(ctx, tenantID, assetID, 0)
	if err != nil {
		return models.TrustedSourcesPolicy{}, err
	}
	return asset.TrustedSources, nil
}
