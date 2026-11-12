package sharedstorage

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"openappsec.io/errors"
	"openappsec.io/httputils/client"
	"openappsec.io/log"
	"openappsec.io/smartsync-tuning/models"
)

const (
	traceClientTimeout = 2 * time.Minute

	//conf Key Reverse Proxy
	sharedStorageKey     = "shared_storage"
	sharedStorageHostKey = sharedStorageKey + ".host"
)

// Configuration exposes an interface of configuration related actions
type Configuration interface {
	GetString(key string) (string, error)
}

// Adapter utilizes shared-storage service for doc like db
type Adapter struct {
	client *http.Client
	host   string
}

// NewAdapter create new shared-storage adapter
func NewAdapter(conf Configuration) (*Adapter, error) {
	a := &Adapter{}
	err := a.initialize(conf)
	if err != nil {
		return &Adapter{}, errors.Wrap(err, "failed to initialize shared storage adapter")
	}
	return a, nil
}

// initialize the adapter
func (a *Adapter) initialize(conf Configuration) error {
	host, err := conf.GetString(sharedStorageHostKey)
	if err != nil {
		return errors.Wrapf(err, "failed to get shared storage host from %v", sharedStorageHostKey)
	}
	baseURL := fmt.Sprintf("http://%s/api", host)
	if _, err = url.Parse(baseURL); err != nil {
		return errors.Wrapf(err, "failed to parse url: %v", baseURL)
	}
	a.host = baseURL

	a.client = client.NewTracerClient(traceClientTimeout)

	return nil
}

// ReportAsset push data of type reportedType of an asset
func (a *Adapter) ReportAsset(
	ctx context.Context,
	reportedType models.ReportedAssetType,
	tenant string,
	asset string,
	data interface{}) error {
	log.WithContext(ctx).Debugf("report data for tenant: %v, asset: %v, type: %v, data: %+v", tenant, asset,
		reportedType, data)
	var bodyReader io.Reader
	if reportedType == models.ReportAll {
		log.WithContext(ctx).Debugf("new attributes: %+v", data)
		body, err := json.Marshal(data)
		if err != nil {
			return errors.Wrap(err, "failed to marshal data")
		}
		bodyReader = bytes.NewReader(body)
	} else {
		var attr models.Attributes
		err := a.GetAssetData(ctx, models.ReportAll, tenant, asset, &attr)
		if err != nil && !errors.IsClass(err, errors.ClassNotFound) {
			return errors.Wrapf(err, "failed to get current asset data")
		}
		attr, err = updateAttributes(attr, reportedType, data)
		if err != nil {
			return errors.Wrap(err, "failed to update attributes")
		}
		log.WithContext(ctx).Debugf("new attributes: %+v", attr)
		body, err := json.Marshal(attr)
		if err != nil {
			return errors.Wrap(err, "failed to marshal updated attributes")
		}
		bodyReader = bytes.NewReader(body)
	}
	assetHash := genAssetHash(asset)
	req, err := http.NewRequest(http.MethodPut, a.host+"/svc/"+assetHash+"/attributes.data",
		bodyReader)
	if err != nil {
		return err
	}
	if tenant == "" {
		log.Warn("missing tenant id using fake")
		tenant = "tenant"
	}
	req.Header.Add("X-Tenant-Id", tenant)
	_, err = a.client.Do(req)

	log.WithContext(ctx).Debugf("request return err: %v", err)

	return err
}

func updateAttributes(attr models.Attributes, reportedType models.ReportedAssetType,
	data interface{}) (models.Attributes, error) {
	switch reportedType {
	case models.ReportStatistics:
		stats, ok := data.(models.Statistics)
		if !ok {
			return attr, errors.Errorf("cast to %T from %T failed", models.Statistics{}, data)
		}
		attr.Statistics = stats
	case models.ReportCertificateInstallationStatus:
		cert, ok := data.(models.CertInstallStatus)
		if !ok {
			return attr, errors.Errorf("failed to convert data %+v to CertInstallStatus", data)
		}
		if attr.CertInstallStatus == nil {
			attr.CertInstallStatus = map[string]models.CertInstallStatus{}
		}
		if cert.URL == "" {
			attr.CertInstallStatus = map[string]models.CertInstallStatus{}
		} else if _, ok := attr.CertInstallStatus[""]; ok {
			delete(attr.CertInstallStatus, "")
		}
		attr.CertInstallStatus[cert.URL] = cert
	case models.ReportUpstreamHealthcheckStatus:
		health, ok := data.(models.UpstreamHealthcheck)
		if !ok {
			return attr, errors.Errorf("failed to convert data %+v to UpstreamHealthcheck", data)
		}
		if attr.UpstreamStatus == nil {
			attr.UpstreamStatus = map[string]models.UpstreamHealthcheck{}
		}
		attr.UpstreamStatus[health.Agent] = health
	case models.ReportTuning:
		tuneEvents, ok := data.([]models.TuneEvent)
		if !ok {
			return attr, errors.Errorf("failed to convert data %+v to tuning events", data)
		}
		attr.TuningEvents = tuneEvents
	case models.ReportTuningDecided:
		tuneEvents, ok := data.([]models.TuneEvent)
		if !ok {
			return attr, errors.Errorf("failed to convert data %+v to tuning events", data)
		}
		attr.TuningEventsDecided = tuneEvents
	case models.ReportTrustedSourcesPolicy:
		trustedSources, ok := data.(models.TrustedSourcesPolicy)
		if !ok {
			return attr, errors.Errorf("failed to convert data %+v to trusted sources policy", data)
		}
		attr.TrustedSourcesPolicy = trustedSources
	case models.ReportAssetExceptions:
		exceptions, ok := data.(models.AssetExceptions)
		if !ok {
			return attr, errors.Errorf("failed to convert data %+v to asset exceptions", data)
		}
		attr.AssetExceptions = exceptions
	case models.ReportAssetPolicyData:
		details, ok := data.(models.AssetDetails)
		if !ok {
			return attr, errors.Errorf("failed to convert data %+v to trusted sources policy", data)
		}
		attr.TrustedSourcesPolicy = details.TrustedSources
		attr.Name = details.Name
		attr.ApplicationUrls = details.ApplicationUrls
		attr.Statistics.MitigationMode = details.Mode
		attr.Statistics.MitigationLevel = details.Level
		attr.MgmtID = details.AssetID
		attr.PolicyVersion = details.PolicyVersion
	case models.ReportAll:
		conv, ok := data.(models.Attributes)
		if !ok {
			return attr, errors.Errorf("failed to convert data %+v to tuning attributes", data)
		}
		attr = conv
	default:
		return attr, errors.Errorf("report type %v not supported", reportedType)
	}
	return attr, nil
}

func genAssetHash(assetID string) string {
	assetHash := sha1.Sum([]byte(assetID))
	return fmt.Sprintf("%x", assetHash)
}

// GetAssetData get data of type reportedType of an asset
func (a *Adapter) GetAssetData(ctx context.Context, reportedType models.ReportedAssetType, tenantID string,
	assetID string, out interface{}) error {
	filePath := genFilePath(tenantID, assetID)
	log.WithContext(ctx).Debugf("get data for tenant: %v, asset: %v, type: %v. path: %v", tenantID, assetID,
		reportedType, filePath)

	attr, err := a.getFile(tenantID, filePath)
	if err != nil {
		return errors.Wrapf(err, "failed to get file: %v", filePath)
	}

	log.WithContext(ctx).Debugf("loaded attributes successfully, attr: %+v", attr)

	var result interface{}

	if ptr, ok := out.(*interface{}); ok {
		err = setOutArgFromAttributes(reportedType, &attr, &result)
		if err != nil {
			return errors.Wrap(err, "failed to set output arg")
		}
		*ptr = result
		return nil
	}
	switch reportedType {
	case models.ReportAll:
		if attrOut, ok := out.(*models.Attributes); ok {
			*attrOut = attr
			return nil
		}
		return errors.Errorf("out type mismatch, got %T expect %T", out, &models.Attributes{})
	case models.ReportStatistics:
		if stats, ok := out.(*models.Statistics); ok {
			*stats = attr.Statistics
			return nil
		}
		return errors.Errorf("out type mismatch, got %T expect %T", out, &models.Statistics{})
	case models.ReportTuningDecided:
		events, ok := out.(*[]models.TuneEvent)
		if !ok {
			return errors.Errorf("out type mismatch, got %T expect %T", out, &[]models.TuneEvent{})
		}
		if attr.TuningEventsDecided == nil {
			*events = []models.TuneEvent{}
			return nil
		}
		*events = attr.TuningEventsDecided
		return nil
	case models.ReportTuning:
		events, ok := out.(*[]models.TuneEvent)
		if !ok {
			return errors.Errorf("out type mismatch, got %T expect %T", out, &[]models.TuneEvent{})
		}
		if attr.TuningEvents == nil {
			*events = []models.TuneEvent{}
			return nil
		}
		*events = attr.TuningEvents
		return nil
	default:
		return errors.Errorf("unsupported report type %v with data type %T", reportedType, out)
	}
}

func genFilePath(_ string, assetID string) string {
	assetHash := genAssetHash(assetID)
	filePath := fmt.Sprintf("/svc/%v/attributes.data", assetHash)
	return filePath
}

func (a *Adapter) getFile(tenantID string, filepath string) (models.Attributes, error) {
	if filepath[0] != '/' {
		filepath = "/" + filepath
	}
	req, err := http.NewRequest(http.MethodGet, a.host+filepath,
		nil)
	if err != nil {
		return models.Attributes{}, errors.Wrap(err, "failed to create new request")
	}
	if tenantID == "" {
		log.Warn("missing tenant id using fake")
		tenantID = "tenant"
	}
	req.Header.Add("X-Tenant-Id", tenantID)
	res, err := a.client.Do(req)
	if err != nil {
		return models.Attributes{}, errors.Wrapf(err, "failed to send request")
	}
	if res.StatusCode != http.StatusOK {
		err := errors.Errorf("request for file: %v returned status: %v",
			filepath, res.Status)
		if res.StatusCode == http.StatusNotFound {
			err.SetClass(errors.ClassNotFound)
		}
		return models.Attributes{}, err
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return models.Attributes{}, errors.Wrap(err, "failed to read response body")
	}
	var attr models.Attributes
	err = json.Unmarshal(body, &attr)
	if err != nil {
		return models.Attributes{}, errors.Wrap(err, "failed to unmarshall response")
	}
	return attr, nil
}

func setOutArgFromAttributes(reportedType models.ReportedAssetType, attr *models.Attributes, out *interface{}) error {
	switch reportedType {
	case models.ReportStatistics:
		*out = &attr.Statistics
		return nil
	case models.ReportTuningDecided:
		if attr.TuningEventsDecided == nil {
			*out = &[]models.TuneEvent{}
			return nil
		}
		*out = &attr.TuningEventsDecided
		return nil
	case models.ReportTuning:
		if attr.TuningEvents == nil {
			*out = &[]models.TuneEvent{}
			return nil
		}
		*out = &attr.TuningEvents
		return nil
	case models.ReportTrustedSourcesPolicy:
		*out = &attr.TrustedSourcesPolicy
		return nil
	case models.ReportAssetExceptions:
		*out = &attr.AssetExceptions
		return nil
	case models.ReportAll:
		*out = attr
		return nil
	}

	return errors.Errorf("unrecognized response report type: %v", reportedType)
}

type contents struct {
	ETag         string `xml:"ETag"`
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	Size         string `xml:"Size"`
}

type listBucketResult struct {
	XMLName  xml.Name   `xml:"ListBucketResult"`
	Contents []contents `xml:"Contents"`
	Prefix   string     `xml:"Prefix"`
	MaxKeys  string     `xml:"MaxKeys"`
	KeyCount string     `xml:"KeyCount"`
}

func extractFilesList(body []byte) ([]string, error) {
	var listRes listBucketResult
	err := xml.Unmarshal(body, &listRes)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, content := range listRes.Contents {
		ids = append(ids, content.Key)
	}
	return ids, nil
}

// GetAllAssetsData not supported
func (a *Adapter) GetAllAssetsData(ctx context.Context, tenantID string) ([]models.Attributes, error) {
	req, err := http.NewRequest(http.MethodGet, a.host+"/?list-type=2&prefix=svc/",
		nil)
	if err != nil {
		return []models.Attributes{}, errors.Wrap(err, "failed to create new request")
	}
	req.Header.Add("X-Tenant-Id", tenantID)
	res, err := a.client.Do(req)
	if err != nil {
		return []models.Attributes{}, errors.Wrapf(err, "failed to send request")
	}
	if res.StatusCode != http.StatusOK {
		return []models.Attributes{}, errors.Errorf("files not found").SetClass(errors.ClassNotFound)
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return []models.Attributes{}, errors.Wrap(err, "failed to read response body")
	}

	files, err := extractFilesList(body)
	if err != nil {
		return []models.Attributes{}, errors.Wrapf(err, "failed to extract files from response: %v", string(body))
	}

	attributes := make([]models.Attributes, len(files))
	for i, file := range files {
		attributes[i], err = a.getFile(tenantID, file)
		if err != nil {
			return []models.Attributes{}, errors.Wrapf(err, "failed to get file %v", file)
		}
	}

	return attributes, nil
}

func isAssetContained(assetID string, assets []models.AssetDetails) bool {
	for _, asset := range assets {
		if asset.AssetID == assetID {
			return true
		}
	}
	return false
}

// PruneAssets not supported
func (a *Adapter) PruneAssets(ctx context.Context, assets []models.AssetDetails, _ int64) error {
	log.WithContext(ctx).Debugf("pruning assets")
	if len(assets) == 0 {
		return errors.Errorf("missing assets")
	}
	tenantID := assets[0].TenantID
	currentAssets, err := a.GetAllAssetsData(ctx, tenantID)
	if err != nil {
		return errors.Wrapf(err, "failed to get all assets of tenant: %v", tenantID)
	}
	for _, asset := range currentAssets {
		if !isAssetContained(asset.MgmtID, assets) {
			filepath := genFilePath(tenantID, asset.MgmtID)
			err = a.deleteFile(ctx, tenantID, filepath)
			if err != nil {
				return errors.Wrapf(err, "failed to delete asset: %v", asset.MgmtID)
			}
		}
	}
	return nil
}

// DeleteAllAssetsOfTenant not supported
func (*Adapter) DeleteAllAssetsOfTenant(context.Context, string) error {
	return errors.New("not supported")
}

func (a *Adapter) deleteFile(ctx context.Context, tenantID string, filepath string) error {
	log.WithContext(ctx).Debugf("delete file %v", filepath)
	req, err := http.NewRequest(http.MethodDelete, a.host+filepath,
		nil)
	if err != nil {
		return errors.Wrap(err, "failed to create new request")
	}
	req.Header.Add("X-Tenant-Id", tenantID)
	res, err := a.client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "failed to send request")
	}
	log.WithContext(ctx).Infof("delete file %v returned: %v", filepath, res.Status)
	if res.StatusCode != http.StatusOK {
		return errors.Errorf("file: %v not found").SetClass(errors.ClassNotFound)
	}
	return nil
}
