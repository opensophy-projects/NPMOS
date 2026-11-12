package s3repository

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"openappsec.io/smartsync-tuning/models"

	"openappsec.io/ctxutils"
	"openappsec.io/errors"
	"openappsec.io/httputils/client"
	"openappsec.io/log"
)

const (
	// configuration keys
	fileName       = "tuning/decisions.data"
	policyFileName = "policy.json"
	policyPath     = "policies"

	traceClientTimeout = 2 * time.Minute

	//conf Key Reverse Proxy
	rp                     = "rp"
	rpBaseURL              = rp + ".baseUrl"
	rpPolicyURL            = rp + ".policyUrl"
	sharedStorageKey       = "shared_storage"
	sharedStorageHostKey   = sharedStorageKey + ".host"
	tenantIDHeader         = "x-tenant-id"
	headerKeyTraceID       = "X-Trace-Id"
	headerKeyCorrelationID = "X-Correlation-Id"

	logMaxSize = 128
)

// Configuration exposes an interface of configuration related actions
type Configuration interface {
	GetString(key string) (string, error)
}

// Adapter to intelligence DB sdk
type Adapter struct {
	conf           Configuration
	HTTPClient     *http.Client
	baseURL        string
	policyURL      string
	tuningFileName string
	policyFileName string
	policiesPath   string
}

// NewAdapter creates new adapter
func NewAdapter(c Configuration) (*Adapter, error) {
	a := &Adapter{conf: c}
	if err := a.initialize(); err != nil {
		return &Adapter{}, errors.Wrap(err, "failed to initialize S3 rp adapter")
	}
	return a, nil
}

// initialize the adapter
func (a *Adapter) initialize() error {
	baseURL, _ := a.conf.GetString(rpBaseURL)
	sharedHost, err := a.conf.GetString(sharedStorageHostKey)
	if err == nil && len(sharedHost) > 0 {
		baseURL = fmt.Sprintf("http://%s/api", sharedHost)
	}
	policyURL, err := a.conf.GetString(rpPolicyURL)
	if err != nil {
		return errors.Wrapf(err, "failed to get reverse proxy baseURL from %v", rpBaseURL)
	}
	if _, err = url.Parse(baseURL); err != nil {
		return err
	}
	a.tuningFileName = fileName
	a.policyFileName = policyFileName
	a.baseURL = baseURL
	a.policyURL = policyURL
	a.policiesPath = policyPath

	a.HTTPClient = client.NewTracerClient(traceClientTimeout)

	return nil
}

// GetPolicyDetails gets the policy details of an asset.
func (a *Adapter) GetPolicyDetails(ctx context.Context, tenantID string, assetID string, policyVersion int64) (models.AssetDetails, error) {
	log.WithContext(ctx).Debugf("get asset details from policy for asset %v", assetID)
	policyFilePath := fmt.Sprintf("%s/V%s/%s", a.policiesPath, strconv.FormatInt(policyVersion, 10), a.policyFileName)

	assetsDetails, err := a.GetPolicy(ctx, tenantID, policyFilePath, policyVersion)
	if err != nil {
		log.WithContext(ctx).Warnf("failed to get assets details for tenant: %v", tenantID)
	}

	for _, asset := range assetsDetails {
		if asset.AssetID == assetID {
			return asset, nil
		}
	}
	return models.AssetDetails{}, errors.Errorf("asset %v not found for tenant %v in asset details %+v", assetID,
		tenantID, assetsDetails)
}

// GetPolicy returns all assets details from the policy file
func (a *Adapter) GetPolicy(ctx context.Context, tenantID string, path string, policyVersion int64) ([]models.AssetDetails, error) {
	policyFilePath := fmt.Sprintf("%s/%s", a.policyURL, path)
	log.WithContext(ctx).Debugf("get asset details from policy file %v", policyFilePath)

	fileData, err := a.getFileRaw(ctx, tenantID, policyFilePath, false)
	if err != nil {
		if errors.IsClass(err, errors.ClassNotFound) {
			log.WithContext(ctx).Infof("file %v not found", policyFilePath)
			return []models.AssetDetails{}, nil
		}
		return []models.AssetDetails{}, errors.Wrapf(err, "failed to get file %v", policyFilePath)
	}

	var policy models.PolicyFile
	err = json.Unmarshal(fileData.Data, &policy)
	if err != nil {
		return []models.AssetDetails{}, errors.Wrap(err, "failed to unmarshal policy data")
	}
	policy.TenantID = tenantID
	policy.Version = policyVersion

	assetsDetails := models.ProcessWaapPolicy(ctx, policy)
	return assetsDetails, nil
}

func (a *Adapter) getFile(ctx context.Context, tenantID string, path string) ([]byte, error) {
	u, err := url.Parse(path)
	if err != nil {
		return []byte{}, err
	}
	req, err := http.NewRequest(http.MethodGet, path, nil)
	if err != nil {
		return []byte{}, errors.Wrapf(err, "failed to generate new request to get decisions from s3 bucket %v",
			u.String())
	}
	setTenantIDHeader(req, tenantID)
	req.Header.Set(headerKeyTraceID, ctxutils.ExtractString(ctx, ctxutils.ContextKeyEventTraceID))
	req.Header.Set(headerKeyCorrelationID, ctxutils.ExtractString(ctx, ctxutils.ContextKeyEventTraceID))

	resp, err := a.HTTPClient.Do(req.WithContext(ctx))
	if err != nil {
		return []byte{}, errors.Wrapf(err, "failed to get from %v", u.String())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return []byte{}, errors.Errorf("file %v not found", path).SetClass(errors.ClassNotFound)
		}
		return []byte{}, errors.Errorf("get %v failed, status: %v", u.String(), resp.Status)
	}

	resBody, bodyErr := ioutil.ReadAll(resp.Body)
	if bodyErr != nil {
		return []byte{}, errors.Errorf("read body from get file resp failed: %v", u.String(), bodyErr)
	}
	return resBody, nil
}

func setTenantIDHeader(req *http.Request, tenantID string) {
	if tenantID == "" {
		tenantID = "tenant"
	}
	req.Header.Add(tenantIDHeader, tenantID)
}

// decompressIfNeeded - decompress when not json is unreadable as plain text
func (a *Adapter) decompressIfNeeded(ctx context.Context, data []byte) ([]byte, bool, error) {
	//might be compressed
	if !json.Valid(data) {
		b := bytes.NewReader(data)
		compressor, err := gzip.NewReader(b)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to create reader, err: %v", err)
			return []byte{}, false, errors.Wrapf(err, "failed to create reader %v", string(data))
		}
		decompressed, err := ioutil.ReadAll(compressor)
		defer compressor.Close()
		if err != nil {
			log.WithContext(ctx).Warnf("failed to decompress, err: %v, is EOF: %v", err, err == io.EOF)
			return []byte{}, false, errors.Wrapf(err, "failed to decompress %v", string(data))
		}
		log.WithContext(ctx).Infof(
			"decompress ok, compression ratio %v", float64(len(decompressed))/float64(len(data)),
		)
		return decompressed, true, nil
	}
	return data, false, nil
}

func (a *Adapter) getFileRawWrapper(ctx context.Context, tenantID string, path string, replaceNaN bool) (models.S3File, error) {
	fileData, err := a.getFileRaw(ctx, tenantID, path+".plain", replaceNaN)
	if err != nil {
		fileData, err = a.getFileRaw(ctx, tenantID, path, replaceNaN)
	}
	return fileData, err
}

// getFileRaw - download file, Decrypt, return raw data and true if data was decompressed
func (a *Adapter) getFileRaw(ctx context.Context, tenantID string, path string, replaceNaN bool) (models.S3File, error) {
	resp, err := a.getFile(ctx, tenantID, path)
	if err != nil {
		return models.S3File{[]byte{}, false, false}, errors.Wrapf(err, "failed to get file %v", path)
	}
	if resp == nil || len(resp) == 0 {
		return models.S3File{[]byte{}, false, false}, errors.Errorf("got empty file: %v", path)
	}

	var isCompressed bool
	var decompressed []byte
	if replaceNaN {
		resp = bytes.Replace(resp, []byte("NaN"), []byte("-100"), -1)
	}
	decompressed, isCompressed, err = a.decompressIfNeeded(ctx, resp)

	if err == nil {
		log.WithContext(ctx).Debugf("got file: %v (compression: %v)", path, isCompressed)
	}
	return models.S3File{decompressed, isCompressed, false}, err
}

// GetDecisions returns tuning decisions for a specific tenantID and assetID from s3 repository
func (a *Adapter) GetDecisions(ctx context.Context, tenantID string, assetID string) (models.Decisions, error) {
	tuningFilePath := fmt.Sprintf("%s/%s/%s/%s", a.baseURL, tenantID, url.PathEscape(assetID), a.tuningFileName)
	fileData, err := a.getFileRawWrapper(ctx, tenantID, tuningFilePath, false)
	if err != nil {
		if errors.IsClass(err, errors.ClassNotFound) {
			log.WithContext(ctx).Infof("file %v not found", tuningFilePath)
			return models.Decisions{}, nil
		}
		return models.Decisions{}, errors.Wrapf(err, "failed to get file %v", tuningFilePath)
	}
	decisions := models.Decisions{}
	if err := json.Unmarshal(fileData.Data, &decisions); err != nil {
		return models.Decisions{}, errors.Wrapf(err, "failed to unmarshal decisions from %v", string(fileData.Data))
	}

	return decisions, nil
}

func (a *Adapter) postFileWrapper(ctx context.Context, tenantID string, path string, data interface{}) error {
	err := a.postFile(ctx, tenantID, path, true, data)
	if err == nil {
		err = a.postFile(ctx, tenantID, path+".plain", false, data)
	}
	return err
}

func (a *Adapter) postFile(ctx context.Context, tenantID string, path string, encrypt bool, data interface{}) error {
	u, err := url.Parse(path)
	if err != nil {
		return err
	}

	requestByte, _ := json.Marshal(data)

	requestReader := bytes.NewReader(requestByte)

	req, err := http.NewRequest(http.MethodPut, path, requestReader)
	if err != nil {
		return errors.Wrapf(err, "failed to generate new request to put decisions in s3 bucket %v", u.String())
	}
	setTenantIDHeader(req, tenantID)
	req.Header.Set(headerKeyTraceID, ctxutils.ExtractString(ctx, ctxutils.ContextKeyEventTraceID))
	req.Header.Set(headerKeyCorrelationID, ctxutils.ExtractString(ctx, ctxutils.ContextKeyEventTraceID))

	resp, err := a.HTTPClient.Do(req.WithContext(ctx))
	if err != nil {
		return errors.Wrapf(err, "failed to put decisions to %v", u.String())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("Put %v failed, status: %v", u.String(), resp.Status)
	}
	return nil
}

// PostDecisions add decision to s3 bucket and override file.
func (a *Adapter) PostDecisions(ctx context.Context, tenantID string, assetID string, decisions models.Decisions) error {
	tuningFilePath := fmt.Sprintf("%s/%s/%s/%s", a.baseURL, tenantID, url.PathEscape(assetID), a.tuningFileName)
	err := a.postFileWrapper(ctx, tenantID, tuningFilePath, decisions)
	return err
}

// AppendDecisions add decision to s3 bucket
func (a *Adapter) AppendDecisions(ctx context.Context, tenantID string, assetID string, decisions []models.TuneEvent) error {
	log.WithContext(ctx).Debugf("appending decisions: %+v", decisions)
	if len(decisions) == 0 {
		return nil
	}
	appliedDecisions, err := a.GetDecisions(ctx, tenantID, assetID)
	if err != nil {
		return errors.Wrap(err, "Unable to append tuning decision")
	}
	appliedDecisions.Decisions = append(appliedDecisions.Decisions, decisions...)
	errPost := a.PostDecisions(ctx, tenantID, assetID, appliedDecisions)
	if errPost != nil {
		return errors.Wrap(errPost, "Unable to append tuning decision")
	}
	return nil
}

func getDecisionIndex(decisions models.Decisions, decision models.TuneEvent) int {
	for index, desc := range decisions.Decisions {
		if (desc.EventTitle == decision.EventTitle) && (desc.EventType == decision.EventType) {
			return index
		}
	}
	return -1
}

func remove(decisions models.Decisions, index int) models.Decisions {
	decisions.Decisions = append(decisions.Decisions[:index], decisions.Decisions[index+1:]...)
	return decisions
}

// RemoveDecisions remove decision from s3 bucket
func (a *Adapter) RemoveDecisions(ctx context.Context, tenantID string, assetID string, decisions []models.TuneEvent) error {
	if len(decisions) == 0 {
		return nil
	}
	appliedDecisions, err := a.GetDecisions(ctx, tenantID, assetID)
	if err != nil {
		return errors.Wrap(err, "Unable to remove tuning decision, could not get decisions")
	}

	for _, decision := range decisions {
		index := getDecisionIndex(appliedDecisions, decision)
		if index == -1 {
			continue
		}
		appliedDecisions = remove(appliedDecisions, index)
	}

	errPost := a.PostDecisions(ctx, tenantID, assetID, appliedDecisions)
	if errPost != nil {
		return errors.Wrap(errPost, "Unable to append tuning decision, could not post decisions")
	}

	return nil
}

// GetConfidenceFile return the confidence file of a tenant's asset
func (a *Adapter) GetConfidenceFile(tenantID, assetID string) (models.ConfidenceData, error) {
	ctx := context.Background()
	path := fmt.Sprintf("%v/%v/%v/Indicators/Confidence/processed/confidence.data", a.baseURL, tenantID,
		url.PathEscape(assetID))

	fileData, err := a.getFileRawWrapper(ctx, tenantID, path, true)
	if err != nil {
		return models.ConfidenceData{}, errors.Wrap(err, "failed to get confidence data")
	}
	if len(fileData.Data) == 0 {
		return models.ConfidenceData{}, nil
	}
	var confidenceData models.ConfidenceData
	err = json.Unmarshal(fileData.Data, &confidenceData)
	if err != nil {
		if len(fileData.Data) > logMaxSize {
			fileData.Data = append(fileData.Data[:logMaxSize], []byte("...")...)
		}
		return models.ConfidenceData{}, errors.Wrapf(err, "failed to unmarshal %v", string(fileData.Data))
	}
	return confidenceData, nil
}

// PostPatterns post the patterns for the agent to read
func (a *Adapter) PostPatterns(ctx context.Context, tenantID string, assetID string, patterns models.Tokens) error {
	path := fmt.Sprintf("%v/%v/%v/Tokenizer/patterns.data", a.baseURL, tenantID, url.PathEscape(assetID))
	err := a.postFileWrapper(ctx, tenantID, path, patterns)
	return err
}

// GetPatterns get the patterns
func (a *Adapter) GetPatterns(ctx context.Context, tenantID string, assetID string) (models.Tokens, error) {
	path := fmt.Sprintf("%v/%v/%v/Tokenizer/patterns.data", a.baseURL, tenantID, url.PathEscape(assetID))
	fileData, err := a.getFileRawWrapper(ctx, tenantID, path, false)
	if err != nil {
		if errors.IsClass(err, errors.ClassNotFound) {
			return models.Tokens{URIsPatterns: [][]string{}, ParamsPatterns: [][]string{}}, nil
		}
		return models.Tokens{}, err
	}

	var patterns models.Tokens
	err = json.Unmarshal(fileData.Data, &patterns)
	if err != nil {
		return models.Tokens{}, err
	}
	return patterns, nil
}
