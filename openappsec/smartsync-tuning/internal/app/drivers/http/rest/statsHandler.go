package rest

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	"openappsec.io/smartsync-tuning/models"
	"openappsec.io/ctxutils"
	"openappsec.io/errors"
	"openappsec.io/httputils/responses"
	"openappsec.io/log"
)

const (
	urlParamTenantID = "tenantId"
	urlParamAssetID  = "assetId"
	querySchemaName  = "QueryIntel"
)

// mockgen --destination mocks/mock_tuningServiceHandler.go  --package mocks --source internal/app/drivers/http/rest/statsHandler.go --mock_names TuningService=MockTuningServiceHandler

// TuningService exposes an interface for demo service operations
type TuningService interface {
	GetStats(ctx context.Context, tenantID, assetID string) ([]byte, error)
	GetTuningEvents(ctx context.Context, tenantID, assetID string) ([]byte, error)
	GetTuningEventsReview(ctx context.Context, tenantID, assetID string) ([]byte, error)
	PostTuningEvents(ctx context.Context, tenantID, assetID string, body []byte) error
}

// mockgen -destination mocks/mock_tuningServiceHandler.go -package mocks -mock_names TuningService=MockTuningServiceHandler -source internal/app/drivers/http/rest/statsHandler.go

// TuningServiceV2 exposes an interface for demo service operations
type TuningServiceV2 interface {
	StandaloneService
	GetAll(ctx context.Context, tenantID, assetID string) ([]models.Attributes, error)
	AsyncResponse(ctx context.Context, tenantID string, attributesArray []models.Attributes) error
}

// StandaloneService handles standalone supported api
type StandaloneService interface {
	GetStats(ctx context.Context, tenantID, assetID string) ([]byte, error)
	GetTuningEvents(ctx context.Context, tenantID, assetID string) ([]byte, error)
	GetTuningEventsReview(ctx context.Context, tenantID, assetID, userID string) ([]byte, error)
	PostTuningEvents(ctx context.Context, tenantID, assetID, userID string, tuningEvents []models.TuneEvent) error
	ProcessTable(ctx context.Context, tenantData models.ProcessTenantNotification) error
	HandleLog(ctx context.Context, log *models.AgentMessage) error
	UpdatePolicy(ctx context.Context, msg models.PolicyMessageData) error
	GetLogs(ctx context.Context, asset string, tuningID string) (models.Logs, error)
}

// ErrorResponse defines a REST request error response schema
type ErrorResponse struct {
	Timestamp string `json:"timestamp"`
	Path      string `json:"path"`
	Code      string `json:"code"`
	Message   string `json:"message"`
}

func httpReturnError(ctx context.Context, w http.ResponseWriter, code int, path string, msg string) {
	b, _ := json.Marshal(ErrorResponse{
		Timestamp: time.Now().UTC().Format(log.RFC3339MillisFormat),
		Path:      path,
		Code:      strconv.Itoa(code),
		Message:   msg,
	})

	responses.HTTPReturn(ctx, w, code, b, true)
}

// GetStats handles get statistics request
func (a *Adapter) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := ctxutils.ExtractString(ctx, ctxutils.ContextKeyTenantID)
	assetID := chi.URLParam(r, urlParamAssetID)
	stats, err := a.tuningService.GetStats(ctx, tenantID, assetID)
	if err != nil {
		if errors.IsClass(err, errors.ClassNotFound) {
			log.WithContext(ctx).Infof("requested statistics for tenantID: (%s) and assetID: (%s) were not found. err %v",
				tenantID, assetID, err)
			httpReturnError(ctx, w, http.StatusNotFound, r.URL.Path, "Statistics not found")
			return
		}
		log.WithContext(ctx).Errorf("Failed to get stats: %v", err)
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path, "unexpected error")
		return
	}
	responses.HTTPReturn(ctx, w, http.StatusOK, stats, false)
	return
}

// GetTuningEvents handles get request for undecided tuning events
func (a *Adapter) GetTuningEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenant := chi.URLParam(r, urlParamTenantID)
	asset := chi.URLParam(r, urlParamAssetID)
	tuningEvents, err := a.tuningService.GetTuningEvents(ctx, tenant, asset)
	if err != nil {
		if errors.IsClass(err, errors.ClassNotFound) {
			log.WithContext(ctx).Debugf("requested tuning events for tenant: %v and asset: %v was not found. err: %v",
				tenant, asset, err)
			httpReturnError(ctx, w, http.StatusNotFound, r.URL.Path, "Tuning events not found")
			return
		}
		if errors.IsClass(err, errors.ClassUnauthorized) {
			log.WithContext(ctx).Debugf("MGMT asset for tenant: %v and asset: %v was not found. err: %v", tenant, asset,
				err)
			httpReturnError(ctx, w, http.StatusBadRequest, r.URL.Path, "MGMT asset not found")
			return
		}
		log.WithContext(ctx).Errorf("unexpected error: %v", err)
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path, "unexpected error")
		return
	}
	responses.HTTPReturn(ctx, w, http.StatusOK, tuningEvents, false)
	return
}

// GetTuningEventsReview handles get request for decided tuning events
func (a *Adapter) GetTuningEventsReview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenant := chi.URLParam(r, urlParamTenantID)
	asset := chi.URLParam(r, urlParamAssetID)
	tuningEvents, err := a.tuningService.GetTuningEventsReview(ctx, tenant, asset)
	if err != nil {
		if errors.IsClass(err, errors.ClassNotFound) {
			log.WithContext(ctx).Debugf("requested tuning events for tenant: %v and asset: %v was not found. err: %v",
				tenant, asset, err)
			httpReturnError(ctx, w, http.StatusNotFound, r.URL.Path, "Tuning events not found")
			return
		}
		if errors.IsClass(err, errors.ClassUnauthorized) {
			log.WithContext(ctx).Debugf("MGMT asset for tenant: %v and asset: %v was not found. err: %v", tenant, asset,
				err)
			httpReturnError(ctx, w, http.StatusBadRequest, r.URL.Path, "MGMT asset not found")
			return
		}
		log.WithContext(ctx).Errorf("unexpected error: %v", err)
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path, "unexpected error")
		return
	}
	responses.HTTPReturn(ctx, w, http.StatusOK, tuningEvents, false)
	return
}

// PostTuningEvents handles post tuning events
func (a *Adapter) PostTuningEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenant := chi.URLParam(r, urlParamTenantID)
	asset := chi.URLParam(r, urlParamAssetID)
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to read body, err %v", err)
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path, "unexpected error handling reading body")
		return
	}
	err = a.tuningService.PostTuningEvents(ctx, tenant, asset, reqBody)
	if err != nil {
		if errors.IsClass(err, errors.ClassBadInput) {
			log.WithContext(ctx).Debugf("got bad request %v, error %v", string(reqBody), err)
			httpReturnError(ctx, w, http.StatusBadRequest, r.URL.Path, http.StatusText(http.StatusBadRequest))
			return
		}
		if errors.IsClass(err, errors.ClassUnauthorized) {
			log.WithContext(ctx).Debugf("MGMT asset for tenant: %v and asset: %v was not found. err: %v", tenant, asset,
				err)
			httpReturnError(ctx, w, http.StatusBadRequest, r.URL.Path, "MGMT asset not found")
			return
		}
		log.WithContext(ctx).Errorf("internal error body %v, err %v", string(reqBody), err)
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path, "unexpected error")
		return
	}
	responses.HTTPReturn(ctx, w, http.StatusOK, nil, false)
}

////////////////////////////////////////// V2 //////////////////////////////////////////////////////////////////

// GetStatsV2 handles get statistics request
func (a *AdapterStandAlone) GetStatsV2(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := ctxutils.ExtractString(ctx, ctxutils.ContextKeyTenantID)
	assetID, err := url.QueryUnescape(chi.URLParam(r, urlParamAssetID))
	if err != nil {
		log.WithContext(ctx).Errorf("failed to unescape asset id: %v", assetID)
		httpReturnError(ctx, w, http.StatusBadRequest, r.URL.Path, http.StatusText(http.StatusBadRequest))
	}
	stats, err := a.standaloneService.GetStats(ctx, tenantID, assetID)
	if err != nil {
		if errors.IsClass(err, errors.ClassNotFound) {
			log.Infof("requested statistics for tenantID: (%s) and assetID: (%s) were not found. err %v", tenantID,
				assetID, err)
			httpReturnError(ctx, w, http.StatusNotFound, r.URL.Path, "Statistics not found")
			return
		}
		if errors.IsClass(err, errors.ClassUnauthorized) {
			log.WithContext(ctx).Debugf("MGMT asset for tenant: %v and asset: %v was not found. err: %v", tenantID,
				assetID, err)
			httpReturnError(ctx, w, http.StatusBadRequest, r.URL.Path, "MGMT asset not found")
			return
		}
		log.WithContext(ctx).Errorf("Failed to get stats: %v", err)
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path, "unexpected error")
		return
	}
	responses.HTTPReturn(ctx, w, http.StatusOK, stats, false)
	return
}

// GetTuningEventsV2 handles get request for undecided tuning events
func (a *AdapterStandAlone) GetTuningEventsV2(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenant := ctxutils.ExtractString(ctx, ctxutils.ContextKeyTenantID)
	asset, err := url.QueryUnescape(chi.URLParam(r, urlParamAssetID))
	if err != nil {
		log.WithContext(ctx).Errorf("failed to unescape asset id: %v", asset)
		httpReturnError(ctx, w, http.StatusBadRequest, r.URL.Path, http.StatusText(http.StatusBadRequest))
	}
	tuningEvents, err := a.standaloneService.GetTuningEvents(ctx, tenant, asset)
	if err != nil {
		if errors.IsClass(err, errors.ClassNotFound) {
			log.WithContext(ctx).Debugf("requested tuning events for tenant: %v and asset: %v was not found. err: %v",
				tenant, asset, err)
			httpReturnError(ctx, w, http.StatusNotFound, r.URL.Path, "Tuning events not found")
			return
		}
		if errors.IsClass(err, errors.ClassUnauthorized) {
			log.WithContext(ctx).Debugf("MGMT asset for tenant: %v and asset: %v was not found. err: %v", tenant, asset,
				err)
			httpReturnError(ctx, w, http.StatusBadRequest, r.URL.Path, "MGMT asset not found")
			return
		}
		log.WithContext(ctx).Errorf("unexpected error: %v", err)
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path, "unexpected error")
		return
	}
	responses.HTTPReturn(ctx, w, http.StatusOK, tuningEvents, false)
	return
}

// GetTuningEventsReviewV2 handles get request for decided tuning events
func (a *AdapterStandAlone) GetTuningEventsReviewV2(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenant := ctxutils.ExtractString(ctx, ctxutils.ContextKeyTenantID)
	asset, err := url.QueryUnescape(chi.URLParam(r, urlParamAssetID))
	if err != nil {
		log.WithContext(ctx).Errorf("failed to unescape asset id: %v", asset)
		httpReturnError(ctx, w, http.StatusBadRequest, r.URL.Path, http.StatusText(http.StatusBadRequest))
	}
	user := r.Header.Get("X-user-id")
	tuningEvents, err := a.standaloneService.GetTuningEventsReview(ctx, tenant, asset, user)

	if err != nil {
		if errors.IsClass(err, errors.ClassNotFound) {
			log.WithContext(ctx).Debugf("requested tuning events for tenant: %v and asset: %v was not found. err: %v",
				tenant, asset, err)
			httpReturnError(ctx, w, http.StatusNotFound, r.URL.Path, "Tuning events not found")
			return
		}
		if errors.IsClass(err, errors.ClassUnauthorized) {
			log.WithContext(ctx).Debugf("MGMT asset for tenant: %v and asset: %v was not found. err: %v", tenant, asset,
				err)
			httpReturnError(ctx, w, http.StatusBadRequest, r.URL.Path, "MGMT asset not found")
			return
		}
		log.WithContext(ctx).Errorf("unexpected error: %v", err)
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path, "unexpected error")
		return
	}
	responses.HTTPReturn(ctx, w, http.StatusOK, tuningEvents, false)
	return
}

// PostTuningEventsV2 handles post tuning events
func (a *AdapterStandAlone) PostTuningEventsV2(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenant := ctxutils.ExtractString(ctx, ctxutils.ContextKeyTenantID)
	asset, err := url.QueryUnescape(chi.URLParam(r, urlParamAssetID))
	if err != nil {
		log.WithContext(ctx).Errorf("failed to unescape asset id: %v", asset)
		httpReturnError(ctx, w, http.StatusBadRequest, r.URL.Path, http.StatusText(http.StatusBadRequest))
	}
	user := r.Header.Get("X-user-id")
	reqBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		log.WithContext(ctx).Errorf("failed to read body, err %v", err)
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path, "unexpected error handling reading body")
		return
	}

	var tuningEvents []models.TuneEvent
	err = json.Unmarshal(reqBody, &tuningEvents)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to parse request, err %v", err)
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path,
			"unexpected error handling parse request body")
		return
	}

	err = a.standaloneService.PostTuningEvents(ctx, tenant, asset, user, tuningEvents)
	if err != nil {
		if errors.IsClass(err, errors.ClassBadInput) {
			log.WithContext(ctx).Debugf("got bad request %v, error %v", string(reqBody), err)
			httpReturnError(ctx, w, http.StatusBadRequest, r.URL.Path, http.StatusText(http.StatusBadRequest))
			return
		}
		if errors.IsClass(err, errors.ClassUnauthorized) {
			log.WithContext(ctx).Debugf("MGMT asset for tenant: %v and asset: %v was not found. err: %v", tenant, asset,
				err)
			httpReturnError(ctx, w, http.StatusBadRequest, r.URL.Path, "MGMT asset not found")
			return
		}
		log.WithContext(ctx).Errorf("internal error body %v, err %v", string(reqBody), err)
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path, "unexpected error")
		return
	}
	responses.HTTPReturn(ctx, w, http.StatusOK, nil, false)
}

//GetTuningEventLogs handle get logs for a tuning event
func (a *AdapterStandAlone) GetTuningEventLogs(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	log.WithContext(ctx).Infof("get tuning events logs")
	asset, err := url.QueryUnescape(chi.URLParam(request, urlParamAssetID))
	if err != nil {
		log.WithContext(ctx).Errorf("failed to unescape asset id: %v", asset)
		httpReturnError(ctx, writer, http.StatusBadRequest, request.URL.Path, http.StatusText(http.StatusBadRequest))
		return
	}
	id := request.URL.Query().Get("id")
	if id == "" {
		httpReturnError(ctx, writer, http.StatusBadRequest, request.URL.Path, "missing tuning id parameter")
		return
	}
	logs, err := a.standaloneService.GetLogs(ctx, asset, id)
	if err != nil {
		log.WithContext(ctx).Warnf("get logs returned error: %v", err)
		if errors.IsClass(err, errors.ClassNotFound) {
			httpReturnError(ctx, writer, http.StatusNotFound, request.URL.Path, "tuning id not found")
		} else {
			httpReturnError(ctx, writer, http.StatusInternalServerError, request.URL.Path, "unexpected error")
		}
		return
	}
	writer.Header().Add("Content-Type", "text/csv")
	bodyWriter := csv.NewWriter(writer)
	bodyWriter.Write(logs.ColumnNames)
	bodyWriter.WriteAll(logs.Rows)
	responses.HTTPReturn(ctx, writer, http.StatusOK, nil, false)
}
