package rest

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	"openappsec.io/errors"
	"openappsec.io/httputils/responses"
	"openappsec.io/log"
)

// TenantReportService define the interface for getting the total number of requests
type TenantReportService interface {
	GetNumOfRequests(ctx context.Context, tenantID string) (int64, error)
}

type getTenantReportResponse struct {
	TotalRequests int64 `json:"httpsRequestsHandledByAppSec"`
}

// GetTenantReport get the total requests for a tenant
func (a *Adapter) GetTenantReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := chi.URLParam(r, urlParamTenantID)

	totalRequests, err := a.tenantReportSvc.GetNumOfRequests(ctx, tenantID)

	if err != nil {
		if errors.IsClass(err, errors.ClassNotFound) {
			log.WithContext(ctx).Debugf("requested tuning events for tenant: %v was not found. err: %v", tenantID, err)
			httpReturnError(ctx, w, http.StatusNotFound, r.URL.Path, "no requests found")
			return
		}
		log.WithContext(ctx).Errorf("unexpected error: %v", err)
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path, "unexpected error")
		return
	}

	resp, err := json.Marshal(getTenantReportResponse{TotalRequests: totalRequests})
	if err != nil {
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path, "unexpected error")
		return
	}
	responses.HTTPReturn(ctx, w, http.StatusOK, resp, true)
	return
}
