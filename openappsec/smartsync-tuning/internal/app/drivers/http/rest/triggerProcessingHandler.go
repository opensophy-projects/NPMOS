package rest

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"openappsec.io/httputils/responses"

	"openappsec.io/smartsync-tuning/models"
	"openappsec.io/log"
)

// TriggerTuning handles process table offline
func (a *AdapterStandAlone) TriggerTuning(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var processTenant models.ProcessTenantNotification

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to read body, err %v", err)
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path,
			"unexpected error handling reading TuningTrigger body")
		return
	}

	err = json.Unmarshal(reqBody, &processTenant.Assets)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to Unmarshal body: %v, err %v", string(reqBody), err)
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path,
			"unexpected error handling Unmarshal TuningTrigger body")
		return
	}

	if len(processTenant.Assets) == 0 {
		log.WithContext(ctx).Errorf("missing assets in: %v", string(reqBody))
		httpReturnError(ctx, w, http.StatusBadRequest, r.URL.Path, "missing assets in request body")
		return
	}

	for i, asset := range processTenant.Assets {
		asset.MgmtID = strings.TrimSuffix(asset.MgmtID, "/")
		processTenant.Assets[i] = asset
	}

	err = a.standaloneService.ProcessTable(ctx, processTenant)
	if err != nil {
		log.Errorf("failed to process table: %v, error: %v", processTenant, err)
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path,
			"unexpected error while process table in TuningTrigger")
		return
	}
	responses.HTTPReturn(ctx, w, http.StatusOK, []byte{}, false)
}
