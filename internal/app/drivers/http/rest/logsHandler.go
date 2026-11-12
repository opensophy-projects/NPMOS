package rest

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"openappsec.io/smartsync-tuning/models"
	"openappsec.io/httputils/responses"
	"openappsec.io/log"
)

//HandleLog handle single log
func (a *AdapterStandAlone) HandleLog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log.WithContext(ctx).Debug("handling single log")
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to read body, err %v", err)
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path, "unexpected error handling reading body")
		return
	}
	var msg models.AgentMessage
	err = json.Unmarshal(reqBody, &msg)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to unmarshal %v, err: %v", string(reqBody), err)
		httpReturnError(ctx, w, http.StatusBadRequest, r.URL.Path, "Failed to unmarshal log")
		return
	}
	if msg.TenantID == "" {
		if msg.Log != nil && msg.Log.K8sClusterID != "" {
			msg.TenantID = msg.Log.K8sClusterID
			msg.Log.TenantID = msg.Log.K8sClusterID
		} else {
			msg.TenantID = "local"
		}
	}
	err = a.standaloneService.HandleLog(ctx, &msg)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to handle %v, err: %v", msg, err)
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path, "failed to process log")
		return
	}
	responses.HTTPReturn(ctx, w, http.StatusOK, nil, false)
}

//HandleLogsBulk handle bulk of logs
func (a *AdapterStandAlone) HandleLogsBulk(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log.WithContext(ctx).Debug("handling logs bulk")
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to read body, err %v", err)
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path, "unexpected error handling reading body")
		return
	}
	var bulkMsg models.Bulk
	err = json.Unmarshal(reqBody, &bulkMsg)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to unmarshal %v, err: %v", string(reqBody), err)
		httpReturnError(ctx, w, http.StatusBadRequest, r.URL.Path, "Failed to unmarshal log")
		return
	}
	if len(bulkMsg.Events) == 0 {
		log.WithContext(ctx).Errorf("failed to decode logs %v, err: %v", string(reqBody), err)
		httpReturnError(ctx, w, http.StatusBadRequest, r.URL.Path, "Failed to unmarshal log")
		return
	}
	for _, msg := range bulkMsg.Events {
		if msg.TenantID == "" {
			msg.TenantID = msg.Log.EventSource.K8sClusterID
		}
		err = a.standaloneService.HandleLog(ctx, &msg)
		if err != nil {
			log.WithContext(ctx).Errorf("failed to handle %v, err: %v", msg, err)
			httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path, "failed to process log")
			return
		}
	}
	responses.HTTPReturn(ctx, w, http.StatusOK, nil, false)
}
