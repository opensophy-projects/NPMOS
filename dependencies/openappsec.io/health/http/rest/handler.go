package rest

import (
	"context"
	"encoding/json"
	"net/http"

	"openappsec.io/errors/errorloader"
	"openappsec.io/health"
	"openappsec.io/httputils/responses"
	"openappsec.io/log"
)

// HealthService exposes an interface of health related actions
type HealthService interface {
	Live() health.LivenessResponse
	Ready(ctx context.Context) health.ReadinessResponse
}

// LivenessHandler returns an HTTP handler for 'Liveness' REST requests
func LivenessHandler(hs HealthService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		liveness := hs.Live()
		healthCheck(w, r, liveness.Up, liveness)
	})

}

// ReadinessHandler returns an HTTP handler for 'Readiness' REST requests
func ReadinessHandler(hs HealthService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		readiness := hs.Ready(r.Context())
		healthCheck(w, r, readiness.Ready, readiness)
	})
}

func healthCheck(w http.ResponseWriter, r *http.Request, up bool, body interface{}) {
	ctx := r.Context()
	result, err := json.Marshal(body)
	if err != nil {
		log.WithContext(ctx).Errorf("health check failed. Error: %s", err.Error())
		errorResponse := errorloader.NewErrorResponse("", err.Error())
		responses.HTTPReturn(ctx, w, http.StatusInternalServerError, []byte(errorResponse.Error()), true)
		return
	}

	var status int
	if up {
		status = http.StatusOK
	} else {
		log.WithContext(ctx).Infof("Service is not healthy: %s", result)
		status = http.StatusServiceUnavailable
	}
	responses.HTTPReturn(ctx, w, status, result, false)
}
