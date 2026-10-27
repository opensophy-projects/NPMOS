package rest

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	chimiddleware "github.com/go-chi/chi/middleware"
	confhandlers "openappsec.io/configuration/http/rest"
	"openappsec.io/ctxutils"
	"openappsec.io/errors/errorloader"
	healthhandlers "openappsec.io/health/http/rest"
	"openappsec.io/httputils/middleware"
	"openappsec.io/log"
)

func (a AdapterBase) newRouter(timeout time.Duration) *chi.Mux {
	router := chi.NewRouter()
	router.Use(chimiddleware.Timeout(timeout))

	return router
}

func (a AdapterBase) setRoutes(router *chi.Mux) *chi.Mux {
	router.Group(func(router chi.Router) {
		router.Route("/health", func(r chi.Router) {
			r.Get("/live", healthhandlers.LivenessHandler(a.healthSvc).ServeHTTP)
			r.Get("/ready", healthhandlers.ReadinessHandler(a.healthSvc).ServeHTTP)
		})

		router.Route("/configuration", func(r chi.Router) {
			r.Get("/", confhandlers.RetrieveEntireConfigurationHandler(a.conf).ServeHTTP)
			r.Post("/", confhandlers.AddConfigurationHandler(a.conf).ServeHTTP)
			r.Get("/{key}", confhandlers.RetrieveConfigurationHandler(a.conf).ServeHTTP)
		})
	})
	return router
}

func (a *AdapterStandAlone) setRoutes(router *chi.Mux) *chi.Mux {
	router = a.AdapterBase.setRoutes(router)
	errorBody := createErrorBody("default-error")
	router.Route("/api/v1/agents/events", func(r chi.Router) {
		r.Use(middleware.Logging(errorBody))
		r.Use(func(next http.Handler) http.Handler {
			return middleware.HeaderToContext(next, "X-Tenant-Id", ctxutils.ContextKeyTenantID, false, "")
		})
		r.Use(middleware.Tracing)
		r.Post("/", a.HandleLog)
		r.Post("/bulk", a.HandleLogsBulk)
	})
	router.Route("/api/v2", func(r chi.Router) {
		r.Use(middleware.Logging(errorBody))
		r.Use(middleware.Tracing)
		r.Use(func(next http.Handler) http.Handler {
			return middleware.HeaderToContext(next, "X-Tenant-Id", ctxutils.ContextKeyTenantID, false, "")
		})
		r.Use(middleware.CorrelationID("missing correlation ID"))
		r.Get("/assets/{assetId}/statistics", a.GetStatsV2)
		r.Get("/assets/{assetId}/tuning", a.GetTuningEventsV2)
		r.Get("/assets/{assetId}/logs", a.GetTuningEventLogs)
		r.Get("/assets/{assetId}/tuning/review", a.GetTuningEventsReviewV2)
		r.Post("/assets/{assetId}/tuning", a.PostTuningEventsV2)
		r.Post("/process-table", a.TriggerTuning)

	})
	router.Route("/api/update-policy-crd", func(r chi.Router) {
		r.Use(middleware.Logging(errorBody))
		r.Use(middleware.TenantID("missing tenant ID"))
		r.Post("/", a.UpdatePolicyByCrd)
	})
	return router
}

// newRouter returns a router including method, path, name, and handler
func (a *Adapter) setRoutes(router *chi.Mux) *chi.Mux {
	router = a.AdapterBase.setRoutes(router)
	errorBody := createErrorBody("default-error")
	router.Group(func(router chi.Router) {
		router.Route("/", func(r chi.Router) {
			r.Use(middleware.Logging(errorBody))
			r.Use(middleware.Tracing)
			r.Use(middleware.CorrelationID("missing correlation ID"))
			r.Use(middleware.TenantID("missing tenant ID"))
			r.Get("/tenants/{tenantId}/tenant-report", a.GetTenantReport)
		})
	})

	return router
}

func createErrorBody(errorName string) string {
	errorResponse, err := errorloader.GetError(context.Background(), errorName)
	if err != nil {
		log.Errorf(err.Error())
		errorBody := errorloader.NewErrorResponse("", http.StatusText(http.StatusInternalServerError))
		return (&errorBody).Error()
	}
	return errorResponse.Error()
}
