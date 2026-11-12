package middleware

import (
	"bytes"
	"io"
	"net/http"
	"time"

	"openappsec.io/ctxutils"
	"openappsec.io/httputils/responses"

	"openappsec.io/log"
)

const (
	logFieldMethod  = "method"
	logFieldPath    = "path"
	logFieldQuery   = "query"
	logFieldHeaders = "headers"
	logFieldBody    = "body"
)

// Logging returns a function which returns a handler function for the relevant router while logging its execution
func Logging(errorMsg string) func(http.Handler) http.Handler {
	return LogWithHeader(errorMsg, []string{})
}

// LogWithHeader returns a function which returns a handler function for the relevant router while logging its execution
// headersKey parameter is an slice of headers keys and values
func LogWithHeader(errorMsg string, headerKeys []string) func(http.Handler) http.Handler {
	return func(inner http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ctx := r.Context()

			logFields := log.Fields{
				logFieldMethod:               r.Method,
				logFieldPath:                 r.URL.Path,
				logFieldQuery:                "?" + r.URL.RawQuery,
				ctxutils.ContextKeyEventTags: "incomingRestRequest",
			}

			headersMap := make(map[string]string)
			for _, headerKey := range headerKeys {
				header := r.Header.Get(headerKey)
				headersMap[headerKey] = header
			}
			logFields[logFieldHeaders] = headersMap

			if log.GetLevel() >= log.DebugLevel {
				var body bytes.Buffer
				if _, err := body.ReadFrom(r.Body); err != nil {
					log.WithContext(ctx).Errorf("Failed to read request body. Error: %s", err.Error())
					responses.HTTPReturn(ctx, w, http.StatusInternalServerError, []byte(errorMsg), true)
					return
				}

				if err := r.Body.Close(); err != nil {
					log.WithContext(ctx).Errorf("Failed to close request body. Error: %s", err.Error())
					responses.HTTPReturn(ctx, w, http.StatusInternalServerError, []byte(errorMsg), true)
					return
				}

				r.Body = io.NopCloser(&body)
				logFields[logFieldBody] = body.String()
			}

			log.WithContextAndFields(ctx, logFields).Infoln("new incoming request")

			inner.ServeHTTP(w, r)

			log.WithContext(ctx).Infoln("Request duration:", time.Since(start))
		})
	}
}
