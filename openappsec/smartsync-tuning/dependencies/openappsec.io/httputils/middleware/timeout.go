package middleware

import (
	"net/http"
	"time"
)

// Timeout returns a timeout handler function for the relevant router.
// When reaching the given `timeout`, the handler cancels the ctx and returns a 503 Service Unavailable status
// with the given `errMsg` body to the client.
//
// Note: The request execution doesn't stop when the context is cancelled.
// The context status should be checked when performing state-change operations (such as db operations, http requests etc.) and heavy (cancelable) calculations.
// In common libraries (such as mongo, http, etc.) there is usually already a ctx status check - no code additions needed.
func Timeout(timeout time.Duration, errMsg string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.TimeoutHandler(next, timeout, errMsg)
	}
}
