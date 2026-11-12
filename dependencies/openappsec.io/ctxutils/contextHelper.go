package ctxutils

import (
	"context"
	"time"
)

type contextKey string

// const for contextKey types
const (
	ContextKeyAgentID        = "agentId"
	ContextKeyTenantID       = "tenantId"
	ContextKeyEventTraceID   = "eventTraceId"
	ContextKeyEventSpanID    = "eventSpanId"
	ContextKeyEventTags      = "eventTags"
	ContextKeySourceID       = "sourceId"
	ContextKeyProfileID      = "profileId"
	ContextKeyRequestID      = "requestId"
	ContextKeyAPIVersion     = "apiVersion"
	ContextKeyUserID         = "userId"
	ContextKeyCallingService = "callingService"
	ContextKeyEventType      = "eventType"
)

// Insert gets a key and value and adds it to the context
func Insert(ctx context.Context, key string, value interface{}) context.Context {
	return context.WithValue(ctx, contextKey(key), value)
}

// Extract returns a value for a given key within the given context
func Extract(ctx context.Context, key string) interface{} {
	return ctx.Value(contextKey(key))
}

// ExtractString returns a value for a given key within the given context
func ExtractString(ctx context.Context, key string) string {
	if val, ok := ctx.Value(contextKey(key)).(string); ok {
		return val
	}
	return ""
}

// Detach returns a context that keeps all the values of its parent context
// but detaches from the cancellation and error handling.
func Detach(ctx context.Context) context.Context { return detachedContext{ctx} }

type detachedContext struct{ parent context.Context }

func (v detachedContext) Deadline() (time.Time, bool)       { return time.Time{}, false }
func (v detachedContext) Done() <-chan struct{}             { return nil }
func (v detachedContext) Err() error                        { return nil }
func (v detachedContext) Value(key interface{}) interface{} { return v.parent.Value(key) }
