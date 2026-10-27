package log

// consts for fields in the log, allowing users to set values for these fields
const (
	// general fields
	EventName         = "eventName"
	EventType         = "eventType"
	EventAudience     = "eventAudience"
	EventAudienceTeam = "eventAudienceTeam"
	EventFrequency    = "eventFrequency"
	EventSeverity     = "eventSeverity"
	EventPriority     = "eventPriority"

	// source fields
	FogID           = "fogId"
	FogType         = "fogType"
	EventTraceID    = "eventTraceId"
	TenantID        = "tenantId"
	AgentID         = "agentId"
	EventSpanID     = "eventSpanId"
	CodeLabel       = "codeLabel"
	IssuingFunction = "issuingFunction"
	IssuingFile     = "issuingFile"
	IssuingLine     = "issuingLine"
	EventID         = "eventId"
	CallingService  = "callingService"

	// message data fields
	StateKey = "stateKey"

	// labels
	EventTags = "eventTags"

	// event severity
	// EventSeverityInfo is the default value of event severity
	EventSeverityInfo     = "Info"
	EventSeverityCritical = "Critical"
	EventSeverityHigh     = "High"

	// event priority
	// EventPriorityMedium is the default value of event priority
	EventPriorityMedium = "Medium"
)

// KnownStringFields are all the string type fields that a user can configure in a log
// via the "WithContext" or "WithContextAndFields" functions
var KnownStringFields = map[string]string{
	EventName:         "",
	EventType:         "",
	EventAudience:     "",
	EventAudienceTeam: "",
	EventFrequency:    "",
	FogID:             "",
	FogType:           "",
	EventTraceID:      "",
	TenantID:          "",
	AgentID:           "",
	EventSpanID:       "",
	CodeLabel:         "",
	IssuingFunction:   "",
	IssuingFile:       "",
	IssuingLine:       "",
	StateKey:          "",
	EventSeverity:     "",
	EventPriority:     "",
	EventID:           "",
	CallingService:    "",
}

// KnownStringSliceFields are all the string slice type fields that a user can configure in a log
// via the "WithContext" or "WithContextAndFields" functions
var KnownStringSliceFields = map[string]string{
	EventTags: "",
}

// Format is the logging format
type Format struct {
	EventTime         string      `json:"eventTime"`
	EventName         string      `json:"eventName"`
	EventType         string      `json:"eventType"`
	EventAudience     string      `json:"eventAudience"`
	EventAudienceTeam string      `json:"eventAudienceTeam"`
	EventFrequency    string      `json:"eventFrequency"`
	EventLogLevel     string      `json:"eventLogLevel"`
	EventSource       EventSource `json:"eventSource"`
	EventData         EventData   `json:"eventData"`
	EventTags         []string    `json:"eventTags"`
	EventPriority     string      `json:"eventPriority"`
	EventSeverity     string      `json:"eventSeverity"`
}

// EventSource is the event source data
type EventSource struct {
	FogID           string `json:"fogId"`
	FogType         string `json:"fogType"`
	EventTraceID    string `json:"eventTraceId"`
	TenantID        string `json:"tenantId"`
	AgentID         string `json:"agentId"`
	EventSpanID     string `json:"eventSpanId"`
	CodeLabel       string `json:"codeLabel"`
	IssuingFunction string `json:"issuingFunction"`
	IssuingFile     string `json:"issuingFile"`
	IssuingLine     string `json:"issuingLine"`
	EventID         string `json:"eventId"`
	CallingService  string `json:"callingService"`
}

// EventData is the event data data
type EventData struct {
	StateKey     string                 `json:"stateKey"`
	EventMessage string                 `json:"eventMessage"`
	MessageData  map[string]interface{} `json:"messageData"`
}
