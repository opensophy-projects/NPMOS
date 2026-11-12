package models

// AgentMessage defines agent's single log
type AgentMessage struct {
	CorrelationID string  `json:"correlation-id,omitempty"`
	SourceID      string  `json:"agent-id,omitempty"`
	RequestID     string  `json:"request-id,omitempty"`
	Log           *LogMsg `json:"log,omitempty"`
	AgentLog      *LogMsg `json:"agentLog,omitempty"` // todo - remove this when new consumer is ready
	TenantID      string  `json:"tenantId"`
	ID            int     `json:"id,omitempty"`
}

// Bulk defines an array of logs
type Bulk struct {
	Events []AgentMessage `json:"logs"`
}

// LogMsg defines agent's log schema
type LogMsg struct {
	EventTime         string `json:"eventTime,omitempty"`
	EventName         string `json:"eventName,omitempty"`
	EventSeverity     string `json:"eventSeverity,omitempty"`
	EventPriority     string `json:"eventPriority,omitempty"`
	EventLogLevel     string `json:"eventLogLevel,omitempty"`
	EventType         string `json:"eventType,omitempty"`
	EventLevel        string `json:"eventLevel,omitempty"`
	EventAudience     string `json:"eventAudience,omitempty"`
	EventAudienceTeam string `json:"eventAudienceTeam,omitempty"`
	EventFrequency    *int   `json:"eventFrequency,omitempty"`
	EventSource       `json:"eventSource,omitempty"`
	EventData         `json:"eventData,omitempty"`
	EventTags         []string `json:"eventTags,omitempty"`
	ID                int      `json:"id,omitempty"`
}

// EventData defines event data fields
type EventData struct {
	LogIndex                                         *int        `json:"logIndex,omitempty"`
	EventMessage                                     string      `json:"eventMessage,omitempty"`
	EventReferenceID                                 string      `json:"eventReferenceId,omitempty"`
	SecurityAction                                   string      `json:"securityAction,omitempty"`
	EventConfidence                                  string      `json:"eventConfidence,omitempty"`
	StateKey                                         string      `json:"stateKey,omitempty"`
	MatchedCategory                                  string      `json:"matchedCategory,omitempty"`
	MatchedIndicators                                string      `json:"matchedIndicators,omitempty"`
	MatchedSample                                    string      `json:"matchedSample,omitempty"`
	MatchedLocation                                  string      `json:"matchedLocation,omitempty"`
	MatchedParameter                                 string      `json:"matchedParameter,omitempty"`
	IPProtocol                                       string      `json:"ipProtocol,omitempty"`
	SourceIP                                         string      `json:"sourceIP,omitempty"`
	SourcePort                                       *int        `json:"sourcePort,omitempty"`
	SourceCountryName                                string      `json:"sourceCountryName,omitempty"`
	DestinationIP                                    string      `json:"destinationIp,omitempty"`
	DestinationPort                                  *int        `json:"destinationPort,omitempty"`
	DestinationCountryName                           string      `json:"destinationCountryName,omitempty"`
	HTTPHostName                                     string      `json:"httpHostName,omitempty"`
	HTTPMethod                                       string      `json:"httpMethod,omitempty"`
	HTTPURI                                          string      `json:"httpUri,omitempty"`
	HTTPRequestBody                                  string      `json:"httpRequestBody,omitempty"`
	HTTPResponseBody                                 string      `json:"httpResponseBody,omitempty"`
	HTTPResponseCode                                 string      `json:"httpResponseCode,omitempty"`
	HTTPURIPath                                      string      `json:"httpUriPath,omitempty"`
	HTTPURIQuery                                     string      `json:"httpUriQuery,omitempty"`
	HTTPSourceID                                     string      `json:"httpSourceId,omitempty"`
	HTTPRequestHeaders                               string      `json:"httpRequestHeaders,omitempty"`
	InterfaceDirection                               string      `json:"interfaceDirection,omitempty"`
	InterfaceName                                    string      `json:"interfaceName,omitempty"`
	PacketLength                                     *int        `json:"packetLength,omitempty"`
	SequenceNumber                                   *int        `json:"sequenceNumber,omitempty"`
	SuppressedLogsCount                              *int        `json:"suppressedLogsCount,omitempty"`
	WaapOverride                                     string      `json:"waapOverride,omitempty"`
	WaapUserReputationScore                          *int        `json:"waapUserReputationScore,omitempty"`
	WaapURIFalsePositiveScore                        *int        `json:"waapUriFalsePositiveScore,omitempty"`
	WaapKeywordsScore                                *int        `json:"waapKeywordsScore,omitempty"`
	WaapFinalScore                                   *int        `json:"waapFinalScore,omitempty"`
	WaapIncidentDetails                              string      `json:"waapIncidentDetails,omitempty"`
	WaapUserReputation                               string      `json:"waapUserReputation,omitempty"`
	WaapFoundIndicators                              string      `json:"waapFoundIndicators,omitempty"`
	WaapIncidentType                                 string      `json:"waapIncidentType,omitempty"`
	LearnedIndicators                                string      `json:"learnedIndicators,omitempty"`
	MaliciousContent                                 string      `json:"maliciousContent,omitempty"`
	ProxyIP                                          string      `json:"proxyIP,omitempty"`
	ProtectionID                                     string      `json:"protectionId,omitempty"`
	ReservedNgenA                                    *int        `json:"reservedNgenA,omitempty"`
	ReservedNgenB                                    *int        `json:"reservedNgenB,omitempty"`
	ReservedNgenC                                    *int        `json:"reservedNgenC,omitempty"`
	ReservedNgenD                                    *int        `json:"reservedNgenD,omitempty"`
	ReservedNgenE                                    *int        `json:"reservedNgenE,omitempty"`
	ReservedNgenF                                    *int        `json:"reservedNgenF,omitempty"`
	ReservedNgenG                                    *int        `json:"reservedNgenG,omitempty"`
	ReservedNgenH                                    *int        `json:"reservedNgenH,omitempty"`
	ReservedNgenI                                    *int        `json:"reservedNgenI,omitempty"`
	ReservedNgenJ                                    *int        `json:"reservedNgenJ,omitempty"`
	IssuingFunction                                  string      `json:"issuingFunction,omitempty"`
	IssuingFile                                      string      `json:"issuingFile,omitempty"`
	IssuingLine                                      *int        `json:"issuingLine,omitempty"`
	DebugMessage                                     string      `json:"debugMessage,omitempty"`
	AssetID                                          string      `json:"assetId,omitempty"`
	AssetName                                        string      `json:"assetName,omitempty"`
	PracticeID                                       string      `json:"practiceId,omitempty"`
	PracticeType                                     string      `json:"practiceType,omitempty"`
	PracticeSubType                                  string      `json:"practiceSubType,omitempty"`
	PracticeName                                     string      `json:"practiceName,omitempty"`
	RuleID                                           string      `json:"ruleId,omitempty"`
	RuleName                                         string      `json:"ruleName,omitempty"`
	ZoneID                                           string      `json:"zoneId,omitempty"`
	ZoneName                                         string      `json:"zoneName,omitempty"`
	NotificationID                                   string      `json:"notificationId,omitempty"`
	EventObject                                      interface{} `json:"eventObject,omitempty"`
	IncidentType                                     string      `json:"incidentType,omitempty"`
	AppsecMatchedSourceIdentifierType                string      `json:"appsecMatchedSourceIdentifierType,omitempty"`
	AppsecMatchedSourceIdentifierValue               string      `json:"appsecMatchedSourceIdentifierValue,omitempty"`
	MatchedSignatureSeverity                         string      `json:"matchedSignatureSeverity,omitempty"`
	MatchedSignaturePerformance                      string      `json:"matchedSignaturePerformance,omitempty"`
	MatchedSignatureConfidence                       string      `json:"matchedSignatureConfidence,omitempty"`
	SourceZoneID                                     string      `json:"sourceZoneId,omitempty"`
	SourceZoneName                                   string      `json:"sourceZoneName,omitempty"`
	DestinationZoneID                                string      `json:"destinationZoneId,omitempty"`
	DestinationZoneName                              string      `json:"destinationZoneName,omitempty"`
	SourceInfo                                       string      `json:"sourceInfo,omitempty"`
	DestinationInfo                                  string      `json:"destinationInfo,omitempty"`
	SourceAssetID                                    string      `json:"sourceAssetId,omitempty"`
	SourceAssetName                                  string      `json:"sourceAssetName,omitempty"`
	DestinationAssetID                               string      `json:"destinationAssetId,omitempty"`
	DestinationAssetName                             string      `json:"destinationAssetName,omitempty"`
	DNSQueriedDomain                                 string      `json:"dnsQueriedDomain,omitempty"`
	DNSResponse                                      string      `json:"dnsResponse,omitempty"`
	MatchedSignatureYear                             string      `json:"matchedSignatureYear,omitempty"`
	MatchedSignatureCVE                              string      `json:"matchedSignatureCVE,omitempty"`
	PreventEngineMatchesSample                       *int        `json:"preventEngineMatchesSample,omitempty"`
	DetectEngineMatchesSample                        *int        `json:"detectEngineMatchesSample,omitempty"`
	IgnoreEngineMatchesSample                        *int        `json:"ignoreEngineMatchesSample,omitempty"`
	AdvisoryName                                     string      `json:"advisoryName,omitempty"`
	AdvisoryLink                                     string      `json:"advisoryLink,omitempty"`
	IotMatchKey                                      string      `json:"iotMatchKey,omitempty"`
	IotMatchValue                                    string      `json:"iotMatchValue,omitempty"`
	IotMatchReason                                   string      `json:"iotMatchReason,omitempty"`
	AssetDataClassificationHintsSource               string      `json:"assetDataClassificationHintsSource,omitempty"`
	AssetDataRecognitionEngineSource                 string      `json:"assetDataRecognitionEngineSource,omitempty"`
	AssetNormalizedManufacturer                      string      `json:"assetNormalizedManufacturer,omitempty"`
	AssetNormalizedFunction                          string      `json:"assetNormalizedFunction,omitempty"`
	AssetNormalizedIPAddr                            string      `json:"assetNormalizedIpAddr,omitempty"`
	UpsertAssetLatencySample                         *int        `json:"upsertAssetLatencySample,omitempty"`
	MacClassificationLatencySample                   *int        `json:"macClassificationLatencySample,omitempty"`
	PublishChangesLatencySample                      *int        `json:"publishChangesLatencySample,omitempty"`
	DiscardChangesLatencySample                      *int        `json:"discardChangesLatencySample,omitempty"`
	AssetDataClassificationHintsSourceFunction       string      `json:"assetDataClassificationHintsSourceFunction,omitempty"`
	AssetDataClassificationHintsSourceFunctionStatus string      `json:"assetDataClassificationHintsSourceFunctionStatus,omitempty"`
	IndicatorsSource                                 string      `json:"indicatorsSource,omitempty"`
	IndicatorsVersion                                string      `json:"indicatorsVersion,omitempty"`
	EventRemediation                                 string      `json:"eventRemediation,omitempty"`
	Layer7Protocol                                   string      `json:"layer7Protocol,omitempty"`
	OriginalRoute                                    string      `json:"originalRoute,omitempty"`
	SelectedRoute                                    string      `json:"selectedRoute,omitempty"`
	MatchReason                                      string      `json:"matchReason,omitempty"`
	DiskUsageAvgSample                               *int        `json:"diskUsageAvgSample,omitempty"`
	DiskUsageMaxSample                               *int        `json:"diskUsageMaxSample,omitempty"`
	FileDescriptorsAvgSample                         *int        `json:"fileDescriptorsAvgSample,omitempty"`
	FileDescriptorsMaxSample                         *int        `json:"fileDescriptorsMaxSample,omitempty"`
	UserDefinedID                                    string      `json:"userDefinedId,omitempty"`
	WatchdogProcessStartupEventsSum                  *int        `json:"watchdogProcessStartupEventsSum,omitempty"`
	NumberOfProtectedAPIAssetsSample                 *int        `json:"numberOfProtectedApiAssetsSample,omitempty"`
	NumberOfProtectedWebAppAssetsSample              *int        `json:"numberOfProtectedWebAppAssetsSample,omitempty"`
	NumberOfProtectedAssetsSample                    *int        `json:"numberOfProtectedAssetsSample,omitempty"`
	ScanRequestsSum                                  *int        `json:"scanRequestsSum,omitempty"`
	PreScanDetectionSum                              *int        `json:"preScanDetectionSum,omitempty"`
	ScanAvgTimeSample                                *int        `json:"scanAvgTimeSample,omitempty"`
	ScanErrorsSum                                    *int        `json:"scanErrorsSum,omitempty"`
	PreventEngineMatchesSum                          *int        `json:"preventEngineMatchesSum,omitempty"`
	DetectEngineMatchesSum                           *int        `json:"detectEngineMatchesSum,omitempty"`
	AskEngineMatchesSum                              *int        `json:"askEngineMatchesSum,omitempty"`
	InformEngineMatchesSum                           *int        `json:"informEngineMatchesSum,omitempty"`
	AcceptEngineMatchesSum                           *int        `json:"acceptEngineMatchesSum,omitempty"`
	DataTypeCategoryPersonalInfoSum                  *int        `json:"dataTypeCategoryPersonalInfoSum,omitempty"`
	DataTypeCategoryFinancialInfoSum                 *int        `json:"dataTypeCategoryFinancialInfoSum,omitempty"`
	DataTypeCategoryIntellectualPropertySum          *int        `json:"dataTypeCategoryIntellectualPropertySum,omitempty"`
	DataTypeCategoryHealthcareDataSum                *int        `json:"dataTypeCategoryHealthcareDataSum,omitempty"`
	DataTypeCategoryNetworkAndITSum                  *int        `json:"dataTypeCategoryNetworkAndITSum,omitempty"`
	DataTypeCategoryHumanResourcesSum                *int        `json:"dataTypeCategoryHumanResourcesSum,omitempty"`
	DataTypeCategoryGeneralPracticesSum              *int        `json:"dataTypeCategoryGeneralPracticesSum,omitempty"`
	InputProtocolHTTPSum                             *int        `json:"inputProtocolHTTPSum,omitempty"`
	InputProtocolHTTPSSum                            *int        `json:"inputProtocolHTTPSSum,omitempty"`
	InputProtocolFTPSum                              *int        `json:"inputProtocolFTPSum,omitempty"`
	InputProtocolSMTPSum                             *int        `json:"inputProtocolSMTPSum,omitempty"`
	ScanTimeoutsSum                                  *int        `json:"scanTimeoutsSum,omitempty"`
	ScanAvgSizeSample                                *int        `json:"scanAvgSizeSample,omitempty"`
	MaxViolationsUserIdentifierSample                string      `json:"maxViolationsUserIdentifierSample,omitempty"`
	MatchedFileSizeString                            string      `json:"matchedFileSizeString,omitempty"`
	*Metrics
}

// EventSource defines event source fields
type EventSource struct {
	EventID                 string   `json:"eventId,omitempty"`
	EventTraceID            string   `json:"eventTraceId,omitempty"`
	EventSpanID             string   `json:"eventSpanId,omitempty"`
	ServiceName             string   `json:"serviceName,omitempty"`
	AgentID                 string   `json:"agentId,omitempty"`
	ProfileID               string   `json:"profileId,omitempty"`
	AgentType               string   `json:"agentType,omitempty"`
	FogID                   string   `json:"fogId,omitempty"`
	FogType                 string   `json:"fogType,omitempty"`
	AttachmentName          string   `json:"attachmentName,omitempty"`
	IssuingEngine           string   `json:"issuingEngine,omitempty"`
	IssuingFile             string   `json:"issuingFile,omitempty"`
	IssuingFunction         string   `json:"issuingFunction,omitempty"`
	IssuingLine             *int     `json:"issuingLine,omitempty"`
	SourceProcess           string   `json:"sourceProcess,omitempty"`
	RuleID                  string   `json:"ruleId,omitempty"`
	RuleName                string   `json:"ruleName,omitempty"`
	AssetID                 string   `json:"assetId,omitempty"`
	AssetName               string   `json:"assetName,omitempty"`
	PracticeID              string   `json:"practiceId,omitempty"`
	PracticeType            string   `json:"practiceType,omitempty"`
	PracticeSubType         string   `json:"practiceSubType,omitempty"`
	PracticeName            string   `json:"practiceName,omitempty"`
	ZoneID                  string   `json:"zoneId,omitempty"`
	ZoneName                string   `json:"zoneName,omitempty"`
	ParameterID             string   `json:"parameterId,omitempty"`
	ParameterName           string   `json:"parameterName,omitempty"`
	TriggerID               string   `json:"triggerId,omitempty"`
	TriggerName             string   `json:"triggerName,omitempty"`
	TenantID                string   `json:"tenantId,omitempty"`
	HTTPSourceID            string   `json:"httpSourceId,omitempty"`
	ServiceID               string   `json:"serviceId,omitempty"`
	ServiceFamilyID         string   `json:"serviceFamilyId,omitempty"`
	IssuingEngineVersion    string   `json:"issuingEngineVersion,omitempty"`
	AgentHostVersion        string   `json:"agentHostVersion,omitempty"`
	AgentHostType           string   `json:"agentHostType,omitempty"`
	AgentHostIdentifier     string   `json:"agentHostIdentifier,omitempty"`
	AgentHostName           string   `json:"agentHostName,omitempty"`
	AgentHostCertificateKey string   `json:"agentHostCertificateKey,omitempty"`
	AgentHostVersionUpdates string   `json:"agentHostVersionUpdates,omitempty"`
	ExceptionIDList         []string `json:"exceptionIdList,omitempty"`
	EventTopic              string   `json:"eventTopic,omitempty"`
	EventContext            string   `json:"eventContext,omitempty"`
	K8sClusterID            string   `json:"k8sClusterId,omitempty"`
	K8sVersion              string   `json:"k8sVersion,omitempty"`
	PolicyVersion           string   `json:"policyVersion,omitempty"`
}

// ErrorResponse defines a response to an invalid agent's log
type ErrorResponse struct {
	ID      int    `json:"id"`
	Code    int    `json:"code,omitempty"`
	Message string `json:"message"`
}

// Metrics defines agent's metric fields
type Metrics struct {
	MessageQueueMaxSizeSample                        *int `json:"messageQueueMaxSizeSample,omitempty"`
	MessageQueueAvgSizeSample                        *int `json:"messageQueueAvgSizeSample,omitempty"`
	MessageQueueSizeSample                           *int `json:"messageQueueSizeSample,omitempty"`
	LogQueueMaxSizeSample                            *int `json:"logQueueMaxSizeSample,omitempty"`
	LogQueueAvgSizeSample                            *int `json:"logQueueAvgSizeSample,omitempty"`
	LogQueueSizeSample                               *int `json:"logQueueSizeSample,omitempty"`
	CPUMaxSample                                     *int `json:"cpuMaxSample,omitempty"`
	CPUAvgSample                                     *int `json:"cpuAvgSample,omitempty"`
	CPUSample                                        *int `json:"cpuSample,omitempty"`
	NumberOfAssetsInCacheSample                      *int `json:"numberOfAssetsInCacheSample,omitempty"`
	AssetsCacheSizeSample                            *int `json:"assetsCacheSizeSample,omitempty"`
	ConnectionTableSizeSample                        *int `json:"connectionTableSizeSample,omitempty"`
	MaxNumberOfAssetsInCacheSample                   *int `json:"maxNumberOfAssetsInCacheSample,omitempty"`
	AssetsMaxCacheSizeSample                         *int `json:"assetsMaxCacheSizeSample,omitempty"`
	ConnectionTableMaxSizeSample                     *int `json:"connectionTableMaxSizeSample,omitempty"`
	AverageofNumberOfAssetsInCacheSample             *int `json:"averageofNumberOfAssetsInCacheSample,omitempty"`
	AssetsAverageCacheSizeSample                     *int `json:"assetsAverageCacheSizeSample,omitempty"`
	ConnectionTableAverageSizeSample                 *int `json:"connectionTableAverageSizeSample,omitempty"`
	AssetsCacheHitsCounterSinceRestartSum            *int `json:"assetsCacheHitsCounterSinceRestartSum,omitempty"`
	AssetsCacheMissesCounterSinceRestartSum          *int `json:"assetsCacheMissesCounterSinceRestartSum,omitempty"`
	AcceptedPacketsCounterSinceRestartSum            *int `json:"acceptedPacketsCounterSinceRestartSum,omitempty"`
	DroppedPacketsCounterSinceRestartSum             *int `json:"droppedPacketsCounterSinceRestartSum,omitempty"`
	StolenPacketsCounterSinceRestartSum              *int `json:"stolenPacketsCounterSinceRestartSum,omitempty"`
	SuccessfulTablesInsertionsCounterSinceRestartSum *int `json:"successfulTablesInsertionsCounterSinceRestartSum,omitempty"`
	FailedTablesInsertionsCounterSinceRestartSum     *int `json:"failedTablesInsertionsCounterSinceRestartSum,omitempty"`
	LogsCounterSinceRestartSum                       *int `json:"logsCounterSinceRestartSum,omitempty"`
	FailedLogsCounterSinceRestartSum                 *int `json:"failedLogsCounterSinceRestartSum,omitempty"`
	TraceDebugsCounterSinceRestartSum                *int `json:"traceDebugsCounterSinceRestartSum,omitempty"`
	DebugDebugsCounterSinceRestartSum                *int `json:"debugDebugsCounterSinceRestartSum,omitempty"`
	InfoDebugsCounterSinceRestartSum                 *int `json:"infoDebugsCounterSinceRestartSum,omitempty"`
	WarningDebugsCounterSinceRestartSum              *int `json:"warningDebugsCounterSinceRestartSum,omitempty"`
	ErrorDebugsCounterSinceRestartSum                *int `json:"errorDebugsCounterSinceRestartSum,omitempty"`
	AssertionDebugsCounterSinceRestartSum            *int `json:"assertionDebugsCounterSinceRestartSum,omitempty"`
	DroppedDebugsBufferIsFullSinceRestartSum         *int `json:"droppedDebugsBufferIsFullSinceRestartSum,omitempty"`
	DroppedDebugsMessageTooLongSinceRestartSum       *int `json:"droppedDebugsMessageTooLongSinceRestartSum,omitempty"`
	MainloopMaxTimeSliceSample                       *int `json:"mainloopMaxTimeSliceSample,omitempty"`
	MainloopAvgTimeSliceSample                       *int `json:"mainloopAvgTimeSliceSample,omitempty"`
	// MainloopAvgSleepTimeSample                       *int `json:"mainloopAvgSleepTimeSample,omitempty"`
	MainloopMaxStressValueSample                          *int `json:"mainloopMaxStressValueSample,omitempty"`
	SentLogsSum                                           *int `json:"sentLogsSum,omitempty"`
	LogQueueCurrentSizeSample                             *int `json:"logQueueCurrentSizeSample,omitempty"`
	SentLogsBulksSum                                      *int `json:"sentLogsBulksSum,omitempty"`
	MainloopLastTimeSliceSample                           *int `json:"mainloopLastTimeSliceSample,omitempty"`
	MainloopMaxSleepTimeSample                            *int `json:"mainloopMaxSleepTimeSample,omitempty"`
	MainloopLastSleepTimeSample                           *int `json:"mainloopLastSleepTimeSample,omitempty"`
	MainloopAvgStressValueSample                          *int `json:"mainloopAvgStressValueSample,omitempty"`
	MainloopLastStressValueSample                         *int `json:"mainloopLastStressValueSample,omitempty"`
	FailedRegistrationsSum                                *int `json:"failedRegistrationsSum,omitempty"`
	FailedConnectionsSum                                  *int `json:"failedConnectionsSum,omitempty"`
	InspectVerdictSum                                     *int `json:"inspectVerdictSum,omitempty"`
	AcceptVeridctSum                                      *int `json:"acceptVeridctSum,omitempty"`
	DropVerdictSum                                        *int `json:"dropVerdictSum,omitempty"`
	InjectVerdictSum                                      *int `json:"injectVerdictSum,omitempty"`
	IrrelevantVerdictSum                                  *int `json:"irrelevantVerdictSum,omitempty"`
	ReconfVerdictSum                                      *int `json:"reconfVerdictSum,omitempty"`
	MaxTransactionTableSizeSample                         *int `json:"maxTransactionTableSizeSample,omitempty"`
	AverageTransactionTableSizeSample                     *int `json:"averageTransactionTableSizeSample,omitempty"`
	LastReportTransactionTableSizeSample                  *int `json:"lastReportTransactionTableSizeSample,omitempty"`
	SuccessfullInspectionTransactionsSum                  *int `json:"successfullInspectionTransactionsSum,omitempty"`
	FailopenTransactionsSum                               *int `json:"failopenTransactionsSum,omitempty"`
	FailcloseTransactionsSum                              *int `json:"failcloseTransactionsSum,omitempty"`
	TransparentModeTransactionsSum                        *int `json:"transparentModeTransactionsSum,omitempty"`
	TotalTimeInTransparentModeSum                         *int `json:"totalTimeInTransparentModeSum,omitempty"`
	ReachInspectVerdictSum                                *int `json:"reachInspectVerdictSum,omitempty"`
	ReachAcceptVerdictSum                                 *int `json:"reachAcceptVerdictSum,omitempty"`
	ReachDropVerdictSum                                   *int `json:"reachDropVerdictSum,omitempty"`
	ReachInjectVerdictSum                                 *int `json:"reachInjectVerdictSum,omitempty"`
	ReachIrrelevantVerdictSum                             *int `json:"reachIrrelevantVerdictSum,omitempty"`
	ReachReconfVerdictSum                                 *int `json:"reachReconfVerdictSum,omitempty"`
	AttachmentThreadReachedTimeoutSum                     *int `json:"attachmentThreadReachedTimeoutSum,omitempty"`
	RegistrationThreadReachedTimeoutSum                   *int `json:"registrationThreadReachedTimeoutSum,omitempty"`
	RequestHeaderThreadReachedTimeoutSum                  *int `json:"requestHeaderThreadReachedTimeoutSum,omitempty"`
	RequestBodyThreadReachedTimeoutSum                    *int `json:"requestBodyThreadReachedTimeoutSum,omitempty"`
	RespondHeaderThreadReachedTimeoutSum                  *int `json:"respondHeaderThreadReachedTimeoutSum,omitempty"`
	RespondBodyThreadReachedTimeoutSum                    *int `json:"respondBodyThreadReachedTimeoutSum,omitempty"`
	AttachmentThreadFailureSum                            *int `json:"attachmentThreadFailureSum,omitempty"`
	HTTPRequestProcessingReachedTimeoutSum                *int `json:"httpRequestProcessingReachedTimeoutSum,omitempty"`
	HTTPResponseProcessingReachedTimeoutSum               *int `json:"httpResponseProcessingReachedTimeoutSum,omitempty"`
	HTTPRequestFailedToReachWebServerUpstreamSum          *int `json:"httpRequestFailedToReachWebServerUpstreamSum,omitempty"`
	RequestCompressionFailureSum                          *int `json:"requestCompressionFailureSum,omitempty"`
	ResponseCompressionFailureSum                         *int `json:"responseCompressionFailureSum,omitempty"`
	RequestDecompressionFailureSum                        *int `json:"requestDecompressionFailureSum,omitempty"`
	ResponseDecompressionFailureSum                       *int `json:"responseDecompressionFailureSum,omitempty"`
	RequestCompressionSuccessSum                          *int `json:"requestCompressionSuccessSum,omitempty"`
	ResponseCompressionSuccessSum                         *int `json:"responseCompressionSuccessSum,omitempty"`
	RequestDecompressionSuccessSum                        *int `json:"requestDecompressionSuccessSum,omitempty"`
	ResponseDecompressionSuccessSum                       *int `json:"responseDecompressionSuccessSum,omitempty"`
	SkippedSessionsUponCorruptedZipSum                    *int `json:"skippedSessionsUponCorruptedZipSum,omitempty"`
	ServiceVirtualMemorySizeMaxSample                     *int `json:"serviceVirtualMemorySizeMaxSample,omitempty"`
	ServiceVirtualMemorySizeMinSample                     *int `json:"serviceVirtualMemorySizeMinSample,omitempty"`
	ServiceVirtualMemorySizeAvgSample                     *int `json:"serviceVirtualMemorySizeAvgSample,omitempty"`
	ServiceRssMemorySizeMaxSample                         *int `json:"serviceRssMemorySizeMaxSample,omitempty"`
	ServiceRssMemorySizeMinSample                         *int `json:"serviceRssMemorySizeMinSample,omitempty"`
	ServiceRssMemorySizeAvgSample                         *int `json:"serviceRssMemorySizeAvgSample,omitempty"`
	RequestBodySizeUponTimeoutAvarageSample               *int `json:"requestBodySizeUponTimeoutAvarageSample,omitempty"`
	RequestBodySizeUponTimeoutMaxSample                   *int `json:"requestBodySizeUponTimeoutMaxSample,omitempty"`
	RequestBodySizeUponTimeoutMinSample                   *int `json:"requestBodySizeUponTimeoutMinSample,omitempty"`
	ResponseBodySizeUponTimeoutAvarageSample              *int `json:"responseBodySizeUponTimeoutAvarageSample,omitempty"`
	ResponseBodySizeUponTimeoutMaxSample                  *int `json:"responseBodySizeUponTimeoutMaxSample,omitempty"`
	ResponseBodySizeUponTimeoutMinSample                  *int `json:"responseBodySizeUponTimeoutMinSample,omitempty"`
	OverallSessionProcessingTimeUntilVerdictAverageSample *int `json:"overallSessionProcessingTimeUntilVerdictAverageSample,omitempty"`
	OverallSessionProcessingTimeUntilVerdictMaxSample     *int `json:"overallSessionProcessingTimeUntilVerdictMaxSample,omitempty"`
	OverallSessionProcessingTimeUntilVerdictMinSample     *int `json:"overallSessionProcessingTimeUntilVerdictMinSample,omitempty"`
	RequestProcessingTimeUntilVerdictAverageSample        *int `json:"requestProcessingTimeUntilVerdictAverageSample,omitempty"`
	RequestProcessingTimeUntilVerdictMaxSample            *int `json:"requestProcessingTimeUntilVerdictMaxSample,omitempty"`
	RequestProcessingTimeUntilVerdictMinSample            *int `json:"requestProcessingTimeUntilVerdictMinSample,omitempty"`
	ResponseProcessingTimeUntilVerdictAverageSample       *int `json:"responseProcessingTimeUntilVerdictAverageSample,omitempty"`
	ResponseProcessingTimeUntilVerdictMaxSample           *int `json:"responseProcessingTimeUntilVerdictMaxSample,omitempty"`
	ResponseProcessingTimeUntilVerdictMinSample           *int `json:"responseProcessingTimeUntilVerdictMinSample,omitempty"`
	FirstPacketHandlingTimeSample                         *int `json:"firstPacketHandlingTimeSample,omitempty"`
	FirstPacketMaxHandlingTimeSample                      *int `json:"firstPacketMaxHandlingTimeSample,omitempty"`
	FirstPacketAvgHandlingTimeSample                      *int `json:"firstPacketAvgHandlingTimeSample,omitempty"`
	GeneralTotalMemorySizeMaxSample                       *int `json:"generalTotalMemorySizeMaxSample,omitempty"`
	GeneralTotalMemorySizeMinSample                       *int `json:"generalTotalMemorySizeMinSample,omitempty"`
	GeneralTotalMemorySizeAvgSample                       *int `json:"generalTotalMemorySizeAvgSample,omitempty"`
}

// FluentSecurityEvents is used to output events as the Fluentd outputs them
// todo - remove this ugly thing once the new consumer is ready
type FluentSecurityEvents struct {
	Events []AgentMessage `json:"message"`
}

// FluentDebugEvents is used to output events as the Fluentd outputs them
// todo - remove this ugly thing once the new consumer is ready
type FluentDebugEvents struct {
	Events     string              `json:"log"`
	Kubernetes *KubernetesMetadata `json:"kubernetes,omitempty"`
}

// KubernetesMetadata defined kuberentes metadata
type KubernetesMetadata struct {
	ContainerName string `json:"container_name,omitempty"`
	NamespaceName string `json:"namespace_name,omitempty"`
}

// Logs represent log rows
type Logs struct {
	ColumnNames []string
	Rows        [][]string
}
