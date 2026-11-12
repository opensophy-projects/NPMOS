package tuning

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"openappsec.io/ctxutils"
	"openappsec.io/errors"
	"openappsec.io/smartsync-tuning/models"
	"openappsec.io/log"
)

// UpdatePolicy updates db according to policy
func (sa *StandAlone) UpdatePolicy(ctx context.Context, msg models.PolicyMessageData) error {
	tenantID := msg.TenantID
	if tenantID == "" {
		tenantID = ctxutils.ExtractString(ctx, ctxutils.ContextKeyTenantID)
	}
	log.WithContext(ctx).Infof("tenant id: %v, msg: %+v, ctx tenant: %v", tenantID, msg, ctxutils.ExtractString(ctx,
		ctxutils.ContextKeyTenantID))
	if tenantID == "" {
		return errors.New("missing tenant ID")
	}
	details, err := sa.policyFetch.GetPolicy(ctx, tenantID, msg.DownloadPath, msg.Version)
	if err != nil {
		return errors.Wrapf(err, "failed to get assets details for tenant: %v", tenantID)
	}
	if err := sa.db.PruneAssets(ctx, details, msg.Version); err != nil {
		log.WithContext(ctx).Warnf("failed to prune assets: %v", err)
	}
	for _, asset := range details {
		err = sa.db.ReportAsset(
			ctx,
			models.ReportAssetPolicyData,
			asset.TenantID,
			asset.AssetID,
			asset,
		)
		if err != nil {
			err = errors.Wrapf(err, "failed to report new policy for asset %v", asset.AssetID)
		}
	}
	return err
}

//GetLogs return the logs associated with the tuning event with id tuningID
func (sa *StandAlone) GetLogs(ctx context.Context, asset string, tuningID string) (models.Logs, error) {
	tuneEvent, err := sa.findTuningEvent(ctx, asset, tuningID)
	if err != nil {
		return models.Logs{}, err
	}
	return sa.lr.GetTuningLogs(ctx, asset, tuneEvent)
}

func (sa *StandAlone) findTuningEvent(ctx context.Context, asset string, tuningID string) (models.TuneEvent, error) {
	var tuneEvents []models.TuneEvent
	err := sa.db.GetAssetData(ctx, models.ReportTuning, "", asset, &tuneEvents)
	if err != nil {
		return models.TuneEvent{}, err
	}
	for _, event := range tuneEvents {
		if event.ID == tuningID {
			return event, nil
		}
	}
	return models.TuneEvent{}, errors.New("not found").SetClass(errors.ClassNotFound)
}

func (sa *StandAlone) getData(ctx context.Context, tenantID, assetID string, reportType models.ReportedAssetType) (
	[]byte,
	error,
) {
	var data interface{}
	err := sa.db.GetAssetData(ctx, reportType, tenantID, assetID, &data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get asset data from repository")
	}
	dataName := dataNameTuning
	if reportType == models.ReportStatistics {
		dataName = dataNameStatistics
	}
	res, err := json.Marshal(map[string]interface{}{dataName: data})
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal data")
	}
	return res, nil
}

// GetStats return the stats of an assetID of a tenantID
func (sa *StandAlone) GetStats(ctx context.Context, tenantID, assetID string) ([]byte, error) {
	ctx = ctxutils.Insert(ctx, ctxutils.ContextKeyTenantID, tenantID)
	statsStr, err := sa.getData(ctx, tenantID, assetID, models.ReportStatistics)
	if err != nil || statsStr == nil {
		noDataResp := models.Statistics{
			Status:           statusNotReady,
			ReadinessDP:      readinessDPNoData,
			ReadinessTP:      readinessTPNoData,
			RecommendationDP: recommendationDPNoData,
			RecommendationTP: recommendationTPVerifyInstallation,
		}
		stats, errJSON := json.Marshal(map[string]models.Statistics{"statistics": noDataResp})
		if errJSON != nil {
			return []byte{}, errors.Wrapf(err, "got %v while generating response", errJSON)
		}
		return stats, nil
	}
	return statsStr, nil
}

// GetTuningEvents return the undecided tuning events of an assetID of a tenantID
func (sa *StandAlone) GetTuningEvents(ctx context.Context, tenantID, assetID string) ([]byte, error) {
	ctx = ctxutils.Insert(ctx, ctxutils.ContextKeyTenantID, tenantID)
	return sa.getData(ctx, tenantID, assetID, models.ReportTuning)
}

// GetTuningEventsReview return the decided tuning events of an assetID of a tenantID
func (sa *StandAlone) GetTuningEventsReview(ctx context.Context, tenantID, assetID, userID string) ([]byte, error) {
	var decisions models.Decisions
	var events []models.TuneEvent

	ctx = ctxutils.Insert(ctx, ctxutils.ContextKeyTenantID, tenantID)

	err := sa.db.GetAssetData(ctx, models.ReportTuningDecided, tenantID, assetID, &events)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get asset data from repository")
	}

	decisions, err = sa.s3.GetDecisions(ctx, tenantID, assetID)
	if err != nil && errors.IsClass(err, errors.ClassNotFound) {
		return nil, errors.Wrap(err, "failed to get decisions data from s3 repository")
	}
	mergedData := mergeTuneEvents(decisions, events)

	response := make([]models.TuneEvent, 0)
	for _, event := range mergedData.Decisions {
		if !event.Enforced {
			response = append(response, event)
		}
	}

	res, err := json.Marshal(map[string]interface{}{dataNameTuning: response})
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal data")
	}
	return res, nil
}

func mergeTuneEvents(decisions models.Decisions, events []models.TuneEvent) models.Decisions {
	for _, event := range events {
		flag := false
		for _, decision := range decisions.Decisions {
			if event.EventTitle == decision.EventTitle && event.EventType == decision.EventType {
				flag = true
				break
			}
		}
		if !flag {
			decisions.Decisions = append(decisions.Decisions, event)
		}
	}
	return decisions
}

func copyTuneEvent(event models.TuneEvent) models.TuneEvent {
	copyEvent := event
	copyEvent.Metrics = make([]models.Metric, len(event.Metrics))
	copy(copyEvent.Metrics, event.Metrics)
	copyEvent.AttackTypes = make([]string, len(event.AttackTypes))
	copy(copyEvent.AttackTypes, event.AttackTypes)
	return copyEvent
}

// PostTuningEvents creates a parameter and attach to an asset
func (sa *StandAlone) PostTuningEvents(ctx context.Context, tenantID, assetID, _ string,
	tuningEvents []models.TuneEvent) error {
	ctx = ctxutils.Insert(ctx, ctxutils.ContextKeyTenantID, tenantID)
	assetID = strings.TrimSuffix(assetID, "/")
	newDecisions := make([]models.TuneEvent, 0)

	// find decision to undo
	var appliedTuning models.Decisions
	var events []models.TuneEvent

	err := sa.db.GetAssetData(ctx, models.ReportTuningDecided, tenantID, assetID, &events)
	if err != nil {
		log.WithContext(ctx).Warnf("failed to get decided tuning events from intelligence, err: %v", err)
	}
	appliedTuning, err = sa.s3.GetDecisions(ctx, tenantID, assetID)
	if err != nil {
		log.WithContext(ctx).Warnf("failed to get decided tuning events from s3 repo, err: %v", err)
	}

	log.WithContext(ctx).Debugf("got decisions; from shared storage: %+v, from repo: %+v", appliedTuning, events)

	appliedTuning = mergeTuneEvents(appliedTuning, events)

	log.WithContext(ctx).Debugf("merged decisions: %+v", appliedTuning)

	var tuningSuggestions []models.TuneEvent
	err = sa.db.GetAssetData(ctx, models.ReportTuning, tenantID, assetID, &tuningSuggestions)
	if err != nil {
		return errors.Wrap(err, "failed to get suggested tuning events")
	}

	log.WithContext(ctx).Debugf("current undecided tuning events: %+v", tuningSuggestions)
	tuningUndecided := tuningSuggestions

	undoDecisions := make([]models.TuneEvent, 0)
	for _, tuneEvent := range tuningEvents {
		for i, tuneEventDecided := range appliedTuning.Decisions {
			if (tuneEventDecided.EventType == tuneEvent.EventType && tuneEventDecided.EventTitle == tuneEvent.EventTitle) ||
				tuneEventDecided.ID == tuneEvent.ID {
				if tuneEventDecided.Decision == tuneEvent.Decision && tuneEvent.Decision != models.DecisionUnknown {
					break
				}
				// remove from decided
				appliedTuning.Decisions[i] = appliedTuning.Decisions[0]
				appliedTuning.Decisions = appliedTuning.Decisions[1:]

				undoTuning := copyTuneEvent(tuneEventDecided)
				undoDecisions = append(undoDecisions, undoTuning)

				copyEvent := copyTuneEvent(tuneEventDecided)
				copyEvent.Decision = tuneEvent.Decision
				copyEvent.Enforced = false
				if tuneEvent.Decision != models.DecisionUnknown {
					newDecisions = append(newDecisions, copyEvent)
				} else {
					tuningUndecided = append(tuningUndecided, copyEvent)
				}
				break
			}
		}
	}

	log.WithContext(ctx).Debugf("undo decisions: %+v", undoDecisions)

	err = sa.s3.RemoveDecisions(ctx, tenantID, assetID, undoDecisions)
	if err != nil {
		return errors.Wrap(err, "failed to undo tuning events")
	}

	for _, tuningEvent := range tuningEvents {
		tuningSuggestions = tuningUndecided
		found := false
		for i, suggestion := range tuningSuggestions {
			if (tuningEvent.EventType == suggestion.EventType && tuningEvent.EventTitle == suggestion.EventTitle) ||
				tuningEvent.ID == suggestion.ID {
				found = true
				// remove from undecided
				if tuningEvent.Decision == models.DecisionUnknown {
					break
				}
				log.WithContext(ctx).Infof("found a suggestion %+v with decision: %+v", suggestion, tuningEvent)
				tuningUndecided[i] = tuningUndecided[0]
				tuningUndecided = tuningUndecided[1:]

				suggestionTuning := copyTuneEvent(suggestion)
				suggestionTuning.Decision = tuningEvent.Decision
				suggestionTuning.Enforced = false

				newDecisions = append(newDecisions, suggestionTuning)
				break
			}
		}
		if !found {
			log.WithContext(ctx).Warnf("event %+v not found in suggestions list, ignoring", tuningEvent)
		}
	}

	log.WithContext(ctx).Debugf("new decisions: %+v", newDecisions)

	if len(newDecisions) == 0 && len(undoDecisions) == 0 {
		return nil
	}

	err = sa.s3.AppendDecisions(ctx, tenantID, assetID, newDecisions)
	if err != nil {
		return errors.Wrap(err, "failed to append new parameters")
	}

	// update data in DB
	appliedTuning.Decisions = append(appliedTuning.Decisions, newDecisions...)

	log.WithContext(ctx).Infof("still undecided tuning events: %+v", tuningUndecided)

	err = sa.db.ReportAsset(
		ctx, models.ReportTuning, tenantID, assetID, tuningUndecided,
	)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to report asset. error %v", err)
	}
	err = sa.db.ReportAsset(
		ctx, models.ReportTuningDecided, tenantID, assetID, appliedTuning.Decisions,
	)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to report asset. error %v", err)
	}

	return nil
}

func (sa *StandAlone) processStats(
	ctx context.Context,
	qRespGen, qRespSev models.QueryResponse,
	filter assetsFilter,
) map[models.AssetInfo]models.Statistics {
	stats := make(map[models.AssetInfo]models.Statistics)
	for tenant, assetCtx := range qRespGen {
		ctxPerTenenat := ctxutils.Insert(ctx, ctxutils.ContextKeyTenantID, tenant)
		for asset, payload := range assetCtx {
			runtime.Gosched()
			if filter.shouldFilterAsset(asset) {
				continue
			}
			log.WithContext(ctxPerTenenat).Debugf("generating statistics for tenant: %v, asset: %v", tenant, asset)
			if len(payload) == 0 {
				log.WithContext(ctxPerTenenat).Warnf("got empty response for tenant: %v, asset: %v", tenant, asset)
				continue
			}
			var currentAttributes models.Attributes
			err := sa.db.GetAssetData(ctxPerTenenat, models.ReportAll, tenant, asset, &currentAttributes)
			if err != nil {
				currentAttributes = models.Attributes{}
				if errors.IsClass(err, errors.ClassUnauthorized) {
					log.WithContext(ctxPerTenenat).Infof("asset: %v is missing from MGMT", asset)
					continue
				}
			}
			data := payload[0].(models.GeneralStatsData)
			tempStats := currentAttributes.Statistics
			tempStats.TenantID = tenant
			tempStats.AssetID = asset
			if tempStats.StartupTime <= minTimestamp {
				tempStats.StartupTime = data.StartupTime
			}
			tempStats.RequestsFromStart = data.TotalRequests
			tempStats.UniqueURLs = int(data.URLsCount)
			tempStats.UniqueSources = int(data.SourcesCount)
			hours := data.ElapsedTime
			if hours >= 24 {
				tempStats.ElapsedTime = fmt.Sprintf("%vd %vh", hours/24, hours%24)
			} else {
				tempStats.ElapsedTime = fmt.Sprintf("%vh", hours)
			}

			tempStats.MalicRequests = 0
			tempStats.LegitRequests = 0

			sevPayload := models.SeverityStatsData{}
			if _, ok := qRespSev[tenant][asset]; ok && len(qRespSev[tenant][asset]) > 0 {
				sevPayload = qRespSev[tenant][asset][0].(models.SeverityStatsData)
			}

			tempStats.CriticalRequests = int(sevPayload.CriticalSeverityRequests)
			tempStats.HighRequests = int(sevPayload.HighSeverityRequests)
			tempStats.TotalRequests = sevPayload.TotalRequests
			tempStats.MalicRequests = tempStats.CriticalRequests + tempStats.HighRequests
			tempStats.LegitRequests = int(tempStats.TotalRequests) - tempStats.MalicRequests

			if tempStats.TotalRequests > 50 {
				tempStats.Status = statusReady
			} else {
				tempStats.Status = statusNotReady
			}

			if currentAttributes.TrustedSourcesPolicy.NumOfSources == 0 && tempStats.Readiness >= readinessGraduate {
				currentAttributes.TrustedSourcesPolicy, err = sa.policyDetails.GetTrustedSourcesPolicy(
					ctxPerTenenat,
					tenant,
					asset,
					sa.uuid,
				)
				if err != nil {
					log.WithContext(ctxPerTenenat).Warnf("failed to get trusted sources policy, err: %v", err)
				} else {
					err := sa.db.ReportAsset(
						ctxPerTenenat,
						models.ReportAssetPolicyData,
						tenant,
						asset,
						currentAttributes.TrustedSourcesPolicy,
					)
					if err != nil {
						err = errors.Wrap(err, "failed to report new trusted sources count for asset")
					}
				}
			}

			learnRatio := 0.0
			runtime.Gosched()
			confidence, err := sa.s3.GetConfidenceFile(tenant, asset)
			if err != nil {
				log.WithContext(ctxPerTenenat).Warn("failed to get confidence file: ", err)
			} else {
				valuesLearned := 0
				for _, values := range confidence.ConfidenceSet {
					valuesLearned += len(values.Value.First)
				}
				learningValues := 0
				for _, values := range confidence.ConfidenceLevels {
					for _, value := range values.Value {
						if value.Value > readinessMinConfidenceLevel {
							learningValues++
						}
					}
				}

				learnRatio = float64(valuesLearned) / float64(learningValues+1)
			}
			elapsedTime := time.Now().Sub(time.Unix(data.StartupTime, 0))
			elapsedTimeHours := elapsedTime.Hours()
			readiness := tempStats.Readiness
			if tempStats.Readiness == readinessNoData &&
				elapsedTimeHours > readinessKindergartenTimeThreshold &&
				data.TotalRequests > readinessKindergartenRequestsThreshold {
				log.WithContext(ctxPerTenenat).Infof("Recover readiness for: %+v", currentAttributes.Statistics)
				tempStats.Readiness, tempStats.PrevLvlReqCount =
					recoverReadiness(elapsedTimeHours, data, currentAttributes.TrustedSourcesPolicy)
				tempStats.StartupTime = data.StartupTime
				readiness = tempStats.Readiness
				log.WithContext(ctxPerTenenat).Infof("Recover readiness output: %v", readiness)
			} else {
				readiness = readinessLevel(
					tempStats.Readiness,
					int64(elapsedTimeHours),
					data.TotalRequests,
					tempStats.PrevLvlReqCount,
					learnRatio,
					currentAttributes.TuningEvents,
					currentAttributes.TuningEventsDecided,
					currentAttributes.TrustedSourcesPolicy,
				)
				if readiness > tempStats.Readiness {
					tempStats.Readiness = readiness
					tempStats.PrevLvlReqCount = data.TotalRequests
				}
			}

			if currentAttributes.TrustedSourcesPolicy.NumOfSources == 0 && tempStats.Readiness >= readinessGraduate {
				currentAttributes.TrustedSourcesPolicy, err = sa.policyDetails.GetTrustedSourcesPolicy(
					ctxPerTenenat,
					tenant,
					asset,
					sa.uuid,
				)
				if err != nil {
					log.WithContext(ctxPerTenenat).Warnf("failed to get trusted sources policy, err: %v", err)
				} else {
					err := sa.db.ReportAsset(
						ctxPerTenenat,
						models.ReportAssetPolicyData,
						tenant,
						asset,
						currentAttributes.TrustedSourcesPolicy,
					)
					if err != nil {
						err = errors.Wrap(err, "failed to report new trusted sources count for asset")
					}
				}
			}

			tempStats.ReadinessDP = readinessDisplayName(readiness)
			nextLevelReq := readinessNextLevelRequirements{}
			tempStats.ReadinessTP, nextLevelReq = readinessTooltip(
				readiness,
				data.TotalRequests,
				tempStats.PrevLvlReqCount,
				elapsedTime,
				currentAttributes.TrustedSourcesPolicy,
			)
			log.WithContext(ctxPerTenenat).Infof("tuning events: %+v", currentAttributes.TuningEvents)
			tempStats.Recommendation = recommendationLevel(readiness, currentAttributes.TuningEvents)
			tempStats.RecommendationDP = recommendationDisplayName(tempStats.Recommendation)
			tempStats.RecommendationTP = sa.recommendationToolTip(ctxPerTenenat, &tempStats, nextLevelReq)
			log.WithContext(ctxPerTenenat).Infof("generated statistics %+v for tenant %v asset %v", tempStats, tenant,
				asset)
			assetInfo := models.AssetInfo{
				TenantID: tempStats.TenantID,
				AssetID:  tempStats.AssetID,
			}
			stats[assetInfo] = tempStats
		}
	}
	return stats
}

func processExceptions(
	ctx context.Context, qResp models.QueryResponse) map[models.AssetInfo]models.AssetExceptions {
	mongoModel := make(map[models.AssetInfo]models.AssetExceptions)
	// hashMap key is a hash combination of asset id and exception id
	for tenant, hashMap := range qResp {
		for _, qDataSlice := range hashMap {
			for _, qData := range qDataSlice {
				qExceptionData, ok := qData.(models.ExceptionsData)
				if !ok {
					log.WithContext(ctx).Warnf(
						"failed to to convert groupedData to ExceptionsData for tenant: %v", tenant,
					)
					continue
				}
				log.WithContext(ctx).Debugf(
					"processing exceptions for tenant: %v, asset: %v", tenant, qExceptionData.AssetID,
				)
				assetInfo := models.AssetInfo{
					TenantID: tenant,
					AssetID:  qExceptionData.AssetID,
				}
				_, exists := mongoModel[assetInfo]
				if !exists {
					mongoModel[assetInfo] = models.AssetExceptions{
						Exceptions: make(map[string]models.ExceptionData),
					}
				}

				_, exists = mongoModel[assetInfo].Exceptions[qExceptionData.ExceptionID]
				if !exists {
					exceptionData := models.ExceptionData{
						LastHitEvent:   qExceptionData.LastHitEvent,
						HitCount:       qExceptionData.HitCountPerAsset,
						SharedHitCount: qExceptionData.HitCountPerException,
					}
					mongoModel[assetInfo].Exceptions[qExceptionData.ExceptionID] = exceptionData
					log.WithContext(ctx).Infof(
						"exception data: %+v for tenant: %v asset: %v",
						exceptionData, tenant, qExceptionData.AssetID,
					)
				} else {
					log.WithContext(ctx).Errorf(
						"unexpected duplicate exception %v for tenant: %v asset: %v",
						qExceptionData.ExceptionID, tenant, qExceptionData.AssetID,
					)
					continue
				}
			}
		}
	}

	return mongoModel
}

func recoverReadiness(
	elapsedTimeHours float64,
	data models.GeneralStatsData,
	trustedSources models.TrustedSourcesPolicy) (int, int64) {
	if elapsedTimeHours < readinessKindergartenTimeThreshold ||
		data.TotalRequests < readinessKindergartenRequestsThreshold {
		return readinessKindergarten, data.TotalRequests
	}
	if elapsedTimeHours < readinessPrimarySchoolTimeThreshold ||
		data.TotalRequests < readinessPrimarySchoolMaxRequests {
		return readinessPrimarySchool, data.TotalRequests
	}
	if elapsedTimeHours < readinessHighSchoolTimeThreshold ||
		data.TotalRequests < readinessHighSchoolMaxRequests {
		return readinessHighSchool, data.TotalRequests
	}
	trustedSourcesCount := countTrustedSources(trustedSources)
	if elapsedTimeHours < readinessGraduateTimeThreshold ||
		data.TotalRequests < readinessGraduateMaxRequests ||
		trustedSourcesCount < trustedSources.NumOfSources+2 {
		return readinessGraduate, data.Count
	}
	if elapsedTimeHours < readinessMasterTimeThreshold ||
		data.TotalRequests < readinessMasterMaxRequests ||
		trustedSourcesCount < trustedSources.NumOfSources+5 {
		return readinessMaster, data.Count
	}
	return readinessPHD, data.TotalRequests
}

func maxRequests(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

type readinessNextLevelRequirements struct {
	requests       int64
	learningHours  int
	trustedSources int
}

func readinessTooltip(
	readiness int,
	requests int64,
	prevReqCount int64,
	elapsedTime time.Duration,
	trustedSourcesPolicy models.TrustedSourcesPolicy,
) (string, readinessNextLevelRequirements) {
	nextLevelRequirements := readinessNextLevelRequirements{
		requests:       0,
		learningHours:  0,
		trustedSources: 0,
	}
	retFormat := "To advance to the next level, %v are required"
	switch readiness {
	case readinessNoData:
		nextLevelRequirements.requests = 1
		return readinessTPNoData, nextLevelRequirements
	case readinessKindergarten:
		var tooltip []string
		if requests < readinessKindergartenRequestsThreshold {
			nextLevelRequirements.requests = readinessKindergartenRequestsThreshold - requests
			tooltip = append(
				tooltip, fmt.Sprintf(
					readinessTPRequestsFormat,
					readinessKindergartenRequestsThreshold-requests,
				),
			)
		}
		if elapsedTime.Hours() < readinessKindergartenTimeThreshold {
			nextLevelRequirements.learningHours = readinessKindergartenTimeThreshold - int(elapsedTime.Hours())
			tooltip = append(
				tooltip, fmt.Sprintf(
					readinessTPTimeFormat,
					readinessKindergartenTimeThreshold-int(elapsedTime.Hours()),
				),
			)
		}
		ret := strings.Join(tooltip, " and ")
		if ret != "" {
			ret = fmt.Sprintf(retFormat, ret)
		} else {
			return "ready to proceed to primary school", nextLevelRequirements
		}
		return ret, nextLevelRequirements
	case readinessPrimarySchool:
		var tooltip []string
		nextLevelRequestThreshold := maxRequests(prevReqCount*2, readinessPrimarySchoolMaxRequests)
		if requests < nextLevelRequestThreshold {
			nextLevelRequirements.requests = nextLevelRequestThreshold - requests
			tooltip = append(
				tooltip, fmt.Sprintf(
					readinessTPRequestsFormat,
					nextLevelRequestThreshold-requests,
				),
			)
		}
		if elapsedTime.Hours() < readinessPrimarySchoolTimeThreshold {
			nextLevelRequirements.learningHours = readinessPrimarySchoolTimeThreshold - int(elapsedTime.Hours())
			tooltip = append(
				tooltip, fmt.Sprintf(
					readinessTPTimeFormat,
					readinessPrimarySchoolTimeThreshold-int(elapsedTime.Hours()),
				),
			)
		}
		ret := strings.Join(tooltip, " and ")
		if ret != "" {
			ret = fmt.Sprintf(retFormat, ret)
		} else {
			return "ready to proceed to high school", nextLevelRequirements
		}
		return ret, nextLevelRequirements
	case readinessHighSchool:
		nextLevelRequestThreshold := maxRequests(prevReqCount*2, readinessHighSchoolMaxRequests)
		var tooltip []string
		if requests < nextLevelRequestThreshold {
			nextLevelRequirements.requests = nextLevelRequestThreshold - requests
			tooltip = append(
				tooltip, fmt.Sprintf(
					readinessTPRequestsFormat,
					nextLevelRequestThreshold-requests,
				),
			)
		}
		if elapsedTime.Hours() < readinessHighSchoolTimeThreshold {
			nextLevelRequirements.learningHours = readinessHighSchoolTimeThreshold - int(elapsedTime.Hours())
			tooltip = append(
				tooltip, fmt.Sprintf(
					readinessTPTimeFormat,
					readinessHighSchoolTimeThreshold-int(elapsedTime.Hours()),
				),
			)
		}
		ret := strings.Join(tooltip, " and ")
		if ret != "" {
			ret = fmt.Sprintf("To graduate, %v are required", ret)
		} else {
			return "ready to graduate", nextLevelRequirements
		}
		return ret, nextLevelRequirements
	case readinessGraduate:
		var tooltip []string
		nextLevelRequestThreshold := maxRequests(prevReqCount*2, readinessGraduateMaxRequests)
		if requests < nextLevelRequestThreshold {
			tooltip = append(
				tooltip, fmt.Sprintf(
					readinessTPRequestsFormat,
					nextLevelRequestThreshold-requests,
				),
			)
		}
		if elapsedTime.Hours() < readinessGraduateTimeThreshold {
			nextLevelRequirements.learningHours = readinessGraduateTimeThreshold - int(elapsedTime.Hours())
			tooltip = append(
				tooltip, fmt.Sprintf(
					readinessTPTimeFormat,
					readinessGraduateTimeThreshold-int(elapsedTime.Hours()),
				),
			)
		}
		trustedSourcesCount := countTrustedSources(trustedSourcesPolicy)
		if trustedSourcesCount < trustedSourcesPolicy.NumOfSources+2 {
			nextLevelRequirements.trustedSources = trustedSourcesPolicy.NumOfSources + 2 - trustedSourcesCount
			tooltip = append(
				tooltip, fmt.Sprintf(
					readinessTPTrustedSourcesFormat,
					trustedSourcesPolicy.NumOfSources+2-trustedSourcesCount,
				),
			)
		}
		ret := strings.Join(tooltip, " and ")
		if ret != "" {
			ret = fmt.Sprintf("To become a master, %v are required", ret)
		} else {
			return "ready to proceed to Master", nextLevelRequirements
		}
		return ret, nextLevelRequirements
	case readinessMaster:
		var tooltip []string
		nextLevelRequestThreshold := maxRequests(prevReqCount*2, readinessMasterMaxRequests)
		if requests < nextLevelRequestThreshold {
			nextLevelRequirements.requests = nextLevelRequestThreshold - requests
			tooltip = append(
				tooltip, fmt.Sprintf(
					readinessTPRequestsFormat,
					nextLevelRequestThreshold-requests,
				),
			)
		}
		if elapsedTime.Hours() < readinessMasterTimeThreshold {
			nextLevelRequirements.learningHours = readinessMasterTimeThreshold - int(elapsedTime.Hours())
			tooltip = append(
				tooltip, fmt.Sprintf(
					readinessTPTimeFormat,
					readinessMasterTimeThreshold-int(elapsedTime.Hours()),
				),
			)
		}
		trustedSourcesCount := countTrustedSources(trustedSourcesPolicy)
		if trustedSourcesCount < trustedSourcesPolicy.NumOfSources+5 {
			nextLevelRequirements.trustedSources = trustedSourcesPolicy.NumOfSources + 5 - trustedSourcesCount
			tooltip = append(
				tooltip, fmt.Sprintf(
					readinessTPTrustedSourcesFormat,
					trustedSourcesPolicy.NumOfSources+5-trustedSourcesCount,
				),
			)
		}
		ret := strings.Join(tooltip, " and ")
		if ret != "" {
			ret = fmt.Sprintf("To get your PhD, %v are required", ret)
		} else {
			return "ready to proceed to PhD", nextLevelRequirements
		}
		return ret, nextLevelRequirements
	}

	return "", readinessNextLevelRequirements{}
}

func (sa *StandAlone) recommendationToolTip(ctx context.Context, stats *models.Statistics,
	readinessTP readinessNextLevelRequirements) string {
	if stats.Readiness >= readinessGraduate && stats.MitigationMode == "" {
		policyVersion, err := sa.policyDetails.GetPolicyVersion(ctx, stats.TenantID, sa.uuid)
		if err != nil {
			log.WithContext(ctx).Errorf("failed to get policy version for tenant, err: %s", err)
			return recommendationTPKeepLearningImproveProtection
		}
		assetDetails, err := sa.policyFetch.GetPolicyDetails(ctx, stats.TenantID, stats.AssetID, int64(policyVersion))
		if err != nil {
			log.WithContext(ctx).Errorf("failed to get asset details from policy, err: %s", err)
			return recommendationTPKeepLearningImproveProtection
		}
		sa.db.ReportAsset(ctx, models.ReportAssetPolicyData, stats.TenantID, stats.AssetID, assetDetails)
		stats.MitigationMode = assetDetails.Mode
		stats.MitigationLevel = assetDetails.Level
	}
	switch stats.Recommendation {
	case recommendationNoData:
		return recommendationTPVerifyInstallation
	case recommendationKeepLearning:
		var reqs []string
		if readinessTP.requests > 0 {
			reqs = append(reqs, "HTTP requests")
		}
		if readinessTP.learningHours > 0 || len(reqs) == 0 {
			reqs = append(reqs, "time")
		}
		return recommendationTPKeepLearningBase + strings.Join(reqs, " and ")
	case recommendationReviewCriticalTuning:
		return recommendationTPReviewCriticalTuning
	case recommendationPreventCritical:
		if stats.MitigationMode == "Detect" {
			return recommendationTPMoveToPreventCritical
		}
		if stats.MitigationLevel == "Critical" {
			return recommendationTPKeepLearningImproveProtectionToHigh
		}
		return recommendationTPKeepLearningImproveProtection
	case recommendationReviewTuning:
		return recommendationTPReviewTuning
	case recommendationPreventHigh:
		if stats.MitigationMode == "Detect" || stats.MitigationLevel == "Critical" {
			return recommendationTPMoveToPreventHigh
		}
		return recommendationTPKeepImproving
	}
	return ""
}

func recommendationDisplayName(recommendation int) string {
	switch recommendation {
	case recommendationNoData:
		return recommendationDPNoData
	case recommendationKeepLearning:
		return recommendationDPKeepLearning
	case recommendationReviewCriticalTuning:
		return recommendationDPReviewCritical
	case recommendationPreventCritical:
		return recommendationDPPreventCritical
	case recommendationReviewTuning:
		return recommendationDPReview
	case recommendationPreventHigh:
		return recommendationDPPrevent
	}
	return ""
}

func readinessDisplayName(readiness int) string {
	switch readiness {
	case readinessNoData:
		return readinessDPNoData
	case readinessKindergarten:
		return readinessDPKindergarten
	case readinessPrimarySchool:
		return readinessDPPrimarySchool
	case readinessHighSchool:
		return readinessDPHighSchool
	case readinessGraduate:
		return readinessDPGraduate
	case readinessMaster:
		return readinessDPMaster
	case readinessPHD:
		return readinessDPPHD
	}
	return ""
}

func (sa *StandAlone) processTuning(
	ctx context.Context,
	response models.QueryResponse,
	severity models.QueryResponse,
	filter assetsFilter,
) map[models.AssetInfo]Tune {
	log.WithContext(ctx).Debugf("processing tuning. args: response : %+v, severity: %+v, assets: %v", response,
		severity, filter)
	tuning := make(map[models.AssetInfo]Tune, 0)
	cr := criteria{}
	if sa.config.IsSet(confKeyTuningThresholdRatio) {
		ratio := sa.config.Get(confKeyTuningThresholdRatio)
		cr.minRatio = ratio.(float64)
	} else {
		cr.minRatio = criteriaTuningRatioThresholdDefault
		log.WithContext(ctx).Warn("minRatio criterion is not set")
	}
	count, err := sa.config.GetInt(confKeyTuningThresholdCount)
	if err == nil {
		cr.minEventsCount = count
	} else {
		cr.minEventsCount = criteriaTuningCountThresholdDefault
		log.WithContext(ctx).Warn("failed to get minEventsCount criterion", err)
	}
	for tenant, assetCtx := range response {
		ctxPerTenenat := ctxutils.Insert(ctx, ctxutils.ContextKeyTenantID, tenant)
		for asset, payload := range assetCtx {
			if filter.shouldFilterAsset(asset) {
				log.WithContext(ctx).Infof("asset: %v is not in asset map %v", asset, filter)
				continue
			}
			runtime.Gosched()

			if len(payload) == 0 {
				log.WithContext(ctxPerTenenat).Warnf("got empty response for tenant: %v, asset: %v", tenant, asset)
				continue
			}

			var tuningDecidedIfc interface{}
			err = sa.db.GetAssetData(ctxPerTenenat, models.ReportTuningDecided, tenant, asset, &tuningDecidedIfc)
			if err != nil {
				if errors.IsClass(err, errors.ClassUnauthorized) {
					log.WithContext(ctxPerTenenat).Infof("asset %v of tenant %v is unreachable", asset, tenant)
					continue
				}
				log.WithContext(ctxPerTenenat).Warnf("failed to fetch decided tuning events, err: %v", err)
			}
			tuningDecided, ok := tuningDecidedIfc.(*[]models.TuneEvent)
			if !ok {
				log.WithContext(ctxPerTenenat).Warnf("failed to fetch decided tuning events, type mismatch: %T",
					tuningDecidedIfc)
				tuningDecided = &[]models.TuneEvent{}
			}

			tune := Tune{AssetInfo: models.AssetInfo{TenantID: tenant, AssetID: asset}}
			decisions, err := sa.s3.GetDecisions(ctxPerTenenat, tenant, asset)
			if err != nil {
				log.WithContext(ctxPerTenenat).Warnf("failed to fetch parameters, err: %v", err)
			}

			qTuningEvents := make([]models.TuningQueryData, len(payload))
			for _, row := range payload {
				qTuningEvents = append(qTuningEvents, row.(models.TuningQueryData))
			}

			qTuningEvents = collapse(qTuningEvents)

			for _, tuningQueryData := range qTuningEvents {
				runtime.Gosched()
				tuneData := models.TuneEvent{AttackTypes: []string{}}
				numOfSources := int(tuningQueryData.SourcesCount)
				numOfURLs := int(tuningQueryData.URLsCount)
				numOfRequests := int(tuningQueryData.Count)

				tuneData.Severity = strings.ToLower(tuningQueryData.Severity)
				tuneData.AttackTypes = tuningQueryData.AttackTypes
				tuneData.EventType = tuningQueryData.ExtraFieldName
				tuneData.EventTitle = tuningQueryData.ExtraFieldValue

				if !checkTuningCriteria(tuningQueryData, severity[tenant][asset], cr) {
					continue
				}

				tuneData.Metrics = append(
					tuneData.Metrics,
					models.Metric{MetricKey: metricEventsCount, Count: numOfRequests},
				)

				switch tuneData.EventType {
				case models.EventTypeURL:
					tuneData.Metrics = append(
						tuneData.Metrics,
						models.Metric{MetricKey: metricSourcesCount, Count: numOfSources},
					)
				case models.EventTypeSource:
					tuneData.Metrics = append(
						tuneData.Metrics,
						models.Metric{MetricKey: metricURLCount, Count: numOfURLs},
					)
				default:
					tuneData.Metrics = append(
						tuneData.Metrics,
						models.Metric{MetricKey: metricSourcesCount, Count: numOfSources},
					)
					tuneData.Metrics = append(
						tuneData.Metrics,
						models.Metric{MetricKey: metricURLCount, Count: numOfURLs},
					)
				}
				tuneData.LogQuery = sa.lr.GenerateLogQuery(tuneData, tuningQueryData.AssetName)
				runtime.Gosched()
				tuneData.Decision = sa.getDecision(decisions, *tuningDecided, tuneData.EventType, tuneData.EventTitle)
				if tuneData.Decision != models.DecisionUnknown {
					continue
				}
				tuneID, err := uuid.NewUUID()
				if err != nil {
					log.WithContext(ctxPerTenenat).Warnf("failed to generate uuid for tuneData, err: %v", err)
					return nil
				}
				tuneData.ID = tuneID.String()
				tune.Tuning = append(tune.Tuning, tuneData)
			}
			assetInfo := models.AssetInfo{
				TenantID: tune.TenantID,
				AssetID:  tune.AssetID,
			}
			tuning[assetInfo] = tune
			runtime.Gosched()
		}
	}
	if len(tuning) > 0 {
		log.WithContext(ctx).Infof("generated tuning events: %v", tuning)
	}
	return tuning
}

func checkTuningCriteria(tuningData models.TuningQueryData, severities models.GroupedResponse, cr criteria) bool {
	if tuningData.Count >= int64(cr.minEventsCount) {
		return true
	}
	for _, assetData := range severities {
		severityData := assetData.(models.SeverityStatsData)
		count := severityData.CriticalSeverityRequests
		if "Critical" != tuningData.Severity {
			count = severityData.HighSeverityRequests
		}
		// at least 10% of all events
		return float64(tuningData.Count) >= float64(count)/(100.0/cr.minRatio)
	}
	log.Warnf("severity %v not found in %v", tuningData.Severity, severities)
	return false
}

func collapse(tuningEvents []models.TuningQueryData) []models.TuningQueryData {
	collapsedTuningEvents := make([]models.TuningQueryData, 0, len(tuningEvents))
	logIDsCount := map[int64]int{}
	for _, tuningEvent := range tuningEvents {
		for _, logID := range tuningEvent.LogIDs {
			if _, ok := logIDsCount[logID]; !ok {
				logIDsCount[logID] = 0
			}
			logIDsCount[logID]++
		}
	}
	collapsingPriorities := map[string]int{
		models.EventTypeParamVal: 1,
		models.EventTypeURL:      2, models.EventTypeSource: 3, models.EventTypeParamName: 4,
	}
	sort.Slice(
		tuningEvents, func(i, j int) bool {
			if tuningEvents[i].Count < tuningEvents[j].Count {
				return true
			}
			if tuningEvents[i].Count == tuningEvents[j].Count {
				return collapsingPriorities[tuningEvents[i].ExtraFieldName] < collapsingPriorities[tuningEvents[j].ExtraFieldName]
			}
			return false
		},
	)
	for _, tuningEvent := range tuningEvents {
		if isEventContained(logIDsCount, tuningEvent) {
			removeLogIDsCount(logIDsCount, tuningEvent)
			continue
		}
		collapsedTuningEvents = append(collapsedTuningEvents, tuningEvent)
	}
	return collapsedTuningEvents
}

func removeLogIDsCount(m map[int64]int, event models.TuningQueryData) {
	for _, logID := range event.LogIDs {
		m[logID]--
	}
}

func isEventContained(count map[int64]int, event models.TuningQueryData) bool {
	counter := 0
	maxNonContained := len(event.LogIDs) * containmentThreshold / 100
	for _, logID := range event.LogIDs {
		if c := count[logID]; c == 1 {
			counter++
			if counter > maxNonContained {
				return false
			}
		}
	}
	return true
}

type assetsFilter map[string]string

func newAssetsFilter(tenantData models.ProcessTenantNotification) assetsFilter {
	assetsMap := make(assetsFilter, len(tenantData.Assets))
	for _, asset := range tenantData.Assets {
		assetsMap[asset.MgmtID] = asset.IntelligenceID
	}
	return assetsMap
}

func (f assetsFilter) shouldFilterAsset(assetID string) bool {
	if _, ok := f["*"]; ok {
		return false
	}
	_, ok := f[assetID]
	return !ok
}

func (sa *StandAlone) processLogs(ctx context.Context, tenantData models.ProcessTenantNotification) error {

	filter := newAssetsFilter(tenantData)

	logQuery, err := sa.lr.TuneLogQuery(ctx, tenantData.TenantID)
	if err != nil {
		return errors.Wrap(err, "failed to query for tuning data")
	}
	qResp, err := sa.lr.GeneralLogQuery(ctx, tenantData.TenantID)
	if err != nil {
		return errors.Wrap(err, "failed to query general statistics")
	}
	qRespSev, err := sa.lr.SeverityLogQuery(ctx, tenantData.TenantID)
	if err != nil {
		return errors.Wrap(err, "failed to query severity statistics")
	}

	tuning := sa.processTuning(ctx, logQuery, qRespSev, filter)

	for _, tune := range tuning {
		log.WithContext(ctx).Infof("reporting tuning events undecided: %v", tune)
		err = sa.db.ReportAsset(
			ctx, models.ReportTuning, tune.TenantID, tune.AssetID, tune.Tuning,
		)
		if err != nil {
			log.Warnf("failed to report asset. error %v", err)
		}
	}

	stats := sa.processStats(ctx, qResp, qRespSev, filter)

	for _, s := range stats {
		err = sa.db.ReportAsset(
			ctx, models.ReportStatistics, s.TenantID, s.AssetID, s,
		)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to report asset. error %v", err)
		}
		if _, ok := tuning[s.AssetInfo]; !ok {
			err = sa.db.ReportAsset(
				ctx, models.ReportTuning, s.TenantID, s.AssetID, []models.TuneEvent{},
			)
			if err != nil {
				log.WithContext(ctx).Warnf("failed to report asset. error %v", err)
			}
		}
	}

	qExceptionsResp, err := sa.lr.ExceptionsLogQuery(ctx, tenantData.TenantID)
	if err != nil {
		return errors.Wrap(err, "failed to query for exceptions data")
	}

	assetToExceptionsMap := processExceptions(ctx, qExceptionsResp)
	for assetInfo, exceptionsData := range assetToExceptionsMap {
		err = sa.db.ReportAsset(
			ctx, models.ReportAssetExceptions, assetInfo.TenantID, assetInfo.AssetID, exceptionsData,
		)
		if err != nil {
			log.WithContext(ctx).Warnf(
				"failed to report exceptions data for asset %v in tenant %v. error %v",
				assetInfo.AssetID, assetInfo.TenantID, err,
			)
		}
	}

	return nil
}

// ProcessTable - process the logs from a specific table
func (sa *StandAlone) ProcessTable(ctx context.Context, tenantData models.ProcessTenantNotification) error {
	return sa.processLogs(ctx, tenantData)
}

// TriggerProcess - process the logs from a all tables
func (sa *StandAlone) TriggerProcess(ctx context.Context) error {
	return sa.processLogs(ctx, models.ProcessTenantNotification{Assets: []models.ProcessAsset{{"*", "*"}}})
}

//HandleLog insert log to logs repository
func (sa *StandAlone) HandleLog(ctx context.Context, log *models.AgentMessage) error {
	if log.Log != nil {
		if len(log.Log.EventSource.AssetID) > 0 && log.Log.EventSource.AssetID[len(log.Log.EventSource.AssetID)-1] == '/' {
			log.Log.EventSource.AssetID = log.Log.EventSource.AssetID[:len(log.Log.EventSource.AssetID)-1]
		}
		if len(log.Log.EventData.AssetID) > 0 && log.Log.EventData.AssetID[len(log.Log.EventData.AssetID)-1] == '/' {
			log.Log.EventData.AssetID = log.Log.EventData.AssetID[:len(log.Log.EventSource.AssetID)-1]
		}
	}
	return sa.lr.InsertLog(ctx, log)
}
