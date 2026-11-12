package tuning

import (
	"context"
	"fmt"
	"hash/fnv"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"openappsec.io/smartsync-tuning/models"

	"openappsec.io/ctxutils"
	"openappsec.io/errors"
	"openappsec.io/log"
)

const (
	statusReady    = "ready"
	statusNotReady = "notReady"

	readinessDPNoData        = "No Data"
	readinessDPKindergarten  = "Kindergarten"
	readinessDPPrimarySchool = "Primary School"
	readinessDPHighSchool    = "High School"
	readinessDPGraduate      = "Graduate"
	readinessDPMaster        = "Master"
	readinessDPPHD           = "PHD"

	readinessTPNoData = "At least one HTTP request is required"

	readinessNoData        = 0
	readinessKindergarten  = 1
	readinessPrimarySchool = 2
	readinessHighSchool    = 3
	readinessGraduate      = 4
	readinessMaster        = 5
	readinessPHD           = 6

	readinessKindergartenTimeThreshold  = 6
	readinessPrimarySchoolTimeThreshold = 24
	readinessHighSchoolTimeThreshold    = 72
	readinessGraduateTimeThreshold      = 7 * 24
	readinessMasterTimeThreshold        = 9 * 24

	readinessKindergartenRequestsThreshold = 1000
	readinessPrimarySchoolMaxRequests      = 10000
	readinessPrimarySchoolMaxRequests2     = 25000
	readinessHighSchoolMaxRequests         = 50000
	readinessGraduateMaxRequests           = 1000000
	readinessMasterMaxRequests             = 10000000

	readinessMinConfidenceLevel = 20

	recommendationDPNoData          = "Send Traffic"
	recommendationDPKeepLearning    = "Keep Learning"
	recommendationDPReviewCritical  = "Review Tuning Suggestions With Critical Severity"
	recommendationDPPreventCritical = "Prevent Critical Severity"
	recommendationDPReview          = "Review Tuning Suggestions"
	recommendationDPPrevent         = "Prevent High Severity And Above"

	recommendationNoData               = 0
	recommendationKeepLearning         = 1
	recommendationReviewCriticalTuning = 2
	recommendationPreventCritical      = 3
	recommendationReviewTuning         = 4
	recommendationPreventHigh          = 5

	recommendationTPVerifyInstallation    = "Verify agent installation"
	recommendationTPKeepLearningBase      = "The learning mechanism requires additional "
	recommendationTPMoveToPreventCritical = "The system is ready to prevent critical severity events." +
		" Please navigate to threat prevention tab and change the web attacks practice settings." +
		" We will recommend to prevent high severity events upon getting a PhD"
	recommendationTPKeepLearningImproveProtection       = "Well done! The asset is protected and critical severity events will be blocked!"
	recommendationTPKeepLearningImproveProtectionToHigh = recommendationTPKeepLearningImproveProtection +
		" We will recommend to prevent high severity events upon getting a PhD"
	recommendationTPReviewCriticalTuning = "The learning mechanism generated critical tuning suggestions, " +
		"review them and decide whether the events are malicious or benign"
	recommendationTPReviewTuning = "The learning mechanism generated tuning suggestions, " +
		"review them and decide whether the events are malicious or benign"
	recommendationTPKeepImproving     = "Well done! The asset is protected and high and critical severity events will be blocked!"
	recommendationTPMoveToPreventHigh = "The system is ready to prevent high and critical severity events." +
		" Please navigate to threat prevention tab and change the web attacks practice settings"

	severityCritical = "Critical"
	severityHigh     = "High"

	dataNameStatistics = "statistics"
	dataNameTuning     = "tuningEvents"

	metricEventsCount  = "events"
	metricSourcesCount = "sources"
	metricURLCount     = "urls"

	criteriaTuningCountThresholdDefault = 50
	criteriaTuningRatioThresholdDefault = 10.0

	containmentThreshold = 10

	dayUNIXTime  = 60 * 60 * 24
	minTimestamp = 1577836800

	readinessTPRequestsFormat       = "at least %v additional HTTP requests"
	readinessTPTimeFormat           = "%v additional learning hours"
	readinessTPTrustedSourcesFormat = "configuration of at least %v additional trusted sources"
)

// Tune represents the collection of tuning events for a tenant's asset
type Tune struct {
	models.AssetInfo
	Tuning []models.TuneEvent `json:"tuningEvents"`
}

type criteria struct {
	minEventsCount int
	minRatio       float64
}

func (t *Tuning) getTenants() ([]string, error) {
	tenants, err := t.config.GetString(confKeyTuningTenantsList)
	if err != nil {
		return []string{}, errors.Wrap(err, "tenants list is not set")
	}
	if tenants == "" {
		return []string{}, errors.New("tenants list is empty")
	}
	tenantsList := strings.Split(tenants, ",")
	for i, tenant := range tenantsList {
		tenantsList[i] = strings.Trim(tenant, " ")
	}
	return tenantsList, nil
}

// Tokenize creates patterns periodically and report to s3
func (t *Tuning) Tokenize(ctx context.Context) error {
	tenantsList, err := t.getTenants()
	if err != nil {
		log.WithContext(ctx).Warnf("failed to get tenants list. error: %v", err)
		return errors.Wrap(err, " failed to get tenants list")
	}
	allURIs, err := t.lr.GetUrlsToCollapse(ctx, tenantsList)
	if err != nil {
		return errors.Wrap(err, "failed to get uris to tokenize")
	}
	allParams, err := t.lr.GetParamsToCollapse(ctx, tenantsList)
	if err != nil {
		return errors.Wrap(err, "failed to get params to tokenize")
	}

	allPatterns := map[string]map[string]models.Tokens{}

	for tenantID, tenantData := range allURIs {
		if _, ok := allPatterns[tenantID]; !ok {
			allPatterns[tenantID] = make(map[string]models.Tokens)
		}
		for assetID, assetData := range tenantData {
			patterns := models.Tokens{}
			var nonClustered []string
			for _, data := range assetData {
				uris := data.(models.UrlsToCollapse)
				p, nc := collapseUrls(uris.Urls)
				patterns.URIsPatterns = append(patterns.URIsPatterns, p...)
				nonClustered = append(nonClustered, nc...)
			}
			log.WithContext(ctx).Infof(
				"generated patterns: %v, non clustered(%v): %v for asset: %v of tenant: %v",
				patterns, len(nonClustered), nonClustered, assetID, tenantID,
			)
			allPatterns[tenantID][assetID] = patterns
		}
	}
	for tenantID, tenantData := range allParams {
		if _, ok := allPatterns[tenantID]; !ok {
			allPatterns[tenantID] = make(map[string]models.Tokens)
		}
		for assetID, assetData := range tenantData {
			if _, ok := allPatterns[tenantID][assetID]; !ok {
				allPatterns[tenantID][assetID] = models.Tokens{}
			}
			patterns := allPatterns[tenantID][assetID]
			var nonClustered []string
			for _, data := range assetData {
				params := data.(models.ParamsToCollapse)
				p, nc := collapseParams(params.Params)
				patterns.ParamsPatterns = append(patterns.ParamsPatterns, p...)
				nonClustered = append(nonClustered, nc...)
			}
			log.WithContext(ctx).Infof(
				"generated params patterns: %v, non clustered(%v): %v for asset: %v of tenant: %v",
				patterns, len(nonClustered), nonClustered, assetID, tenantID,
			)
			allPatterns[tenantID][assetID] = patterns
		}
	}
	for tenantID, tenantData := range allPatterns {
		for assetID, assetData := range tenantData {
			patterns := assetData
			if len(patterns.URIsPatterns) == 0 && len(patterns.ParamsPatterns) == 0 {
				continue
			}
			origData, err := t.s3.GetPatterns(ctx, tenantID, assetID)
			if err != nil {
				log.WithContext(ctx).Warnf("failed to get current tokens for merging")
			} else {
				patterns.URIsPatterns = mergePatterns(origData.URIsPatterns, patterns.URIsPatterns)
				patterns.ParamsPatterns = mergePatterns(origData.ParamsPatterns, patterns.ParamsPatterns)
			}
			err = t.s3.PostPatterns(ctx, tenantID, assetID, patterns)
			if err != nil {
				return errors.Wrapf(
					err, "failed to post patterns to tenant: %v asset: %v",
					tenantID, assetID,
				)
			}
		}
	}
	return nil
}

func sliceContains(container [][]string, elem []string) bool {
	for _, existingTokens := range container {
		if len(elem) == len(existingTokens) {
			sort.Strings(elem)
			sort.Strings(existingTokens)
			if reflect.DeepEqual(elem, existingTokens) {
				return true
			}
		}
	}
	return false
}

func mergePatterns(base [][]string, newPatterns [][]string) [][]string {
	for _, tokens := range newPatterns {
		if !sliceContains(base, tokens) {
			base = append(base, tokens)
		}
	}
	return base
}

func readinessLevel(
	prevLevel int,
	elapsedTime int64,
	requestsCount int64,
	prevRequestsCount int64,
	learnRatio float64,
	suggestions []models.TuneEvent,
	decisions []models.TuneEvent,
	trustedSources models.TrustedSourcesPolicy,
) int {
	trustedSourcesCount := countTrustedSources(trustedSources)
	switch prevLevel {
	case readinessNoData:
		if requestsCount > 0 {
			return prevLevel + 1
		}
	case readinessKindergarten:
		if elapsedTime >= readinessKindergartenTimeThreshold && requestsCount >= readinessKindergartenRequestsThreshold {
			return prevLevel + 1
		}
	case readinessPrimarySchool:
		if requestsCount < 2*prevRequestsCount || requestsCount < readinessPrimarySchoolMaxRequests {
			break
		}
		if elapsedTime >= readinessPrimarySchoolTimeThreshold ||
			(elapsedTime >= 18 &&
				learnRatio >= 0.1 &&
				requestsCount >= readinessPrimarySchoolMaxRequests2) {
			return prevLevel + 1
		}
	case readinessHighSchool:
		if requestsCount < 2*prevRequestsCount || requestsCount < readinessHighSchoolMaxRequests {
			break
		}
		if elapsedTime >= 72 {
			return prevLevel + 1
		}
		if elapsedTime >= 48 && learnRatio >= 0.3 {
			return prevLevel + 1
		}
	case readinessGraduate:
		if trustedSourcesCount < 2+trustedSources.NumOfSources {
			break
		}
		if requestsCount < 2*prevRequestsCount || requestsCount < readinessGraduateMaxRequests {
			break
		}
		countCriticalSuggestions := 0
		for _, event := range suggestions {
			if strings.ToLower(event.Severity) == "critical" {
				countCriticalSuggestions++
			}
		}
		if elapsedTime >= 7*24 {
			return prevLevel + 1
		}
		if countCriticalSuggestions >= 2 {
			break
		}
		if elapsedTime >= 5*24 {
			return prevLevel + 1
		}
		if elapsedTime >= 72 && len(decisions) > 0 {
			return prevLevel + 1
		}
	case readinessMaster:
		if trustedSourcesCount < 5+trustedSources.NumOfSources {
			break
		}
		if requestsCount < 2*prevRequestsCount || requestsCount < readinessMasterMaxRequests {
			break
		}
		if elapsedTime >= 9*24 {
			return prevLevel + 1
		}
		countSuggestions := len(suggestions)
		if countSuggestions >= 2 {
			break
		}
		if elapsedTime >= 7*24 {
			return prevLevel + 1
		}
		if elapsedTime >= 4*24 && learnRatio > 0.5 {
			return prevLevel + 1
		}
	case readinessPHD:
	default:
		return -1
	}
	return prevLevel
}

func countTrustedSources(policy models.TrustedSourcesPolicy) int {
	ipv4re := regexp.MustCompile("(?:\\d+\\.){3}\\d+(/\\d+)?")
	count := 0
	for _, srcID := range policy.SourcesIdentifiers {
		match := ipv4re.FindStringSubmatch(srcID.Value)
		if match == nil {
			if strings.Contains(srcID.Value, "*") {
				count += 5
				continue
			}
			count++
			continue
		}
		if match[1] == "" {
			count++
			continue
		}
		cidrMask, err := strconv.Atoi(match[1][1:])
		if err != nil {
			log.Warnf("failed to calculate cidr mask from %v, err: %v", match[1][1:], err)
		} else {
			count += int(math.Pow(2, float64(32-cidrMask)))
		}
	}
	return count
}

func recommendationLevel(readinessLevel int, suggestions []models.TuneEvent) int {
	if readinessLevel < 0 {
		return -1
	}
	if readinessLevel == 0 {
		return recommendationNoData
	}
	if readinessLevel == readinessGraduate || readinessLevel == readinessMaster {
		criticalCount := 0
		for _, suggestion := range suggestions {
			if strings.ToLower(suggestion.Severity) == "critical" {
				criticalCount++
			}
		}
		if criticalCount == 0 {
			return recommendationPreventCritical
		}
		return recommendationReviewCriticalTuning
	}
	if readinessLevel == readinessPHD {
		if len(suggestions) == 0 {
			return recommendationPreventHigh
		}
		return recommendationReviewTuning
	}
	return recommendationKeepLearning
}

func hasActiveAsset(attributes []models.Attributes) bool {
	for _, atrr := range attributes {
		if atrr.Statistics.StartupTime != 0 {
			return true
		}
	}
	return false
}

// InitTenant deletes from all assets and invalidates all records in the Intelligence cache
// which are associated with the given tenant ID
func (t *Tuning) InitTenant(ctx context.Context, tenantID string) error {
	if err := t.db.DeleteAllAssetsOfTenant(ctx, tenantID); err != nil {
		return errors.Wrapf(err, "failed to delete all assets of tenant")
	}

	log.WithContext(ctx).WithEventID("c696c36a-5bbe-46d4-b3d0-e81ff47a9dfd").
		Debugf("init tenant - successfully deleted all assets from tuning DB, invalidating in intelligence..")

	if err := t.cdb.InitTenantInvalidation(ctx, tenantID); err != nil {
		return errors.Wrapf(err, "failed to invalidate intelligence records")
	}

	return nil
}

// UpdatePolicy updates policy after consuming msg from Kafka
func (t *Tuning) UpdatePolicy(ctx context.Context, msg models.PolicyMessageData) error {
	tenantID := fmt.Sprint(ctxutils.Extract(ctx, ctxutils.ContextKeyTenantID))
	details, err := t.policyFetch.GetPolicy(ctx, tenantID, msg.DownloadPath, msg.Version)
	if err != nil {
		return errors.Wrapf(err, "failed to get assets details for tenant: %v", tenantID)
	}

	if err := t.mpl.BlockingLockTenant(ctx, tenantID); err != nil {
		if err == context.Canceled {
			log.WithContext(ctx).Infof("update is canceled")
			return nil
		}
		return err
	}
	defer func(mpl MultiplePodsLock, ctx context.Context, tenantID string) {
		log.WithContext(ctx).Infof("unlock for tenant: %v", tenantID)
		err := mpl.UnlockTenant(ctx, tenantID)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to unlock for tenant: %v", tenantID)
		}
	}(t.mpl, ctx, tenantID)

	if err := t.db.PruneAssets(ctx, details, msg.Version); err != nil {
		log.WithContext(ctx).Warnf("failed to prune assets: %v", err)
	}
	for _, asset := range details {
		err := t.db.ReportAsset(
			ctx,
			models.ReportAssetPolicyData,
			asset.TenantID,
			asset.AssetID,
			asset,
		)
		if err != nil {
			err = errors.Wrap(err, "failed to report new trusted sources count for asset")
		}
		decisions, err := t.s3.GetDecisions(ctx, asset.TenantID, asset.AssetID)
		if err != nil && !errors.IsClass(err, errors.ClassNotFound) {
			return errors.Wrap(err, "failed to get decisions data from s3 repository")
		}
		isEnforced := false
		for i, decision := range decisions.Decisions {
			if decision.Enforced {
				continue
			}
			isEnforced = true
			decisions.Decisions[i].Enforced = true
		}
		if isEnforced {
			err = t.s3.PostDecisions(ctx, asset.TenantID, asset.AssetID, decisions)
			if err != nil {
				log.WithContext(ctx).Warnf("failed to post decisions. Got error: %v", err)
			}
			err = t.db.ReportAsset(
				ctx,
				models.ReportTuningDecided,
				asset.TenantID,
				asset.AssetID,
				decisions.Decisions,
			)
			if err != nil {
				log.WithContext(ctx).Warnf("failed to report asset. Got error: %v", err)
			}
		}
	}

	return nil
}

// UpdateCertStatus updates the DB with the cert installation status
func (t *Tuning) UpdateCertStatus(ctx context.Context, certStatus models.CertStatus) error {
	return t.db.ReportAsset(
		ctx,
		models.ReportCertificateInstallationStatus,
		certStatus.Tenant,
		certStatus.Asset,
		certStatus.Data,
	)
}

// UpdateUpstreamStatus updates the DB with the cert installation status
func (t *Tuning) UpdateUpstreamStatus(ctx context.Context, upstreamStatus models.UpstreamStatus) error {
	var attr models.Attributes
	err := t.db.GetAssetData(ctx, models.ReportAll, upstreamStatus.Tenant, upstreamStatus.Asset, &attr)
	if err != nil {
		log.WithContext(ctx).Warnf("failed to get asset data, err: %v", err)
	} else {
		if !hasChanged(attr, upstreamStatus) {
			return nil
		}
	}
	return t.db.ReportAsset(
		ctx,
		models.ReportUpstreamHealthcheckStatus,
		upstreamStatus.Tenant,
		upstreamStatus.Asset,
		upstreamStatus,
	)
}

func hasChanged(attr models.Attributes, status models.UpstreamStatus) bool {
	if len(attr.UpstreamStatus) == 0 {
		return true
	}
	version, ok := attr.AgentVersion[status.Data.Agent]
	if !ok || version != status.Version {
		return true
	}
	statusData, ok := attr.UpstreamStatus[status.Data.Agent]
	if !ok || !(status.Data.Status == statusData.Status && status.Data.Message == statusData.Message) {
		// agent id must be equal since it is the map key
		return true
	}
	return false
}

// UpdateFirstRequest updates data in repository if actually first request
func (t *Tuning) UpdateFirstRequest(ctx context.Context, firstRequestData models.FirstRequestNotification) error {
	log.WithContext(ctx).Infof("handling notification for %v", firstRequestData)
	var ret interface{}
	err := t.db.GetAssetData(ctx, models.ReportStatistics, firstRequestData.Tenant, firstRequestData.Asset, &ret)
	stats, ok := ret.(*models.Statistics)
	if !ok && err == nil {
		log.WithContext(ctx).Errorf("Failed to cast %T to %T", ret, stats)
		return nil
	}
	if errors.IsClass(err, errors.ClassUnauthorized) {
		log.WithContext(ctx).Errorf("asset unreachable. err: %v", err)
		return nil
	}
	if errors.IsClass(err, errors.ClassNotFound) || (err == nil && stats.Readiness == 0) {
		stats = &models.Statistics{
			AssetInfo:        models.AssetInfo{TenantID: firstRequestData.Tenant, AssetID: firstRequestData.Asset},
			Status:           statusNotReady,
			ElapsedTime:      "",
			TotalRequests:    1,
			CriticalRequests: 0,
			HighRequests:     0,
			UniqueURLs:       1,
			UniqueSources:    1,
			StartupTime:      time.Now().Unix(),
			LegitRequests:    0,
			MalicRequests:    0,
			Readiness:        1,
			ReadinessDP:      readinessDPKindergarten,
			ReadinessTP:      "",
			PrevLvlReqCount:  0,
			Recommendation:   1,
			RecommendationDP: recommendationDPKeepLearning,
			RecommendationTP: "",
		}
		if firstRequestData.Severity == "Critical" {
			stats.CriticalRequests = 1
			stats.MalicRequests = 1
		} else if firstRequestData.Severity == "High" {
			stats.HighRequests = 1
			stats.MalicRequests = 1
		} else {
			stats.LegitRequests = 1
		}
		nextLevelReqs := readinessNextLevelRequirements{}
		stats.ReadinessTP, nextLevelReqs = readinessTooltip(
			stats.Readiness, 1, 0, time.Millisecond, models.TrustedSourcesPolicy{},
		)
		stats.RecommendationTP = t.recommendationToolTip(ctx, stats, nextLevelReqs)
		err = t.db.ReportAsset(ctx, models.ReportStatistics, firstRequestData.Tenant, firstRequestData.Asset, *stats)
		if err != nil {
			err = errors.Wrap(err, "failed to report new asset")
		}
		return err
	} else if err == nil {
		log.WithContext(ctx).Infof("asset already exists")
		return nil
	}
	return err
}

// ProcessTable - process the logs from a specific table
func (t *Tuning) ProcessTable(ctx context.Context, tenantData models.ProcessTenantNotification) error {
	if tenantData.TenantID == t.elpisTenant {
		log.WithContext(ctx).Infof("detected elpis tenant(%v), not processing", tenantData.TenantID)
		return nil
	}
	// acquire lock
	assetsHash := fnv.New32a()
	for _, asset := range tenantData.Assets {
		_, err := assetsHash.Write([]byte(asset.MgmtID))
		if err != nil {
			log.WithContext(ctx).Warnf("Failed to write asset hash. Got error: %v", err)
		}
	}
	tenantLockKey := fmt.Sprintf("%v_%v", tenantData.TenantID, assetsHash.Sum32())
	if !t.mpl.LockTenant(ctx, tenantLockKey) {
		log.WithContext(ctx).Infof("Tenant %v is already in process", tenantData.TenantID)
		return nil
	}

	err := t.StandAlone.ProcessTable(ctx, tenantData)
	if errors.IsClass(err, errors.ClassNotFound) {
		attributes, errGet := t.db.GetAllAssetsData(ctx, tenantData.TenantID)
		if errGet != nil {
			log.WithContext(ctx).Warnf("failed to get all assets data, err: %v", errGet)
		} else if !hasActiveAsset(attributes) {
			log.WithContext(ctx).Warnf("tenant(%v) has no active asset, err: %v", tenantData.TenantID, err)
			return nil
		}
	}
	return err
}

// GetAll get all tuning data from the repository
func (t *Tuning) GetAll(ctx context.Context, tenantID, assetID string) ([]models.Attributes, error) {
	ctx = ctxutils.Insert(ctx, ctxutils.ContextKeyTenantID, tenantID)

	if assetID == "*" {
		return t.getAllAssetsTuningData(ctx, tenantID)
	}
	return t.getSingleAssetTuningData(ctx, tenantID, assetID)

}

func (t *Tuning) getAllAssetsTuningData(ctx context.Context, tenantID string) ([]models.Attributes, error) {
	data, err := t.db.GetAllAssetsData(ctx, tenantID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get all assets data from repository")
	}
	return data, nil
}

func (t *Tuning) getSingleAssetTuningData(ctx context.Context, tenantID, assetID string) ([]models.Attributes, error) {
	var data models.Attributes
	err := t.db.GetAssetData(ctx, models.ReportAll, tenantID, assetID, &data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get asset data from repository")
	}
	return []models.Attributes{data}, nil
}

// AsyncResponse notifies that async response is ready
func (t *Tuning) AsyncResponse(ctx context.Context, tenantID string, attributesArray []models.Attributes) error {
	for _, attr := range attributesArray {
		t.cdb.Invalidate(ctx, tenantID, attr)
	}
	return nil
}

// RevokeAgent handles clearing agent related data from repo
func (t *Tuning) RevokeAgent(ctx context.Context, agent models.RevokeAgent) error {
	assets, err := t.db.GetAllAssetsData(ctx, agent.TenantID)
	if err != nil {
		return errors.Wrap(err, "failed to get all assets data from repository")
	}
	for _, asset := range assets {
		if _, ok := asset.UpstreamStatus[agent.AgentID]; ok {
			delete(asset.UpstreamStatus, agent.AgentID)
			err = t.db.ReportAsset(ctx, models.ReportAll, agent.TenantID, asset.MgmtID, asset)
			if err != nil {
				return errors.Wrapf(err, "failed to update asset: %v", asset.MgmtID)
			}
		}
	}
	return nil
}
