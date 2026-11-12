package query

import (
	"context"
	"database/sql/driver"
	"fmt"
	"hash/fnv"
	"io"
	"runtime"
	"strings"
	"sync"
	"time"

	"openappsec.io/smartsync-tuning/models"

	"golang.org/x/sync/errgroup"
	"google.golang.org/api/iterator"
	"openappsec.io/errors"
	"openappsec.io/log"
)

const (
	confKeyQuery                         = "query"
	confKeyQueryDurationWarningThreshold = confKeyQuery + ".warningThreshold"
	confKeyQueryDB                       = confKeyQuery + ".db"
	confKeyQueryDBHost                   = confKeyQueryDB + ".host"
	confKeyQueryDBPort                   = confKeyQueryDB + ".port"
	confKeyQueryDBUser                   = confKeyQueryDB + ".user"
	confKeyQueryDBSSLMode                = confKeyQueryDB + ".sslmode"
	confKeyQueryDBPass                   = confKeyQueryDB + ".password"

	maxRetries = 3
)

// Field names for smartview queries
const (
	fieldNameSeverity   = "eventseverity"
	fieldNameSource     = "httpsourceid"
	fieldNameURL        = "httpuripath"
	fieldNameParamName  = "matchedparameter"
	fieldNameParamValue = "matchedsample"
	fieldNameAssetName  = "assetname"
)

const defaultQueryDurationWarningThreshold = 5 * time.Minute
const (
	attackTypeUnknown = "General"
	attackTypeDefault = "uncategorized indication"
)

// GenQueries gen queries per sql server
type GenQueries interface {
	GetTotalRequests(tenantID string) string
	GetGeneralStatsQuery(tenantID string) string
	GetElapsedTime(tenantID string) string
	GetSeverityStatsQuery(tenantID string) string
	GetTuneParameterQuery(parameter string, minCount int, tenantID string) string
	GetTuneURLQueryFormat(minCount int, tenantID string) string
	GetExceptionsQuery(tenantID string) string
	GetParamsForCollapsingFormat(tenantID string) string
	GetUrlsForCollapsingFormat(tenantID string) string
	GetNumOfRequests(tenantID string) string
	GenerateLogQuery(data models.TuneEvent, assetName string) string
	Insert(message *models.AgentMessage) (string, []driver.Value, error)
	CreateTable(id string) (string, error)
	CreateDatabase() string
	CreateTablePartition(id string, eventTime string) (string, error)
	ParseError(err error) errors.Class
	ScanArray(value driver.Value, arr any) error
}

// Adapter for querying datatube in bigquery
type Adapter struct {
	config      Configuration
	driver      driver.Driver
	genQuery    GenQueries
	dbName      string
	rootConn    string
	projectID   string
	datasetID   string
	elpisTenant string
	tenantsList []string
	tenantsLock sync.Locker
}

type converter func(columns []string, data []driver.Value) interface{}

// Configuration used to get the configuration of the datatube dataset
type Configuration interface {
	GetString(key string) (string, error)
	IsSet(key string) bool
	GetDuration(key string) (time.Duration, error)
}

// NewAdapter creates an empty new adapter
func NewAdapter(ctx context.Context, c Configuration, g GenQueries, driver driver.Driver) (*Adapter, error) {
	dbHost, err := c.GetString(confKeyQueryDBHost)
	if err != nil {
		return nil, err
	}

	dbPort, err := c.GetString(confKeyQueryDBPort)
	if err != nil {
		return nil, err
	}

	dbUser, err := c.GetString(confKeyQueryDBUser)
	if err != nil {
		return nil, err
	}

	pass, err := c.GetString(confKeyQueryDBPass)
	if err != nil {
		return nil, err
	}

	sslMode, err := c.GetString(confKeyQueryDBSSLMode)
	if err != nil {
		return nil, err
	}

	dbName := fmt.Sprintf("postgres://%s:%s@%s:%v/i2datatubeschemasecurityeventlogsv03?sslmode=%s",
		dbUser, pass, dbHost, dbPort, sslMode)

	log.WithContext(ctx).Infof("db name: %s", dbName)

	a := &Adapter{config: c, tenantsLock: &sync.Mutex{}, genQuery: g, driver: driver, dbName: dbName}
	return a, nil
}

// SetTenantsList set tenants list to query - if first entry is All queries all tenants in dataset
func (qa *Adapter) setTenantsList(tenants []string) {
	qa.tenantsLock.Lock()
	qa.tenantsList = tenants
}

// GenerateLogQuery created a log query for smartview
func (qa *Adapter) GenerateLogQuery(data models.TuneEvent, assetName string) string {
	return qa.genQuery.GenerateLogQuery(data, assetName)
}

func convertGroupedDataToGeneralStatsData(columns []string, rawData []driver.Value) interface{} {
	data := models.GeneralStatsData{}
	for i, columnName := range columns {
		switch columnName {
		case models.FieldNameTenantID:
			break
		case models.FieldNameAssetID:
			break
		case models.FieldNameStartTime:
			data.StartupTime = rawData[i].(int64)
		case models.FieldNameElapsedTime:
			data.ElapsedTime = rawData[i].(int64)
		case models.FieldNameCountAll:
			data.Count = rawData[i].(int64)
		case models.FieldNameCountURLs:
			data.URLsCount = rawData[i].(int64)
		case models.FieldNameCountSources:
			data.SourcesCount = rawData[i].(int64)
		}
	}
	return data
}

type elapsedTimeStatsData struct {
	ElapsedTime  int64
	RequestCount int64
}

func convertGroupedDataToElapsedTimeStatsData(columns []string, rawData []driver.Value) interface{} {
	data := elapsedTimeStatsData{}
	for i, columnName := range columns {
		switch columnName {
		case models.FieldNameTenantID:
			break
		case models.FieldNameAssetID:
			break
		case models.FieldNameCountAll:
			data.RequestCount = rawData[i].(int64)
		case models.FieldNameStartTime:
			data.ElapsedTime = rawData[i].(int64)
		}
	}
	return data
}

// GeneralLogQuery sends a query on all tables in a dataset looking for general data
func (qa *Adapter) GeneralLogQuery(ctx context.Context, tenantID string) (models.QueryResponse, error) {
	errChan := make(chan error)
	genStatsCh := make(chan models.QueryResponse, 1)
	elapsedTimesCh := make(chan models.QueryResponse, 1)
	totalRequestsCh := make(chan models.QueryResponse, 1)
	go func() {
		resp, err := qa.queryLogs(ctx, qa.genQuery.GetGeneralStatsQuery(tenantID),
			[]string{models.FieldNameTenantID, models.FieldNameAssetID}, convertGroupedDataToGeneralStatsData)
		if err != nil {
			errChan <- err
		}
		genStatsCh <- resp
	}()
	go func() {

		elapsedTimes, err := qa.queryLogs(ctx, qa.genQuery.GetElapsedTime(tenantID),
			[]string{models.FieldNameTenantID, models.FieldNameAssetID}, convertGroupedDataToElapsedTimeStatsData)
		if err != nil {
			errChan <- err
		}
		elapsedTimesCh <- elapsedTimes
	}()
	go func() {
		totalRequests, err := qa.queryLogs(ctx, qa.genQuery.GetTotalRequests(tenantID),
			[]string{models.FieldNameTenantID, models.FieldNameAssetID}, convertGroupedDataToElapsedTimeStatsData)
		if err != nil {
			errChan <- err
		}
		totalRequestsCh <- totalRequests
	}()

	var resp, elapsedTimes, totalRequests models.QueryResponse
	for i := 0; i < 3; i++ {
		select {
		case err := <-errChan:
			return models.QueryResponse{}, err
		case resp = <-genStatsCh:
		case elapsedTimes = <-elapsedTimesCh:
		case totalRequests = <-totalRequestsCh:
		}
	}

	runtime.Gosched()

	for tenant, tenantData := range resp {
		for asset, assetData := range tenantData {
			for i, data := range assetData {
				stats := data.(models.GeneralStatsData)
				if _, ok := elapsedTimes[tenant][asset]; ok {
					stats.StartupTime = elapsedTimes[tenant][asset][i].(elapsedTimeStatsData).ElapsedTime
					stats.TotalRequests = totalRequests[tenant][asset][i].(elapsedTimeStatsData).RequestCount
				} else {
					stats.StartupTime = time.Now().Add(time.Duration(-stats.ElapsedTime) * time.Hour).Unix()
					stats.TotalRequests = stats.Count
				}
				resp[tenant][asset][i] = stats
				runtime.Gosched()
			}
		}
	}
	for tenant, tenantData := range elapsedTimes {
		for asset, assetData := range tenantData {
			for _, data := range assetData {
				if _, ok := resp[tenant][asset]; !ok {
					elapsedData := data.(elapsedTimeStatsData)
					if _, exists := resp[tenant]; !exists {
						resp[tenant] = models.TenantResponse{}
					}
					if _, exists := resp[tenant][asset]; !exists {
						resp[tenant][asset] = models.GroupedResponse{}
					}
					resp[tenant][asset] = append(resp[tenant][asset],
						models.GeneralStatsData{StartupTime: elapsedData.ElapsedTime,
							TotalRequests: totalRequests[tenant][asset][0].(elapsedTimeStatsData).RequestCount})
					runtime.Gosched()
				}
			}
		}
	}
	return resp, nil
}

func convertGroupedDataToSeverityStatsData(columns []string, rawData []driver.Value) interface{} {
	data := models.SeverityStatsData{}
	for i, columnName := range columns {
		switch columnName {
		case models.FieldNameTenantID:
			break
		case models.FieldNameAssetID:
			break
		case models.FieldNameCountAll:
			data.TotalRequests = rawData[i].(int64)
		case models.FieldNameCountCritical:
			data.CriticalSeverityRequests = rawData[i].(int64)
		case models.FieldNameCountHigh:
			data.HighSeverityRequests = rawData[i].(int64)
		}
	}
	return data
}

// SeverityLogQuery sends a query on all tables in a dataset looking for data grouped by severity
func (qa *Adapter) SeverityLogQuery(ctx context.Context, tableName string) (models.QueryResponse, error) {
	return qa.queryLogs(ctx, qa.genQuery.GetSeverityStatsQuery(tableName),
		[]string{models.FieldNameTenantID, models.FieldNameAssetID}, convertGroupedDataToSeverityStatsData)
}

func mergeResponse(orig, new models.QueryResponse) models.QueryResponse {
	for tenantID, assetCtx := range new {
		_, exists := orig[tenantID]
		if !exists {
			orig[tenantID] = models.TenantResponse{}
		}
		for assetID, assetData := range assetCtx {
			_, exists = orig[tenantID][assetID]
			if !exists {
				orig[tenantID][assetID] = models.GroupedResponse{}
			}

			orig[tenantID][assetID] = append(orig[tenantID][assetID], assetData...)
		}
	}
	return orig
}

// GetNumOfRequests gets the number of requests for a specific dataset
func (qa *Adapter) GetNumOfRequests(ctx context.Context, tenantID string) (int64, error) {
	queryStr := qa.genQuery.GetNumOfRequests(tenantID)

	conn, err := qa.driver.Open(qa.dbName)
	if err != nil {
		return 0, errors.Wrap(err, "failed to open connection to SQL server")
	}

	query, err := conn.Prepare(queryStr)
	if err != nil {
		return 0, errors.Wrap(err, "failed to prepare a SQL statement")
	}

	qctx, ok := query.(driver.StmtQueryContext)
	if !ok {
		return 0, errors.New("driver not implementing driver.QueryerContext interface")
	}

	r, err := qctx.QueryContext(ctx, nil)
	if err != nil {
		return 0, errors.Wrap(err, "failed to query")
	}
	row := make([]driver.Value, 1)
	err = r.Next(row)
	if err == iterator.Done {
		return 0, errors.Errorf("no data found for dataset %v", tenantID).SetClass(errors.ClassNotFound)
	} else if err != nil {
		return 0, errors.Wrap(err, "failed to read query response")
	}

	if row[0] == nil {
		return 0, errors.Errorf("no data found for dataset %v", tenantID).SetClass(errors.ClassNotFound)
	}

	return row[0].(int64), nil
}

// TuneLogQuery sends a query on all tables in a dataset looking for tuning data
func (qa *Adapter) TuneLogQuery(ctx context.Context, tenantID string) (models.QueryResponse, error) {
	log.WithContext(ctx).Info("run tuning queries")
	fields := []string{fieldNameURL, fieldNameSource, fieldNameParamName, fieldNameParamValue}
	response := models.QueryResponse{}
	numOfQueries := len(fields) + 1
	qResponseChan := make(chan models.QueryResponse, numOfQueries)
	errG, ctx := errgroup.WithContext(ctx)
	for _, fieldName := range fields {
		// avoids race
		fieldNameCopy := fieldName
		errG.Go(func() error {
			qResponse, err := qa.queryLogs(
				ctx, qa.genQuery.GetTuneParameterQuery(fieldNameCopy, 3, tenantID),
				[]string{models.FieldNameTenantID, models.FieldNameAssetID}, qa.convertGroupedDataToTuningData)

			if err != nil {
				return errors.Wrapf(err, "failed to query tuning info for field: %v", fieldName)
			}
			qResponseChan <- qResponse
			return nil
		})
	}
	errG.Go(func() error {
		qResponse, err := qa.queryLogs(
			ctx, qa.genQuery.GetTuneURLQueryFormat(3, tenantID),
			[]string{models.FieldNameTenantID, models.FieldNameAssetID}, qa.convertGroupedDataToTuningData)

		if err != nil {
			return errors.Wrapf(err, "failed to query url tuning info")
		}
		qResponseChan <- qResponse
		return nil
	})

	if err := errG.Wait(); err != nil {
		return models.QueryResponse{}, err
	}

	close(qResponseChan)
	for qResponse := range qResponseChan {
		response = mergeResponse(response, qResponse)
	}

	return response, nil
}

func (qa *Adapter) convertGroupedDataToTuningData(columns []string, rawData []driver.Value) interface{} {
	data := models.TuningQueryData{AttackTypes: []string{}, LogIDs: []int64{}}
	for i, name := range columns {
		switch name {
		case models.FieldNameTenantID:
			break
		case models.FieldNameAssetID:
			break
		case models.FieldNameAssetName:
			data.AssetName = fmt.Sprint(rawData[i])
		case models.FieldNameSeverity:
			data.Severity = fmt.Sprint(rawData[i])
		case models.FieldNameCountAll:
			data.Count = rawData[i].(int64)
		case models.FieldNameCountURLs:
			data.URLsCount = rawData[i].(int64)
		case models.FieldNameCountSources:
			data.SourcesCount = rawData[i].(int64)
		case models.FieldNameCountParameters:
			data.ParametersCount = rawData[i].(int64)
		case models.FieldNameAttackTypes:
			var types []string
			if err := qa.genQuery.ScanArray(rawData[i], &types); err != nil {
				log.Error(err)
				continue
			}
			attackTypes := unionAttackTypes(types)
			if len(attackTypes) == 0 {
				data.AttackTypes = []string{attackTypeDefault}
			} else {
				data.AttackTypes = attackTypes
			}
		case models.FieldNameLogIDs:
			err := qa.genQuery.ScanArray(rawData[i], &data.LogIDs)
			if err != nil {
				log.Errorf("failed to scan array: %s, err: %v", rawData[i], err)
			}
		default:
			data.ExtraFieldName = name
			data.ExtraFieldValue = fmt.Sprint(rawData[i])
		}
	}
	return data
}

func unionAttackTypes(types []string) []string {
	attackTypesSet := make(map[string]struct{})
	for _, attackTypesStr := range types {
		splitAttackTypes := strings.Split(attackTypesStr, ", ")
		for _, attackType := range splitAttackTypes {
			if attackType == attackTypeUnknown {
				continue
			}
			attackTypesSet[attackType] = struct{}{}
		}
	}
	attackTypes := make([]string, 0)
	for t := range attackTypesSet {
		attackTypes = append(attackTypes, t)
	}
	return attackTypes
}

func (qa *Adapter) runQuery(
	ctx context.Context, q string) (driver.Rows, error) {
	log.WithContext(ctx).Infof("run query: %v", q)

	conn, err := qa.driver.Open(qa.dbName)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open connection to SQL server")
	}

	query, err := conn.Prepare(q)
	if err != nil {
		return nil, errors.Wrap(err, "failed to prepare a SQL statement")
	}
	start := time.Now()

	warningThreshold, err := qa.config.GetDuration(confKeyQueryDurationWarningThreshold)
	if err != nil {
		warningThreshold = defaultQueryDurationWarningThreshold
		log.WithContext(ctx).Warnf(
			"failed to get query warning duration threshold, err: %v. using default %v", err,
			defaultQueryDurationWarningThreshold,
		)
	}

	qctx, ok := query.(driver.StmtQueryContext)
	if !ok {
		return nil, errors.New("driver not implementing driver.QueryerContext interface")
	}

	rows, err := qctx.QueryContext(ctx, nil)

	if err != nil {
		log.WithContext(ctx).Warnf("got error reading query: %v", err)
		if qa.genQuery.ParseError(err) == errors.ClassForbidden {
			for i := 0; i < maxRetries; i++ {
				time.Sleep(time.Second * time.Duration(i+1))
				log.WithContext(ctx).Infof("retry query")
				rows, err = qctx.QueryContext(ctx, nil)
				if err == nil {
					break
				}
			}
		}
		if err != nil {
			if qa.genQuery.ParseError(err) == errors.ClassNotFound {
				return nil, errors.Wrapf(err, "not found").SetClass(errors.ClassNotFound)
			}
			return nil, errors.Wrapf(err, "failed to read query job: %v", q)
		}
	}

	end := time.Now()
	elapsed := end.Sub(start)

	if elapsed > warningThreshold {
		log.WithContext(ctx).Warnf("query %v took %v (over the %v threshold)", q, elapsed, warningThreshold)
	}

	return rows, nil
}

// GetTuningLogs return the logs based on the tuning event
func (qa *Adapter) GetTuningLogs(ctx context.Context, asset string, event models.TuneEvent) (models.Logs, error) {
	log.WithContext(ctx).Debugf("get logs for asset: %v, event: %v", asset, event)
	query := qa.genQuery.GenerateLogQuery(event, asset)
	return qa.queryLogsRaw(ctx, query)
}

func (qa *Adapter) queryLogsRaw(ctx context.Context, q string) (models.Logs, error) {
	result := models.Logs{}
	rowIt, err := qa.runQuery(ctx, q)
	if err != nil {
		return result, err
	}

	columns := rowIt.Columns()
	row := make([]driver.Value, len(columns))
	err = rowIt.Next(row)
	if err == io.EOF {
		log.WithContext(ctx).Infof("got empty response for query: %v", q)
		return result, nil
	}

	result.ColumnNames = columns
	result.Rows = [][]string{}
	for err == nil {
		rowStr := make([]string, len(columns))
		for i := range row {
			rowStr[i] = fmt.Sprint(row[i])
		}
		result.Rows = append(result.Rows, rowStr)
		err = rowIt.Next(row)
	}
	if err != io.EOF {
		return models.Logs{}, errors.Wrapf(err, "failed while handling response on row: %v", row)
	}
	return result, nil
}

func (qa *Adapter) queryLogs(
	ctx context.Context, q string, orderedColumns []string, conv converter) (models.QueryResponse, error) {

	result := models.QueryResponse{}
	rowIt, err := qa.runQuery(ctx, q)
	if err != nil {
		return result, err
	}

	columns := rowIt.Columns()
	row := make([]driver.Value, len(columns))
	err = rowIt.Next(row)
	if err == io.EOF {
		log.WithContext(ctx).Infof("got empty response for query: %v", q)
		return result, nil
	}
	indices := make([]int, len(orderedColumns), len(orderedColumns))
	for i := range indices {
		indices[i] = -1
	}

	for i, columnName := range orderedColumns {
		for schemaColumnIdx, name := range columns {
			if name == columnName {
				indices[i] = schemaColumnIdx
			}
		}
	}

	for i, schemaColumnIdx := range indices {
		if schemaColumnIdx == -1 {
			return result, errors.Errorf("missing %s in query", orderedColumns[i])
		}
	}

	for {
		tenant := fmt.Sprint(row[indices[0]])
		if len(tenant) == 0 {
			tenant = "local"
		}
		var groupedByColumn string
		if len(indices) > 2 {
			exceptionAssetHashCombine := fnv.New32a()
			for _, schemaColumnIdx := range indices[1:] {
				_, err := exceptionAssetHashCombine.Write([]byte(fmt.Sprint(row[schemaColumnIdx])))
				if err != nil {
					log.WithContext(ctx).Warnf(
						"Failed to write hash combination. Got error: %v", err)
				}
			}
			groupedByColumn = fmt.Sprint(exceptionAssetHashCombine.Sum32())
		} else {
			groupedByColumn = fmt.Sprint(row[indices[1]])
		}
		groupedData := conv(columns, row)

		log.WithContext(ctx).Debugf("insert response: %+v", groupedData)

		_, exists := result[tenant]
		if !exists {
			result[tenant] = models.TenantResponse{}
		}
		_, exists = result[tenant][groupedByColumn]
		if !exists {
			result[tenant][groupedByColumn] = models.GroupedResponse{}
		}
		result[tenant][groupedByColumn] = append(result[tenant][groupedByColumn], groupedData)
		err = rowIt.Next(row)
		if err == io.EOF {
			break
		} else if err != nil {
			return models.QueryResponse{}, errors.Wrapf(err, "failed to fetch row in query response")
		}
	}
	return result, nil
}

// queryAllLogs sends a query on all tables in a dataset
func (qa *Adapter) queryAllLogs(ctx context.Context, queryFormat func(string) string,
	conv converter) (models.QueryResponse, error) {
	tenantsList := qa.tenantsList
	qa.tenantsLock.Unlock()
	if len(tenantsList) == 0 {
		return models.QueryResponse{}, errors.New("tenants list is not set")
	}
	if tenantsList[0] == "All" {
		q := queryFormat(tenantsList[0])
		return qa.queryLogs(ctx, q, []string{models.FieldNameTenantID, models.FieldNameAssetID}, conv)
	}

	result := models.QueryResponse{}
	for _, tenant := range tenantsList {
		q := queryFormat(tenant)
		res, err := qa.queryLogs(ctx, q, []string{models.FieldNameTenantID, models.FieldNameAssetID}, conv)
		if err != nil {
			return models.QueryResponse{}, errors.Wrapf(err, "failed to query dataset %v", tenant)
		}
		result[tenant] = res[tenant]
	}
	return result, nil
}

func (qa *Adapter) convertGroupedDataToUrls(columns []string, rawData []driver.Value) interface{} {
	data := models.UrlsToCollapse{}
	for i, name := range columns {
		switch name {
		case models.FieldNameTenantID:
			break
		case models.FieldNameAssetID:
			break
		case models.FieldNameURIs:
			err := qa.genQuery.ScanArray(rawData[i], &data.Urls)
			if err != nil {
				log.Errorf("failed to scan array %v, err: %v", rawData[i], err)
			}
		}
	}
	return data
}

func (qa *Adapter) convertGroupedDataToParams(columns []string, rawData []driver.Value) interface{} {
	data := models.ParamsToCollapse{}
	for i, name := range columns {
		switch name {
		case models.FieldNameTenantID:
			break
		case models.FieldNameAssetID:
			break
		case models.FieldNameParams:
			err := qa.genQuery.ScanArray(rawData[i], &data.Params)
			if err != nil {
				log.Errorf("failed to scan array %v, err: %v", rawData[i], err)
			}
		}
	}
	return data
}

// GetUrlsToCollapse return a list of urls to collapse for each dataset and asset
func (qa *Adapter) GetUrlsToCollapse(ctx context.Context, tenants []string) (models.QueryResponse, error) {
	qa.setTenantsList(tenants)
	return qa.queryAllLogs(ctx, qa.genQuery.GetUrlsForCollapsingFormat, qa.convertGroupedDataToUrls)
}

// GetParamsToCollapse return a list of urls to collapse for each dataset and asset
func (qa *Adapter) GetParamsToCollapse(ctx context.Context, tenants []string) (models.QueryResponse, error) {
	qa.setTenantsList(tenants)
	return qa.queryAllLogs(ctx, qa.genQuery.GetParamsForCollapsingFormat, qa.convertGroupedDataToParams)
}

func convertGroupedDataToExceptionData(columns []string, rawData []driver.Value) interface{} {
	data := models.ExceptionsData{}
	for i, name := range columns {
		switch name {
		case models.FieldNameTenantID:
			break
		case models.FieldNameAssetID:
			data.AssetID = fmt.Sprint(rawData[i])
		case models.FieldNameExceptionID:
			data.ExceptionID = fmt.Sprint(rawData[i])
		case models.FieldNameLastHitEvent:
			data.LastHitEvent = fmt.Sprint(rawData[i])
		case models.FieldNameHitCountPerAsset:
			data.HitCountPerAsset = rawData[i].(int64)
		case models.FieldNameHitCountPerException:
			data.HitCountPerException = rawData[i].(int64)
		}
	}
	return data
}

// ExceptionsLogQuery returns query response model of exceptions data
func (qa *Adapter) ExceptionsLogQuery(ctx context.Context, tenantID string) (models.QueryResponse, error) {
	return qa.queryLogs(ctx, qa.genQuery.GetExceptionsQuery(tenantID),
		[]string{models.FieldNameTenantID, models.FieldNameAssetID, models.FieldNameExceptionID},
		convertGroupedDataToExceptionData)
}

// InsertLog insert log to log repository
func (qa *Adapter) InsertLog(ctx context.Context, message *models.AgentMessage) error {
	stmtStr, args, err := qa.genQuery.Insert(message)
	if err != nil {
		return errors.Wrap(err, "failed to generate insert statement")
	}
	log.WithContext(ctx).Infof("insert statement: %v, db name: %s", stmtStr, qa.dbName)
	conn, err := qa.driver.Open(qa.dbName)
	if err != nil {
		errCreateDB := qa.createDB(ctx)
		if errCreateDB != nil {
			log.WithContext(ctx).Warnf("failed to create db, err: %v", errCreateDB)
			return errors.Wrap(err, "failed to open connection to DB")
		}
		conn, err = qa.driver.Open(qa.dbName)
		if err != nil {
			return errors.Wrap(err, "failed to open connection to DB")
		}
	}
	affected, err := executeStmt(ctx, conn, stmtStr, args)
	if err != nil {
		log.WithContext(ctx).Infof("encounter error: %v on first insertion attempt", err)
		err = qa.createTablePartition(ctx, conn, message)
		if err != nil {
			return errors.Wrap(err, "failed to create table")
		}
		affected, err = executeStmt(ctx, conn, stmtStr, args)
		if err != nil {
			return errors.Wrap(err, "failed to insert log after table creation")
		}
		if affected == 0 {
			return errors.Errorf("failed to insert log: %v", message)
		}
	}
	return nil
}

func executeStmt(ctx context.Context, conn driver.Conn, stmtStr string, args []driver.Value) (int64, error) {
	stmt, err := conn.Prepare(stmtStr)
	if err != nil {
		return 0, errors.Wrapf(err, "failed to prepare stmt: %v", stmtStr)
	}
	var res driver.Result
	if stmtCtx, ok := stmt.(driver.StmtExecContext); ok {
		namedArgs := make([]driver.NamedValue, len(args))
		for i, arg := range args {
			namedArgs[i] = driver.NamedValue{Value: arg}
		}
		res, err = stmtCtx.ExecContext(ctx, namedArgs)
	} else {
		res, err = stmt.Exec(args)
	}
	log.WithContext(ctx).Infof("execute: %v, result: %+v, err: %+v", stmtStr, res, err)
	if err != nil {
		return 0, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return affected, nil
}

func (qa *Adapter) createTablePartition(ctx context.Context, conn driver.Conn, message *models.AgentMessage) error {
	createStmt, err := qa.genQuery.CreateTablePartition(message.TenantID, message.Log.EventTime)
	if err != nil {
		return errors.Wrap(err, "failed to generate statement")
	}
	_, err = executeStmt(ctx, conn, createStmt, nil)
	if err != nil {
		log.WithContext(ctx).Infof("failed to create table partition, err: %v", err)
		if qa.genQuery.ParseError(err) == errors.ClassNotFound {
			err = qa.createTable(ctx, conn, message)
			if err != nil {
				return errors.Wrap(err, "failed to create table")
			}
			_, err = executeStmt(ctx, conn, createStmt, nil)
		} else {
			err = errors.Wrapf(err, "failed to create table partition")
		}
	}
	return err
}

func (qa *Adapter) createTable(ctx context.Context, conn driver.Conn, message *models.AgentMessage) error {
	createStmt, err := qa.genQuery.CreateTable(message.TenantID)
	if err != nil {
		return err
	}
	_, err = executeStmt(ctx, conn, createStmt, nil)
	if err != nil {
		log.WithContext(ctx).Infof("failed to create table, err: %v", err)
		if qa.genQuery.ParseError(err) == errors.ClassNotFound {
			err = qa.createDB(ctx)
			if err != nil {
				return errors.Wrap(err, "failed to create database")
			}
			_, err = executeStmt(ctx, conn, createStmt, nil)
		} else {
			err = errors.Wrapf(err, "failed to create table")
		}
	}
	return err
}

func (qa *Adapter) createDB(ctx context.Context) error {
	stmt := qa.genQuery.CreateDatabase()

	dbHost, err := qa.config.GetString(confKeyQueryDBHost)
	if err != nil {
		return err
	}

	dbPort, err := qa.config.GetString(confKeyQueryDBPort)
	if err != nil {
		return err
	}

	dbUser, err := qa.config.GetString(confKeyQueryDBUser)
	if err != nil {
		return err
	}

	pass, err := qa.config.GetString(confKeyQueryDBPass)
	if err != nil {
		return err
	}

	sslMode, err := qa.config.GetString(confKeyQueryDBSSLMode)
	if err != nil {
		return err
	}

	rootConn := fmt.Sprintf("postgres://%s:%s@%s:%v/?sslmode=%s", dbUser, pass, dbHost, dbPort, sslMode)

	conn, err := qa.driver.Open(rootConn)
	if err != nil {
		return errors.Wrap(err, "failed to open connection as root user")
	}
	log.WithContext(ctx).Infof("run stmt: %v", stmt)
	_, err = executeStmt(ctx, conn, stmt, nil)
	return err
}
