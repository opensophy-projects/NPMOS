package pg

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"
	"time"

	"github.com/lib/pq"
	"openappsec.io/errors"
	"openappsec.io/log"
	"openappsec.io/smartsync-tuning/models"
)

const (
	timeLayout        = "2006-01-02T15:04:05.000"
	confKeySchemaPath = "query.schema.path"

	// Field names
	fieldNameLogID         = "logindex"
	fieldNameCountHigh     = "high_severity"
	fieldNameCountCritical = "critical_severity"
	fieldNameSeverity      = "eventseverity"
	fieldNameIncidentTypes = "waapincidenttype"
	fieldNameSource        = "httpsourceid"
	fieldNameURL           = "httpuripath"
	fieldNameParamName     = "matchedparameter"
	fieldNameParamValue    = "matchedsample"
	fieldNameAssetName     = "assetname"
	fieldNameLocation      = "matchedlocation"
)

type schemaField struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Mode string `json:"mode,omitempty"`
}

type schema struct {
	PartitioningField string        `json:"partitioning_field"`
	Fields            []schemaField `json:"fields"`
}

type schemaFile struct {
	Name   string `json:"name"`
	Schema schema `json:"schema"`
}

//NewPQDriver create a postgres driver
func NewPQDriver() *pq.Driver {
	return &pq.Driver{}
}

//QueriesGen generates postgres queries and statement
type QueriesGen struct {
	schema    schemaFile
	fieldsSet map[string]bool
}

// Configuration used to get the configuration of the datatube dataset
type Configuration interface {
	GetString(key string) (string, error)
}

// NewQueriesGen creates custom operations and queries for postgres
func NewQueriesGen(configuration Configuration) (*QueriesGen, error) {
	// get schema file location - TODO: MUST BE UPDATED WITH AGENT CHANGES
	fileLocation, err := configuration.GetString(confKeySchemaPath)
	if err != nil {
		return &QueriesGen{}, err
	}
	// open file unmarshal to schema
	schemaContent, err := ioutil.ReadFile(fileLocation)
	if err != nil {
		return &QueriesGen{}, err
	}
	var schema schemaFile
	err = json.Unmarshal(schemaContent, &schema)
	if err != nil {
		return &QueriesGen{}, err
	}
	qg := &QueriesGen{schema: schema, fieldsSet: map[string]bool{}}
	// create fields set
	for _, field := range schema.Schema.Fields {
		qg.fieldsSet[strings.ToLower(field.Name)] = true
	}
	return qg, nil
}

//GetTotalRequests query for total requests
func (qg *QueriesGen) GetTotalRequests(tenantID string) string {
	table := qg.genTableName(tenantID)

	internalQSelect := "SELECT eventtime, assetid, agentid, logindex, max(reservedngena) as reservedngena"
	internalQFrom := fmt.Sprintf("FROM %v", table)
	internalQWhere := "WHERE LOWER(eventname)='waap telemetry' and eventtime::timestamp <= CURRENT_TIMESTAMP " +
		"and reservedngena is not null "
	internalQGroupBy := "GROUP BY eventtime, assetid, agentid, logindex"
	internalQuery := fmt.Sprintf("%v %v %v %v", internalQSelect, internalQFrom, internalQWhere, internalQGroupBy)
	queryStr := fmt.Sprintf("select '' as tenant_id, assetid, "+
		"sum(reservedngena) as %v FROM (%v) as requests GROUP BY assetid",
		models.FieldNameCountAll, internalQuery)

	return queryStr
}

// ScanArray scan response value into array arr
func (qg *QueriesGen) ScanArray(value driver.Value, arr any) error {
	pqArr := pq.Array(arr)
	if err := pqArr.Scan(value); err != nil {
		return err
	}
	return nil
}

// GetGeneralStatsQuery generates a query to get general data of an assetID
func (qg *QueriesGen) GetGeneralStatsQuery(tenantID string) string {
	table := qg.genTableName(tenantID)
	return fmt.Sprintf(
		"SELECT '' as tenant_id, "+models.FieldNameAssetID+","+
			"count(distinct "+fieldNameSource+") as number_of_sources,"+
			"count(distinct "+fieldNameURL+") as number_of_urls,count(*) as number_of_requests,"+
			"(EXTRACT(epoch from (max(CURRENT_TIMESTAMP - eventtime::timestamp)))/3600)::bigint as "+models.
			FieldNameElapsedTime+" FROM %v "+
			"WHERE eventtime::timestamp > CURRENT_TIMESTAMP - interval '7 days' "+
			"and eventname='Web Request' and (practicesubtype='Web Application' or practicesubtype='Web API') "+
			"GROUP BY "+models.FieldNameAssetID, table,
	)
}

// GetElapsedTime generates a query to get general data of an assetID
func (qg *QueriesGen) GetElapsedTime(tenantID string) string {
	table := qg.genTableName(tenantID)

	queryStr := fmt.Sprintf("select '' as tenant_id, assetid, "+
		"extract(epoch from min(eventtime::timestamp))::INTEGER as %v FROM %v WHERE "+
		"LOWER(eventname)='waap telemetry' and eventtime::timestamp <= CURRENT_TIMESTAMP and reservedngena>0 "+
		" GROUP BY assetid", models.FieldNameStartTime, table)

	return queryStr
}

// GetSeverityStatsQuery generates a query to get specific data with respect to severity
func (qg *QueriesGen) GetSeverityStatsQuery(tenantID string) string {
	table := qg.genTableName(tenantID)

	str := `SELECT '' as tenant_id, 
  ` + models.FieldNameAssetID + `,
  SUM(requests) AS ` + models.FieldNameCountAll + `,
  SUM(high_severity) AS ` + fieldNameCountHigh + `,
  SUM(critical_severity) AS ` + fieldNameCountCritical + `
FROM (
  SELECT
    eventtime,
    assetid,
    agentid,
    logindex,
    COALESCE(MAX(reservedngena), 0) AS requests,
    COALESCE(MAX(reservedngeni), 0) AS high_severity,
    COALESCE(MAX(reservedngenj), 0) AS critical_severity
  FROM
    ` + table + `
  WHERE
    LOWER(eventname)='waap telemetry'
    AND eventtime::timestamp > CURRENT_TIMESTAMP - interval '7 days'
    AND reservedngena IS NOT NULL 
  GROUP BY
    eventtime,
    assetid,
    agentid,
    logindex) as telemetry
GROUP BY
  assetid`
	return str
}

func count(fieldName, modelFieldName string) string {
	count := "distinct " + fieldName
	if fieldName == "*" {
		count = fieldName
	}
	return fmt.Sprintf("count(%v) as %v", count, modelFieldName)
}

//GetTuneParameterQuery gen query for tuning events
func (qg *QueriesGen) GetTuneParameterQuery(parameter string, minCount int, tenantID string) string {
	table := qg.genTableName(tenantID)

	renameMap := map[string]string{
		fieldNameURL:        models.EventTypeURL,
		fieldNameSource:     models.EventTypeSource,
		fieldNameParamName:  models.EventTypeParamName,
		fieldNameParamValue: models.EventTypeParamVal,
	}
	var havingClause string
	switch parameter {
	case fieldNameURL:
		havingClause = fmt.Sprintf("HAVING count(distinct %v)>=%v", fieldNameParamName, minCount)
	case fieldNameSource:
		havingClause = fmt.Sprintf("HAVING count(distinct %v)>=%v", fieldNameURL, minCount)
	case fieldNameParamName:
		havingClause = fmt.Sprintf("HAVING count(distinct %v)>=%v", fieldNameSource, minCount)
	case fieldNameParamValue:
		havingClause = fmt.Sprintf(
			"HAVING (count(distinct %v)>=%v or count(distinct %v)>=%v) and count(distinct %v)>=%v",
			fieldNameURL, minCount,
			fieldNameParamName, minCount,
			fieldNameSource, minCount)
	}

	whereClause := "eventtime::timestamp > CURRENT_TIMESTAMP - INTERVAL '120 days' " +
		"and eventtime::timestamp > t - INTERVAL '7 days' " +
		"and " + fieldNameLogID + " IS NOT NULL " +
		"and eventname='Web Request' and (practicesubtype='Web Application' or practicesubtype='Web API') and (" +
		fieldNameSeverity + "='Critical' or " + fieldNameSeverity + "='High') "
	if parameter == fieldNameParamName {
		whereClause += "and " + fieldNameParamName + "!='' "
	}

	selectClause := "SELECT '' as tenant_id, A." +
		models.FieldNameAssetID + "," + "max(" + fieldNameAssetName + ") as " + models.FieldNameAssetName + ", " +
		parameter + " as " + renameMap[parameter] + ", " +
		count(fieldNameSource, models.FieldNameCountSources) + "," +
		fieldNameSeverity + " as " + models.FieldNameSeverity + "," +
		"ARRAY_AGG(distinct COALESCE(" + fieldNameIncidentTypes + ", 'General')) as " + models.FieldNameAttackTypes +
		"," + count(fieldNameURL, models.FieldNameCountURLs) + "," +
		count(fieldNameParamName, models.FieldNameCountParameters) + "," +
		count("*", models.FieldNameCountAll) + "," +
		"ARRAY_AGG(distinct " + fieldNameLogID + ") as " + models.FieldNameLogIDs

	fromClause := table + " AS A" +
		" INNER JOIN (SELECT" +
		"   assetid," +
		"   MAX(eventtime::timestamp) AS t" +
		" FROM" +
		" " + table +
		" WHERE" +
		"   eventtime::timestamp > CURRENT_TIMESTAMP - INTERVAL '120 days'" +
		"   AND eventname='Web Request'" +
		"   AND (practicesubtype='Web Application' or practicesubtype='Web API') " +
		" GROUP BY" +
		"   assetid) AS B " +
		" ON A.assetid = B.assetid"

	return fmt.Sprintf(
		selectClause+
			" FROM %[2]v WHERE "+whereClause+
			"GROUP BY A."+models.FieldNameAssetID+","+
			fieldNameSeverity+",%[1]v %[3]v",
		parameter, fromClause, havingClause,
	)
}

// GetTuneURLQueryFormat generate query for url tuning event
func (qg *QueriesGen) GetTuneURLQueryFormat(minCount int, tenantID string) string {
	havingClause := fmt.Sprintf("HAVING count(distinct %v)>=%v and count(distinct %v)=0",
		fieldNameSource, minCount, fieldNameParamName)

	whereClause := "eventtime::timestamp > CURRENT_TIMESTAMP - INTERVAL '7 days' " +
		"and eventname='Web Request' and (practicesubtype='Web Application' or practicesubtype='Web API') and (" +
		fieldNameSeverity + "='Critical' or " + fieldNameSeverity + "='High') " +
		"and " + fieldNameLocation + "='body' "

	selectClause := "SELECT '' as tenant_id, A." + models.FieldNameAssetID + "," +
		"max(" + fieldNameAssetName + ") as " + models.FieldNameAssetName + "," +
		fieldNameURL + " as " + models.EventTypeURL + "," +
		count(fieldNameSource, models.FieldNameCountSources) + "," +
		fieldNameSeverity + " as " + models.FieldNameSeverity + "," +
		"ARRAY_AGG(distinct COALESCE(" + fieldNameIncidentTypes + ", 'General')) as " + models.FieldNameAttackTypes +
		"," + count(fieldNameURL, models.FieldNameCountURLs) + "," +
		count(fieldNameParamName, models.FieldNameCountParameters) + "," +
		count("*", models.FieldNameCountAll) + "," +
		"ARRAY_AGG(distinct " + fieldNameLogID + ") as " + models.FieldNameLogIDs

	table := qg.genTableName(tenantID)

	fromClause := table + " AS A" +
		" INNER JOIN (SELECT" +
		"   assetid," +
		"   MAX(eventtime::timestamp) AS t" +
		" FROM" +
		" " + table +
		" WHERE" +
		"   eventtime::timestamp > '2017-1-1'" +
		"   AND eventname='Web Request'" +
		"   AND (practicesubtype='Web Application' or practicesubtype='Web API')" +
		" GROUP BY" +
		"   assetid) AS B " +
		" ON A.assetid = B.assetid"

	return fmt.Sprintf(
		selectClause+
			" FROM %[2]v WHERE "+whereClause+
			"GROUP BY A."+models.FieldNameAssetID+","+
			fieldNameSeverity+",%[1]v %[3]v",
		fieldNameURL, fromClause, havingClause,
	)
}

//GetExceptionsQuery query for exceptions
func (qg *QueriesGen) GetExceptionsQuery(tenantID string) string {
	table := qg.genTableName(tenantID)
	return fmt.Sprintf(
		`SELECT
			'' as tenant_id,
			exceptionId,
			assetid,
			MAX(eventtime) AS lastHitEvent,
			COUNT(exceptionId) AS hitCountPerAsset,
			SUM(COUNT(exceptionId))
				OVER (
					PARTITION BY exceptionId
					ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
				) AS hitCountPerException
		FROM ` + table + `,
			UNNEST(exceptionIdList) exceptionId
		WHERE
			eventtime::timestamp > CURRENT_TIMESTAMP - INTERVAL '14 days'
			AND exceptionId IS NOT NULL
		GROUP BY exceptionId, assetid
		ORDER BY exceptionId`)
}

//GetParamsForCollapsingFormat get params for tokenizer
func (qg *QueriesGen) GetParamsForCollapsingFormat(tenantID string) string {
	table := qg.genTableName(tenantID)
	return fmt.Sprintf("SELECT '' as tenant_id, assetid, ARRAY_AGG(DISTINCT matchedparameter) as %v"+
		" FROM %v WHERE eventname='Web Request' AND (practicesubtype='Web Application' or practicesubtype='Web API') "+
		"AND eventtime::timestamp > CURRENT_TIMESTAMP - INTERVAL '7 days'"+
		" AND matchedparameter is not null AND matchedlocation='body'"+
		" GROUP BY assetid", models.FieldNameParams, table)
}

//GetUrlsForCollapsingFormat get urls for tokenizer
func (qg *QueriesGen) GetUrlsForCollapsingFormat(tenantID string) string {
	table := qg.genTableName(tenantID)
	return fmt.Sprintf("SELECT '' as tenant_id, assetid, ARRAY_AGG(DISTINCT httpuripath) as %v"+
		" FROM %v WHERE eventname='Web Request' AND (practicesubtype='Web Application' or practicesubtype='Web API') "+
		"AND eventtime::timestamp > CURRENT_TIMESTAMP - INTERVAL '7 days'"+
		" AND ((matchedparameter is null AND matchedlocation='body') OR matchedlocation='url')"+
		" AND httpuripath is not null "+
		" GROUP BY assetid", models.FieldNameURIs, table)
}

//GetNumOfRequests query for total requests
func (qg *QueriesGen) GetNumOfRequests(tenantID string) string {
	table := qg.genTableName(tenantID)

	internalQSelect := "SELECT eventtime, assetid, agentid, logindex, max(reservedngena) as reservedngena"
	internalQFrom := fmt.Sprintf("FROM %v", table)
	internalQWhere := "WHERE LOWER(eventname)='waap telemetry' and DATE(eventtime) >= " +
		"'2021-01-01' "
	internalQGroupBy := "GROUP BY eventtime, assetid, agentid, logindex"
	internalQuery := fmt.Sprintf("%v %v %v %v", internalQSelect, internalQFrom, internalQWhere, internalQGroupBy)
	return fmt.Sprintf("select '' as tenant_id, sum(reservedngena) as %v FROM (%v) as requests",
		models.FieldNameCountAll, internalQuery)
}

func (qg *QueriesGen) extractNamedVals(value reflect.Value) map[string]driver.Value {
	namedVals := map[string]driver.Value{}
	t := value.Type()
	for i := 0; i < t.NumField(); i++ {
		fieldStruct := t.Field(i)
		fieldValue := value.FieldByName(fieldStruct.Name)
		if fieldValue.Kind() == reflect.Ptr {
			if fieldValue.IsZero() {
				// skip handling nil
				continue
			}
			fieldValue = fieldValue.Elem()
		}
		if fieldValue.Kind() == reflect.Struct {
			// recursive call on structs
			recNameVals := qg.extractNamedVals(fieldValue)
			for name, val := range recNameVals {
				// avoid duplications
				if _, ok := namedVals[name]; !ok {
					namedVals[name] = val
				}
			}
			continue
		}

		if fieldValue.IsZero() {
			continue
		}

		name := strings.ToLower(fieldStruct.Name)
		// add to insert stmt if exists in schema
		if _, ok := qg.fieldsSet[name]; !ok {
			continue
		}

		if fieldValue.CanInt() {
			namedVals[name] = driver.Value(fieldValue.Int())
			continue
		}
		if fieldValue.Kind() == reflect.Slice {
			strs := make([]string, fieldValue.Len())
			for i := 0; i < fieldValue.Len(); i++ {
				strs[i] = fieldValue.Index(i).String()
			}
			arr := pq.Array(strs)
			val, err := arr.Value()
			if err != nil {
				log.Errorf("failed to convert array to driver Value")
			}
			namedVals[name] = val
			log.Infof("added array: %[1]v (%[1]T) from %v", namedVals[name], strs)
			continue
		}
		namedVals[name] = driver.Value(fieldValue.String())
	}
	return namedVals
}

func (qg *QueriesGen) extractColNameAndValue(value reflect.Value) ([]string, []driver.Value) {
	nameVals := qg.extractNamedVals(value)
	var columns []string
	var vals []driver.Value
	for name, val := range nameVals {
		columns = append(columns, name)
		vals = append(vals, val)
	}
	return columns, vals
}

//GenerateLogQuery created a log query for psql
func (qg *QueriesGen) GenerateLogQuery(data models.TuneEvent, assetName string) string {
	queryFieldsMap := map[string]string{
		models.EventTypeSource:                     fieldNameSource,
		models.EventTypeURL:                        fieldNameURL,
		strings.ToLower(models.EventTypeParamName): fieldNameParamName,
		strings.ToLower(models.EventTypeParamVal):  fieldNameParamValue,
	}
	querySelection := map[string]string{
		"eventTime":           "Event Time",
		"eventName":           "Event Name",
		"eventReferenceId":    "Event Reference ID",
		"eventSeverity":       "Event Severity",
		"eventConfidence":     "Event Confidence",
		"eventLevel":          "Event Level",
		"agentId":             "Agent UUID",
		"practiceType":        "Practice Type",
		"practiceSubType":     "Practice SubType",
		"httpSourceId":        "Source Identifier",
		"httpHostName":        "HTTP Host",
		"httpMethod":          "HTTP Method",
		"httpUriPath":         "HTTP URI Path",
		"httpUriQuery":        "HTTP URI Query",
		"waapIncidentType":    "AppSec Incident Type",
		"waapUserReputation":  "AppsSec User Reputation",
		"matchedLocation":     "Matched Location",
		"matchedParameter":    "Matched Parameter",
		"matchedSample":       "Matched Sample",
		"waapFoundIndicators": "Found Indicators",
		"waapOverride":        "AppSec Override",
		"securityAction":      "Security Action",
		"ruleName":            "Rule Name",
		"assetName":           "Asset Name",
		"practiceName":        "Practice Name",
		"sourceIp":            "Source IP",
		"sourcePort":          "Source Port",
	}
	columns := []string{"eventTime", "eventName", "eventReferenceId", "eventSeverity", "eventConfidence",
		"eventLevel", "agentId", "practiceType", "practiceSubType", "httpSourceId", "httpHostName",
		"httpMethod", "httpUriPath", "httpUriQuery", "waapIncidentType", "waapUserReputation", "matchedLocation",
		"matchedParameter", "matchedSample", "waapFoundIndicators", "waapOverride", "securityAction", "ruleName",
		"assetName", "practiceName", "sourceIp", "sourcePort"}
	selectClause := ""
	for i, field := range columns {
		displayName := querySelection[field]
		if i == 0 {
			selectClause = fmt.Sprintf("select %v as \"%v\"", field, displayName)
			continue
		}
		selectClause += fmt.Sprintf(", %v as \"%v\"", field, displayName)
	}
	query := selectClause + " from " + qg.genTableName("") + " where "
	queryCondition := []string{fmt.Sprintf("%v='%v'", fieldNameSeverity, strings.Title(data.Severity))}
	if assetName != "" {
		queryCondition = append(queryCondition, fmt.Sprintf("%v='%v'", models.FieldNameAssetID, assetName))
	}
	queryCondition = append(queryCondition, "eventtime::timestamp >= CURRENT_TIMESTAMP - interval '7 days'")
	queryCondition = append(queryCondition, fmt.Sprintf("%v='%v'", queryFieldsMap[strings.ToLower(data.EventType)],
		data.EventTitle))
	return query + strings.Join(queryCondition, " and ")
}

//Insert prepares statement and args for sql driver
func (qg *QueriesGen) Insert(message *models.AgentMessage) (string, []driver.Value, error) {
	stmt := "INSERT INTO " + qg.genTableName(message.TenantID)

	// iterate message fields
	v := reflect.ValueOf(*message)
	columns, vals := qg.extractColNameAndValue(v)
	placeHolders := genPlaceholders(vals)

	stmt += " (" + strings.Join(columns, ", ") + ") VALUES " + placeHolders + ";"
	return stmt, vals, nil
}

func genPlaceholders(values []driver.Value) string {
	places := len(values)
	placeholders := make([]string, places)
	for i := range placeholders {
		placeholders[i] = fmt.Sprintf("$%v", i+1)
	}
	return "(" + strings.Join(placeholders, ", ") + ")"
}

// CreateTable generates a table creation statement
func (qg *QueriesGen) CreateTable(id string) (string, error) {
	tableName := qg.genTableName(id)
	stmt := "CREATE TABLE " + tableName + " ("
	fields := qg.schema.Schema.Fields
	for i, field := range fields {
		if field.Mode == "REPEATED" {
			stmt += fmt.Sprintf("%s %s[]", field.Name, field.Type)
		} else {
			stmt += fmt.Sprintf("%s %s", field.Name, field.Type)
		}
		if i < len(fields)-1 {
			stmt += ", "
		}
	}
	if qg.schema.Schema.PartitioningField == "" {
		return "", errors.New("missing partition field")
	}
	stmt += ") PARTITION BY RANGE(" + qg.schema.Schema.PartitioningField + ");"
	return stmt, nil
}

// CreateDatabase generates a database creation statement
func (qg *QueriesGen) CreateDatabase() string {
	return "CREATE DATABASE " + qg.schema.Name
}

func (qg *QueriesGen) genTableName(_ string) string {
	return "appsec"
}

//CreateTablePartition generate create partition statement
func (qg *QueriesGen) CreateTablePartition(id string, eventTime string) (string, error) {
	t, err := time.Parse(timeLayout, eventTime)
	if err != nil {
		return "", errors.Wrapf(err, "failed to parse event time: %v", eventTime)
	}
	year, month, day := t.Date()
	dateFmt := "%04d-%02d-%02d"
	startDate := fmt.Sprintf(dateFmt, year, month, day)
	year, month, day = t.Add(time.Hour * 24).Date()
	endDate := fmt.Sprintf(dateFmt, year, month, day)
	stmt := fmt.Sprintf("CREATE TABLE %v_%d_%d_%d PARTITION OF %v FOR VALUES FROM ('%v') TO ('%v')",
		qg.genTableName(id), year, month, day, qg.genTableName(id), startDate, endDate)
	return stmt, nil
}

// ParseError return the appropriate class for driver specific error
func (qg *QueriesGen) ParseError(err error) errors.Class {
	if pqErr, ok := err.(*pq.Error); ok {
		switch pqErr.Code {
		case "23514":
			//fallthrough
		case "42P01":
			return errors.ClassNotFound
		default:
			return errors.ClassUnknown
		}
	}
	return errors.ClassUnknown
}
