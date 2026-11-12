package rest

import (
	"context"
	"io/ioutil"
	"math"
	"net/http"
	"strconv"
	"time"

	"openappsec.io/errors"
	"openappsec.io/errors/errorloader"
	"openappsec.io/health"
	"openappsec.io/log"
)

const (
	serverConfBaseKey         = "server"
	serverPortConfKey         = serverConfBaseKey + ".port"
	serverTimeoutConfKey      = serverConfBaseKey + ".timeout"
	serverQueryTimeoutConfKey = serverConfBaseKey + ".queryTimeout"

	schemaValidatorConfBaseKey = "schemaValidator"
	schemaFilePathConfKey      = schemaValidatorConfBaseKey + ".schemaFilePath"

	errorsConfBaseKey = "errors"
	errorsFilePathKey = errorsConfBaseKey + ".filepath"
	errorsCodeKey     = errorsConfBaseKey + ".code"

	confKeyIntelligenceAssetTTL = "intel.ttl"

	readySignal = "ready"
)

// Configuration exposes an interface of configuration related actions
type Configuration interface {
	SetMany(ctx context.Context, conf map[string]interface{}) error
	Set(ctx context.Context, key string, value interface{}) error
	Get(key string) interface{}
	GetString(key string) (string, error)
	GetInt(key string) (int, error)
	GetDuration(key string) (time.Duration, error)
	GetAll() map[string]interface{}
	IsSet(key string) bool
}

// JSONSchemaValidator handle input json validation
type JSONSchemaValidator interface {
	CalculateSchemaPath(folder string, fileSubFix string) error
	SetSchemaFromBytes(name string, inputJSON []byte) error
	ValidateSchemaFromBytes(schemaName string, inputJSON []byte) error
}

// HealthService exposes an interface of health related actions
type HealthService interface {
	Live() health.LivenessResponse
	Ready(ctx context.Context) health.ReadinessResponse
	AddReadinessChecker(checker health.Checker)
}

// Server http server interface
type Server interface {
	ListenAndServe() error
	Shutdown(ctx context.Context) error
}

// AdapterBase base operation
type AdapterBase struct {
	server    Server
	conf      Configuration
	healthSvc HealthService
}

// AdapterStandAlone standalone server adapter
type AdapterStandAlone struct {
	AdapterBase

	standaloneService StandaloneService
}

// Adapter server adapter
type Adapter struct {
	AdapterBase

	tuningService       TuningService
	tuningServiceV2     TuningServiceV2
	tenantReportSvc     TenantReportService
	jsonSchemaValidator JSONSchemaValidator

	auxTimeout time.Duration
	assetTTL   int
	cache      map[string]map[string][]byte
}

// Start REST webserver
func (a *AdapterBase) Start(serverReadyChan chan<- string) error {
	log.Infoln("Server is starting...")
	serverReadyChan <- readySignal
	return a.server.ListenAndServe()
}

// Stop REST webserver
func (a *AdapterBase) Stop(ctx context.Context) error {
	var stopError error

	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	log.WithContext(ctx).Infoln("Shutting down server...")
	if err := a.server.Shutdown(ctx); err != nil {
		stopError = errors.New("Failed to gracefully stop server")
	}
	return stopError
}

func (a *AdapterBase) initServer(handler http.Handler) error {
	log.Debug("initialize http server")
	server := &http.Server{
		Handler: handler,
	}

	port, err := a.conf.GetInt(serverPortConfKey)
	if err != nil {
		return errors.Wrap(err, "failed to get port from configuration")
	}

	if port > math.MaxUint16 {
		return errors.Errorf("invalid port: %v", port)
	}

	if port > 0 {
		server.Addr = ":" + strconv.Itoa(port)
	}

	a.server = server
	return nil
}

func newAdapterBase(cs Configuration, hs HealthService) AdapterBase {
	return AdapterBase{
		server:    nil,
		conf:      cs,
		healthSvc: hs,
	}
}

// NewAdapterStandAlone creates a standalone compatible adapter
func NewAdapterStandAlone(cs Configuration,
	hs HealthService,
	ls StandaloneService) (*AdapterStandAlone, error) {
	ra := AdapterStandAlone{
		AdapterBase:       newAdapterBase(cs, hs),
		standaloneService: ls,
	}
	serverTimeout, err := cs.GetDuration(serverTimeoutConfKey)
	if err != nil {
		return nil, err
	}

	r := ra.setRoutes(ra.newRouter(serverTimeout))
	err = ra.initServer(r)
	if err != nil {
		return &AdapterStandAlone{}, err
	}
	return &ra, nil
}

// NewAdapter is a rest adapter provider
func NewAdapter(
	cs Configuration,
	hs HealthService,
	ds TuningService,
	gems TuningServiceV2,
	trs TenantReportService,
	jsv JSONSchemaValidator,
) (*Adapter, error) {
	ra := Adapter{
		AdapterBase:         newAdapterBase(cs, hs),
		tuningService:       ds,
		tuningServiceV2:     gems,
		tenantReportSvc:     trs,
		jsonSchemaValidator: jsv,
		cache:               map[string]map[string][]byte{},
	}
	serverTimeout, err := cs.GetDuration(serverTimeoutConfKey)
	if err != nil {
		return &Adapter{}, err
	}

	r := ra.setRoutes(ra.newRouter(serverTimeout))
	err = ra.initServer(r)
	if err != nil {
		return &Adapter{}, err
	}

	serverQueryTimeout, err := cs.GetDuration(serverQueryTimeoutConfKey)
	if err != nil {
		return nil, err
	}
	ra.auxTimeout = serverQueryTimeout

	schemaFilePath, err := cs.GetString(schemaFilePathConfKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read schema file path from configuration")
	}

	err = initJSONSchemaValidator(jsv, schemaFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initial json schema validator")
	}

	ttl, err := cs.GetInt(confKeyIntelligenceAssetTTL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get asset ttl from configuration")
	}
	ra.assetTTL = ttl

	errorsPath, err := cs.GetString(errorsFilePathKey)
	if err != nil {
		return nil, err
	}

	errorsCode, err := cs.GetString(errorsCodeKey)
	if err != nil {
		return nil, err
	}

	// init the error loader singleton
	err = errorloader.Configure(errorsPath, errorsCode)
	if err != nil {
		return nil, err
	}

	return &ra, nil
}

func initJSONSchemaValidator(jvs JSONSchemaValidator, schemaFilePath string) error {
	auxQuerySchema, err := ioutil.ReadFile(schemaFilePath)
	if err != nil {
		return errors.Wrap(err, "failed to read assets schema")
	}

	err = jvs.SetSchemaFromBytes(querySchemaName, auxQuerySchema)
	if err != nil {
		return errors.Wrap(err, "failed to set assets schema")
	}

	return nil
}
