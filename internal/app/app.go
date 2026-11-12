package app

import (
	"context"
	"os"
	"os/signal"
	"time"

	"openappsec.io/errors"
	"openappsec.io/health"
	"openappsec.io/log"
	"openappsec.io/tracer"
)

const (
	appName = "smartsync-tuning"

	// configuration keys
	logConfBaseKey       = "log"
	logLevelConfKey      = logConfBaseKey + ".level"
	tracerConfBaseKey    = "tracer"
	tracerHostConfKey    = tracerConfBaseKey + ".host"
	tracerEnabledConfKey = tracerConfBaseKey + ".enabled"
)

// Scheduler defines the interface to start and stop a scheduler
type Scheduler interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// RestAdapter defines a driving adapter interface.
type RestAdapter interface {
	Start(serverStartErrorChan chan<- string) error
	Stop(ctx context.Context) error
}

// Intelligence exposes an interface of intelligence related actions
type Intelligence interface {
	RegistrationHeartbeat(ctx context.Context)
}

// EventConsumerDriver defines an event consumer driving adapter interface
type EventConsumerDriver interface {
	Start(ctx context.Context)
	Stop(ctx context.Context) error
	HealthCheck(ctx context.Context) (string, error)
}

// Configuration exposes an interface of configuration related actions
type Configuration interface {
	SetMany(ctx context.Context, conf map[string]interface{}) error
	Set(ctx context.Context, key string, value interface{}) error
	Get(key string) interface{}
	GetString(key string) (string, error)
	GetInt(key string) (int, error)
	GetBool(key string) (bool, error)
	GetDuration(key string) (time.Duration, error)
	GetAll() map[string]interface{}
	IsSet(key string) bool
	RegisterHook(key string, hook func(value interface{}) error)
	HealthCheck(ctx context.Context) (string, error)
}

// HealthService defines a health domain service
type HealthService interface {
	AddReadinessChecker(checker health.Checker)
}

// DistLock defines interface for a distributed lock driven adapter
type DistLock interface {
	TearDown(ctx context.Context) error
}

//mockgen -destination mocks/mock_dbAdapter.go -package mocks openappsec.io/smartsync-tuning/internal/app DBAdapter

// DBAdapter defines db interface
type DBAdapter interface {
	TearDown(ctx context.Context) error
}

// StandAlone available components for standalone
type StandAlone struct {
	httpDriver RestAdapter
	conf       Configuration
	health     HealthService
	ecDriver   EventConsumerDriver
	scheduler  Scheduler
}

// Stop standalone app operation
func (a *StandAlone) Stop(ctx context.Context) []error {
	log.Debug("stop stand-alone drivers")
	var stopErrs []error
	if err := a.scheduler.Stop(ctx); err != nil {
		stopErrs = append(stopErrs, errors.Errorf("Failed to gracefully shutdown scheduler. Errors: %v", err))
	}

	if err := a.httpDriver.Stop(ctx); err != nil {
		stopErrs = append(stopErrs, errors.Errorf("Failed to gracefully shutdown server. Errors: %v", err))
	}

	if err := a.ecDriver.Stop(ctx); err != nil {
		stopErrs = append(
			stopErrs,
			errors.Errorf("Failed to gracefully stop event consumer driver. Errors: %v", err),
		)
	}

	return stopErrs
}

// App defines the application struct.
type App struct {
	StandAlone
	distLock     DistLock
	dbAdapter    DBAdapter
	intelligence Intelligence
}

// NewAppStandAlone create a standalone app
func NewAppStandAlone(
	c Configuration,
	h HealthService,
	ra RestAdapter,
	ec EventConsumerDriver,
	s Scheduler,
) *StandAlone {
	return &StandAlone{
		httpDriver: ra,
		conf:       c,
		health:     h,
		ecDriver:   ec,
		scheduler:  s,
	}
}

// NewApp returns a new instance of the App struct with its dependencies
func NewApp(
	c Configuration,
	h HealthService,
	ra RestAdapter,
	ec EventConsumerDriver,
	dl DistLock,
	dba DBAdapter,
	i Intelligence) *App {
	return &App{
		StandAlone: StandAlone{
			httpDriver: ra,
			conf:       c,
			health:     h,
			ecDriver:   ec,
		},
		distLock:     dl,
		dbAdapter:    dba,
		intelligence: i,
	}
}

// Start standalone app operation
func (a *StandAlone) Start() error {
	log.Debug("start stand-alone application")
	if err := a.loggerInit(); err != nil {
		return errors.Wrap(err, "Failed to initialize logger")
	}

	if err := a.tracerInit(); err != nil {
		return errors.Wrap(err, "Failed to initialize tracer")
	}
	a.healthInit()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		c := <-signalChan
		log.WithContext(ctx).Infof("Received signal: %+v", c)
		cancel()
	}()

	// start drivers (e.g. http, event consumer)
	return a.serveDriver(ctx)
}

// Start begins the flow of the app
func (a *App) Start() error {
	log.Debug("start fog application")
	if err := a.loggerInit(); err != nil {
		return errors.Wrap(err, "Failed to initialize logger")
	}

	if err := a.tracerInit(); err != nil {
		return errors.Wrap(err, "Failed to initialize tracer")
	}

	a.healthInit()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		c := <-signalChan
		log.WithContext(ctx).Infof("Received signal: %+v", c)
		cancel()
	}()

	// start drivers (e.g. http, event consumer)
	return a.serveDriver(ctx)
}

func (a *StandAlone) serveDriver(ctx context.Context) error {
	log.Debug("start stand-alone drivers")
	serverStartErrorChan := make(chan error, 1)
	serverReadyChan := make(chan string, 1)
	go func() {
		if err := a.httpDriver.Start(serverReadyChan); err != nil {
			serverStartErrorChan <- err
		}
	}()

	go a.ecDriver.Start(ctx)

	err := a.scheduler.Start(ctx)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to start scheduler. err: %v", err)
	}

	for {
		select {
		case <-serverReadyChan:
			log.WithContext(ctx).Infof("server is ready")
		case <-ctx.Done():
			// gracefully shutdown flow, return no error
			// main.go will call Stop()
			return nil
		case err := <-serverStartErrorChan:
			return errors.Wrap(err, "Failed to start server")
		}
	}
}

func (a *App) serveDriver(ctx context.Context) error {
	log.Debug("start fog drivers")
	serverStartErrorChan := make(chan error, 1)
	serverReadyChan := make(chan string, 1)
	go func() {
		if err := a.httpDriver.Start(serverReadyChan); err != nil {
			serverStartErrorChan <- err
		}
	}()

	go a.ecDriver.Start(ctx)

	for {
		select {
		case <-serverReadyChan:
			a.intelligence.RegistrationHeartbeat(ctx)
		case <-ctx.Done():
			// gracefully shutdown flow, return no error
			// main.go will call Stop()
			return nil
		case err := <-serverStartErrorChan:
			return errors.Wrap(err, "Failed to start server")
		}
	}
}

// Stop does a graceful shutdown of the app
func (a *App) Stop(ctx context.Context) []error {
	log.Debug("stop fog drivers")
	var stopErrs []error

	if err := a.httpDriver.Stop(ctx); err != nil {
		stopErrs = append(stopErrs, errors.Errorf("Failed to gracefully shutdown server. Errors: %v", err))
	}

	if err := a.ecDriver.Stop(ctx); err != nil {
		stopErrs = append(
			stopErrs,
			errors.Errorf("Failed to gracefully stop event consumer driver. Errors: %v", err),
		)
	}

	if err := a.distLock.TearDown(ctx); err != nil {
		stopErrs = append(
			stopErrs,
			errors.Errorf("Failed to gracefully tear down distributed lock. Errors: %v", err),
		)
	}

	if err := a.dbAdapter.TearDown(ctx); err != nil {
		stopErrs = append(
			stopErrs,
			errors.Errorf("Failed to gracefully tear down DB adapter. Errors: %v", err),
		)
	}

	return stopErrs
}

func (a *StandAlone) healthInit() {
	log.Info("health init")
	//TODO: add readiness checks here
}

func (a *StandAlone) loggerInit() error {
	if err := a.setLogLevelFromConfiguration(); err != nil {
		return errors.Wrap(err, "Failed to set log level from configuration")
	}
	a.conf.RegisterHook(
		logLevelConfKey, func(value interface{}) error {
			if err := a.setLogLevelFromConfiguration(); err != nil {
				return errors.Wrap(err, "Failed to set log level from configuration")
			}

			return nil
		},
	)

	return nil
}

func (a *StandAlone) setLogLevelFromConfiguration() error {
	logLevel, err := a.conf.GetString(logLevelConfKey)
	if err != nil {
		return err
	}

	err = log.SetLevel(logLevel)
	if err != nil {
		return errors.Wrapf(err, "Failed to set log level (%s)", logLevel).SetClass(errors.ClassBadInput)
	}

	log.WithContext(context.Background()).Infof("Set log level to: %s", logLevel)

	return nil
}

func (a *StandAlone) tracerInit() error {
	ctx := context.Background()
	tracerHost, err := a.conf.GetString(tracerHostConfKey)
	if err != nil {
		return errors.Errorf("Failed to get key (%s) from configuration", tracerHostConfKey)
	}

	tracerEnabled, err := a.conf.GetBool(tracerEnabledConfKey)
	if err != nil {
		return errors.Errorf("Failed to get key (%s) from configuration", tracerEnabledConfKey)
	}

	if tracerEnabled {
		if err := tracer.InitGlobalTracer(appName, tracerHost); err != nil {
			log.WithContext(ctx).Errorf("Could not initialize tracer %v", err)
			return err
		}
		log.WithContext(ctx).Infof("Sending traces to host: %+s", tracerHost)
	}

	return nil
}
