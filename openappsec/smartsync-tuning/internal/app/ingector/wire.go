//go:build wireinject
// +build wireinject

package ingector

import (
	"context"
	"database/sql/driver"
	"openappsec.io/smartsync-tuning/internal/pkg/policy"

	"openappsec.io/smartsync-tuning/internal/app/drivers/crdlistener"
	"openappsec.io/smartsync-tuning/internal/app/drivers/eventconsumer"
	"openappsec.io/smartsync-tuning/internal/app/drivers/scheduler"
	"openappsec.io/smartsync-tuning/internal/pkg/db/sharedstorage"
	"openappsec.io/smartsync-tuning/internal/pkg/query/pg"

	tuningV2 "openappsec.io/smartsync-tuning/internal/app/tuningdomain/v2"
	s3 "openappsec.io/smartsync-tuning/internal/pkg/db/s3"
	"openappsec.io/smartsync-tuning/internal/pkg/query"

	"github.com/google/wire"
	"github.com/lib/pq"

	"openappsec.io/configuration"
	"openappsec.io/configuration/viper"
	"openappsec.io/health"
	"openappsec.io/smartsync-tuning/internal/app"
	"openappsec.io/smartsync-tuning/internal/app/drivers/http/rest"
)

// InitializeAppStandAlone is an Adapter injector
func InitializeAppStandAlone(ctx context.Context) (*app.StandAlone, error) {
	wire.Build(
		viper.NewViper,
		wire.Bind(new(configuration.Repository), new(*viper.Adapter)),

		configuration.NewConfigurationService,
		wire.Bind(new(rest.Configuration), new(*configuration.Service)),
		wire.Bind(new(app.Configuration), new(*configuration.Service)),
		wire.Bind(new(query.Configuration), new(*configuration.Service)),
		wire.Bind(new(pg.Configuration), new(*configuration.Service)),
		wire.Bind(new(sharedstorage.Configuration), new(*configuration.Service)),
		wire.Bind(new(s3.Configuration), new(*configuration.Service)),
		wire.Bind(new(tuningV2.Configuration), new(*configuration.Service)),
		wire.Bind(new(crdlistener.Configuration), new(*configuration.Service)),
		wire.Bind(new(scheduler.Configuration), new(*configuration.Service)),

		health.NewService,
		wire.Bind(new(rest.HealthService), new(*health.Service)),
		wire.Bind(new(app.HealthService), new(*health.Service)),

		sharedstorage.NewAdapter,
		wire.Bind(new(tuningV2.RepositoryV2), new(*sharedstorage.Adapter)),

		s3.NewAdapter,
		wire.Bind(new(tuningV2.S3Repo), new(*s3.Adapter)),

		crdlistener.NewReader,
		wire.Bind(new(tuningV2.PolicyFetch), new(*crdlistener.ReaderClient)),
		wire.Bind(new(tuningV2.PolicyDetails), new(*crdlistener.ReaderClient)),
		wire.Bind(new(crdlistener.ReaderInterface), new(*crdlistener.ReaderClient)),

		crdlistener.NewAdapter,
		wire.Bind(new(app.EventConsumerDriver), new(*crdlistener.Adapter)),

		tuningV2.NewStandAlone,
		wire.Bind(new(rest.StandaloneService), new(*tuningV2.StandAlone)),
		wire.Bind(new(crdlistener.TuningAppService), new(*tuningV2.StandAlone)),
		wire.Bind(new(scheduler.Service), new(*tuningV2.StandAlone)),

		pg.NewQueriesGen,
		wire.Bind(new(query.GenQueries), new(*pg.QueriesGen)),

		pg.NewPQDriver,
		wire.Bind(new(driver.Driver), new(*pq.Driver)),

		query.NewAdapter,
		wire.Bind(new(tuningV2.LogRepositoryAdapter), new(*query.Adapter)),

		rest.NewAdapterStandAlone,
		wire.Bind(new(app.RestAdapter), new(*rest.AdapterStandAlone)),

		scheduler.NewAdapter,
		wire.Bind(new(app.Scheduler), new(*scheduler.Adapter)),

		app.NewAppStandAlone,
	)

	return &app.StandAlone{}, nil
}

// InitializeAppStandAloneDocker is an Adapter injector
func InitializeAppStandAloneDocker(ctx context.Context) (*app.StandAlone, error) {
	wire.Build(
		viper.NewViper,
		wire.Bind(new(configuration.Repository), new(*viper.Adapter)),

		configuration.NewConfigurationService,
		wire.Bind(new(rest.Configuration), new(*configuration.Service)),
		wire.Bind(new(app.Configuration), new(*configuration.Service)),
		wire.Bind(new(query.Configuration), new(*configuration.Service)),
		wire.Bind(new(pg.Configuration), new(*configuration.Service)),
		wire.Bind(new(sharedstorage.Configuration), new(*configuration.Service)),
		wire.Bind(new(s3.Configuration), new(*configuration.Service)),
		wire.Bind(new(tuningV2.Configuration), new(*configuration.Service)),
		wire.Bind(new(scheduler.Configuration), new(*configuration.Service)),
		wire.Bind(new(policy.Configuration), new(*configuration.Service)),

		health.NewService,
		wire.Bind(new(rest.HealthService), new(*health.Service)),
		wire.Bind(new(app.HealthService), new(*health.Service)),

		sharedstorage.NewAdapter,
		wire.Bind(new(tuningV2.RepositoryV2), new(*sharedstorage.Adapter)),

		s3.NewAdapter,
		wire.Bind(new(tuningV2.S3Repo), new(*s3.Adapter)),

		policy.NewAdapter,
		wire.Bind(new(tuningV2.PolicyFetch), new(*policy.Adapter)),
		wire.Bind(new(tuningV2.PolicyDetails), new(*policy.Adapter)),

		eventconsumer.NewDockerAdapter,
		wire.Bind(new(app.EventConsumerDriver), new(*eventconsumer.DockerAdapter)),

		tuningV2.NewStandAlone,
		wire.Bind(new(rest.StandaloneService), new(*tuningV2.StandAlone)),
		wire.Bind(new(scheduler.Service), new(*tuningV2.StandAlone)),

		pg.NewQueriesGen,
		wire.Bind(new(query.GenQueries), new(*pg.QueriesGen)),

		pg.NewPQDriver,
		wire.Bind(new(driver.Driver), new(*pq.Driver)),

		query.NewAdapter,
		wire.Bind(new(tuningV2.LogRepositoryAdapter), new(*query.Adapter)),

		rest.NewAdapterStandAlone,
		wire.Bind(new(app.RestAdapter), new(*rest.AdapterStandAlone)),

		scheduler.NewAdapter,
		wire.Bind(new(app.Scheduler), new(*scheduler.Adapter)),

		app.NewAppStandAlone,
	)

	return &app.StandAlone{}, nil
}
