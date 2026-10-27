package crdlistener

import (
	"context"
	"time"

	"github.com/google/uuid"
	"openappsec.io/smartsync-tuning/models"
	"openappsec.io/ctxutils"
	"openappsec.io/errors"
	"openappsec.io/log"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
)

const (
	confKeyKubernetesListenerBase       = "kubernetesListener."
	confKeyKubernetesListenerBasePeriod = confKeyKubernetesListenerBase + "period"
)

// Configuration exposes an interface of configuration related actions
type Configuration interface {
	GetString(key string) (string, error)
	GetDuration(key string) (time.Duration, error)
}

// TuningAppService exposes the domain interface for handling events
type TuningAppService interface {
	PostTuningEvents(ctx context.Context, tenantID, assetID, userID string, tuningEvents []models.TuneEvent) error
}

// mockgen -destination mocks/mock_crdsReader.go -package mocks -mock_names ReaderInterface=MockCrdsReader openappsec.io/smartsync-tuning/internal/app/drivers/crdlistener ReaderInterface

// ReaderInterface defines the interface for the crd reader client
type ReaderInterface interface {
	ListTuningDecision(opts metav1.ListOptions) (*models.TuningDecisionList, error)
	ListPolicy(opts metav1.ListOptions) (*models.PolicyList, error)
	GetTrustedSources(name string, opts metav1.GetOptions) (*models.TrustedSource, error)
	GetPractice(name string, opts metav1.GetOptions) (*models.Practice, error)
}

// Adapter listener adapter
type Adapter struct {
	tuningService TuningAppService
	reader        ReaderInterface
	conf          Configuration
	cancel        context.CancelFunc
	chanStop      chan string
}

// Listen starts the tuning crd listener
func (a *Adapter) Listen(ctx context.Context) error {
	err := AddToScheme(scheme.Scheme)
	if err != nil {
		return errors.Wrap(err, "crd listener failed to add to scheme")
	}

	listeningPeriod, err := a.conf.GetDuration(confKeyKubernetesListenerBasePeriod)
	if err != nil {
		return errors.Wrap(err, "failed to get listening period from configuration")
	}
	ticker := time.NewTicker(listeningPeriod)

	defer func() {
		ticker.Stop()
		a.chanStop <- "stopped"
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			ctx := ctxutils.Insert(ctx, ctxutils.ContextKeyEventTraceID, uuid.NewString())
			tuningDecisions, err := a.reader.ListTuningDecision(metav1.ListOptions{})
			if err != nil {
				log.WithContext(ctx).Warnf("crd listener failed to get objects, error: %v", err)
				continue
			}

			if len(tuningDecisions.Items) > 0 {
				log.WithContext(ctx).Infof("Tuning decisions found: %+v", tuningDecisions)
				err = a.postTuningEvents(ctx, tuningDecisions)
				if err != nil {
					log.WithContext(ctx).Warnf("crd listener failed to post tuning events, err: %v", err)
				}
			} else {
				log.WithContext(ctx).Infof("Didn't find tuning decisions")
			}
		}
	}

}

func (a *Adapter) postTuningEvents(ctx context.Context, tuningDecisions *models.TuningDecisionList) error {
	tuningEvents := map[string][]models.TuneEvent{}
	for _, item := range tuningDecisions.Items {
		for _, decision := range item.Spec.Decisions {
			tuningEvents[decision.AssetID] = append(tuningEvents[decision.AssetID], models.TuneEvent{
				ID:       decision.TuningID,
				Decision: decision.Decision,
			})
		}
	}

	errs := []error{}

	for asset, events := range tuningEvents {
		err := a.tuningService.PostTuningEvents(ctx, "",
			asset, "", events)
		if err != nil {
			if errors.IsClass(err, errors.ClassBadInput) {
				errs = append(errs, errors.Wrapf(err, "got bad request %+v", tuningEvents))
			}
			if errors.IsClass(err, errors.ClassUnauthorized) {
				errs = append(errs, errors.Wrapf(err, "MGMT asset for asset: %v was not found. ",
					asset))
			}
			errs = append(errs, errors.Wrapf(err, "internal error decisions: %+v", tuningEvents))
		}
	}
	if len(errs) > 0 {
		return errors.Errorf("errors occurred during handling of decisions, errs: %v", errs)
	}
	return nil
}

// Start running the consumers
func (a *Adapter) Start(ctx context.Context) {
	log.WithContext(ctx).Infof("starting crd listener")

	ctx, cancel := context.WithCancel(ctx)
	a.cancel = cancel

	err := a.Listen(ctx)
	if err != nil {
		log.WithContext(ctx).Errorf("crd listener failed to listen, err: %+v", err)
		return
	}

}

// Stop stopping the consumers
func (a *Adapter) Stop(ctx context.Context) error {
	log.WithContext(ctx).Infof("stopping crd listener")
	a.cancel()
	select {
	case <-a.chanStop:
		close(a.chanStop)
		log.WithContext(ctx).Infof("crd listener stopped")
		return nil
	}
}

// HealthCheck checks adapter health
func (a *Adapter) HealthCheck(ctx context.Context) (string, error) {
	return "", nil
}

// NewAdapter is a crd listener adapter provider
func NewAdapter(ts TuningAppService, r ReaderInterface, c Configuration) (*Adapter, error) {
	a := &Adapter{
		tuningService: ts,
		conf:          c,
		chanStop:      make(chan string, 1),
		reader:        r,
	}

	return a, nil
}
