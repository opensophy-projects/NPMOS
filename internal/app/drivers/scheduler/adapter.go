package scheduler

import (
	"context"
	"time"

	"github.com/google/uuid"
	"openappsec.io/ctxutils"
	"openappsec.io/errors"
	"openappsec.io/log"
)

const (
	schedulerBaseKey     = "scheduler"
	schedulerIntervalKey = schedulerBaseKey + ".tuningInterval"
)

// Service the main module
type Service interface {
	TriggerProcess(ctx context.Context) error
}

//Adapter handle scheduling periodic calls to process
type Adapter struct {
	svc             Service
	triggerInterval time.Duration
	stopFunc        context.CancelFunc
}

// Configuration used to get the configuration for the scheduler adapter
type Configuration interface {
	GetDuration(key string) (time.Duration, error)
}

//NewAdapter creates a new scheduler adapter
func NewAdapter(conf Configuration, svc Service) (*Adapter, error) {
	interval, err := conf.GetDuration(schedulerIntervalKey)
	if err != nil {
		return &Adapter{}, errors.Wrap(err, "failed to get scheduler interval")
	}
	return &Adapter{triggerInterval: interval, svc: svc}, nil
}

//Start starts the scheduler
func (a *Adapter) Start(ctx context.Context) error {
	ctx, a.stopFunc = context.WithCancel(ctx)

	now := time.Now()
	nextTick := now.Truncate(a.triggerInterval).Add(a.triggerInterval)
	firstTick := time.Until(nextTick)
	log.WithContext(ctx).Infof("next tick: %v, first tick in: %v", nextTick, firstTick)
	if firstTick > a.triggerInterval {
		return errors.Errorf("unexpected time to first tick: %v, and intervals are: %v", firstTick, a.triggerInterval)
	}
	go func(ctx context.Context) {
		timer := time.NewTimer(firstTick)
		ticker := time.NewTicker(a.triggerInterval)
		for {
			select {
			case <-timer.C:
				ticker.Reset(a.triggerInterval)
				a.triggerProcessTables()
			case <-ticker.C:
				a.triggerProcessTables()
			case <-ctx.Done():
				log.WithContext(ctx).Infof("scheduler stopped")
				return
			}
		}
	}(ctx)
	return nil
}

func (a *Adapter) triggerProcessTables() {
	ctx := ctxutils.Insert(context.Background(), ctxutils.ContextKeyEventTraceID, uuid.NewString())
	log.WithContext(ctx).Infof("trigger scheduled processing")
	err := a.svc.TriggerProcess(ctx)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to trigger process tables, err: %v", err)
	}
}

// Stop gracefully stop the scheduler
func (a *Adapter) Stop(ctx context.Context) error {
	log.WithContext(ctx).Infof("stopping scheduler")
	a.stopFunc()
	return nil
}
