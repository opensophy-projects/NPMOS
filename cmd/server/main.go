package main

import (
	"context"
	"os"
	"time"

	"openappsec.io/smartsync-tuning/internal/app/ingector"

	"openappsec.io/errors/errorloader"
	"openappsec.io/log"
)

const (
	initTimeout    = 15
	stopTimeout    = 15
	exitCauseError = 1
	exitCauseDone  = 0

	// error response scheme consts
	errorsFilePath = "configs/error-responses.json"
	msrvErrCode    = "116"
)

// Apps represents application
type Apps interface {
	Start() error
	Stop(ctx context.Context) []error
}

func main() {
	initCtx, initCancel := context.WithTimeout(context.Background(), initTimeout*time.Second)

	err := errorloader.Configure(errorsFilePath, msrvErrCode)
	if err != nil {
		log.WithContext(initCtx).Errorf("Failed to configure error loader. Error: %s", err.Error())
		os.Exit(exitCauseError)
	}

	var app Apps

	isK8sEnv := os.Getenv("K8S_NAMESPACE") != ""
	if isK8sEnv {
		app, err = ingector.InitializeAppStandAlone(initCtx)
	} else {
		app, err = ingector.InitializeAppStandAloneDocker(initCtx)
	}
	initCancel()
	if err != nil {
		log.WithContext(initCtx).Error("Failed to inject dependencies! Error: ", err.Error())
		os.Exit(exitCauseError)
	}

	exitCode := exitCauseDone
	if err = app.Start(); err != nil {
		log.WithContext(initCtx).Error("Failed to start app: ", err.Error())
		exitCode = exitCauseError
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), stopTimeout*time.Second)
	if errs := app.Stop(stopCtx); len(errs) > 0 {
		log.WithContext(context.Background()).Error("Failed to stop app: ", errs)
		exitCode = exitCauseError
	}

	stopCancel()
	os.Exit(exitCode)
}
