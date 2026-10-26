package crdlistener

import (
	"openappsec.io/errors"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

// ReaderClient is a specific clientset for accessing the TuningDecision custom resource
type ReaderClient struct {
	restClient rest.Interface
	ns         string
}

// NewReader gets crds reader client for specific namespace
func NewReader(conf Configuration) (*ReaderClient, error) {
	clientSet, err := initClientSet()
	if err != nil {
		return nil, errors.Wrap(err, "crd listener failed to initialize client")
	}

	err = AddToScheme(scheme.Scheme)
	if err != nil {
		return nil, errors.Wrap(err, "crd listener failed to add to scheme")
	}

	namespace, err := conf.GetString("K8S_NAMESPACE")
	if err != nil {
		return nil, errors.Wrap(err, "crd listener failed to get namespace from conf")
	}

	return &ReaderClient{
		restClient: clientSet.restClient,
		ns:         namespace,
	}, nil
}

func initClientSet() (*V1Beta1HttpClient, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, errors.Wrap(err, "crd listener failed to create rest config")
	}
	clientSet, err := NewV1Beta1HttpClient(config)
	if err != nil {
		return nil, errors.Wrap(err, "crd listener failed to create clientset object")
	}

	return &clientSet, nil
}
