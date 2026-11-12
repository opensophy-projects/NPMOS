package crdlistener

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

// V1Beta1HttpClient is the central point of entry for accessing the custom resources
type V1Beta1HttpClient struct {
	restClient rest.Interface
}

// NewV1Beta1HttpClient is clientset’s constructor function for resource version V1Beta1
func NewV1Beta1HttpClient(c *rest.Config) (V1Beta1HttpClient, error) {
	config := *c
	config.ContentConfig.GroupVersion = &schema.GroupVersion{Group: GroupName, Version: GroupVersion}
	config.APIPath = "/apis"
	config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	config.UserAgent = rest.DefaultKubernetesUserAgent()

	client, err := rest.RESTClientFor(&config)
	if err != nil {
		return V1Beta1HttpClient{}, err
	}

	return V1Beta1HttpClient{restClient: client}, nil
}
