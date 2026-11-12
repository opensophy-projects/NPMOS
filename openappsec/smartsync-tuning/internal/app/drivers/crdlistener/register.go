package crdlistener

import (
	"openappsec.io/smartsync-tuning/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Tuning decision crd's values
const (
	GroupName    = "openappsec.io"
	GroupVersion = "v1beta1"
)

// Scheme builder
var (
	SchemeGroupVersion = schema.GroupVersion{Group: GroupName, Version: GroupVersion}
	SchemeBuilder      = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme        = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&models.TuningDecision{},
		&models.TuningDecisionList{},
		&models.Policy{},
		&models.PolicyList{},
		&models.TrustedSource{},
		&models.Practice{},
	)

	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
