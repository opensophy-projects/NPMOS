package models

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// TrustedSourcesSpec defines the trusted sources' spec
type TrustedSourcesSpec struct {
	Name               string   `json:"name"`
	NumOfSources       int      `json:"minNumOfSources" validate:"required" yaml:"minNumOfSources"`
	SourcesIdentifiers []string `json:"sourcesIdentifiers" validate:"required" bson:"sourcesIdentifiers" yaml:"sourcesIdentifiers"`
}

// TrustedSource defines the trusted sources' policy crd
type TrustedSource struct {
	metav1.TypeMeta   `json:"typeMeta,inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec TrustedSourcesSpec `json:"spec"`
}

// PracticeSpec is the practice spec's crd
type PracticeSpec struct {
	Name       string
	WebAttacks `json:"web-attacks,omitempty" yaml:"web-attacks"`
}

//WebAttacks policy for WAAP
type WebAttacks struct {
	OverrideMode      string `json:"override-mode,omitempty" yaml:"override-mode"`
	MinimumConfidence string `json:"minimum-confidence,omitempty" yaml:"minimum-confidence"`
}

// Practice is the crd
type Practice struct {
	metav1.TypeMeta   `json:"typeMeta,inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec PracticeSpec `json:"spec"`
}

// PolicySpec is the policy spec's crd
type PolicySpec struct {
	DefaultPolicy rule   `json:"default,omitempty" yaml:"default"`
	SpecificRules []rule `json:"specific-rules,omitempty" yaml:"specific-rules"`
}

// Policy is the crd
type Policy struct {
	metav1.TypeMeta   `json:"typeMeta,inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec PolicySpec `json:"spec"`
}

// PolicyList is a list of policies
type PolicyList struct {
	metav1.TypeMeta `json:"typeMeta,inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Policy `json:"items"`
}

// TuningDecisionSpec is the tuning decision spec's crd
type TuningDecisionSpec struct {
	Decisions []Decision `json:"decisions"`
}

// Decision is the tuning decision spec's crd
type Decision struct {
	AssetID  string `json:"url"`
	TuningID string `json:"tuningId"`
	Decision string `json:"decision"`
}

// TuningDecision is the crd
type TuningDecision struct {
	metav1.TypeMeta   `json:"typeMeta,inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec TuningDecisionSpec `json:"spec"`
}

// TuningDecisionList is a list of tuning decisions
type TuningDecisionList struct {
	metav1.TypeMeta `json:"typeMeta,inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []TuningDecision `json:"items"`
}

type rule struct {
	IngressRule       string   `json:"host,omitempty" yaml:"host,omitempty"`
	Mode              string   `json:"mode"`
	Practices         []string `json:"practices,flow,omitempty"`
	LogTriggers       []string `json:"triggers,flow,omitempty"`
	WebResponse       string   `json:"custom-response"`
	SourceIdentifiers string   `json:"source-identifiers"`
	TrustedSources    string   `json:"trusted-sources" yaml:"trusted-sources"`
	Exceptions        []string `json:"exceptions,flow"`
}

type webAttacks struct {
	MinimumConfidence string `json:"minimum-confidence,omitempty"`
}

// DeepCopyInto copies all properties of this object into another object of the
// same type that is provided as a pointer.
func (in *Practice) DeepCopyInto(out *Practice) {
	out.TypeMeta = in.TypeMeta
	out.ObjectMeta = in.ObjectMeta
	event := in.Spec
	out.Spec = PracticeSpec{
		WebAttacks: WebAttacks{
			MinimumConfidence: event.WebAttacks.MinimumConfidence,
		},
	}
}

// DeepCopyObject returns a generically typed copy of an object
func (in *Practice) DeepCopyObject() runtime.Object {
	out := Practice{}
	in.DeepCopyInto(&out)

	return &out
}

// DeepCopyInto copies all properties of this object into another object of the
// same type that is provided as a pointer.
func (in *TrustedSource) DeepCopyInto(out *TrustedSource) {
	out.TypeMeta = in.TypeMeta
	out.ObjectMeta = in.ObjectMeta
	event := in.Spec
	out.Spec = TrustedSourcesSpec{
		NumOfSources:       event.NumOfSources,
		SourcesIdentifiers: event.SourcesIdentifiers,
	}
}

// DeepCopyObject returns a generically typed copy of an object
func (in *TrustedSource) DeepCopyObject() runtime.Object {
	out := TrustedSource{}
	in.DeepCopyInto(&out)

	return &out
}

// DeepCopyInto copies all properties of this object into another object of the
// same type that is provided as a pointer.
func (in *Policy) DeepCopyInto(out *Policy) {
	out.TypeMeta = in.TypeMeta
	out.ObjectMeta = in.ObjectMeta
	event := in.Spec
	out.Spec = PolicySpec{
		DefaultPolicy: rule{
			IngressRule:       event.DefaultPolicy.IngressRule,
			Mode:              event.DefaultPolicy.Mode,
			Practices:         event.DefaultPolicy.Practices,
			LogTriggers:       event.DefaultPolicy.LogTriggers,
			WebResponse:       event.DefaultPolicy.WebResponse,
			SourceIdentifiers: event.DefaultPolicy.SourceIdentifiers,
			TrustedSources:    event.DefaultPolicy.TrustedSources,
			Exceptions:        event.DefaultPolicy.Exceptions,
		},
		SpecificRules: nil,
	}
}

// DeepCopyObject returns a generically typed copy of an object
func (in *Policy) DeepCopyObject() runtime.Object {
	out := Policy{}
	in.DeepCopyInto(&out)

	return &out
}

// DeepCopyObject returns a generically typed copy of an object
func (in *PolicyList) DeepCopyObject() runtime.Object {
	out := PolicyList{}
	out.TypeMeta = in.TypeMeta
	out.ListMeta = in.ListMeta

	if in.Items != nil {
		out.Items = make([]Policy, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}

	return &out
}

// DeepCopyInto copies all properties of this object into another object of the
// same type that is provided as a pointer.
func (in *TuningDecision) DeepCopyInto(out *TuningDecision) {
	out.TypeMeta = in.TypeMeta
	out.ObjectMeta = in.ObjectMeta
	for _, event := range in.Spec.Decisions {
		out.Spec.Decisions = append(out.Spec.Decisions, Decision{
			Decision: event.Decision,
			TuningID: event.TuningID,
			AssetID:  event.AssetID,
		})
	}
}

// DeepCopyObject returns a generically typed copy of an object
func (in *TuningDecision) DeepCopyObject() runtime.Object {
	out := TuningDecision{}
	in.DeepCopyInto(&out)

	return &out
}

// DeepCopyObject returns a generically typed copy of an object
func (in *TuningDecisionList) DeepCopyObject() runtime.Object {
	out := TuningDecisionList{}
	out.TypeMeta = in.TypeMeta
	out.ListMeta = in.ListMeta

	if in.Items != nil {
		out.Items = make([]TuningDecision, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}

	return &out
}
