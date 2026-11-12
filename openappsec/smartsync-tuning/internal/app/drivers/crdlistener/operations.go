package crdlistener

import (
	"context"
	"net/url"
	"strings"

	"openappsec.io/log"

	"openappsec.io/smartsync-tuning/models"
	"openappsec.io/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
)

// ListTuningDecision takes label and field selectors, and returns the list of tuning decisions that match those selectors.
func (c *ReaderClient) ListTuningDecision(opts metav1.ListOptions) (*models.TuningDecisionList, error) {
	//from all namespaces https://localhost/apis/tuningdecisions, from specific-https://localhost/apis/namespaces/default/tuningdecisions
	result := models.TuningDecisionList{}
	err := c.restClient.
		Get().
		Resource("tuningdecisions").
		VersionedParams(&opts, scheme.ParameterCodec).
		Do().
		Into(&result)

	return &result, err
}

// ListPolicy takes label and field selectors, and returns the list of policies that match those selectors.
func (c *ReaderClient) ListPolicy(opts metav1.ListOptions) (*models.PolicyList, error) {
	//from all namespaces https://localhost/apis/policy, from specific-https://localhost/apis/namespaces/default/policy
	result := models.PolicyList{}
	err := c.restClient.
		Get().
		Resource("policies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Do().
		Into(&result)

	return &result, err
}

// GetTrustedSources takes name of the trusted sources, and returns the corresponding trusted sources object, and an error if there is any.
func (c *ReaderClient) GetTrustedSources(name string, opts metav1.GetOptions) (*models.TrustedSource, error) {
	result := models.TrustedSource{}
	err := c.restClient.
		Get().
		Resource("trustedsources").
		Name(name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Do().
		Into(&result)

	return &result, err
}

// GetPractice takes name of the practice, and returns the corresponding practice object, and an error if there is any.
func (c *ReaderClient) GetPractice(name string, opts metav1.GetOptions) (*models.Practice, error) {
	result := models.Practice{}
	err := c.restClient.
		Get().
		Resource("practices").
		Name(name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Do().
		Into(&result)
	return &result, err
}

// Get takes name of the tuning decisions, and returns the corresponding tuning decisions object, and an error if there is any.
func (c *ReaderClient) Get(name string, opts metav1.GetOptions) (*models.TuningDecision, error) {
	result := models.TuningDecision{}
	err := c.restClient.
		Get().
		Resource("tuningdecisions").
		Name(name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Do().
		Into(&result)

	return &result, err
}

// Create takes the representation of a tuning decisions and creates it.  Returns the server's representation of the tuning decisions, and an error, if there is any.
func (c *ReaderClient) Create(decision *models.TuningDecision) (*models.TuningDecision, error) {
	result := models.TuningDecision{}
	err := c.restClient.
		Post().
		Resource("tuningdecisions").
		Body(decision).
		Do().
		Into(&result)

	return &result, err
}

// GetPolicyDetails gets the policy details of an asset
func (c *ReaderClient) GetPolicyDetails(ctx context.Context, tenantID string, assetID string, policyVersion int64) (models.AssetDetails, error) {
	assetsDetails, err := c.GetPolicy(ctx, tenantID, "", policyVersion)
	if err != nil {
		log.WithContext(ctx).Warnf("crd policy getter failed to get assets details for asset: %v", assetID)
	}
	for _, asset := range assetsDetails {
		if asset.AssetID == assetID {
			return asset, nil
		}
	}
	return models.AssetDetails{}, errors.Errorf("asset %v not found in asset details %+v from kubernetes policy file",
		assetID, assetsDetails)
}

// GetPolicy gets policy
func (c *ReaderClient) GetPolicy(ctx context.Context, tenantID string, _ string, _ int64) ([]models.AssetDetails,
	error) {
	log.WithContext(ctx).Debugf("get asset details from kubernetes policy file")
	policies, err := c.ListPolicy(metav1.ListOptions{})

	if err != nil {
		return []models.AssetDetails{}, errors.Wrapf(err, "failed to get policy file from kubernetes")
	}
	// TODO get an answer about number of policies per namespace and which to consider
	var assetsDetails []models.AssetDetails
	for _, item := range policies.Items {
		for _, rule := range item.Spec.SpecificRules {
			var asset models.AssetDetails
			asset.TenantID = tenantID
			u, err := url.Parse(rule.IngressRule)
			if err != nil {
				return []models.AssetDetails{}, errors.Wrap(err, "failed to convert url")
			}
			asset.AssetID = strings.TrimSuffix(u.Hostname()+u.Path, "/")
			asset.TrustedSources, err = c.GetTrustedSourcesPolicy(ctx, "", "", rule.TrustedSources)
			if err != nil {
				return []models.AssetDetails{}, errors.Wrapf(err,
					"failed to get Trusted Sources crd for asset: %s, from kubernetes policy file", asset.AssetID)
			}
			asset.ApplicationUrls = rule.IngressRule
			asset.Name = rule.IngressRule
			asset.Mode = rule.Mode

			for _, practiceName := range rule.Practices {
				practice, err := c.GetPractice(practiceName, metav1.GetOptions{})
				if err != nil {
					return []models.AssetDetails{}, errors.Wrapf(err,
						"failed to get practice crd for asset: %s, from kubernetes policy file", asset.AssetID)
				}
				log.WithContext(ctx).Infof("loaded practice: %+v", practice)
				if practice.Spec.MinimumConfidence != "" {
					asset.Level = practice.Spec.MinimumConfidence
					break
				}
			}
			assetsDetails = append(assetsDetails, asset)
		}
	}

	return assetsDetails, nil
}

// GetTrustedSourcesPolicy gets the trusted Sources from policy
func (c *ReaderClient) GetTrustedSourcesPolicy(_ context.Context, _, _, resourceName string) (models.TrustedSourcesPolicy, error) {
	trustedSources, err := c.GetTrustedSources(resourceName, metav1.GetOptions{})
	if err != nil {
		return models.TrustedSourcesPolicy{}, errors.Wrap(err, "failed to get trustedsources crd")
	}
	identifiers := make([]models.Identifier, len(trustedSources.Spec.SourcesIdentifiers))
	for i, source := range trustedSources.Spec.SourcesIdentifiers {
		identifiers[i] = models.Identifier{Value: source}
	}
	return models.TrustedSourcesPolicy{
		NumOfSources:       trustedSources.Spec.NumOfSources,
		SourcesIdentifiers: identifiers,
	}, nil
}

// GetPolicyVersion gets the version, in kubernetes it is always the updated one.
func (c *ReaderClient) GetPolicyVersion(_ context.Context, _ string, _ string) (int, error) {
	return 0, nil
}
