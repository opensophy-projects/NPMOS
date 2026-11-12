package rest

import (
	"net/http"

	"openappsec.io/ctxutils"

	"openappsec.io/httputils/responses"

	"openappsec.io/log"
	"openappsec.io/smartsync-tuning/models"
)

// UpdatePolicyByCrd updating policy from kubernetes policy
func (a *AdapterStandAlone) UpdatePolicyByCrd(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log.WithContext(ctx).Infof("update policy from crd")

	tenantID := ctxutils.ExtractString(ctx, ctxutils.ContextKeyTenantID)
	err := a.standaloneService.UpdatePolicy(ctx, models.PolicyMessageData{TenantID: tenantID})
	if err != nil {
		log.WithContext(ctx).Errorf("failed to update policy, err %v", err)
		httpReturnError(ctx, w, http.StatusInternalServerError, r.URL.Path, "failed to update crd policy")
		return
	}
	responses.HTTPReturn(ctx, w, http.StatusOK, []byte{}, false)
}
