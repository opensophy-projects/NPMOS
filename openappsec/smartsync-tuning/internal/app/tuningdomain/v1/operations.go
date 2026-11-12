package v1

import (
	"context"
	"encoding/json"

	"openappsec.io/smartsync-tuning/models"

	"openappsec.io/errors"
	"openappsec.io/log"
)

const (
	statusNotReady = "notReady"

	dataNameStatistics = "statistics"
	dataNameTuning     = "tuningEvents"
)

// Tune represents the collection of tuning events for a tenant's asset
type Tune struct {
	models.AssetInfo
	Tuning []models.TuneEvent `json:"tuningEvents"`
}

func (t *Tuning) getData(ctx context.Context, tenantID, assetID string, reportType models.ReportedAssetType) ([]byte, error) {
	var data interface{}
	err := t.db.GetAssetData(ctx, reportType, tenantID, assetID, &data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get asset data from repository")
	}
	dataName := dataNameTuning
	if reportType == models.ReportStatistics {
		dataName = dataNameStatistics
	}
	res, err := json.Marshal(map[string]interface{}{dataName: data})
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal data")
	}
	return res, nil
}

// GetStats return the stats of an assetID of a tenantID
func (t *Tuning) GetStats(ctx context.Context, tenantID, assetID string) ([]byte, error) {
	statsStr, err := t.getData(ctx, tenantID, assetID, models.ReportStatistics)
	if err != nil || statsStr == nil {
		stats, errJSON := json.Marshal(map[string]models.Statistics{"statistics": {Status: statusNotReady}})
		if errJSON != nil {
			return []byte{}, errors.Wrapf(err, "got %v while handling error", errJSON)
		}
		return stats, err
	}
	return statsStr, nil
}

// GetTuningEvents return the undecided tuning events of an assetID of a tenantID
func (t *Tuning) GetTuningEvents(ctx context.Context, tenantID, assetID string) ([]byte, error) {
	return t.getData(ctx, tenantID, assetID, models.ReportTuning)
}

// GetTuningEventsReview return the decided tuning events of an assetID of a tenantID
func (t *Tuning) GetTuningEventsReview(ctx context.Context, tenantID, assetID string) ([]byte, error) {
	var data []models.TuneEvent
	err := t.db.GetAssetData(ctx, models.ReportTuningDecided, tenantID, assetID, &data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get asset data from repository")
	}
	currentPolicyVersion, err := t.mgmt.GetPolicyVersion(tenantID)
	if err != nil {
		log.Warn("failed to get policy version")
	}
	response := make([]models.TuneEvent, 0)
	updateRepository := false
	for i, event := range data {
		if event.PolicyVersion == currentPolicyVersion {
			response = append(response, event)
		}
		if event.PolicyVersion == 0 {
			event.PolicyVersion = currentPolicyVersion
			updateRepository = true
			response = append(response, event)
			data[i] = event
		}
	}
	if updateRepository {
		err = t.db.ReportAsset(ctx, models.ReportTuningDecided, tenantID, assetID, data)
		if err != nil {
			log.Warn("failed to update DB err: ", err)
		}
	}
	res, err := json.Marshal(map[string]interface{}{dataNameTuning: response})
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal data")
	}
	return res, nil
}

func copyTuneEvent(event models.TuneEvent) models.TuneEvent {
	copyEvent := event
	copyEvent.Metrics = make([]models.Metric, len(event.Metrics))
	copy(copyEvent.Metrics, event.Metrics)
	copyEvent.AttackTypes = make([]string, len(event.AttackTypes))
	copy(copyEvent.AttackTypes, event.AttackTypes)
	return copyEvent
}

// PostTuningEvents creates a parameter and attach to an asset
func (t *Tuning) PostTuningEvents(ctx context.Context, tenantID, assetID string, body []byte) error {
	var tuningEvents []models.TuneEvent
	err := json.Unmarshal(body, &tuningEvents)
	if err != nil {
		return errors.Wrapf(err, "failed to parse request").SetClass(errors.ClassBadInput)
	}
	newDecisions := make([]models.TuneEvent, 0)

	// find decision to undo
	var appliedTuning []models.TuneEvent

	err = t.db.GetAssetData(ctx, models.ReportTuningDecided, tenantID, assetID, &appliedTuning)
	if err != nil {
		log.Warnf("failed to get decided tuning events, err: %v", err)
	}

	policyVersion, err := t.mgmt.GetPolicyVersion(tenantID)
	if err != nil {
		log.Warn("failed to get policy version")
	}

	var tuningSuggestions []models.TuneEvent
	err = t.db.GetAssetData(ctx, models.ReportTuning, tenantID, assetID, &tuningSuggestions)
	if err != nil {
		return errors.Wrap(err, "failed to get suggested tuning events")
	}

	tuningUndecided := tuningSuggestions

	undoDecisions := make([]models.TuneEvent, 0)
	for _, tuneEvent := range tuningEvents {
		for i, tuneEventDecided := range appliedTuning {
			if tuneEventDecided.EventType == tuneEvent.EventType &&
				tuneEventDecided.EventTitle == tuneEvent.EventTitle {
				// remove from decided
				appliedTuning[i] = appliedTuning[0]
				appliedTuning = appliedTuning[1:]

				undoTuning := copyTuneEvent(tuneEventDecided)
				undoDecisions = append(undoDecisions, undoTuning)

				copyEvent := copyTuneEvent(tuneEventDecided)
				copyEvent.Decision = tuneEvent.Decision
				copyEvent.PolicyVersion = policyVersion
				if tuneEvent.Decision != models.DecisionUnknown {
					newDecisions = append(newDecisions, copyEvent)
				} else {
					copyEvent.PolicyVersion = 0
					tuningUndecided = append(tuningUndecided, copyEvent)
				}
				break
			}
		}
	}

	err = t.mgmt.RemoveParameters(tenantID, assetID, undoDecisions)
	if err != nil {
		return errors.Wrap(err, "failed to undo tuning events")
	}

	for _, tuningEvent := range tuningEvents {
		for i, suggestion := range tuningSuggestions {
			if tuningEvent.EventType == suggestion.EventType &&
				tuningEvent.EventTitle == suggestion.EventTitle {
				// remove from undecided
				tuningUndecided[i] = tuningUndecided[0]
				tuningUndecided = tuningUndecided[1:]

				suggestionTuning := copyTuneEvent(suggestion)
				suggestionTuning.Decision = tuningEvent.Decision
				suggestionTuning.PolicyVersion = policyVersion

				newDecisions = append(newDecisions, suggestionTuning)
				break
			}
		}
	}

	err = t.mgmt.AppendParameters(tenantID, assetID, newDecisions)
	if err != nil {
		return errors.Wrap(err, "failed to append new parameters")
	}

	// update data in DB
	appliedTuning = append(appliedTuning, newDecisions...)

	err = t.db.ReportAsset(
		ctx, models.ReportTuning, tenantID, assetID, tuningUndecided,
	)
	if err != nil {
		log.Errorf("failed to report asset. error %v", err)
	}

	err = t.db.ReportAsset(
		ctx, models.ReportTuningDecided, tenantID, assetID, appliedTuning,
	)
	if err != nil {
		log.Errorf("failed to report asset. error %v", err)
	}

	return nil
}
