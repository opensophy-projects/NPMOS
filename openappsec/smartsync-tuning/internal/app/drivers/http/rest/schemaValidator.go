package rest

import "openappsec.io/errors"

func (a *Adapter) validJSONSchema(schemaName string, inputJSON []byte) error {
	err := a.jsonSchemaValidator.ValidateSchemaFromBytes(schemaName, inputJSON)
	if err != nil {
		if errors.IsClass(err, errors.ClassInternal) {
			return errors.Wrapf(err, "failed to validate request body: %v", string(inputJSON))
		}
		return errors.Wrapf(
			err,
			"JSON input is invalid. Schema validator failed. query body: %v",
			string(inputJSON),
		)
	}
	return nil
}
