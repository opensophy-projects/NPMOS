package flatten

import "openappsec.io/errors"

// Map receive a map[string]interface{} and flatten the map to a map[string]interface{} (with delimiter as a separate between keys)
func Map(prefix string, m interface{}, delimiter string, res map[string]interface{}) error {
	switch m1 := m.(type) {
	case map[string]interface{}:
		for k, v := range m1 {
			if prefix == "" {
				if err := Map(k, v, delimiter, res); err != nil {
					return err
				}
			} else {
				if err := Map(joinKeys(prefix, k, delimiter), v, delimiter, res); err != nil {
					return err
				}
			}
		}
	case string, int, bool:
		res[prefix] = m1
	default:
		return errors.Errorf("Invalid format of map input: %v", m1)
	}

	return nil
}

// Concat two keys with delimiter (dot, path, etc.) between them.
// If one of the keys is empty, return the other one
func joinKeys(key1, key2 string, delimiter string) string {
	if key1 != "" && key2 != "" {
		return key1 + delimiter + key2
	}

	if key1 == "" {
		return key2
	}

	return key1
}
