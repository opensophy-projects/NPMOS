package jsonschema

import (
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/xeipuuv/gojsonschema"
	"openappsec.io/errors"
)

const (
	generated = "gen"
)

// Service implements the configuration service.
type Service struct {
	schemas map[string]*gojsonschema.Schema
}

// NewJSONSchemaService returns a new instance of the configuration service
func NewJSONSchemaService() *Service {
	return &Service{
		schemas: make(map[string]*gojsonschema.Schema),
	}
}

// SetSchemaFromString add new json schema from string
func (s *Service) SetSchemaFromString(name string, inputJSON string) error {
	schemaLoader := gojsonschema.NewStringLoader(inputJSON)
	schema, err := gojsonschema.NewSchema(schemaLoader)
	if err != nil {
		return errors.Errorf("Failed to read json schema: %s", err)
	}

	s.schemas[name] = schema
	return nil
}

// SetSchemaFromBytes add new json schema from bytes
func (s *Service) SetSchemaFromBytes(name string, inputJSON []byte) error {
	schemaLoader := gojsonschema.NewBytesLoader(inputJSON)
	schema, err := gojsonschema.NewSchema(schemaLoader)
	if err != nil {
		return errors.Errorf("Failed to read json schema: %s", err)
	}

	s.schemas[name] = schema
	return nil
}

// ValidateSchemaFromString validate string json input with schema
func (s *Service) ValidateSchemaFromString(schemaName string, inputJSON string) error {
	baseSchema, ok := s.schemas[schemaName]
	if !ok {
		return errors.Errorf("No schema found for: %s", schemaName).SetClass(errors.ClassInternal)
	}

	r, err := baseSchema.Validate(gojsonschema.NewStringLoader(inputJSON))
	if err != nil {
		return errors.Errorf("Failed to read json input: %s", err).SetClass(errors.ClassBadInput)
	}

	if !r.Valid() {
		return errors.Errorf("Json input is invalid, see the following errors: %s", r.Errors()).SetClass(errors.ClassBadInput)
	}

	return nil
}

// ValidateSchemaFromBytes validate bytes json input with schema
func (s *Service) ValidateSchemaFromBytes(schemaName string, inputJSON []byte) error {
	baseSchema, ok := s.schemas[schemaName]
	if !ok {
		return errors.Errorf("No schema found for: %s", schemaName).SetClass(errors.ClassInternal)
	}

	r, err := baseSchema.Validate(gojsonschema.NewBytesLoader(inputJSON))
	if err != nil {
		return errors.Errorf("Failed to read json input: %s", err).SetClass(errors.ClassBadInput)
	}

	if !r.Valid() {
		return errors.Errorf("Json input is invalid, see the following errors: %s", r.Errors()).SetClass(errors.ClassBadInput)
	}

	return nil
}

// CalculateSchemaPath changes the references in the json schema from relative path to full path
// the regex catches "$ref": "file:///./iot.json" and changes it to "$ref": "file:///full/path/iot.json"
// or from "$ref": "file:///./iot.json#/definitions/def" and changes it to "$ref": "file:///full/path/iot.json#/definitions/def"
// it first looks for the schema files in working directory, and if not found - looks under the executable directory.
func (s *Service) CalculateSchemaPath(folder string, fileSubFix string) error {
	d, err := getSchemaDir(folder)
	if err != nil {
		return errors.Wrap(err, "Could not preprocess json schemas")
	}

	files, err := filepath.Glob(d + "/*.json")
	if err != nil {
		return errors.Wrapf(err, "could not preprocess json schemas. unable to load all json files")
	}

	ptr := "(\\\"\\$ref\\\"\\:\\s*\"file:\\/\\/\\/)(((.*)(\\/.*#.*\"))|(([^#\"]*)(\\/[^#\"\\/]*\")))"
	rgx := regexp.MustCompile(ptr)
	for _, file := range files {
		f, err := ioutil.ReadFile(file)
		if err != nil {
			return errors.Wrapf(err, "could not preprocess json schemas. unable to read file: %s", file)
		}
		fileAsString := string(f)
		str := rgx.ReplaceAllString(fileAsString, "${1}"+d+"$5$8")
		split := strings.Split(file, ".")
		end := ""
		if len(split) > 1 {
			end = "." + split[len(split)-1]
		}
		endlessFile := []string{strings.Join(split[:len(split)-1], ".")}
		file = strings.Join(append(endlessFile, fileSubFix, end), "")

		if err := ioutil.WriteFile(file, []byte(str), os.FileMode(0644)); err != nil {
			return errors.Wrapf(err, "could not preprocess json schemas. Could not write to file %s content \n%s", file, str)
		}
	}

	return nil
}

func getSchemaDir(folder string) (string, error) {
	p, err := os.Getwd()
	if err != nil {
		return "", errors.Wrapf(err, "Unable to get absolute path")
	}
	p = strings.ReplaceAll(path.Join(p, folder), "\\", "/")
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		return p, nil
	}

	// schema folder not found in working dir, look for it in executable dir.
	ex, err := os.Executable()
	if err != nil {
		return "", errors.Wrapf(err, "Failed to get executable path")
	}
	exDir := filepath.Dir(ex)
	p = strings.ReplaceAll(path.Join(exDir, folder), "\\", "/")
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return "", errors.Errorf("Could not find (%s) folder", folder)
	}

	return p, nil
}
