# JSONSchema

This library aims to provide a means for registering a set of JSON schemas and validating inputs against them.
To achieve this several capabilities are provided. 

## Capabilities:

### SetSchemaFromString
Accepts a JSON schema in `string` format and a name under which to save the given schema. 

Once saved, this schema can then be used in validations. 

### SetSchemaFromBytes
Accepts a JSON schema in `[]byte` format and a name under which to save the given schema. 

Once saved, this schema can then be used in validations. 

### ValidateSchemaFromString
Accepts a `string` format input and a schema name, indicating against which schema the input should be validated.

If the given input represents a JSON matching the selected schema a `nil` error is returned, otherwise an error indicating the failure is returned. 

### CalculateSchemaPath
Accepts a folder containing all the schemas, and a subfix.

it first looks for the folder in working directory, and if not found - looks under the executable directory.

The function scans all the schemas in the given path for external references and cerates a new version of the schemas containing them. 

Where every relative path is converted to a full path. 

The names these new files begins with the original files name and ends with the given subfix and original filetype ending. 

### ValidateSchemaFromBytes
Accepts a `byte` format input and a schema name, indicating against which schema the input should be validated.

If the given input represents a JSON matching the selected schema a `nil` error is returned, otherwise an error indicating the failure is returned. 


## Example:

```go
package main

import (
	"fmt"

	"openappsec.io/jsonschema"
)

const (
	exampleSchema = `{
    "$id": "https://example.com/person.schema.json",
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Person",
    "type": "object",
    "required": ["firstName"],
    "properties": {
  	"firstName": {
		  "type": "string",
		  "description": "The person's first name."
		},
		"lastName": {
		  "type": "string",
		  "description": "The person's last name."
		},
		"age": {
		  "description": "Age in years which must be equal to or greater than zero.",
		  "type": "integer",
		  "minimum": 0
		}
	  }
	}`

	validInput = `{
		  "firstName": "John",
		  "lastName": "Doe",
		  "age": 21
		}`

	invalidInput = `{
		  "lastName": "Doe",
		  "age": 21
		}`
)

func main() {
	schemaService := jsonschema.NewJSONSchemaService()
	_ = schemaService.SetSchemaFromString("exampleSchema", exampleSchema)
	fmt.Println(schemaService.ValidateSchemaFromString("exampleSchema",validInput)) // prints nil since this is a valid JSON based on the schema
	fmt.Println(schemaService.ValidateSchemaFromBytes("exampleSchema",[]byte(invalidInput))) // prints error since this is not a valid JSON based on the schema
}
```
