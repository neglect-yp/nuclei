package openapi

import (
	"io"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
)

// OpenAPIFormat is a OpenAPI Schema File parser
type OpenAPIFormat struct {
	logger *gologger.Logger
	opts   formats.InputFormatOptions
}

// New creates a new OpenAPI format parser
func New() *OpenAPIFormat {
	return &OpenAPIFormat{}
}

func NewWithLogger(logger *gologger.Logger) *OpenAPIFormat {
	return &OpenAPIFormat{logger: logger}
}

var _ formats.Format = &OpenAPIFormat{}

// Name returns the name of the format
func (j *OpenAPIFormat) Name() string {
	return "openapi"
}

func (j *OpenAPIFormat) SetOptions(options formats.InputFormatOptions) {
	j.opts = options
}

// Parse parses the input and calls the provided callback
// function for each RawRequest it discovers.
func (j *OpenAPIFormat) Parse(input io.Reader, resultsCb formats.ParseReqRespCallback, filePath string) error {
	loader := openapi3.NewLoader()
	schema, err := loader.LoadFromIoReader(input)
	if err != nil {
		return errors.Wrap(err, "could not decode openapi 3.0 schema")
	}
	return GenerateRequestsFromSchemaWithLogger(schema, j.opts, resultsCb, j.logger)
}
