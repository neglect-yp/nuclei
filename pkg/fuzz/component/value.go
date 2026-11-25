package component

import (
	"reflect"
	"strconv"

	"github.com/leslie-qiwa/flat"
	"github.com/logrusorgru/aurora/v4"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/internal/logging"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/dataformat"
)

// Value is a value component containing a single
// parameter for the component
//
// It is a type of container that is used to represent
// all the data values that are used in a request.
type Value struct {
	logger     *gologger.Logger
	data       string
	parsed     dataformat.KV
	dataFormat string
	encoder    dataformat.DataFormat
}

// NewValue returns a new value component
func NewValue(data string) *Value {
	return newValue(data, gologger.DefaultLogger)
}

func newValue(data string, logger *gologger.Logger) *Value {
	if data == "" {
		return &Value{logger: logger}
	}
	v := &Value{data: data, logger: logger}

	// Do any dataformat decoding on the data if needed
	decodedDataformat, err := dataformat.Decode(data)
	if err == nil && decodedDataformat != nil {
		v.SetParsed(decodedDataformat.Data, decodedDataformat.DataFormat)
	}
	return v
}

// Clones current state of this value
func (v *Value) Clone() *Value {
	return &Value{
		logger:     v.logger,
		data:       v.data,
		parsed:     v.parsed.Clone(),
		dataFormat: v.dataFormat,
		encoder:    v.encoder,
	}
}

// String returns the string representation of the value
func (v *Value) String() string {
	return v.data
}

// Parsed returns the parsed value
func (v *Value) Parsed() dataformat.KV {
	return v.parsed
}

// SetParsed sets the parsed value map
func (v *Value) SetParsed(data dataformat.KV, dataFormat string) {
	v.dataFormat = dataFormat
	if data.OrderedMap != nil {
		v.parsed = data
		return
	}
	parsed := data.Map
	flattened, err := flat.Flatten(parsed, flatOpts)
	if err == nil {
		v.parsed = dataformat.KVMap(flattened)
	} else {
		v.parsed = dataformat.KVMap(parsed)
	}
}

// SetParsedValue sets the parsed value for a key
// in the parsed map
func (v *Value) SetParsedValue(key, value string) bool {
	if key == "" {
		return false
	}

	origValue := v.parsed.Get(key)
	if origValue == nil {
		v.parsed.Set(key, value)
		return true
	}

	// TODO(dwisiswant0): I'm sure that this can be simplified because
	// `dataformat.KV.*` is a type of `mapsutil.*` where the value is `any`. So,
	// it looks like we won't type conversion here or even have its own methods
	// inside `dataformat.KV`.

	// If the value is a list, append to it
	// otherwise replace it
	switch typed := origValue.(type) {
	case []interface{}:
		// update last value
		if len(typed) > 0 {
			typed[len(typed)-1] = value
		}
		origValue = typed
	case string:
		origValue = value
	case int, int32, int64, float32, float64:
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return false
		}
		origValue = parsed
	case bool:
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return false
		}
		origValue = parsed
	default:
		// explicitly check for typed slice
		if val, ok := IsTypedSlice(typed); ok {
			if len(val) > 0 {
				val[len(val)-1] = value
			}
			origValue = val
		} else {
			// make it default warning instead of error
			logging.OrDefault(v.logger).Print().Msgf("[%v] unknown type %T for value %s", aurora.BrightYellow("WARN"), typed, typed)
		}
	}
	v.parsed.Set(key, origValue)
	return true
}

// Delete removes a key from the parsed value
func (v *Value) Delete(key string) bool {
	return v.parsed.Delete(key)
}

// Encode encodes the value into a string
// using the dataformat and encoding
func (v *Value) encode(data dataformat.KV) (string, error) {
	encoder := v.encoder
	if encoder == nil {
		encoder = dataformat.Get(v.dataFormat)
	}
	if form, ok := encoder.(*dataformat.Form); ok {
		return form.EncodeWithLogger(data, logging.OrDefault(v.logger))
	}
	if encoder != nil {
		return encoder.Encode(data)
	}
	return dataformat.Encode(data, v.dataFormat)
}

func (v *Value) Encode() (string, error) {
	toEncodeStr := v.data
	if v.parsed.OrderedMap != nil {
		// flattening orderedmap not supported
		if v.dataFormat != "" {
			dataformatStr, err := v.encode(v.parsed)
			if err != nil {
				return "", err
			}
			toEncodeStr = dataformatStr
		}
		return toEncodeStr, nil
	}

	nested, err := flat.Unflatten(v.parsed.Map, flatOpts)
	if err != nil {
		return "", err
	}
	if v.dataFormat != "" {
		dataformatStr, err := v.encode(dataformat.KVMap(nested))
		if err != nil {
			return "", err
		}
		toEncodeStr = dataformatStr
	}
	return toEncodeStr, nil
}

// In go, []int, []string are not implictily converted to []interface{}
// when using type assertion and they need to be handled separately.
func IsTypedSlice(v interface{}) ([]interface{}, bool) {
	if reflect.ValueOf(v).Kind() == reflect.Slice {
		// iterate and convert to []interface{}
		slice := reflect.ValueOf(v)
		interfaceSlice := make([]interface{}, slice.Len())
		for i := 0; i < slice.Len(); i++ {
			interfaceSlice[i] = slice.Index(i).Interface()
		}
		return interfaceSlice, true
	}
	return nil, false
}
