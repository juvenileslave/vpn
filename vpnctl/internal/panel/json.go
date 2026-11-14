package panel

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxJSONBytes = 16 << 20
	maxJSONDepth = 128
)

// Canonical normalizes JSON object order, whitespace and exact decimal numbers.
// Array order is significant. Duplicate keys and trailing values are rejected.
// Parse errors never include input or parser diagnostics.
func Canonical(data []byte) ([]byte, error) {
	value, err := jsonValue(data)
	if err != nil {
		return nil, err
	}
	result, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return result, nil
}

func jsonValue(data []byte) (any, error) {
	invalidSize := len(data) == 0 || len(data) > maxJSONBytes
	if invalidSize || !utf8.Valid(data) {
		return nil, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := readJSONValue(decoder, 0)
	if err != nil {
		return nil, ErrInvalidInput
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidInput
	}
	return value, nil
}

func readJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, ErrInvalidInput
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, ErrInvalidInput
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return nil, ErrInvalidInput
				}
				name, ok := key.(string)
				if !ok {
					return nil, ErrInvalidInput
				}
				if _, exists := object[name]; exists {
					return nil, ErrInvalidInput
				}
				item, err := readJSONValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				object[name] = item
			}
			if closer, err := decoder.Token(); err != nil || closer != json.Delim('}') {
				return nil, ErrInvalidInput
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				item, err := readJSONValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, item)
			}
			if closer, err := decoder.Token(); err != nil || closer != json.Delim(']') {
				return nil, ErrInvalidInput
			}
			return array, nil
		}
		return nil, ErrInvalidInput
	case json.Number:
		return exactNumber(value)
	case string, bool, nil:
		return value, nil
	default:
		return nil, ErrInvalidInput
	}
}

// exactNumber uses decimal digits, not float64: adjacent large integers must
// never compare equal. Exponents are kept compact, never expanded into zeros.
func exactNumber(number json.Number) (json.Number, error) {
	text := string(number)
	negative := strings.HasPrefix(text, "-")
	if negative {
		text = text[1:]
	}
	var exponent int64
	if index := strings.IndexAny(text, "eE"); index >= 0 {
		parsed, err := strconv.ParseInt(text[index+1:], 10, 64)
		if err != nil {
			return "", ErrInvalidInput
		}
		exponent = parsed
		text = text[:index]
	}
	fraction := 0
	if index := strings.IndexByte(text, '.'); index >= 0 {
		fraction = len(text) - index - 1
		text = text[:index] + text[index+1:]
	}
	text = strings.TrimLeft(text, "0")
	if text == "" {
		return json.Number("0"), nil
	}
	trimmed := strings.TrimRight(text, "0")
	shift := int64(len(text) - len(trimmed) - fraction)
	const maxInt64 = int64(^uint64(0) >> 1)
	const minInt64 = -maxInt64 - 1
	if shift > 0 && exponent > maxInt64-shift {
		return "", ErrInvalidInput
	}
	if shift < 0 && exponent < minInt64-shift {
		return "", ErrInvalidInput
	}
	exponent += shift
	if negative {
		trimmed = "-" + trimmed
	}
	if exponent != 0 {
		trimmed += "e" + strconv.FormatInt(exponent, 10)
	}
	return json.Number(trimmed), nil
}

func decodeStrict(data []byte, target any) error {
	if _, err := jsonValue(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalidInput
	}
	return nil
}

// MarshalJSON prevents accidentally serializing the credential-bearing bundle.
func (b Bundle) MarshalJSON() ([]byte, error) {
	return []byte(`{"contents":"redacted"}`), nil
}
