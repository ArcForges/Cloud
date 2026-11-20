// SPDX-License-Identifier: AGPL-3.0-only

package paddle

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

var errJSON = errors.New("invalid Paddle JSON shape")

// Reject duplicate object members (including aliases that encoding/json
// matches case-insensitively) before interpreting any fields. Unknown
// Paddle response fields remain compatible with additive v1 changes.
func decodeJSON(body []byte, out any) error {
	if !utf8.Valid(body) {
		return errJSON
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	first, err := d.Token()
	if err != nil || first != json.Delim('{') && first != json.Delim('[') {
		return errJSON
	}
	if err := checkedJSON(d, first, 1); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errJSON
	}
	if err := json.Unmarshal(body, out); err != nil {
		return errJSON
	}
	return nil
}

func checkedJSON(d *json.Decoder, token json.Token, depth int) error {
	delimiter, container := token.(json.Delim)
	if !container {
		return nil
	}
	if depth > 32 || delimiter != '{' && delimiter != '[' {
		return errJSON
	}
	if delimiter == '{' {
		fields := make(map[string]bool)
		for d.More() {
			name, err := d.Token()
			key, ok := name.(string)
			key = strings.ToLower(key)
			if err != nil || !ok || fields[key] {
				return errJSON
			}
			fields[key] = true
			value, err := d.Token()
			if err != nil || checkedJSON(d, value, depth+1) != nil {
				return errJSON
			}
		}
	} else {
		for d.More() {
			value, err := d.Token()
			if err != nil || checkedJSON(d, value, depth+1) != nil {
				return errJSON
			}
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') && end != json.Delim(']') {
		return errJSON
	}
	return nil
}

func providerID(id, prefix string) bool {
	value, ok := strings.CutPrefix(id, prefix)
	if !ok || len(value) != 26 {
		return false
	}
	for i := range len(value) {
		c := value[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func validIntent(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
