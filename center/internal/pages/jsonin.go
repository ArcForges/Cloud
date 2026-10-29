// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"regexp"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The strict reading of the WebBrowserSession request bodies (Contracts public/http/v1/web-browser.schema.json at 62ccef1): each is
// one JSON object without a repeated key or an unknown field, whose members meet the document's types, patterns and bounds. A
// refusal is VALIDATION/invalid_argument naming the member by its JSON path. Shape validity is not authentication, CSRF, origin or
// flow-state authorization; those come from the layers around it.

const (
	maxJSONDepth    = 8
	maxJSONElements = 4096
)

var (
	uuidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	textPattern      = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)
	base64urlPattern = regexp.MustCompile(`^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2,3})?$`)
	hashPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// object is a decoded JSON object whose members are read by name.
type object struct {
	path   string
	fields map[string]json.RawMessage
}

func (o object) at(name string) string {
	if o.path == "" {
		return name
	}
	return o.path + "." + name
}

// parseObject reads one JSON object: no byte after it, no repeated key at any depth, a bounded depth and size, and only the
// allowed members.
func parseObject(data []byte, path string, allowed ...string) (object, *arc.Refusal) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' || !validStructure(data) {
		return object{}, arc.InvalidArgument(orBody(path), "malformed")
	}
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&fields); err != nil || fields == nil {
		return object{}, arc.InvalidArgument(orBody(path), "malformed")
	}
	result := object{path: path, fields: fields}
	for name := range fields {
		if !slices.Contains(allowed, name) {
			return object{}, arc.InvalidArgument(result.at(name), "unknown")
		}
	}
	return result, nil
}

func orBody(path string) string {
	if path == "" {
		return "body"
	}
	return path
}

// validStructure walks the whole document: well formed, one value and nothing after it, no repeated key in any object, at most
// maxJSONDepth levels and maxJSONElements values.
func validStructure(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	elements := 0
	var walk func(depth int) bool
	walk = func(depth int) bool {
		token, err := decoder.Token()
		if err != nil || depth > maxJSONDepth {
			return false
		}
		elements++
		if elements > maxJSONElements {
			return false
		}
		delimiter, isDelimiter := token.(json.Delim)
		if !isDelimiter {
			return true
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				key, isString := keyToken.(string)
				if err != nil || !isString || seen[key] {
					return false
				}
				seen[key] = true
				if !walk(depth + 1) {
					return false
				}
			}
		case '[':
			for decoder.More() {
				if !walk(depth + 1) {
					return false
				}
			}
		}
		_, err = decoder.Token()
		return err == nil
	}
	if !walk(0) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func (o object) has(name string) bool {
	raw, ok := o.fields[name]
	return ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// textRule bounds a string member: its length in characters, its pattern and its closed set of values.
type textRule struct {
	min, max int
	pattern  *regexp.Regexp
	enum     []string
}

// text reads a string member within the rule; present reports whether the member exists (a JSON null is absent).
func (o object) text(name string, rule textRule) (string, bool, *arc.Refusal) {
	if !o.has(name) {
		return "", false, nil
	}
	var value string
	if err := json.Unmarshal(o.fields[name], &value); err != nil {
		return "", false, arc.InvalidArgument(o.at(name), "type")
	}
	if !utf8.ValidString(value) {
		return "", false, arc.InvalidArgument(o.at(name), "pattern")
	}
	if length := utf8.RuneCountInString(value); length < rule.min || rule.max > 0 && length > rule.max {
		return "", false, arc.InvalidArgument(o.at(name), "length")
	}
	if rule.pattern != nil && !rule.pattern.MatchString(value) {
		return "", false, arc.InvalidArgument(o.at(name), "pattern")
	}
	if rule.enum != nil && !slices.Contains(rule.enum, value) {
		return "", false, arc.InvalidArgument(o.at(name), "enum")
	}
	return value, true, nil
}

// requiredText is a member that must exist.
func (o object) requiredText(name string, rule textRule) (string, *arc.Refusal) {
	value, present, refusal := o.text(name, rule)
	if refusal != nil {
		return "", refusal
	}
	if !present {
		return "", arc.InvalidArgument(o.at(name), "required")
	}
	return value, nil
}

// child is a member that must be an object.
func (o object) child(name string, allowed ...string) (object, bool, *arc.Refusal) {
	if !o.has(name) {
		return object{}, false, nil
	}
	if raw := bytes.TrimSpace(o.fields[name]); len(raw) == 0 || raw[0] != '{' {
		return object{}, false, arc.InvalidArgument(o.at(name), "type")
	}
	child, refusal := parseObject(o.fields[name], o.at(name), allowed...)
	return child, refusal == nil, refusal
}

func (o object) requiredChild(name string, allowed ...string) (object, *arc.Refusal) {
	child, present, refusal := o.child(name, allowed...)
	if refusal != nil {
		return object{}, refusal
	}
	if !present {
		return object{}, arc.InvalidArgument(o.at(name), "required")
	}
	return child, nil
}

// uuid is a member holding a canonical lowercase UUID that is not the nil UUID (rule nonzeroUuid).
func (o object) uuid(name string) (platform.ID, bool, *arc.Refusal) {
	value, present, refusal := o.text(name, textRule{min: 36, max: 36, pattern: uuidPattern})
	if refusal != nil || !present {
		return platform.ID{}, false, refusal
	}
	id, ok := parseUUID(value)
	if !ok {
		return platform.ID{}, false, arc.InvalidArgument(o.at(name), "pattern")
	}
	return id, true, nil
}

func (o object) requiredUUID(name string) (platform.ID, *arc.Refusal) {
	id, present, refusal := o.uuid(name)
	if refusal != nil {
		return platform.ID{}, refusal
	}
	if !present {
		return platform.ID{}, arc.InvalidArgument(o.at(name), "required")
	}
	return id, nil
}

// parseUUID reads a canonical lowercase UUID that is not nil.
func parseUUID(text string) (platform.ID, bool) {
	var id platform.ID
	if !uuidPattern.MatchString(text) {
		return id, false
	}
	hex := make([]byte, 0, 32)
	for index := range len(text) {
		if text[index] != '-' {
			hex = append(hex, text[index])
		}
	}
	for index := range id {
		high, low := hexValue(hex[2*index]), hexValue(hex[2*index+1])
		id[index] = high<<4 | low
	}
	return id, id != platform.ID{}
}

func hexValue(c byte) byte {
	if c >= 'a' {
		return c - 'a' + 10
	}
	return c - '0'
}

// bytes is a member holding unpadded base64url text of bytes within the rule's text length, in canonical form.
func (o object) bytes(name string, minChars, maxChars int) ([]byte, bool, *arc.Refusal) {
	value, present, refusal := o.text(name, textRule{min: minChars, max: maxChars, pattern: base64urlPattern})
	if refusal != nil || !present {
		return nil, false, refusal
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, false, arc.InvalidArgument(o.at(name), "pattern")
	}
	return decoded, true, nil
}

func (o object) requiredBytes(name string, minChars, maxChars int) ([]byte, *arc.Refusal) {
	value, present, refusal := o.bytes(name, minChars, maxChars)
	if refusal != nil {
		return nil, refusal
	}
	if !present {
		return nil, arc.InvalidArgument(o.at(name), "required")
	}
	return value, nil
}

// list is a member holding an array of strings.
func (o object) list(name string, maxItems int, itemRule textRule) ([]string, *arc.Refusal) {
	if !o.has(name) {
		return nil, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(o.fields[name], &items); err != nil {
		return nil, arc.InvalidArgument(o.at(name), "type")
	}
	if len(items) > maxItems {
		return nil, arc.InvalidArgument(o.at(name), "max_items")
	}
	values := make([]string, 0, len(items))
	for index, raw := range items {
		holder := object{path: o.at(name), fields: map[string]json.RawMessage{itoa(index): raw}}
		value, present, refusal := holder.text(itoa(index), itemRule)
		if refusal != nil {
			return nil, refusal
		}
		if !present {
			return nil, arc.InvalidArgument(holder.at(itoa(index)), "type")
		}
		values = append(values, value)
	}
	return values, nil
}

func itoa(value int) string { return strconv.Itoa(value) }

// The purposes and methods the WebBrowserSession documents name.
var (
	purposes = []string{"authenticate", "enroll", "stepUp", "recover", "cancelDeletion"}
	methods  = []string{"passkey", "email", "password", "oidc"}
)

// browserBegin is a WebBrowserBeginAuthenticationRequest.
type browserBegin struct {
	Method     string
	Purpose    string
	Claim      device.Claim
	LoginHint  *string
	ProviderID *string
}

func parseBegin(data []byte) (browserBegin, *arc.Refusal) {
	root, refusal := parseObject(data, "", "method", "loginHint", "installation", "providerId", "purpose")
	if refusal != nil {
		return browserBegin{}, refusal
	}
	var result browserBegin
	if result.Method, refusal = root.requiredText("method", textRule{enum: methods}); refusal != nil {
		return browserBegin{}, refusal
	}
	if result.Purpose, refusal = root.requiredText("purpose", textRule{enum: purposes}); refusal != nil {
		return browserBegin{}, refusal
	}
	if hint, present, refusal := root.text("loginHint", textRule{min: 3, max: 320, pattern: loginHintPattern}); refusal != nil {
		return browserBegin{}, refusal
	} else if present {
		result.LoginHint = &hint
	}
	if provider, present, refusal := root.text("providerId", textRule{min: 1, max: 128, pattern: textPattern}); refusal != nil {
		return browserBegin{}, refusal
	} else if present {
		result.ProviderID = &provider
	}
	if result.Claim, refusal = parseClaim(root); refusal != nil {
		return browserBegin{}, refusal
	}
	return result, nil
}

var loginHintPattern = regexp.MustCompile(`^[\x21-\x3F\x41-\x7E]+@[\x21-\x3F\x41-\x7E]+$`)

// parseClaim reads the WebBrowserInstallationClaim of a request.
func parseClaim(root object) (device.Claim, *arc.Refusal) {
	claim, refusal := root.requiredChild("installation", "installationId", "product", "platform", "appVersion")
	if refusal != nil {
		return device.Claim{}, refusal
	}
	var result device.Claim
	if result.InstallationID, refusal = claim.requiredUUID("installationId"); refusal != nil {
		return device.Claim{}, refusal
	}
	if result.Product, refusal = claim.requiredText("product", textRule{enum: []string{"arcscope", "companion", "arcforges-web"}}); refusal != nil {
		return device.Claim{}, refusal
	}
	if result.Platform, refusal = claim.requiredText("platform", textRule{min: 1, max: 128, pattern: textPattern}); refusal != nil {
		return device.Claim{}, refusal
	}
	if result.AppVersion, refusal = claim.requiredText("appVersion", textRule{min: 1, max: 128, pattern: textPattern}); refusal != nil {
		return device.Claim{}, refusal
	}
	return result, nil
}

// readAssertion reads a WebBrowserWebAuthnAssertion; the user handle is required of a discoverable sign-in and a step-up.
func readAssertion(parent object, name string) (passkey.Assertion, *arc.Refusal) {
	node, refusal := parent.requiredChild(name, "credentialId", "clientDataJson", "authenticatorData", "signature", "userHandle")
	if refusal != nil {
		return passkey.Assertion{}, refusal
	}
	var result passkey.Assertion
	if result.CredentialID, refusal = node.requiredBytes("credentialId", 2, 1364); refusal != nil {
		return passkey.Assertion{}, refusal
	}
	if result.ClientDataJSON, refusal = node.requiredBytes("clientDataJson", 2, 21846); refusal != nil {
		return passkey.Assertion{}, refusal
	}
	if result.AuthenticatorData, refusal = node.requiredBytes("authenticatorData", 2, 21846); refusal != nil {
		return passkey.Assertion{}, refusal
	}
	if result.Signature, refusal = node.requiredBytes("signature", 2, 342); refusal != nil {
		return passkey.Assertion{}, refusal
	}
	if result.UserHandle, refusal = node.requiredBytes("userHandle", 2, 86); refusal != nil {
		return passkey.Assertion{}, refusal
	}
	return result, nil
}

// readCreation reads a WebBrowserWebAuthnCreation.
func readCreation(parent object, name string) (passkey.Creation, *arc.Refusal) {
	node, refusal := parent.requiredChild(name, "credentialId", "clientDataJson", "attestationObject", "transports")
	if refusal != nil {
		return passkey.Creation{}, refusal
	}
	var result passkey.Creation
	if result.CredentialID, refusal = node.requiredBytes("credentialId", 2, 1364); refusal != nil {
		return passkey.Creation{}, refusal
	}
	if result.ClientDataJSON, refusal = node.requiredBytes("clientDataJson", 2, 21846); refusal != nil {
		return passkey.Creation{}, refusal
	}
	if result.AttestationObject, refusal = node.requiredBytes("attestationObject", 2, 21846); refusal != nil {
		return passkey.Creation{}, refusal
	}
	if result.Transports, refusal = node.list("transports", 8, textRule{min: 1, max: 128, pattern: textPattern}); refusal != nil {
		return passkey.Creation{}, refusal
	}
	return result, nil
}

// browserComplete is a WebBrowserCompleteAuthenticationRequest or WebBrowserCompleteStepUpRequest: the flow and a passkey proof.
type browserComplete struct {
	FlowID    platform.ID
	Assertion passkey.Assertion
}

// parseComplete reads a completion whose proof is a passkey assertion; another proof of the document's AuthProof (an e-mail code, a
// recovery code, a password, a provider receipt, an admin grant) is not offered here.
func parseComplete(data []byte) (browserComplete, *arc.Refusal) {
	root, refusal := parseObject(data, "", "flowId", "proof")
	if refusal != nil {
		return browserComplete{}, refusal
	}
	var result browserComplete
	if result.FlowID, refusal = root.requiredUUID("flowId"); refusal != nil {
		return browserComplete{}, refusal
	}
	proof, refusal := root.requiredChild("proof", "passkey", "emailCode", "recoveryCode", "password", "providerReceipt", "adminGrant")
	if refusal != nil {
		return browserComplete{}, refusal
	}
	if len(proof.fields) != 1 {
		return browserComplete{}, arc.InvalidArgument("proof", "one_of")
	}
	if !proof.has("passkey") {
		return browserComplete{}, arc.InvalidArgument("proof", "not_offered")
	}
	if result.Assertion, refusal = readAssertion(proof, "passkey"); refusal != nil {
		return browserComplete{}, refusal
	}
	return result, nil
}

// browserEnrollment is a WebBrowserCompleteEnrollmentRequest of the owner bootstrap.
type browserEnrollment struct {
	FlowID      platform.ID
	LocalCode   string
	Creation    passkey.Creation
	DisplayName string
	Locale      *string
	Timezone    *string
}

func parseEnrollment(data []byte) (browserEnrollment, *arc.Refusal) {
	root, refusal := parseObject(data, "", "flowId", "proof", "credential", "profile")
	if refusal != nil {
		return browserEnrollment{}, refusal
	}
	var result browserEnrollment
	if result.FlowID, refusal = root.requiredUUID("flowId"); refusal != nil {
		return browserEnrollment{}, refusal
	}
	proof, refusal := root.requiredChild("proof", "emailCode", "localCode", "providerReceipt")
	if refusal != nil {
		return browserEnrollment{}, refusal
	}
	if len(proof.fields) != 1 {
		return browserEnrollment{}, arc.InvalidArgument("proof", "one_of")
	}
	if !proof.has("localCode") {
		return browserEnrollment{}, arc.InvalidArgument("proof", "not_offered")
	}
	if result.LocalCode, refusal = proof.requiredText("localCode", textRule{min: 1, max: 128}); refusal != nil {
		return browserEnrollment{}, refusal
	}
	credential, refusal := root.requiredChild("credential", "passkey", "password")
	if refusal != nil {
		return browserEnrollment{}, refusal
	}
	if len(credential.fields) != 1 {
		return browserEnrollment{}, arc.InvalidArgument("credential", "one_of")
	}
	if !credential.has("passkey") {
		return browserEnrollment{}, arc.InvalidArgument("credential", "not_offered")
	}
	if result.Creation, refusal = readCreation(credential, "passkey"); refusal != nil {
		return browserEnrollment{}, refusal
	}
	profile, refusal := root.requiredChild("profile", "displayName", "locale", "timezone", "avatar", "clearAvatar")
	if refusal != nil {
		return browserEnrollment{}, refusal
	}
	if profile.has("avatar") || profile.has("clearAvatar") {
		return browserEnrollment{}, arc.InvalidArgument("profile.avatar", "not_offered")
	}
	// The contract bounds the display name at 1 to 256 characters; the account core's own rule (at most 128 UTF-16 units) decides.
	if result.DisplayName, refusal = profile.requiredText("displayName", textRule{min: 1, max: 256}); refusal != nil {
		return browserEnrollment{}, refusal
	}
	if value, present, refusal := profile.text("locale", textRule{min: 1, max: 128, pattern: textPattern}); refusal != nil {
		return browserEnrollment{}, refusal
	} else if present {
		result.Locale = &value
	}
	if value, present, refusal := profile.text("timezone", textRule{min: 1, max: 128, pattern: textPattern}); refusal != nil {
		return browserEnrollment{}, refusal
	} else if present {
		result.Timezone = &value
	}
	return result, nil
}

// browserStepUp is a WebBrowserBeginStepUpRequest.
type browserStepUp struct {
	Class      string
	Method     string
	TargetHash *string
}

func parseStepUp(data []byte) (browserStepUp, *arc.Refusal) {
	root, refusal := parseObject(data, "", "operationClass", "method", "targetHash")
	if refusal != nil {
		return browserStepUp{}, refusal
	}
	var result browserStepUp
	if result.Class, refusal = root.requiredText("operationClass", textRule{min: 1, max: 128, pattern: textPattern}); refusal != nil {
		return browserStepUp{}, refusal
	}
	if result.Method, refusal = root.requiredText("method", textRule{enum: methods}); refusal != nil {
		return browserStepUp{}, refusal
	}
	if hash, present, refusal := root.text("targetHash", textRule{min: 64, max: 64, pattern: hashPattern}); refusal != nil {
		return browserStepUp{}, refusal
	} else if present {
		result.TargetHash = &hash
	}
	return result, nil
}
