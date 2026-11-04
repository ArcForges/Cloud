// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
)

// The text of every refusal a page can show (accessibility: error text for every refusal). A refusal's text is fixed per code and, for
// two codes, per reason: it never repeats anything the request said, only registry values choose it.

// refusalText maps CATEGORY/code to the text shown for it.
var refusalText = map[string]string{
	"VALIDATION/invalid_argument":       "Some of the information was not accepted. Check it and try again.",
	"VALIDATION/invalid_cursor":         "The list position is not valid. Open the list again.",
	"AUTHENTICATION/unauthenticated":    "That did not work. Sign in again and retry.",
	"AUTHENTICATION/token_expired":      "Your session has ended. Sign in again.",
	"AUTHENTICATION/credential_revoked": "Your session has ended. Sign in again.",
	"AUTHENTICATION/step_up_required":   "This change needs a passkey check first. Go back and try again.",
	"AUTHORIZATION/permission_denied":   "This is not allowed.",
	"ENTITLEMENT/feature_not_entitled":  "This is not part of your plan.",
	"CONFLICT/code_reused":              "That step was already used. Start again.",
	"CONFLICT/already_exists":           "That passkey is already registered.",
	"CONFLICT/command_id_reused":        "That request was already used for something else. Go back and try again.",
	"CONFLICT/revision_conflict":        "This item changed meanwhile. Open the page again and retry.",
	"STATE/not_found":                   "That item no longer exists.",
	"STATE/invalid_state":               "The account's state does not allow this change.",
	"STATE/expired":                     "This step took too long. Start again.",
	"STATE/not_activated":               "This page is not available.",
	"RESOURCE/rate_limited":             "Too many attempts. Wait a little and try again.",
	"RESOURCE/overloaded":               "The service is busy. Try again in a moment.",
	"VALIDATION/code_invalid":           "That code cannot be used. Check it, or start the sign-in again on the node.",
	"INTERNAL/internal":                 "Something went wrong on our side. The request may or may not have been completed, so check before you do it again.",
}

// reasonText maps CATEGORY/code and state.reason to a more exact text; the reasons are registry values.
var reasonText = map[string]string{
	"STATE/invalid_state|last_credential":                      "This is your only way to sign in, so it cannot be removed. Add another passkey first.",
	"STATE/invalid_state|credentials_locked":                   "The account's state does not allow passkeys to be changed.",
	"STATE/invalid_state|no_catalogue":                         "This center has no plan catalogue, so there is nothing to grant.",
	"STATE/invalid_state|self_hosted":                          "Operator grants exist only on the official hosted center.",
	"STATE/invalid_state|catalogue_wide":                       "A grant of every feature is not allowed on this center. Choose some of them.",
	"STATE/invalid_state|self_approval_required":               "A grant to your own account needs a justification.",
	"STATE/invalid_state|account_state":                        "That account's state does not allow a grant.",
	"VALIDATION/invalid_argument|expires_at: too_far":          "The grant lasts too long for this center. Use fewer days.",
	"VALIDATION/invalid_argument|expires_days: pattern":        "Enter the number of days as a whole number from 1 to 400.",
	"VALIDATION/invalid_argument|features: conflicts_with_all": "Choose every feature or some of them, not both.",
	"VALIDATION/invalid_argument|reason: encoding":             "The reason is not valid text. Type it again.",
	"VALIDATION/invalid_argument|self_approval: encoding":      "The justification is not valid text. Type it again.",
	"VALIDATION/invalid_argument|source_ref: encoding":         "The source reference is not valid text. Type it again.",
	"VALIDATION/invalid_argument|features: required":           "Choose at least one feature.",
	"VALIDATION/invalid_argument|features: not_in_catalogue":   "A chosen feature is not in this center's catalogue.",
	"VALIDATION/invalid_argument|account: format":              "The account is not a valid account identifier.",
	"VALIDATION/invalid_argument|reason: length_or_characters": "The reason needs 1 to 512 characters and no control characters.",
	"VALIDATION/invalid_argument|source_ref: format":           "The source reference needs 1 to 96 letters, digits or the characters . _ : -.",
	"VALIDATION/invalid_argument|credential: not_verified":     "Your device could not confirm the new passkey. Start again.",
	"VALIDATION/invalid_argument|display_name: length":         "The name is too long. Use 64 characters or fewer.",
	"VALIDATION/invalid_argument|display_name: pattern":        "The name needs at least one visible character and no control characters.",
	"VALIDATION/invalid_argument|name: length":                 "The name is too long. Use 64 characters or fewer.",
	"VALIDATION/invalid_argument|name: pattern":                "The name needs at least one visible character and no control characters.",
	"VALIDATION/invalid_argument|query: not_admitted":          "This page does not take a query string.",
	// The fleet pages (AF-CTR-04 E3). invalid_state carries the lower-case state name of a sign-in request or not_reviewed (C0).
	"VALIDATION/invalid_argument|flow_id: pattern":          "This link is not complete. Start the sign-in again on the node.",
	"VALIDATION/invalid_argument|user_code: pattern":        "Enter the 8 letters the node shows, for example BCDF-GHJK.",
	"VALIDATION/invalid_argument|decision: pattern":         "Choose to connect or to deny the node.",
	"VALIDATION/invalid_argument|fingerprint_tail: pattern": "Enter the last 4 characters of the fingerprint your node shows.",
	"VALIDATION/invalid_argument|fingerprint_tail: mismatch": "Those are not the last 4 characters of this node's fingerprint. Check the fingerprint your node " +
		"shows. If it differs, deny the request.",
	"STATE/invalid_state|not_reviewed": "This request needs a fresh review. Open it again from the start.",
	"STATE/invalid_state|pending":      "This request is still waiting for a decision.",
	"STATE/invalid_state|approved":     "This request is already approved.",
	"STATE/invalid_state|denied":       "This request was denied. Start again on the node.",
	"STATE/invalid_state|completed":    "This node already finished signing in with this request.",
	"STATE/invalid_state|revoked":      "This request was ended. Start again on the node.",
	"STATE/invalid_state|expired":      "This sign-in request has expired. Start again on the node.",
	// A Restricted account is refused at the operation table with the operation's ID as the reason (a refused Origin or CSRF token
	// names the page route instead, and keeps the generic text).
	"AUTHORIZATION/permission_denied|fleet.getNodeSignInFlow": "This account is restricted, so it cannot connect nodes now.",
	"AUTHORIZATION/permission_denied|fleet.approveNodeSignIn": "This account is restricted, so it cannot connect nodes now.",
	"AUTHORIZATION/permission_denied|fleet.lookupDeviceCode":  "This account is restricted, so it cannot connect nodes now.",
	"AUTHORIZATION/permission_denied|fleet.approveDeviceCode": "This account is restricted, so it cannot connect nodes now.",
}

// fleetText is the text of the refusals whose meaning differs on the fleet pages from the account pages'.
var fleetText = map[string]string{
	"STATE/expired":                   "This sign-in request has expired. Start again on the node.",
	"STATE/not_found":                 "This sign-in request does not exist, or another account decided it. Start again on the node.",
	"CONFLICT/command_id_reused":      "That form was already used. Open the request again from the start.",
	"AUTHENTICATION/step_up_required": "Approving needs a passkey check. Try again and confirm with your passkey.",
}

// limitText is the text of a refusal chosen by the limit it names (E2: code_invalid tells an unknown code from one whose lookups are
// spent), with the limit's value where the text has a %d: what is left, or the maximum.
var limitText = map[string]struct {
	text    string
	none    string
	maximum bool
}{
	"VALIDATION/code_invalid|device_entry_account": {text: "That code was not recognized. You can try %d more codes now; after that, wait a while before trying again.",
		none: "That code was not recognized, and no attempts are left. Wait a while before trying again."},
	"VALIDATION/code_invalid|device_code_lookups": {text: "This code was looked up too often. Start the sign-in again on the node.",
		none: "This code was looked up too often. Start the sign-in again on the node."},
	"RESOURCE/quota_exceeded|max_nodes_per_account": {text: "This account has reached its limit of %d nodes. Revoke a node on the devices page, then start " +
		"again on the node.", maximum: true},
}

// operationsText is the text of the refusals whose meaning differs on the operations surface from the account pages'.
var operationsText = map[string]string{
	"CONFLICT/already_exists": "These features were already granted with that source reference. Use another reference for another grant.",
}

// messageFor is the text of a refusal for a page.
func messageFor(value *foundationv1.ArcError, now time.Time) string {
	return messageForSurface(value, now, false)
}

// messageForSurface is the text of a refusal, on a fleet page when fleetPage: a text chosen by the refusal's limit first, then by its
// state reason, then the fleet's own text of the code, then the shared text of the code.
func messageForSurface(value *foundationv1.ArcError, now time.Time, fleetPage bool) string {
	key := strings.TrimPrefix(value.GetCategory().String(), "ERROR_CATEGORY_") + "/" + value.GetCode()
	if limit := value.GetDetails().GetLimit(); limit != nil {
		if row, ok := limitText[key+"|"+limit.GetLimitName()]; ok {
			maximum, maximumOK := decimalCount(limit.GetMaximum())
			available, availableOK := decimalCount(limit.GetAvailable())
			switch {
			case row.maximum && maximumOK:
				return withRetry(fmt.Sprintf(row.text, maximum), value, now)
			case row.maximum:
			case availableOK && available <= 0:
				return withRetry(row.none, value, now)
			case strings.Contains(row.text, "%d") && availableOK:
				return withRetry(fmt.Sprintf(row.text, available), value, now)
			case !strings.Contains(row.text, "%d"):
				return withRetry(row.text, value, now)
			}
		}
	}
	if reason := value.GetDetails().GetState().GetReason(); reason != "" {
		if text, ok := reasonText[key+"|"+reason]; ok {
			return withRetry(text, value, now)
		}
	}
	if text, ok := fleetText[key]; ok && fleetPage {
		return withRetry(text, value, now)
	}
	if text, ok := refusalText[key]; ok {
		return withRetry(text, value, now)
	}
	return withRetry("The request could not be completed.", value, now)
}

// withRetry adds the advised wait of a refusal that states one.
func withRetry(text string, value *foundationv1.ArcError, now time.Time) string {
	at := value.GetRetry().GetRetryAt()
	if at == nil {
		return text
	}
	seconds := int(instantOf(at).Sub(now).Round(time.Second).Seconds())
	switch {
	case seconds <= 1:
		return text
	case seconds < 120:
		return fmt.Sprintf("%s Try again in %d seconds.", text, seconds)
	}
	return fmt.Sprintf("%s Try again in about %d minutes.", text, (seconds+59)/60)
}

// headingFor is the heading of an error page for a refusal: an internal failure may have had its effect (INTERNAL/internal advises
// NEVER with UNKNOWN), so its page never says "Try again shortly", which the heading of a 503 or 500 says of a busy service.
func headingFor(status int, value *foundationv1.ArcError) string {
	if value.GetCategory() == foundationv1.ErrorCategory_ERROR_CATEGORY_INTERNAL {
		return "Something went wrong"
	}
	return pageHeading(status)
}

// pageHeading is the heading of an error page for a status.
func pageHeading(status int) string {
	switch status {
	case 403:
		return "This is not allowed"
	case 404:
		return "Page not found"
	case 413, 415:
		return "The request was not accepted"
	case 429:
		return "Too many requests"
	case 503, 500:
		return "Try again shortly"
	}
	return "The request was not accepted"
}

// decimalCount reads a whole, non-negative count of a limit (foundation Decimal); anything else is no count.
func decimalCount(value *foundationv1.Decimal) (int64, bool) {
	if value == nil || value.Value == nil {
		return 0, false
	}
	count, err := strconv.ParseInt(value.GetValue(), 10, 64)
	return count, err == nil && count >= 0 && strconv.FormatInt(count, 10) == value.GetValue()
}
