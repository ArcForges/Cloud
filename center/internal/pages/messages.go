// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"fmt"
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
	"INTERNAL/internal":                 "Something went wrong on our side. Try again in a moment.",
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
}

// operationsText is the text of the refusals whose meaning differs on the operations surface from the account pages'.
var operationsText = map[string]string{
	"CONFLICT/already_exists": "These features were already granted with that source reference. Use another reference for another grant.",
}

// messageFor is the text of a refusal for a page.
func messageFor(value *foundationv1.ArcError, now time.Time) string {
	key := strings.TrimPrefix(value.GetCategory().String(), "ERROR_CATEGORY_") + "/" + value.GetCode()
	if reason := value.GetDetails().GetState().GetReason(); reason != "" {
		if text, ok := reasonText[key+"|"+reason]; ok {
			return withRetry(text, value, now)
		}
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
