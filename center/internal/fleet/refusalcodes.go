// SPDX-License-Identifier: AGPL-3.0-only

package fleet

// refusalCodes is the fixed, append-only table of the refusal codes a routing record names (decisions B-2; migration 0010's
// fleet.refusal_code): every CATEGORY/code of the Contracts error catalogue of cohort 1.0.0-ci.437.1 (Contracts e67a6b0) with its
// smallint value, numbered 1 to 67 in alphabetical order of CATEGORY/code. A value never changes and is never reused; a code outside the table is RefusalOther. A
// later catalogue's new code is appended, with the next value, here and by a migration. TestTheRefusalCodesAreFixed pins every value,
// that every catalogue code maps, and that the migration's rows are this table.
var refusalCodes = map[string]int16{
	"authentication/credential_revoked":    1,
	"authentication/signature_invalid":     2,
	"authentication/step_up_required":      3,
	"authentication/token_expired":         4,
	"authentication/unauthenticated":       5,
	"authorization/account_mismatch":       6,
	"authorization/approval_required":      7,
	"authorization/command_pattern_denied": 8,
	"authorization/peer_policy_denied":     9,
	"authorization/permission_denied":      10,
	"conflict/already_exists":              11,
	"conflict/code_reused":                 12,
	"conflict/command_id_reused":           13,
	"conflict/digest_mismatch":             14,
	"conflict/purchase_already_linked":     15,
	"conflict/revision_conflict":           16,
	"entitlement/feature_not_entitled":     17,
	"entitlement/plan_limit_reached":       18,
	"execution/adopt_not_permitted":        19,
	"execution/integration_write_failed":   20,
	"execution/operation_failed":           21,
	"execution/provider_error":             22,
	"internal/internal":                    23,
	"internal/store_corrupt":               24,
	"resource/disk_space":                  25,
	"resource/enforcement_unavailable":     26,
	"resource/kill_switch_active":          27,
	"resource/overloaded":                  28,
	"resource/queue_full":                  29,
	"resource/quota_exceeded":              30,
	"resource/rate_limited":                31,
	"resource/too_large":                   32,
	"state/cloud_unreachable":              33,
	"state/dirty_worktree":                 34,
	"state/expired":                        35,
	"state/in_use":                         36,
	"state/invalid_state":                  37,
	"state/link_down":                      38,
	"state/managed_externally":             39,
	"state/node_offline":                   40,
	"state/node_stopping":                  41,
	"state/node_unreachable":               42,
	"state/not_activated":                  43,
	"state/not_attached":                   44,
	"state/not_found":                      45,
	"state/not_signed_in":                  46,
	"state/pause_unsupported":              47,
	"state/peer_blocked":                   48,
	"state/peer_incompatible":              49,
	"state/peer_unreachable":               50,
	"state/plan_expired":                   51,
	"state/purchase_pending":               52,
	"state/sas_mismatch":                   53,
	"state/secrets_unavailable":            54,
	"state/update_in_progress":             55,
	"validation/code_invalid":              56,
	"validation/incompatible_version":      57,
	"validation/inputs_required":           58,
	"validation/invalid_argument":          59,
	"validation/invalid_cursor":            60,
	"validation/invalid_dependency":        61,
	"validation/invalid_policy":            62,
	"validation/path_not_found":            63,
	"validation/program_not_found":         64,
	"validation/purchase_invalid":          65,
	"validation/unsafe_batch_argument":     66,
	"validation/unsupported_shell":         67,
	"conflict/file_changed":                68,
	"conflict/occurrence_mismatch":         69,
	"state/file_access_denied":             70,
}

// RefusalOther is the value of a refusal code outside the table.
const RefusalOther int16 = 0

// RefusalCode is the value of a CATEGORY/code key (lower case), or RefusalOther.
func RefusalCode(key string) int16 {
	if value, ok := refusalCodes[key]; ok {
		return value
	}
	return RefusalOther
}

// RefusalCodes is a copy of the table (tests).
func RefusalCodes() map[string]int16 {
	copied := make(map[string]int16, len(refusalCodes))
	for key, value := range refusalCodes {
		copied[key] = value
	}
	return copied
}
