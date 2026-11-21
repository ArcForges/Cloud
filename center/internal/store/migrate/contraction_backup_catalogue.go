// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"errors"
	"slices"
	"strings"

	"github.com/ArcForges/Cloud/center/internal/schema"
)

const contractionSchema17MigrationSHA = "c47a969fded0473e654178eab94e9092dfe8d5319881cd05eee6bd6ddd0d0bbb"

// Native PostgreSQL 18.7 produced this digest and 429 exact TOC entries.
const contractionSchema17CatalogueSHA = "673aff018a34cc5a7a24eda07c97490dc4407dfe852d0237cc78ea4063192bb7"

const contractionSchema17InventoryRetired = `CONSTRAINT fleet refusal_code refusal_code_pkey
CONSTRAINT fleet refusal_code refusal_code_unique
CONSTRAINT fleet routed_call routed_call_pkey
CONSTRAINT fleet routed_command_id routed_command_id_pkey
CONSTRAINT fleet routed_file_call routed_file_call_pkey
CONSTRAINT fleet routed_file_target routed_file_target_pkey
CONSTRAINT identity mobile_authorization mobile_authorization_pkey
FK CONSTRAINT fleet routed_call routed_call_account
FK CONSTRAINT fleet routed_call routed_call_node
FK CONSTRAINT fleet routed_call routed_call_refusal
FK CONSTRAINT fleet routed_command_id routed_command_id_account
FK CONSTRAINT fleet routed_file_call routed_file_call_account
FK CONSTRAINT fleet routed_file_call routed_file_call_node
FK CONSTRAINT fleet routed_file_call routed_file_call_refusal
FK CONSTRAINT fleet routed_file_target routed_file_target_account_id_fkey
FK CONSTRAINT fleet routed_file_target routed_file_target_node_enrollment_id_fkey
FK CONSTRAINT identity mobile_authorization mobile_authorization_approver_session
FK CONSTRAINT identity mobile_authorization mobile_authorization_session
FK CONSTRAINT identity mobile_authorization mobile_authorization_user
FK CONSTRAINT identity mobile_authorization mobile_authorization_viewer
FUNCTION fleet refusal_code_fixed()
FUNCTION fleet reserve_routed_command_id()
FUNCTION fleet routed_call_guarded()
FUNCTION fleet routed_command_id_fixed()
FUNCTION fleet routed_file_call_guarded()
FUNCTION fleet routed_file_target_fixed()
FUNCTION identity refuse_final_mobile_authorization_change()
FUNCTION management legacy_frozen()
INDEX fleet routed_call_account_created
INDEX fleet routed_call_node_created
INDEX fleet routed_call_open
INDEX fleet routed_call_refusal_code
INDEX fleet routed_file_call_account_created
INDEX fleet routed_file_call_node_created
INDEX fleet routed_file_call_open
INDEX fleet routed_file_call_refusal_code
INDEX fleet routed_file_target_enrollment
INDEX identity mobile_authorization_approver_session
INDEX identity mobile_authorization_expires_at
INDEX identity mobile_authorization_session
INDEX identity mobile_authorization_user
INDEX identity mobile_authorization_viewer
TABLE DATA fleet refusal_code
TABLE DATA fleet routed_call
TABLE DATA fleet routed_command_id
TABLE DATA fleet routed_file_call
TABLE DATA fleet routed_file_target
TABLE DATA identity mobile_authorization
TABLE fleet refusal_code
TABLE fleet routed_call
TABLE fleet routed_command_id
TABLE fleet routed_file_call
TABLE fleet routed_file_target
TABLE identity mobile_authorization
TRIGGER fleet refusal_code refusal_code_fixed
TRIGGER fleet routed_call legacy_task_frozen
TRIGGER fleet routed_call routed_call_command_id
TRIGGER fleet routed_call routed_call_guarded
TRIGGER fleet routed_command_id routed_command_id_fixed
TRIGGER fleet routed_file_call legacy_file_frozen
TRIGGER fleet routed_file_call routed_file_call_command_id
TRIGGER fleet routed_file_call routed_file_call_guarded
TRIGGER fleet routed_file_target legacy_target_frozen
TRIGGER fleet routed_file_target routed_file_target_fixed
TRIGGER identity mobile_authorization mobile_authorization_final`

func contractionBackupDefinition() (string, string, error) {
	previous, _, err := hostedCommerceBackupDefinition()
	if err != nil {
		return "", "", err
	}
	build, err := Load(schema.Migrations())
	if err != nil || len(build) < schema.ContractionVersion ||
		build[schema.ContractionVersion-1].Name != "0017_retire_legacy_routing.sql" ||
		build[schema.ContractionVersion-1].SHA256 != contractionSchema17MigrationSHA ||
		!restoreDigest.MatchString(contractionSchema17CatalogueSHA) {
		return "", "", errors.New("schema17 backup catalogue qualification does not match this migration build")
	}
	retired := strings.Split(contractionSchema17InventoryRetired, "\n")
	objects := strings.Split(strings.TrimSuffix(previous, "\n"), "\n")
	expected := len(objects) - len(retired)
	objects = slices.DeleteFunc(objects, func(object string) bool { return slices.Contains(retired, object) })
	if len(objects) != expected {
		return "", "", errors.New("schema17 backup catalogue does not match the retired object inventory")
	}
	objects = append(objects, "FUNCTION platform runtime_contraction_ready()", "VIEW platform runtime_schema_history")
	slices.Sort(objects)
	return strings.Join(objects, "\n") + "\n", contractionSchema17CatalogueSHA, nil
}
