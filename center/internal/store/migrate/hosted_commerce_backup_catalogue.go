// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"errors"
	"slices"
	"strings"

	"github.com/ArcForges/Cloud/center/internal/schema"
)

const hostedCommerceSchema16MigrationSHA = "dff7e02565e017d055a555ca1ff5c549e5a2aa976aded5b51312b06d504f0b4e"

// Native PostgreSQL 18.7 on H-22 at 4e64bbcf8045e726a0fb5cad7db876bfd699cdd0
// retained all 390 schema15 entries and added 102. The 492-entry inventory has SHA256
// bc7e06def0c69afb52fb5461263e8c3bc2a121b41de890994316ca8f5637cfac.
const hostedCommerceSchema16CatalogueSHA = "2d58b28bd5f4e5563be2d9ad26df33b52433645b3eea0d3ca3bf665b1c8c7f0a"

const hostedCommerceSchema16InventoryDelta = `CONSTRAINT commerce billing_entry billing_entry_pkey
CONSTRAINT commerce billing_entry billing_entry_provider_environment_provider_entry_ref_kind_key
CONSTRAINT commerce checkout checkout_account_id_command_id_key
CONSTRAINT commerce checkout checkout_checkout_id_account_id_provider_environment_key
CONSTRAINT commerce checkout checkout_pkey
CONSTRAINT commerce checkout checkout_provider_environment_provider_checkout_ref_key
CONSTRAINT commerce checkout checkout_provider_environment_provider_intent_id_key
CONSTRAINT commerce customer customer_account_id_provider_environment_provider_customer__key
CONSTRAINT commerce customer customer_pkey
CONSTRAINT commerce customer customer_provider_environment_provider_customer_ref_key
CONSTRAINT commerce provider_environment provider_environment_environment_key
CONSTRAINT commerce provider_environment provider_environment_pkey
CONSTRAINT commerce provider_event provider_event_pkey
CONSTRAINT commerce purchase purchase_account_id_command_id_key
CONSTRAINT commerce purchase purchase_pkey
CONSTRAINT commerce purchase purchase_purchase_id_account_id_provider_environment_key
CONSTRAINT commerce renewal renewal_account_id_command_id_key
CONSTRAINT commerce renewal renewal_pkey
CONSTRAINT commerce settled_period settled_period_pkey
CONSTRAINT commerce settled_period settled_period_provider_environment_provider_transaction_re_key
CONSTRAINT commerce settled_period settled_period_subscription_id_provider_period_ref_key
CONSTRAINT commerce settled_period settled_period_term_id_account_id_key
CONSTRAINT commerce subscription subscription_pkey
CONSTRAINT commerce subscription subscription_provider_environment_provider_subscription_ref_key
CONSTRAINT commerce subscription subscription_subscription_id_account_id_provider_environmen_key
FK CONSTRAINT commerce billing_entry billing_entry_account_id_fkey
FK CONSTRAINT commerce billing_entry billing_entry_environment_fkey
FK CONSTRAINT commerce billing_entry billing_entry_provider_environment_event_ref_fkey
FK CONSTRAINT commerce billing_entry billing_entry_subscription_id_account_id_provider_environm_fkey
FK CONSTRAINT commerce checkout checkout_account_id_provider_environment_provider_customer_fkey
FK CONSTRAINT commerce checkout checkout_purchase_id_account_id_provider_environment_fkey
FK CONSTRAINT commerce customer customer_account_id_fkey
FK CONSTRAINT commerce customer customer_environment_fkey
FK CONSTRAINT commerce provider_event provider_event_account_id_fkey
FK CONSTRAINT commerce provider_event provider_event_environment_fkey
FK CONSTRAINT commerce purchase purchase_account_id_fkey
FK CONSTRAINT commerce purchase purchase_environment_fkey
FK CONSTRAINT commerce renewal renewal_subscription_id_account_id_provider_environment_fkey
FK CONSTRAINT commerce settled_period settled_period_control_grant_id_account_id_fkey
FK CONSTRAINT commerce settled_period settled_period_nodes_grant_id_account_id_fkey
FK CONSTRAINT commerce settled_period settled_period_provider_environment_event_ref_fkey
FK CONSTRAINT commerce settled_period settled_period_subscription_id_account_id_provider_environ_fkey
FK CONSTRAINT commerce settled_period settled_period_term_id_account_id_fkey
FK CONSTRAINT commerce settled_period settled_period_view_grant_id_account_id_fkey
FK CONSTRAINT commerce subscription subscription_account_id_provider_environment_provider_cust_fkey
FK CONSTRAINT commerce subscription subscription_checkout_id_account_id_provider_environment_fkey
FUNCTION commerce guard_checkout()
FUNCTION commerce guard_provider_event()
FUNCTION commerce guard_purchase()
FUNCTION commerce guard_renewal()
FUNCTION commerce guard_subscription()
FUNCTION commerce refuse_change()
INDEX commerce billing_entry_account
INDEX commerce billing_entry_environment
INDEX commerce billing_entry_event
INDEX commerce billing_entry_subscription
INDEX commerce checkout_purchase
INDEX commerce checkout_unexpired_purchase
INDEX commerce customer_environment
INDEX commerce provider_event_account
INDEX commerce provider_event_environment
INDEX commerce provider_event_resource
INDEX commerce provider_event_work
INDEX commerce purchase_environment
INDEX commerce purchase_unresolved_account
INDEX commerce renewal_subscription
INDEX commerce renewal_unresolved_subscription
INDEX commerce settled_period_control_grant
INDEX commerce settled_period_event
INDEX commerce settled_period_nodes_grant
INDEX commerce settled_period_view_grant
INDEX commerce subscription_account
INDEX commerce subscription_checkout
SCHEMA - commerce
TABLE DATA commerce billing_entry
TABLE DATA commerce checkout
TABLE DATA commerce customer
TABLE DATA commerce provider_environment
TABLE DATA commerce provider_event
TABLE DATA commerce purchase
TABLE DATA commerce renewal
TABLE DATA commerce settled_period
TABLE DATA commerce subscription
TABLE commerce billing_entry
TABLE commerce checkout
TABLE commerce customer
TABLE commerce provider_environment
TABLE commerce provider_event
TABLE commerce purchase
TABLE commerce renewal
TABLE commerce settled_period
TABLE commerce subscription
TRIGGER commerce billing_entry billing_entry_append_only
TRIGGER commerce checkout checkout_guard
TRIGGER commerce customer customer_append_only
TRIGGER commerce provider_environment provider_environment_append_only
TRIGGER commerce provider_event provider_event_guard
TRIGGER commerce purchase purchase_guard
TRIGGER commerce renewal renewal_guard
TRIGGER commerce settled_period settled_period_append_only
TRIGGER commerce subscription subscription_guard
VIEW commerce provider_cleanup_pending`

func hostedCommerceBackupDefinition() (string, string, error) {
	previous, _, err := hostedEntitlementBackupDefinition()
	if err != nil {
		return "", "", err
	}
	build, err := Load(schema.Migrations())
	if err != nil || len(build) < 16 || build[15].Name != "0016_hosted_web_commerce.sql" ||
		build[15].SHA256 != hostedCommerceSchema16MigrationSHA {
		return "", "", errors.New("schema16 backup catalogue qualification does not match this migration build")
	}
	objects := strings.Split(strings.TrimSuffix(previous, "\n")+"\n"+hostedCommerceSchema16InventoryDelta, "\n")
	slices.Sort(objects)
	return strings.Join(objects, "\n") + "\n", hostedCommerceSchema16CatalogueSHA, nil
}
