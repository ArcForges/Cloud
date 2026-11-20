// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

type hostedCommerceFacts struct {
	account, purchase, checkout, subscription platform.ID
}

func commerceFact(t *testing.T, owner *pgx.Conn, statement string, args ...any) {
	t.Helper()
	if _, err := owner.Exec(context.Background(), statement, args...); err != nil {
		t.Fatal(Sanitize("record supplied commerce fixture", err))
	}
}

func seedHostedCommerceFacts(t *testing.T, owner *pgx.Conn, account platform.ID) hostedCommerceFacts {
	t.Helper()
	f := hostedCommerceFacts{account: account, purchase: platform.NewID(), checkout: platform.NewID(), subscription: platform.NewID()}
	ctx := context.Background()
	var now time.Time
	if err := owner.QueryRow(ctx, "SELECT statement_timestamp()").Scan(&now); err != nil {
		t.Fatal(Sanitize("read commerce fixture clock", err))
	}
	// Supplied provider facts exercise archive/migration integrity only.
	// Commerce's own fixtures exercise the signature and business decision.
	commerceFact(t, owner, "INSERT INTO commerce.provider_environment (environment) VALUES (2) ON CONFLICT (singleton) DO NOTHING")
	commerceFact(t, owner, `INSERT INTO commerce.customer(account_id,provider,environment,provider_customer_ref,created_at)
VALUES($1,1,2,'ctm_archive',$2)`, account, now)
	commerceFact(t, owner, `INSERT INTO commerce.purchase
(purchase_id,account_id,command_id,provider,environment,catalog_version,offer_ref,product_ref,price_ref,price_version,
 definition_version,currency,amount_minor,billing_interval,region,adjustment_policy,intent_sha256,state,created_at,expires_at,updated_at,rev)
VALUES($1,$2,gen_random_uuid(),1,2,'archive-catalog','archive-offer','pro_archive','pri_archive','archive-price',
 'archive-entitlement','USD',1234,'month','US','preserve_partial_end_full_or_chargeback',
 sha256('original purchase'),3,$3::timestamptz-interval '2 days',$3-interval '1 day',$3,1)`, f.purchase, account, now)
	commerceFact(t, owner, `INSERT INTO commerce.checkout
(checkout_id,purchase_id,account_id,command_id,provider,environment,intent_sha256,return_path,provider_intent_id,provider_checkout_ref,
 provider_customer_ref,state,send_claimed_at,created_at,expires_at,updated_at)
VALUES($1,$2,$3,gen_random_uuid(),1,2,sha256('original checkout'),'/billing',gen_random_uuid(),'txn_archive','ctm_archive',3,
 $4::timestamptz-interval '2 days',$4-interval '2 days',$4-interval '1 day',$4)`, f.checkout, f.purchase, account, now)
	commerceFact(t, owner, `INSERT INTO commerce.subscription
(subscription_id,account_id,provider,environment,provider_customer_ref,provider_subscription_ref,checkout_id,catalog_version,
 product_ref,price_ref,state,valid_from,valid_until,auto_renew,provider_revision,provider_updated_at,provider_snapshot_sha256,verified_at,rev)
VALUES($1,$2,1,2,'ctm_archive','sub_archive',$3,'archive-catalog','pro_archive','pri_archive',5,
 $4::timestamptz-interval '2 days',$4-interval '1 day',false,'archive-evidence',$4,sha256('verified subscription'),$4,1)`,
		f.subscription, account, f.checkout, now)
	commerceFact(t, owner, `INSERT INTO commerce.renewal
(renewal_id,subscription_id,account_id,command_id,provider,environment,intent_sha256,auto_renew,state,
 result_subscription_rev,result_valid_from,result_valid_until,created_at,updated_at)
VALUES(gen_random_uuid(),$1,$2,gen_random_uuid(),1,2,sha256('original renewal'),false,2,
 1,$3::timestamptz-interval '2 days',$3-interval '1 day',$3,$3)`, f.subscription, account, now)
	commerceFact(t, owner, `INSERT INTO commerce.provider_event
(provider,environment,event_ref,payload_sha256,semantic_sha256,event_kind,resource_ref,account_id,occurred_at,state,verified_at,received_at,processed_at)
VALUES(1,2,'evt_archive',sha256('original event bytes'),sha256('original event meaning'),'transaction.completed','txn_archive',
 $1,$2,2,$2,$2,$2)`, account, now)
	term, nodes, view, control := platform.NewID(), platform.NewID(), platform.NewID(), platform.NewID()
	commerceFact(t, owner, `INSERT INTO entitlement.service_term
(term_id,account_id,kind,subscription_ref,period_ref,starts_at,ends_at,authorized_at,created_at)
VALUES($1,$2,1,'sub_archive','archive-period',$3::timestamptz-interval '2 days',$3-interval '1 day',$3-interval '2 days',$3-interval '2 days')`, term, account, now)
	commerceFact(t, owner, `INSERT INTO entitlement.grant
(grant_id,account_id,kind,subject,value,source,source_ref,effective_from,effective_until,issued_by_actor,created_at)
VALUES ($2,$1,1,'center.nodes','{}',1,'archive-nodes',$5::timestamptz-interval '2 days',$5-interval '1 day','fixture:provider',$5),
       ($3,$1,1,'remote.view','{}',1,'archive-view',$5-interval '2 days',$5-interval '1 day','fixture:provider',$5),
       ($4,$1,1,'remote.control','{}',1,'archive-control',$5-interval '2 days',$5-interval '1 day','fixture:provider',$5)`,
		account, nodes, view, control, now)
	commerceFact(t, owner, `INSERT INTO commerce.settled_period
(period_id,subscription_id,account_id,provider,environment,provider_transaction_ref,provider_period_ref,term_id,nodes_grant_id,
 view_grant_id,control_grant_id,valid_from,valid_until,settled_at,event_ref)
VALUES(gen_random_uuid(),$1,$2,1,2,'txn_archive','archive-period',$3,$4,$5,$6,
 $7::timestamptz-interval '2 days',$7-interval '1 day',$7,'evt_archive')`,
		f.subscription, account, term, nodes, view, control, now)
	commerceFact(t, owner, `INSERT INTO commerce.billing_entry
(entry_id,account_id,subscription_id,provider,environment,provider_entry_ref,kind,currency,amount_minor,occurred_at,recorded_at,event_ref)
VALUES(gen_random_uuid(),$1,$2,1,2,'txn_archive',1,'USD',1234,$3,$3,'evt_archive'),
      (gen_random_uuid(),$1,$2,1,2,'adj_archive',6,'USD',-725,$3,$3,'evt_archive')`, account, f.subscription, now)
	return f
}

func checkCommercePending(t *testing.T, q Querier, account platform.ID, want bool) {
	t.Helper()
	var pending bool
	err := q.QueryRow(context.Background(), "SELECT EXISTS (SELECT 1 FROM commerce.provider_cleanup_pending WHERE account_id=$1)", account).Scan(&pending)
	if err != nil || pending != want {
		t.Fatalf("provider cleanup pending=%v want=%v: %v", pending, want, Sanitize("read commerce cleanup facts", err))
	}
}

func seedQueuedCommerceEvent(t *testing.T, owner *pgx.Conn) {
	t.Helper()
	commerceFact(t, owner, `INSERT INTO commerce.provider_event
(provider,environment,event_ref,payload_sha256,semantic_sha256,event_kind,resource_ref,occurred_at,state,verified_at,received_at,next_check_at)
VALUES(1,2,'evt_archive_queued',sha256('pending event bytes'),sha256('pending event meaning'),'transaction.completed','txn_archive',
 statement_timestamp(),1,statement_timestamp(),statement_timestamp(),statement_timestamp())`)
}

func TestHostedCommerceAppendPreservesSchema15AndGuards(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	runtime := name + "_runtime"
	options := Options{Runner: "isolated-commerce-append", RuntimeRole: runtime}
	build := centerBuild(t)
	if len(build) < 16 || build[15].Name != "0016_hosted_web_commerce.sql" {
		t.Fatal("the build is missing the canonical schema16 append")
	}
	before, err := Apply(ctx, owner, build[:15], options)
	if err != nil || before.Version != 15 || before.State != StateCurrent {
		t.Fatalf("prepare exact schema15: %v", err)
	}
	var oldReadOnly bool
	err = owner.QueryRow(ctx, `SELECT to_regnamespace('commerce') IS NULL
 AND NOT has_table_privilege($1,'entitlement.service_term_action','INSERT')
 AND NOT has_table_privilege($1,'entitlement.account_status_fact','INSERT')`, runtime).Scan(&oldReadOnly)
	if err != nil || !oldReadOnly {
		t.Fatalf("schema15 runtime scope changed: %v", Sanitize("check schema15 permissions", err))
	}
	result, err := Apply(ctx, owner, build[:16], options)
	if err != nil || result.Version != 16 || len(result.Ran) != 1 || result.Ran[0].SHA256 != build[15].SHA256 {
		t.Fatalf("append schema16: %v", err)
	}
	if !slices.EqualFunc(before.Applied, result.Applied[:15], func(old, current Applied) bool {
		return old.Version == current.Version && old.Name == current.Name && old.SHA256 == current.SHA256 &&
			old.AppliedAt.Equal(current.AppliedAt) && old.AppliedBy == current.AppliedBy
	}) {
		t.Fatal("schema16 changed applied migration history")
	}
	if version, err := CheckCompatible(ctx, owner, build[:15]); err != nil || version != 16 {
		t.Fatalf("schema15 runtime could not use the expanded database: %v", err)
	}

	var grants bool
	err = owner.QueryRow(ctx, `SELECT has_table_privilege($1,'entitlement.service_term_action','INSERT')
 AND has_table_privilege($1,'entitlement.account_status_fact','INSERT')
 AND has_table_privilege($1,'commerce.provider_cleanup_pending','SELECT')
 AND has_table_privilege($1,'commerce.provider_environment','INSERT')
 AND NOT has_table_privilege($1,'commerce.provider_environment','UPDATE,DELETE,TRUNCATE')
 AND NOT has_table_privilege($1,'commerce.provider_cleanup_pending','INSERT,UPDATE,DELETE,TRUNCATE')
 AND NOT has_table_privilege($1,'commerce.billing_entry','UPDATE,DELETE,TRUNCATE')
 AND NOT has_table_privilege($1,'commerce.settled_period','UPDATE,DELETE,TRUNCATE')
 AND NOT has_function_privilege($1,'identity.finish_account_deletion(uuid,timestamptz)','EXECUTE')
 AND NOT has_function_privilege($1,'commerce.guard_provider_event()','EXECUTE')`, runtime).Scan(&grants)
	if err != nil || !grants {
		t.Fatalf("schema16 runtime grant boundary is invalid: %v", Sanitize("check schema16 permissions", err))
	}
	f := seedHostedCommerceFacts(t, owner, seedNamespaceFixture(t, owner).account)
	checkCommercePending(t, owner, f.account, false)
	seedQueuedCommerceEvent(t, owner)
	checkCommercePending(t, owner, f.account, true)
	other := seedNamespaceFixture(t, owner).account
	checkCommercePending(t, owner, other, false)
	commerceFact(t, owner, `INSERT INTO entitlement.service_term
(term_id,account_id,kind,subscription_ref,period_ref,starts_at,ends_at,authorized_at,created_at)
VALUES(gen_random_uuid(),$1,1,'sub_unqualified','history-only',now()-interval '2 days',now()-interval '1 day',
 now()-interval '2 days',now()-interval '2 days')`, other)
	checkCommercePending(t, owner, other, true)
	commerceFact(t, owner, `UPDATE commerce.provider_event SET state=5,processed_at=statement_timestamp(),next_check_at=NULL
	WHERE event_ref='evt_archive_queued'`)
	checkCommercePending(t, owner, f.account, false)

	commerceFact(t, owner, `INSERT INTO commerce.purchase
(purchase_id,account_id,command_id,provider,environment,catalog_version,offer_ref,product_ref,price_ref,price_version,
 definition_version,currency,amount_minor,billing_interval,region,adjustment_policy,intent_sha256,state,created_at,expires_at,updated_at,rev)
SELECT gen_random_uuid(),$1,gen_random_uuid(),provider,environment,catalog_version,offer_ref,product_ref,price_ref,price_version,
 definition_version,currency,amount_minor,billing_interval,region,adjustment_policy,sha256('pending quoted purchase'),
 1,now(),now()+interval '1 day',now(),1 FROM commerce.purchase WHERE purchase_id=$2`, other, f.purchase)
	for _, statement := range []string{
		"UPDATE commerce.provider_environment SET environment=1",
		"DELETE FROM commerce.provider_environment",
		"UPDATE commerce.customer SET provider_customer_ref='ctm_replaced'",
		"UPDATE commerce.purchase SET state=1,rev=rev+1 WHERE state=3",
		"UPDATE commerce.purchase SET amount_minor=1,rev=rev+1 WHERE state=1",
		"UPDATE commerce.checkout SET send_claimed_at=NULL",
		"UPDATE commerce.provider_event SET payload_sha256=sha256('replaced event') WHERE event_ref='evt_archive'",
		"UPDATE commerce.subscription SET provider_snapshot_sha256=sha256('conflicting same revision'),rev=rev+1",
		"UPDATE commerce.renewal SET result_valid_until=result_valid_until+interval '1 day'",
		"UPDATE commerce.settled_period SET provider_transaction_ref='txn_replaced'",
		"UPDATE commerce.billing_entry SET amount_minor=1",
	} {
		if _, err := owner.Exec(ctx, statement); !pgtest.IsCode(err, "23514") {
			t.Fatalf("changing a retained commerce fact or outcome: %v", Sanitize("check the commerce database guard", err))
		}
	}
	if _, err := owner.Exec(ctx, `INSERT INTO commerce.billing_entry
(entry_id,account_id,subscription_id,provider,environment,provider_entry_ref,kind,currency,amount_minor,occurred_at,recorded_at)
VALUES(gen_random_uuid(),$1,$2,1,2,'txn_cross_account',1,'USD',1234,now(),now())`, other, f.subscription); !pgtest.IsCode(err, "23503") {
		t.Fatalf("cross-account billing reference: %v", Sanitize("check the commerce account foreign key", err))
	}
	if _, err := owner.Exec(ctx, `INSERT INTO commerce.customer (account_id,provider,environment,provider_customer_ref,created_at)
VALUES($1,1,1,'ctm_wrong_env',now())`, other); !pgtest.IsCode(err, "23503") {
		t.Fatalf("cross-environment customer reference: %v", Sanitize("check the durable provider environment", err))
	}
	if _, err := owner.Exec(ctx, `INSERT INTO commerce.billing_entry
(entry_id,account_id,subscription_id,provider,environment,provider_entry_ref,kind,currency,amount_minor,occurred_at,recorded_at)
VALUES(gen_random_uuid(),$1,$2,1,2,'txn_signed_payment',1,'USD',-725,now(),now())`, f.account, f.subscription); !pgtest.IsCode(err, "23514") {
		t.Fatalf("signed payment magnitude: %v", Sanitize("check the typed billing amount", err))
	}
}
