-- plan: entitlement.commit
-- version: 1
-- access: write
-- tail: v1 events=1
-- statement: params=text,scope,int64
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'entitlement.workspace-revision', CASE WHEN COALESCE((SELECT rev FROM entitlement_revision WHERE workspace_id = ?), 0) = CAST(? AS INTEGER) THEN 1 ELSE 0 END;
-- statement: params=scope,int64,int64,int64
INSERT INTO entitlement_revision (workspace_id, rev, updated_at) VALUES (?, CAST(? AS INTEGER), CAST(? AS INTEGER))
ON CONFLICT (workspace_id) DO UPDATE SET rev = excluded.rev, updated_at = excluded.updated_at WHERE entitlement_revision.rev = CAST(? AS INTEGER);
-- statement: params=scope,text
INSERT INTO entitlement_grant (grant_id, workspace_id, kind, subject, value, source, source_ref, effective_from, effective_until, issued_by_actor, created_at, reason)
SELECT json_extract(j.value, '$.id'), ?, json_extract(j.value, '$.kind'), json_extract(j.value, '$.subject'), json_extract(j.value, '$.value'), json_extract(j.value, '$.source'), json_extract(j.value, '$.sourceRef'), CAST(json_extract(j.value, '$.from') AS INTEGER), CAST(json_extract(j.value, '$.until') AS INTEGER), json_extract(j.value, '$.actor'), CAST(json_extract(j.value, '$.createdAt') AS INTEGER), json_extract(j.value, '$.reason')
FROM json_each(?) AS j;
-- statement: params=text
INSERT INTO entitlement_revocation (revocation_id, grant_id, reason_code, effective_from, issued_by_actor, created_at)
SELECT json_extract(j.value, '$.id'), json_extract(j.value, '$.grantId'), json_extract(j.value, '$.reasonCode'), CAST(json_extract(j.value, '$.from') AS INTEGER), json_extract(j.value, '$.actor'), CAST(json_extract(j.value, '$.createdAt') AS INTEGER)
FROM json_each(?) AS j;
-- statement: params=scope,text
INSERT INTO entitlement_service_term (service_term_id, workspace_id, realm_id, kind, subscription_ref, period_ref, starts_at, ends_at, grace_ends_at, supersedes_id, offer_id, offer_snapshot_id, authorized_at, selection_priority, created_at)
SELECT json_extract(j.value, '$.id'), ?, json_extract(j.value, '$.realmId'), json_extract(j.value, '$.kind'), json_extract(j.value, '$.subscriptionRef'), json_extract(j.value, '$.periodRef'), CAST(json_extract(j.value, '$.startsAt') AS INTEGER), CAST(json_extract(j.value, '$.endsAt') AS INTEGER), CAST(json_extract(j.value, '$.graceEndsAt') AS INTEGER), json_extract(j.value, '$.supersedesId'), json_extract(j.value, '$.offerId'), json_extract(j.value, '$.offerSnapshotId'), CAST(json_extract(j.value, '$.authorizedAt') AS INTEGER), CAST(json_extract(j.value, '$.selectionPriority') AS INTEGER), CAST(json_extract(j.value, '$.createdAt') AS INTEGER)
FROM json_each(?) AS j;
-- statement: params=text
INSERT INTO entitlement_service_term_action (term_action_id, term_id, kind, effective_at, recorded_at, source_ref, replacement_term_id)
SELECT json_extract(j.value, '$.id'), json_extract(j.value, '$.termId'), json_extract(j.value, '$.kind'), CAST(json_extract(j.value, '$.effectiveAt') AS INTEGER), CAST(json_extract(j.value, '$.recordedAt') AS INTEGER), json_extract(j.value, '$.sourceRef'), json_extract(j.value, '$.replacementTermId')
FROM json_each(?) AS j;
-- statement: params=scope,text
INSERT INTO entitlement_definitions_activation (workspace_id, activated_at, definitions_version)
SELECT ?, CAST(json_extract(j.value, '$.activatedAt') AS INTEGER), json_extract(j.value, '$.version')
FROM json_each(?) AS j;
-- statement: params=scope,text
INSERT INTO entitlement_workspace_status_fact (status_fact_id, workspace_id, recorded_at, status, auto_renew, purchase_pending, source_ref)
SELECT json_extract(j.value, '$.id'), ?, CAST(json_extract(j.value, '$.recordedAt') AS INTEGER), json_extract(j.value, '$.status'), json_extract(j.value, '$.autoRenew'), json_extract(j.value, '$.purchasePending'), json_extract(j.value, '$.sourceRef')
FROM json_each(?) AS j;
-- statement: params=scope,int64,int64,int64,text,text,text
INSERT INTO entitlement_snapshot (workspace_id, entitlement_version, computed_at, valid_until, capabilities, quotas, features)
VALUES (?, CAST(? AS INTEGER), CAST(? AS INTEGER), NULLIF(CAST(? AS INTEGER), -1), ?, ?, ?)
ON CONFLICT (workspace_id) DO UPDATE SET entitlement_version = excluded.entitlement_version, computed_at = excluded.computed_at, valid_until = excluded.valid_until, capabilities = excluded.capabilities, quotas = excluded.quotas, features = excluded.features;
-- statement: params=text,text?,text,text,text,text,int64,int64,int64
INSERT INTO platform_command (command_id, workspace_id, actor_ref, operation, request_hash, status, result_payload, result_rev, error_code, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, 2, ?, NULLIF(CAST(? AS INTEGER), -1), NULL, CAST(? AS INTEGER), CAST(? AS INTEGER));
-- statement: params=scope,int64
INSERT INTO platform_sequence_stream (stream_key, last_sequence, published_watermark, publish_rev, fence, ack_receipt, updated_at)
VALUES (?, 1, 0, 0, 0, NULL, CAST(? AS INTEGER))
ON CONFLICT (stream_key) DO UPDATE SET last_sequence = last_sequence + 1, updated_at = excluded.updated_at;
-- statement: params=text,text,text,int64,text,text,text?,text,text?,int64
INSERT INTO platform_outbox (outbox_id, aggregate_kind, aggregate_id, aggregate_rev, event_type, payload, workspace_id, correlation_id, causation_id, state, attempts, created_at, dispatched_at)
VALUES (?, ?, ?, CAST(? AS INTEGER), ?, ?, ?, ?, ?, 1, 0, CAST(? AS INTEGER), NULL);
-- statement: params=text,scope,scope
INSERT INTO platform_outbox_position (outbox_id, stream_key, sequence)
VALUES (?, ?, (SELECT last_sequence FROM platform_sequence_stream WHERE stream_key = ?));
-- statement: params=int64
INSERT INTO platform_sequence_stream (stream_key, last_sequence, published_watermark, publish_rev, fence, ack_receipt, updated_at)
VALUES ('platform:change-archive', 1, 0, 0, 0, NULL, CAST(? AS INTEGER))
ON CONFLICT (stream_key) DO UPDATE SET last_sequence = last_sequence + 1, updated_at = excluded.updated_at;
-- statement: params=text,int64,text,bytes,int64
INSERT INTO platform_change_archive (archive_sequence, command_id, schema_version, record, record_hash, created_at)
VALUES ((SELECT last_sequence FROM platform_sequence_stream WHERE stream_key = 'platform:change-archive'), ?, CAST(? AS INTEGER), ?, ?, CAST(? AS INTEGER));
-- statement: params=text
DELETE FROM platform_command_guard WHERE command_id = ?;
