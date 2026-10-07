-- plan: families.entitlement-definition-resolution.commit-current
-- version: 1
-- access: write
-- guard: kind=authorization module=platform key=recovery-current table=platform_recovery_epoch by=realm_id match=recovery_generation,state,rev
-- guard: kind=policy module=config key=current-definitions-head table=config_revision by=realm_id,config_revision_id match=content_hash
-- guard: kind=revision module=entitlement key=workspace-revision table=entitlement_revision by=scope:workspace_id rev=rev
-- guard: kind=policy module=entitlement key=resolver-profile table=entitlement_resolver_definition_profile by=realm_id,definitions_version match=profile_hash,artifact_id,artifact_hash,artifact_length,realm_kind
-- statement: module=entitlement class=record key=a-revision params=scope,int64,int64,int64
INSERT INTO entitlement_revision (workspace_id, rev, updated_at) VALUES (?, CAST(? AS INTEGER), CAST(? AS INTEGER))
ON CONFLICT (workspace_id) DO UPDATE SET rev = excluded.rev, updated_at = excluded.updated_at WHERE entitlement_revision.rev = CAST(? AS INTEGER);
-- statement: module=entitlement class=record key=b-grants params=scope,text
INSERT INTO entitlement_grant (grant_id, workspace_id, kind, subject, value, source, source_ref, effective_from, effective_until, issued_by_actor, created_at, reason)
SELECT json_extract(j.value, '$.id'), ?, json_extract(j.value, '$.kind'), json_extract(j.value, '$.subject'), json_extract(j.value, '$.value'), json_extract(j.value, '$.source'), json_extract(j.value, '$.sourceRef'), CAST(json_extract(j.value, '$.from') AS INTEGER), CAST(json_extract(j.value, '$.until') AS INTEGER), json_extract(j.value, '$.actor'), CAST(json_extract(j.value, '$.createdAt') AS INTEGER), json_extract(j.value, '$.reason')
FROM json_each(?) AS j;
-- statement: module=entitlement class=record key=c-revocations params=text
INSERT INTO entitlement_revocation (revocation_id, grant_id, reason_code, effective_from, issued_by_actor, created_at)
SELECT json_extract(j.value, '$.id'), json_extract(j.value, '$.grantId'), json_extract(j.value, '$.reasonCode'), CAST(json_extract(j.value, '$.from') AS INTEGER), json_extract(j.value, '$.actor'), CAST(json_extract(j.value, '$.createdAt') AS INTEGER)
FROM json_each(?) AS j;
-- statement: module=entitlement class=record key=d-terms params=scope,text
INSERT INTO entitlement_service_term (service_term_id, workspace_id, realm_id, kind, subscription_ref, period_ref, starts_at, ends_at, grace_ends_at, supersedes_id, offer_id, offer_snapshot_id, authorized_at, selection_priority, created_at)
SELECT json_extract(j.value, '$.id'), ?, json_extract(j.value, '$.realmId'), json_extract(j.value, '$.kind'), json_extract(j.value, '$.subscriptionRef'), json_extract(j.value, '$.periodRef'), CAST(json_extract(j.value, '$.startsAt') AS INTEGER), CAST(json_extract(j.value, '$.endsAt') AS INTEGER), CAST(json_extract(j.value, '$.graceEndsAt') AS INTEGER), json_extract(j.value, '$.supersedesId'), json_extract(j.value, '$.offerId'), json_extract(j.value, '$.offerSnapshotId'), CAST(json_extract(j.value, '$.authorizedAt') AS INTEGER), CAST(json_extract(j.value, '$.selectionPriority') AS INTEGER), CAST(json_extract(j.value, '$.createdAt') AS INTEGER)
FROM json_each(?) AS j;
-- statement: module=entitlement class=record key=e-actions params=text
INSERT INTO entitlement_service_term_action (term_action_id, term_id, kind, effective_at, recorded_at, source_ref, replacement_term_id)
SELECT json_extract(j.value, '$.id'), json_extract(j.value, '$.termId'), json_extract(j.value, '$.kind'), CAST(json_extract(j.value, '$.effectiveAt') AS INTEGER), CAST(json_extract(j.value, '$.recordedAt') AS INTEGER), json_extract(j.value, '$.sourceRef'), json_extract(j.value, '$.replacementTermId')
FROM json_each(?) AS j;
-- statement: module=entitlement class=record key=f-activations params=scope,text
INSERT INTO entitlement_definitions_activation (workspace_id, activated_at, definitions_version)
SELECT ?, CAST(json_extract(j.value, '$.activatedAt') AS INTEGER), json_extract(j.value, '$.version')
FROM json_each(?) AS j;
-- statement: module=entitlement class=record key=g-facts params=scope,text
INSERT INTO entitlement_workspace_status_fact (status_fact_id, workspace_id, recorded_at, status, auto_renew, purchase_pending, source_ref)
SELECT json_extract(j.value, '$.id'), ?, CAST(json_extract(j.value, '$.recordedAt') AS INTEGER), json_extract(j.value, '$.status'), json_extract(j.value, '$.autoRenew'), json_extract(j.value, '$.purchasePending'), json_extract(j.value, '$.sourceRef')
FROM json_each(?) AS j;
-- statement: module=entitlement class=record key=h-snapshot params=scope,int64,int64,int64,text,text,text
INSERT INTO entitlement_snapshot (workspace_id, entitlement_version, computed_at, valid_until, capabilities, quotas, features)
VALUES (?, CAST(? AS INTEGER), CAST(? AS INTEGER), NULLIF(CAST(? AS INTEGER), -1), ?, ?, ?)
ON CONFLICT (workspace_id) DO UPDATE SET entitlement_version = excluded.entitlement_version, computed_at = excluded.computed_at, valid_until = excluded.valid_until, capabilities = excluded.capabilities, quotas = excluded.quotas, features = excluded.features;
-- statement: module=platform class=record key=a-receipt params=text,text?,text,text,text,text,int64,int64,int64
INSERT INTO platform_command (command_id, workspace_id, actor_ref, operation, request_hash, status, result_payload, result_rev, error_code, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, 2, ?, NULLIF(CAST(? AS INTEGER), -1), NULL, CAST(? AS INTEGER), CAST(? AS INTEGER));
-- statement: module=platform class=record key=b-stream params=scope,int64
INSERT INTO platform_sequence_stream (stream_key, last_sequence, published_watermark, publish_rev, fence, ack_receipt, updated_at)
VALUES (?, 1, 0, 0, 0, NULL, CAST(? AS INTEGER))
ON CONFLICT (stream_key) DO UPDATE SET last_sequence = last_sequence + 1, updated_at = excluded.updated_at;
-- statement: module=platform class=record key=c-outbox params=text,text,text,int64,text,text,text?,text,text?,int64
INSERT INTO platform_outbox (outbox_id, aggregate_kind, aggregate_id, aggregate_rev, event_type, payload, workspace_id, correlation_id, causation_id, state, attempts, created_at, dispatched_at)
VALUES (?, ?, ?, CAST(? AS INTEGER), ?, ?, ?, ?, ?, 1, 0, CAST(? AS INTEGER), NULL);
-- statement: module=platform class=record key=d-position params=text,scope,scope
INSERT INTO platform_outbox_position (outbox_id, stream_key, sequence)
VALUES (?, ?, (SELECT last_sequence FROM platform_sequence_stream WHERE stream_key = ?));
-- statement: module=platform class=record key=e-archive-stream params=int64
INSERT INTO platform_sequence_stream (stream_key, last_sequence, published_watermark, publish_rev, fence, ack_receipt, updated_at)
VALUES ('platform:change-archive', 1, 0, 0, 0, NULL, CAST(? AS INTEGER))
ON CONFLICT (stream_key) DO UPDATE SET last_sequence = last_sequence + 1, updated_at = excluded.updated_at;
-- statement: module=platform class=record key=f-archive params=text,int64,text,bytes,int64
INSERT INTO platform_change_archive (archive_sequence, command_id, schema_version, record, record_hash, created_at)
VALUES ((SELECT last_sequence FROM platform_sequence_stream WHERE stream_key = 'platform:change-archive'), ?, CAST(? AS INTEGER), ?, ?, CAST(? AS INTEGER));
