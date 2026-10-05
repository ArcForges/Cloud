-- plan: families.account-enrollment.create-user
-- version: 1
-- access: write
-- guard: kind=revision module=identity key=credential-id table=identity_auth_identity by=auth_identity_id rev=rev
-- guard: kind=revision module=identity key=credential-subject table=identity_auth_identity by=realm_id,provider_id,subject rev=rev
-- guard: kind=revision module=identity key=user table=identity_user by=realm_id,user_id rev=rev
-- guard: kind=revision module=workspace key=owner table=workspace_workspace by=realm_id,owner_user_id rev=rev
-- guard: kind=revision module=workspace key=workspace table=workspace_workspace by=scope:workspace_id rev=rev
-- statement: module=identity class=record key=account params=text,text,text,int64
INSERT INTO identity_user (user_id, realm_id, display_name, state, created_at, deletion_requested_at, rev)
VALUES (?, ?, ?, 1, CAST(? AS INTEGER), NULL, 1);
-- statement: module=identity class=record key=credential params=text,text,int64,text,bytes?,bytes?,int64,int64,text?,int64,text?,int64,text,text,text?
INSERT INTO identity_auth_identity (auth_identity_id, user_id, method, subject, public_key, user_handle, backup_eligible, backup_state, transports, sign_count, label, created_at, last_used_at, revoked_at, realm_id, provider_id, password_hash, rev)
VALUES (?, ?, CAST(? AS INTEGER), ?, ?, ?, NULLIF(CAST(? AS INTEGER), -1), NULLIF(CAST(? AS INTEGER), -1), ?, NULLIF(CAST(? AS INTEGER), -1), ?, CAST(? AS INTEGER), NULL, NULL, ?, ?, ?, 1);
-- statement: module=workspace class=record key=workspace params=scope,text,text,text,text,int64
INSERT INTO workspace_workspace (workspace_id, realm_id, owner_user_id, name, data_region, protection_profile, state, created_at, rev)
VALUES (?, ?, ?, ?, ?, 1, 1, CAST(? AS INTEGER), 1);
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
