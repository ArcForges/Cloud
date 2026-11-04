-- 0005 The user codes of every device authorization (AF-CTR-04 part E2; ArcForges-Design data/cloud-store.md section 6).
--
-- Applied by `arcforges-center migrate` in one transaction with the migration role; no grant changes. 0004's only index on
-- fleet.device_authorization.user_code_hash is the partial unique index of the live (PENDING) codes, which a query for a code in any
-- other state cannot use. LookupDeviceCode and ApproveDeviceCode answer an expired code or a code in another state (STATE/expired,
-- STATE/invalid_state) and let the approving account deny an APPROVED authorization, so they find a row by its user code in every
-- state: without this index each such entry would read the whole table, which only grows until AF-PLAT-01's sweeps exist.

CREATE INDEX device_authorization_user_code ON fleet.device_authorization (user_code_hash);
