-- plan: foundation.receipt-load
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope,text returns=text,text
SELECT request_hash, result_json FROM probe_receipt WHERE scope = ? AND command_id = ?;
