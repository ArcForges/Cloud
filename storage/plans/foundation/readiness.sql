-- plan: foundation.readiness
-- version: 1
-- access: read
-- maxRows: 1
-- statement: returns=int64
SELECT CAST(version AS TEXT) FROM probe_schema;
