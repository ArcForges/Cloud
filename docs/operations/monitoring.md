# Center operational monitoring

Scrape the Center's separate loopback admin listener at `/metrics` when it is enabled. The public listener serves neither that route nor `/readyz`. The guarded hosted Container retains the same aggregate fields in the `centerPulse` object on its periodic `metrics` log. Its default reporting interval is one minute. Keep log collection and alert delivery under operator control.

## Connection and watch limits

Use `arcforges_center_resource_in_use` and `arcforges_center_resource_limit` from the same Center process and resource. These are reservations against enforced limits.

| Resource | What holds the reservation | Hosted pulse field |
| --- | --- | --- |
| `http_request_connections` and `grpc_request_connections` | One accepted request socket on the respective listener, including an idle keep-alive or multiplexed socket. | `httpRequestConnections`, `grpcRequestConnections` |
| `http_node_connections` and `grpc_node_connections` | One upgraded Node socket or handshake reserving a Node slot. The gRPC listener does not offer the HTTP upgrade. | `httpNodeConnections`, `grpcNodeConnections` |
| `management_watch` | One admitted typed V2 management watch. The process-wide limit is half the configured maximum request connections, rounded down with a minimum of one. A watch makes one pull at a time. | `managementWatch` |

A reservation moves from the request pool to the Node pool during upgrade. The active request gauge excludes the listener's pending accept. The watch pool also enforces a limit of eight per account and eight per Node. `arcforges_center_watch_refusals_total` records the first full scope, using the fixed `global`, `account`, and `node` labels. Compare counter increments within the same process and account for restarts. The hosted fields are `watchGlobalRefusals`, `watchAccountRefusals`, and `watchNodeRefusals`.

Page on a process reservation pool that remains full for a minute and on watch-limit refusals observed in a five-minute window. Check an affected listener or scope before changing capacity. A continuously connected Node can keep the hosted Container active even without new calls. Concurrency and occupancy describe technical usage. Provider invoicing and any production spend limit require the provider's actual usage and billing evidence.

## Storage, uncertainty, and billing

The database sample is shared by admin scrapes and the periodic log. A sample is reused for ten seconds. Each configured readiness check and each read-only queue transaction has a 500 ms deadline. The query itself has a 400 ms statement timeout. Each queue reads at most 513 matching records and reports up to 512. `pending_truncated` means the count and sampled oldest age are lower bounds. A sparse manual-review queue can exceed the deadline on a large event history. The collector represents that result as unavailable and omits its count and age.

| Metric or queue label | Source and interpretation | Hosted pulse field |
| --- | --- | --- |
| `arcforges_center_store_ready{check="database"}` | Runtime role can ping the configured PostgreSQL store. | `runtimeDatabase` |
| `arcforges_center_store_ready{check="schema_admission"}` | Runtime role confirms the build's applied migration identity and ordinary database admission. A reachable quarantined restore does not pass this check. | `schemaAdmission` |
| `remote_unknown` | Durable V2 remote operations in the UNKNOWN state. Age is measured since the oldest sampled operation was last updated. | `remoteUnknown` |
| `billing_due` | A recorded provider event that is pending or retryable and due for work. Age is measured since the oldest sampled due record was received. | `billingDue` |
| `billing_review` | A recorded retry-state provider event held for review, with no scheduled check. Age is measured since it was received. | `billingReview` |

Use `arcforges_center_pending_available` with the queue's `arcforges_center_pending_items`, `arcforges_center_pending_oldest_seconds` and `arcforges_center_pending_truncated`. An available sample with zero pending records has count and age zero. Failed samples have availability zero and no values. Disabled sources have no metric series and appear as `disabled` in the hosted pulse. Billing telemetry is enabled only with the configured merchant surface. The pulse contains no account, Node, commerce, command, payload or backup identifiers.

The version-controlled [Center Prometheus rule group](../../deploy/monitoring/center-pulse.rules.json) maps these series to the indexed alert routes and runbooks. In a guarded hosted deployment, the corresponding log fields can supply the same predicates to the private collector. Treat a missing stream of samples as missing monitoring data. Enable remote notification only with the deployment owner's approval.

## Backup and restore evidence

Use the private [recovery procedure](self-host-recovery.md) to capture the original archive, the matching sidecar, the original `admin backup-logical` receipt and its operator-recorded UTC completion timestamp. Bind date and archive evidence in the same restricted operator record. Verify the hashes, source and schema identity before using that timestamp for the existing backup-lag alert. An absent or mismatched record leaves backup lag unproven.

A successful runtime ping and schema admission do not establish recoverability. Record the independently restored target's original typed restore receipt and the typed Node result after its required reapproval. Check the recovered private data and preserve the original receipt hashes in the operator record. Keep the backup and recovery files outside the runtime user's access and the monitoring labels.
