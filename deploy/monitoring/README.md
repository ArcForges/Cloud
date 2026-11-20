# Cloud service levels and alert routing

This directory is the OPS.01 monitoring artifact. It is an internal engineering objective set, not an external SLA, availability promise, or claim that live telemetry has already been collected. Targets are initial reviewed baselines because the adopted Cloud bootstrap had no operational history; changing them requires code review and an explicit history-based rationale.

`sli-objectives.json` defines a rolling 30-day user-visible success objective for Cloud API, identity, sync control plane and realtime, plus separate objectives for bounded dependencies. A dependency-attributed failure is counted in both its capability and its dependency objective. Each objective has its own denominator and error budget.

`sli.mjs` accepts only the closed capability/dependency identifiers, a `good`/`bad` outcome and an optional dependency identifier. It accepts no user, tenant, route, prompt, payload, URL, exception or provider-supplied dimension. Empty windows are `insufficient-data`, not fabricated success. Error-budget consumption and remaining budget are returned with each objective.

Each active page-worthy alert has one version-controlled file under `alerts/`. The alert index identifies the current monitor set. `alert-routing.json` binds page, ticket and dashboard routes to stable logical destinations. `dashboard/error-budget.json` displays per-capability and per-dependency objective, success, count and budget fields.

Each page alert points to an indexed alert-response runbook under `runbooks/`. OPS.03 owns rehearsal and the broader required runbooks under WP-45.02.

The Cloud repository's root `package.json` has an explicit, not auto-discovered, test list. Its only OPS.01 support change appends `deploy/monitoring/monitoring.test.mjs` to that existing list so `npm run check` executes the offline suite; dependencies, lockfiles, workflows and test semantics are unchanged.

`center-pulse.rules.json` is a Prometheus rule group for the Center's private metrics. Its rule labels bind alerts to the existing logical page route and indexed runbook. The operator guide describes the equivalent hosted log fields, queue sampling bounds and separate backup and recovery evidence. See [Center monitoring](../../docs/operations/monitoring.md).
