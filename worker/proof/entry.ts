// SPDX-License-Identifier: AGPL-3.0-only
// The isolated proof Worker entry (CLOUD.84 D1). Wrangler builds this module only for the proof environment (wrangler.json env.proof main),
// so the proof-only foundation, the run alarm, the storage and objects outbound hosts, the proof Container and the wake queue consumer
// are in this bundle and in no other. The production entry (worker/index.ts) imports none of them. The proof Container extends the
// production class, so the base class keeps its ai.internal host registration and this class registers its own handlers under its name.
import { ContainerProxy, type OutboundHandler } from "@cloudflare/containers";
import { CloudContainer } from "../foundation/cloud-container.ts";
import { containerEnvironment } from "../foundation/container-env.ts";
import { fetchEntry, queueEntry, type WorkerEnv } from "../foundation/entry.ts";
import { handleObjects } from "../foundation/objects.ts";
import { proofEnabled, type FoundationEnv } from "../foundation/types.ts";
import { harnessInternalOutbound } from "../harness/run-alarm-core.ts";
import { proofRouteTable } from "../ingress/proof-table.ts";
import { handleExecutePlan } from "../storage/handler.ts";

export { ContainerProxy };
export { FoundationJobCoordinator } from "../foundation/durable.ts";
export { HarnessRunAlarm } from "../harness/run-alarm.ts";

// Only the isolated proof environment binds this subclass (wrangler.json env.proof). The outbound registry is keyed by class name,
// so nothing below reaches CloudContainer.
export class FoundationContainer extends CloudContainer {
  constructor(ctx: ConstructorParameters<typeof CloudContainer>[0], env: WorkerEnv) {
    super(ctx, env);
    this.envVars = containerEnvironment(env);
  }
}

// The proof Container reaches bindings only through these exact virtual hosts; everything else
// stays closed because enableInternet is false. Assigned (not declared as a static field) so the
// base class setter registers the handlers for this class name. harness.internal is the run alarm
// of HAR.40: it arms and cancels one run's wake and is reachable from the proof class only.
const storageOutbound: OutboundHandler<WorkerEnv> = (request, env) =>
  handleExecutePlan(request, env as FoundationEnv);
const objectsOutbound: OutboundHandler<WorkerEnv> = (request, env) =>
  handleObjects(request, env as FoundationEnv);
FoundationContainer.outboundByHost = {
  "storage.internal": storageOutbound as OutboundHandler,
  "objects.internal": objectsOutbound as OutboundHandler,
  "harness.internal": harnessInternalOutbound as OutboundHandler,
};

// The proof table is routed with only when the proof flag is set, as before the split.
export default {
  fetch: (request: Request, env: WorkerEnv, context: ExecutionContext) =>
    fetchEntry(request, env, context, proofEnabled(env) ? proofRouteTable : undefined),
  queue: queueEntry,
};
