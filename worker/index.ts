// SPDX-License-Identifier: AGPL-3.0-only
import { Container, ContainerProxy, type OutboundHandler } from "@cloudflare/containers";
import { aiInternalOutbound } from "./ai/internal/outbound.ts";
import { containerEnvironment } from "./foundation/container-env.ts";
import { fetchEntry, queueEntry, type WorkerEnv } from "./foundation/entry.ts";
import { handleObjects } from "./foundation/objects.ts";
import type { FoundationEnv } from "./foundation/types.ts";
import { harnessInternalOutbound } from "./harness/internal/outbound.ts";
import { handleExecutePlan } from "./storage/handler.ts";

export { ContainerProxy };
export { FoundationJobCoordinator } from "./foundation/durable.ts";
export { HarnessRunAlarm } from "./harness/run-alarm.ts";

// The production Container class is the Hello class plus one outbound host: ai.internal, the thin
// Workers AI transport of HAR.40. It has no environment hook, and enableInternet stays false, so the
// container reaches nothing but the exact virtual host registered below.
export class CloudContainer extends Container {
  override defaultPort = 8080;
  override sleepAfter = "60s";
  override enableInternet = false;
}

// Assigned (not declared as a static field) so the base class setter registers the handler under
// the production class name only; FoundationContainer has its own registry entry.
CloudContainer.outboundByHost = {
  "ai.internal": aiInternalOutbound as OutboundHandler,
};

// Only the isolated proof environment binds this subclass (wrangler.json env.proof). The
// outbound registry is keyed by class name, so nothing below reaches CloudContainer.
export class FoundationContainer extends CloudContainer {
  constructor(ctx: ConstructorParameters<typeof Container>[0], env: WorkerEnv) {
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

export default {
  fetch: (request: Request, env: WorkerEnv, context: ExecutionContext) =>
    fetchEntry(request, env, context),
  queue: queueEntry,
};
