// SPDX-License-Identifier: AGPL-3.0-only
import { Container, ContainerProxy, type OutboundHandler } from "@cloudflare/containers";
import { containerEnvironment } from "./foundation/container-env.ts";
import { fetchEntry, queueEntry, type WorkerEnv } from "./foundation/entry.ts";
import { handleObjects } from "./foundation/objects.ts";
import type { FoundationEnv } from "./foundation/types.ts";
import { handleExecutePlan } from "./storage/handler.ts";

export { ContainerProxy };
export { FoundationJobCoordinator } from "./foundation/durable.ts";

export class CloudContainer extends Container<WorkerEnv> {
  override defaultPort = 8080;
  override sleepAfter = "60s";
  override enableInternet = false;

  constructor(ctx: ConstructorParameters<typeof Container>[0], env: WorkerEnv) {
    super(ctx, env);
    // Empty in production: the host's foundation module stays disabled without it.
    this.envVars = containerEnvironment(env);
  }
}

// The Container reaches bindings only through these exact virtual hosts; everything else stays
// closed because enableInternet is false. Assigned (not declared as a static field) so the base
// class setter registers the handlers for this class name.
const storageOutbound: OutboundHandler<WorkerEnv> = (request, env) =>
  handleExecutePlan(request, env as FoundationEnv);
const objectsOutbound: OutboundHandler<WorkerEnv> = (request, env) =>
  handleObjects(request, env as FoundationEnv);
CloudContainer.outboundByHost = {
  "storage.internal": storageOutbound as OutboundHandler,
  "objects.internal": objectsOutbound as OutboundHandler,
};

export default {
  fetch: (request: Request, env: WorkerEnv, context: ExecutionContext) =>
    fetchEntry(request, env, context),
  queue: queueEntry,
};
