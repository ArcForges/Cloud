// SPDX-License-Identifier: AGPL-3.0-only
import { Container, ContainerProxy, type OutboundHandler } from "@cloudflare/containers";
import {
  commerceOutboundHosts,
  commerceTransportEnvironment,
  type CommerceEgressEnvironment,
} from "./commerce-provider/egress.ts";
import { containerEnvironment } from "./foundation/container-env.ts";
import { fetchEntry, queueEntry, type WorkerEnv } from "./foundation/entry.ts";
import { handleObjects } from "./foundation/objects.ts";
import type { FoundationEnv } from "./foundation/types.ts";
import { handleExecutePlan } from "./storage/handler.ts";

export { ContainerProxy };
export { FoundationJobCoordinator } from "./foundation/durable.ts";

type ContainerEnvironment = WorkerEnv & CommerceEgressEnvironment;

// The public ingress and class identity are preserved. Only the explicitly configured,
// exact-host commerce transport is added; global Internet access remains disabled.
export class CloudContainer extends Container {
  override defaultPort = 8080;
  override sleepAfter = "60s";
  override enableInternet = false;
  constructor(ctx: ConstructorParameters<typeof Container>[0], env: ContainerEnvironment) {
    super(ctx, env);
    this.envVars = commerceTransportEnvironment(env);
    this.interceptHttps = this.envVars.ARCFORGES_COMMERCE_EGRESS === "enabled";
  }
}

// Only the isolated proof environment binds this subclass (wrangler.json env.proof). The
// outbound registry is keyed by class name, so private foundation handlers stay isolated.
export class FoundationContainer extends CloudContainer {
  constructor(ctx: ConstructorParameters<typeof Container>[0], env: ContainerEnvironment) {
    super(ctx, env);
    this.envVars = { ...this.envVars, ...containerEnvironment(env) };
  }
}

// The proof Container reaches bindings only through these exact virtual hosts; everything else
// stays closed because enableInternet is false. Assigned (not declared as a static field) so the
// base class setter registers the handlers for this class name.
const storageOutbound: OutboundHandler<WorkerEnv> = (request, env) =>
  handleExecutePlan(request, env as FoundationEnv);
const objectsOutbound: OutboundHandler<WorkerEnv> = (request, env) =>
  handleObjects(request, env as FoundationEnv);
const commerceOutbound = commerceOutboundHosts as Record<string, OutboundHandler>;
CloudContainer.outboundByHost = { ...commerceOutbound };
FoundationContainer.outboundByHost = {
  ...commerceOutbound,
  "storage.internal": storageOutbound as OutboundHandler,
  "objects.internal": objectsOutbound as OutboundHandler,
};

export default {
  fetch: (request: Request, env: WorkerEnv, context: ExecutionContext) =>
    fetchEntry(request, env, context),
  queue: queueEntry,
};
