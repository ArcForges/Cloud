// SPDX-License-Identifier: AGPL-3.0-only
// The acceptance Worker entry (AF-CTR-02): the `proof` environment (proof.arcforges.com, deployed only by the protected manual
// dispatch on main) serves the Go center in official-hosted mode, like production, against its own PostgreSQL database. It is
// the production Worker and Container under the proof environment's existing names: the Container class keeps the name
// FoundationContainer, so its Durable Object namespace and Container application stay, and the two Durable Object classes of the
// retired C# proof foundation are kept as inert classes, so their stored state is retained (never deleted by automation) until
// AF-CTR-09. The C# proof routes, the foundation, its outbound hosts and the wake queue consumer are not in this bundle; their
// sources stay in worker/proof and worker/foundation.
import { Container, ContainerProxy } from "@cloudflare/containers";
import type { DurableObject } from "cloudflare:workers";
import {
  applyCenterContainer,
  CloudContainer,
  type CenterEnvironment,
} from "../foundation/cloud-container.ts";
import { routeRequest, type CloudBindings } from "../router.ts";

export { ContainerProxy };

/** The Go center's Container under the proof environment's Container class name. */
export class FoundationContainer extends CloudContainer {
  constructor(ctx: ConstructorParameters<typeof CloudContainer>[0], env: object) {
    super(ctx, env);
    applyCenterContainer(this, env as CenterEnvironment);
  }
}

const DurableObjectBase = Object.getPrototypeOf(Container) as typeof DurableObject;

/**
 * Retained state of the C# proof foundation's job coordinator. Nothing binds it any longer and it has no fetch handler; a pending
 * alarm ends here without doing anything.
 */
export class FoundationJobCoordinator extends DurableObjectBase {
  async alarm(): Promise<void> {}
}

/** Retained state of the C# harness run alarm; a pending alarm ends here without waking anything. */
export class HarnessRunAlarm extends DurableObjectBase {
  async alarm(): Promise<void> {}
}

/** The production Worker's routing, as worker/index.ts exports it (no module imports the Worker entry itself). */
export default {
  fetch: (request: Request, env: CloudBindings, context: ExecutionContext) =>
    routeRequest(request, env, context),
};
