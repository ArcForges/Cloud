// SPDX-License-Identifier: AGPL-3.0-only
// The production Worker entry (CLOUD.84 D1). It holds only the public Hello Worker and re-exports its Container class. The isolated proof
// environment has its own entry, worker/proof/entry.ts, which is the only module that imports the proof-only foundation, harness storage
// and objects code; the production bundle built from this file contains none of it (tests/ArchitectureTests/WorkerAdapter).
import { ContainerProxy } from "@cloudflare/containers";
import { CloudContainer } from "./foundation/cloud-container.ts";
import { routeRequest, type CloudBindings } from "./router.ts";

export { CloudContainer, ContainerProxy };

export default {
  fetch: (request: Request, env: CloudBindings, context: ExecutionContext) =>
    routeRequest(request, env, context),
};
