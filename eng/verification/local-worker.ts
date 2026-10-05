// SPDX-License-Identifier: AGPL-3.0-only
// The Worker module the local integration harness runs under Miniflare (workerd) with local D1, R2,
// Durable Object and Queue emulation. It executes the same entry glue, storage handler, object facade,
// queue consumer and Durable Object as the deployed Worker; only the Container is replaced by a
// service binding that the harness points at a locally started host process. Local-only: it is not
// part of the deployed bundle and nothing imports it.
import { fetchEntry, queueEntry, type WorkerEnv } from "../../worker/foundation/entry.ts";
import { handleObjects } from "../../worker/foundation/objects.ts";
import type { FoundationEnv } from "../../worker/foundation/types.ts";
import { handleExecutePlan } from "../../worker/storage/handler.ts";

export { FoundationJobCoordinator } from "../../worker/foundation/durable.ts";

interface LocalEnv {
  /** The host process over real HTTP, as the platform's Container stub reaches it: closing a request closes the connection. */
  CONTAINER_SERVICE: { fetch(request: Request | string): Promise<Response> };
  /** The harness's control channel: it stops and restarts the host process. */
  CONTAINER_CONTROL: { fetch(request: Request | string): Promise<Response> };
}

// The host's virtual-host requests arrive under a path prefix and are handed to the handlers exactly
// as the Container outbound interception would hand them, with the virtual host restored.
function asVirtualHost(request: Request, host: string, prefix: string): Request {
  const url = new URL(request.url);
  return new Request(`http://${host}${url.pathname.slice(prefix.length)}${url.search}`, request);
}

function withContainer(env: WorkerEnv & LocalEnv): WorkerEnv {
  return {
    ...env,
    // The rate limit binding is a deployed-only platform feature; locally every request passes it.
    HELLO_RATE_LIMITER: { limit: async () => ({ success: true }) },
    CLOUD_CONTAINER: {
      getByName: () => ({
        fetch: (request: Request) => env.CONTAINER_SERVICE.fetch(request),
        stop: async () => {
          await env.CONTAINER_CONTROL.fetch("http://container/__stop");
        },
      }),
    },
  };
}

export default {
  async fetch(
    request: Request,
    env: WorkerEnv & LocalEnv,
    context: { waitUntil(promise: Promise<unknown>): void },
  ): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (pathname.startsWith("/__storage/"))
      return handleExecutePlan(
        asVirtualHost(request, "storage.internal", "/__storage"),
        env as FoundationEnv,
      );
    if (pathname.startsWith("/__objects/"))
      return handleObjects(
        asVirtualHost(request, "objects.internal", "/__objects"),
        env as FoundationEnv,
      );
    // A harness-only fault: the named bindings are absent for this one request, as in a deployment that forgot them.
    const dropped = (request.headers.get("x-harness-drop-binding") ?? "")
      .split(",")
      .filter(Boolean);
    const effective = withContainer(env) as unknown as Record<string, unknown>;
    for (const name of dropped) delete effective[name];
    return fetchEntry(request, effective as unknown as WorkerEnv, context);
  },
  queue: (batch: Parameters<typeof queueEntry>[0], env: WorkerEnv & LocalEnv) =>
    queueEntry(batch, withContainer(env)),
};
