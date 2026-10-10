// SPDX-License-Identifier: AGPL-3.0-only
// The public /api entry of the Worker. Routing, admission, credentials and the Container hand-off live
// in worker/ingress; this module keeps the stable names and the disposal of an unread upload.
import { bodyTimeoutError } from "./ingress/errors.ts";
import { readBytes } from "./ingress/io.ts";
import { handleApiRequest } from "./ingress/pipeline.ts";
import { healthPath, helloPath, maxBodyBytes, type RouteTable } from "./ingress/routes.ts";

export { healthPath, helloPath, maxBodyBytes };

export interface CloudBindings {
  SOURCE_REVISION: string;
  BUILD_IDENTITY?: string;
  /** Set only in the isolated proof environment: enables the proof-only pipeline probe methods. */
  FOUNDATION_PROOF?: string;
  /** The one exact Origin that may use a browser session cookie. Absent means no cookie credential is admitted. */
  ALLOWED_ORIGIN?: string;
  CLOUD_CONTAINER: {
    getByName(name: string): { fetch(request: Request): Promise<Response> };
  };
  HELLO_RATE_LIMITER: { limit(options: { key: string }): Promise<{ success: boolean }> };
}

export async function routeRequest(
  request: Request,
  env: CloudBindings,
  context?: { waitUntil(promise: Promise<unknown>): void },
  routes?: RouteTable,
): Promise<Response> {
  try {
    return await handleApiRequest(request, env, routes);
  } finally {
    if (request.body && !request.bodyUsed) {
      // Early rejection can leave an HTTP connection with unread upload bytes. Wrangler's
      // source-mode middleware hides this; the immutable no_bundle artifact has no middleware.
      // Dispose a small upload in the background without extending the RPC deadline or
      // accepting an unlimited body. A stalled/large upload is canceled instead.
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(bodyTimeoutError), 1000);
      const cleanup = readBytes(request.body, maxBodyBytes + 1, controller.signal)
        .then(() => {})
        .catch(() => {})
        .finally(() => clearTimeout(timer));
      context?.waitUntil(cleanup);
    }
  }
}
