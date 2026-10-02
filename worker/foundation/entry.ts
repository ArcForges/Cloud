// SPDX-License-Identifier: AGPL-3.0-only
// The Worker entry glue, kept free of Cloudflare-only imports so offline tests and the local
// integration harness execute exactly the code the deployed Worker runs.
import { routeRequest, type CloudBindings } from "../router.ts";
import { postSigned } from "./container-client.ts";
import { handleProof, isProofPath } from "./proof-routes.ts";
import { maxSliceItems, maxSliceMilliseconds, processWake, type MessageLike } from "./queue.ts";
import { proofEnabled, type FoundationEnv } from "./types.ts";

/** Production binds only the Hello bindings; the isolated proof environment adds the rest. */
export type WorkerEnv = CloudBindings & Partial<FoundationEnv>;

export function fetchEntry(
  request: Request,
  env: WorkerEnv,
  context: { waitUntil(promise: Promise<unknown>): void },
): Promise<Response> {
  if (proofEnabled(env) && isProofPath(new URL(request.url).pathname))
    return handleProof(request, env as FoundationEnv);
  return routeRequest(request, env, context);
}

export async function queueEntry(
  batch: { messages: readonly MessageLike[] },
  env: WorkerEnv,
): Promise<void> {
  const proof = env as FoundationEnv;
  for (const message of batch.messages) {
    if (!proofEnabled(env)) {
      // No consumer work exists outside the proof environment.
      message.retry({ delaySeconds: 60 });
      continue;
    }
    await processWake(message, {
      coordinators: proof.JOB_COORDINATOR,
      queue: proof.WAKE_QUEUE,
      newEventId: () => crypto.randomUUID(),
      callSlice: (wake) =>
        postSigned(
          proof,
          "job/slice",
          new TextEncoder().encode(
            JSON.stringify({
              scope: wake.scope,
              jobId: wake.jobId,
              eventId: wake.eventId,
              maxItems: maxSliceItems,
              maxMilliseconds: maxSliceMilliseconds,
            }),
          ),
          { requestId: crypto.randomUUID() },
        ),
    });
  }
}
