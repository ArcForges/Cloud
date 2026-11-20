// SPDX-License-Identifier: AGPL-3.0-only
// The check the local Worker diagnostic (`npm run test:worker`, tooling/project.ts) applies to the generated not_activated replies.
// The Worker fills the unary error's correlation slot or both slots of a typed watch frame. The diagnostic itself needs Docker
// and `wrangler dev`, so its checks are pinned here against the real Worker's reply.
import assert from "node:assert/strict";
import test from "node:test";
import { assertNotActivatedReply } from "../../tooling/generated-replies.ts";
import { correlationIdBytes, newCorrelationId } from "../../worker/ingress/correlation.ts";
import { routeRequest, type CloudBindings } from "../../worker/router.ts";
import {
  notActivatedReplies,
  notActivatedReplyCorrelationOffsets,
  replyCorrelationBytes,
  surfaceRoutes,
  watchNotActivatedReply,
  watchNotActivatedReplyCorrelationOffsets,
} from "../../worker/tables/center-tables.generated.ts";

const offset = notActivatedReplyCorrelationOffsets.identity;

/** A genuine reply: the template with a correlation id written into the slot, as the Worker does. */
function genuine(id: string = newCorrelationId()): Uint8Array {
  const body = Uint8Array.from(Buffer.from(notActivatedReplies.identity, "base64"));
  body.set(correlationIdBytes(id), offset);
  return body;
}

test("the diagnostic accepts the Worker's reply to every disabled method and no two replies are equal", async () => {
  const refused = () => {
    throw new Error("a disabled surface calls neither the Container nor a limiter");
  };
  const env = {
    SOURCE_REVISION: "candidate",
    FLAGSHIP_SURFACES: "",
    CLOUD_CONTAINER: { getByName: refused },
    HELLO_RATE_LIMITER: { limit: refused },
    IDENTITY_RATE_LIMITER: { limit: refused },
  } as unknown as CloudBindings;
  const ids = new Set<string>();
  for (const route of surfaceRoutes) {
    const response = await routeRequest(
      new Request(`https://worker.example/api${route.path}`, {
        method: "POST",
        headers: { "content-type": "application/grpc-web+proto" },
        body: new Uint8Array([0, 0, 0, 0, 0]),
      }),
      env,
    );
    assert.equal(response.status, 200, route.path);
    ids.add(
      assertNotActivatedReply(
        route.surface,
        new Uint8Array(await response.arrayBuffer()),
        route.path,
      ),
    );
  }
  assert.equal(ids.size, surfaceRoutes.length);
});

test("the diagnostic refuses what is not the generated reply with a correlation id", () => {
  const id = newCorrelationId();
  assert.equal(assertNotActivatedReply("identity", genuine(id), "a genuine reply"), id);

  const raw = Uint8Array.from(Buffer.from(notActivatedReplies.identity, "base64"));
  assert.throws(
    () => assertNotActivatedReply("identity", raw, "the raw template"),
    /still holds the template's marker/,
  );
  const nil = genuine();
  nil.fill(0, offset, offset + replyCorrelationBytes);
  assert.throws(() => assertNotActivatedReply("identity", nil, "a nil id"), /canonical, non-nil/);
  assert.throws(
    () => assertNotActivatedReply("identity", genuine().subarray(1), "a shorter reply"),
    /template's length/,
  );
  assert.throws(
    () => assertNotActivatedReply("identity", new Uint8Array([...genuine(), 0]), "a longer reply"),
    /template's length/,
  );
  for (const index of [0, 5, offset - 1, offset + replyCorrelationBytes, genuine().length - 1]) {
    const changed = genuine();
    changed[index] = (changed[index] ?? 0) ^ 1;
    assert.throws(
      () => assertNotActivatedReply("identity", changed, `byte ${index} changed`),
      /the template's/,
      `a change at byte ${index} must be refused`,
    );
  }
});

test("typed watch diagnostics require an exact watch frame with one correlation in both slots", () => {
  const paths = [
    "/arcforges.sandbox.v2.RunService/WatchOutput",
    "/arcforges.sandbox.v2.NodeService/WatchEvents",
    "/arcforges.sandbox.v2.ResourceService/WatchUsage",
  ];
  assert.deepEqual(
    surfaceRoutes
      .filter((route) => route.remoteTarget && route.kind === "serverStream")
      .map((route) => route.path),
    paths,
  );
  const [first, second] = watchNotActivatedReplyCorrelationOffsets;
  assert(first !== undefined && second !== undefined && second >= first + replyCorrelationBytes);
  const id = newCorrelationId();
  const template = Buffer.from(watchNotActivatedReply, "base64");
  const frame = Buffer.from(template);
  for (const offset of [first, second]) frame.set(correlationIdBytes(id), offset);
  for (const path of paths) assert.equal(assertNotActivatedReply("nodes", frame, path), id);

  const [watch] = paths;
  assert(watch);
  const mismatched = Buffer.from(frame);
  mismatched.set(correlationIdBytes(newCorrelationId()), second);
  assert.throws(() => assertNotActivatedReply("nodes", mismatched, watch), /same correlation id/);
  for (const offset of [first, second]) {
    const nil = Buffer.from(frame);
    nil.fill(0, offset, offset + replyCorrelationBytes);
    assert.throws(() => assertNotActivatedReply("nodes", nil, watch), /canonical, non-nil/);
    const marker = Buffer.from(frame);
    template.copy(marker, offset, offset, offset + replyCorrelationBytes);
    assert.throws(() => assertNotActivatedReply("nodes", marker, watch), /template's marker/);
  }
  for (const index of [0, first - 1, first + replyCorrelationBytes, frame.length - 1]) {
    const changed = Buffer.from(frame);
    changed[index] = (changed[index] ?? 0) ^ 1;
    assert.throws(() => assertNotActivatedReply("nodes", changed, watch), /the template's/);
  }
  assert.throws(
    () =>
      assertNotActivatedReply("nodes", frame, "/arcforges.sandbox.v2.DataService/InspectTransfer"),
    /template's length/,
  );
  assert.throws(() => assertNotActivatedReply("nodes", genuine(id), watch), /template's length/);
});
