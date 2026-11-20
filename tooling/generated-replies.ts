// SPDX-License-Identifier: AGPL-3.0-only
// Checks of the Worker's generated replies for the local Worker diagnostic (`npm run test:worker`) and its unit test. A generated
// STATE/not_activated reply is a template the Worker finishes per call. The unary error carries the call's correlation id.
// Typed watch frames also carry the same correlation id in ResponseMeta. Every other byte matches the generated template.
import assert from "node:assert/strict";
import { isCorrelationId } from "../worker/ingress/correlation.ts";
import {
  notActivatedReplies,
  notActivatedReplyCorrelationOffsets,
  replyCorrelationBytes,
  surfaceRoutes,
  type Surface,
  watchNotActivatedReply,
  watchNotActivatedReplyCorrelationOffsets,
} from "../worker/tables/center-tables.generated.ts";

/** The 16 bytes as the canonical lowercase UUID text of an Id. */
function idText(bytes: Uint8Array): string {
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Asserts the generated not_activated template for a surface. An exact typed watch path uses the watch frame template.
 * Both watch slots must hold the same canonical, non-nil correlation id that the Worker supplied.
 */
export function assertNotActivatedReply(surface: Surface, body: Uint8Array, what: string): string {
  const typedWatch = surfaceRoutes.some(
    (route) =>
      route.surface === surface &&
      route.path === what &&
      route.kind === "serverStream" &&
      route.remoteTarget === true,
  );
  const template = Buffer.from(
    typedWatch ? watchNotActivatedReply : notActivatedReplies[surface],
    "base64",
  );
  const offsets = typedWatch
    ? watchNotActivatedReplyCorrelationOffsets
    : [notActivatedReplyCorrelationOffsets[surface]];
  const slotCount = typedWatch ? 2 : 1;
  assert.equal(offsets.length, slotCount, `${what}: the template's correlation slot count`);
  assert.equal(
    new Set(offsets).size,
    slotCount,
    `${what}: the template's distinct correlation slots`,
  );
  assert.equal(body.length, template.length, `${what}: the reply has the template's length`);
  const normalized = Buffer.from(body);
  let id: string | undefined;
  for (const offset of offsets) {
    const end = offset + replyCorrelationBytes;
    const slot = idText(body.subarray(offset, end));
    assert(
      isCorrelationId(slot),
      `${what}: the slot holds a canonical, non-nil correlation id: ${slot}`,
    );
    assert.notEqual(
      slot,
      idText(template.subarray(offset, end)),
      `${what}: the slot still holds the template's marker`,
    );
    if (id !== undefined)
      assert.equal(slot, id, `${what}: both slots must carry the same correlation id`);
    id = slot;
    template.copy(normalized, offset, offset, end);
  }
  assert.deepEqual(
    normalized,
    template,
    `${what}: the bytes outside the correlation slots are the template's`,
  );
  assert(id !== undefined, `${what}: the reply contains a correlation id`);
  return id;
}
