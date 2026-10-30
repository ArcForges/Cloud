// SPDX-License-Identifier: AGPL-3.0-only
// Checks of the Worker's generated replies for the local Worker diagnostic (`npm run test:worker`) and its unit test. A generated
// STATE/not_activated reply is a template the Worker finishes per call: the 16-byte slot at the surface's offset holds the call's own
// correlation id (E4-1; Contracts requires ArcError.correlation_id), every other byte is the template's.
import assert from "node:assert/strict";
import { isCorrelationId } from "../worker/ingress/correlation.ts";
import {
  notActivatedReplies,
  notActivatedReplyCorrelationOffsets,
  replyCorrelationBytes,
  type Surface,
} from "../worker/tables/center-tables.generated.ts";

/** The 16 bytes as the canonical lowercase UUID text of an Id. */
function idText(bytes: Uint8Array): string {
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Asserts that a body is the generated not_activated reply of a surface: the template's length and bytes except the correlation
 * slot, and in the slot a canonical, non-nil correlation id that is not the template's marker (the Worker wrote one). It returns
 * the id.
 */
export function assertNotActivatedReply(surface: Surface, body: Uint8Array, what: string): string {
  const template = Buffer.from(notActivatedReplies[surface], "base64");
  const offset = notActivatedReplyCorrelationOffsets[surface];
  const end = offset + replyCorrelationBytes;
  assert.equal(body.length, template.length, `${what}: the reply has the template's length`);
  assert.deepEqual(
    Buffer.from(body.subarray(0, offset)),
    template.subarray(0, offset),
    `${what}: the bytes before the correlation slot are the template's`,
  );
  assert.deepEqual(
    Buffer.from(body.subarray(end)),
    template.subarray(end),
    `${what}: the bytes after the correlation slot are the template's`,
  );
  const id = idText(body.subarray(offset, end));
  assert(isCorrelationId(id), `${what}: the slot holds a canonical, non-nil correlation id: ${id}`);
  assert.notEqual(
    id,
    idText(template.subarray(offset, end)),
    `${what}: the slot still holds the template's marker`,
  );
  return id;
}
