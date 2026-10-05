// SPDX-License-Identifier: AGPL-3.0-only
// What a Container start failure looks like to the Worker, and the one refusal a public caller gets for it. The
// classification is pinned to the exact locked @cloudflare/containers so an upgrade cannot silently change it.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  classifyStartFailure,
  classifyStartFailureResponse,
  containerUnavailable,
  containerUnavailableText,
  noInstanceText,
  startFailedText,
} from "../../worker/readiness/container.ts";

const root = path.resolve(import.meta.dirname, "../..");
const library = readFileSync(
  path.join(root, "node_modules/@cloudflare/containers/dist/lib/container.js"),
  "utf8",
);

test("the classification matches the responses the locked Containers library builds", () => {
  // The library answers a request it could not serve with plain text and these statuses. If an upgrade changes any of
  // them, this test fails and the classification is revisited; an unrecognized response would otherwise only lose its
  // retry hint (it stays an unavailable refusal), never become a success.
  const noInstance =
    /isNoInstanceError\(e\)\)\s*\{\s*return new Response\('([^']*)',\s*\{ status: (\d+) \}\)/u.exec(
      library,
    );
  assert(noInstance, "the no-instance response");
  assert((noInstance[1] ?? "").startsWith(noInstanceText), "no-instance text");
  assert.equal(noInstance[2], "503");
  const startFailed =
    /return new Response\(`(Failed to start container:)[^`]*`,\s*\{\s*status: (\d+),?\s*\}\)/u.exec(
      library,
    );
  assert(startFailed, "the start-failure response");
  assert.equal(startFailed[1], startFailedText);
  assert.equal(startFailed[2], "500");
  const rateLimited =
    /isRateLimitedError\(e\)\)\s*\{\s*return new Response\([^)]*\),\s*\{ status: (\d+) \}\)/u.exec(
      library,
    );
  assert(rateLimited, "the rate-limited response");
  assert.equal(rateLimited[1], "429");
});

test("only plain text with the library's own opening is a start failure", () => {
  const text = "text/plain;charset=UTF-8";
  assert.equal(classifyStartFailure(503, text, `${noInstanceText}\nmore`), "no_instance_available");
  assert.equal(classifyStartFailure(500, text, `${startFailedText} anything`), "start_failed");
  assert.equal(classifyStartFailure(429, "text/plain", "slow down"), "rate_limited");
  // A host reply is JSON or gRPC-Web, and an ordinary failure has none of these openings.
  assert.equal(classifyStartFailure(503, "application/json", noInstanceText), null);
  assert.equal(classifyStartFailure(503, "application/grpc-web+proto", noInstanceText), null);
  assert.equal(classifyStartFailure(503, null, noInstanceText), null);
  assert.equal(classifyStartFailure(503, text, "Service Unavailable"), null);
  assert.equal(classifyStartFailure(500, text, "Internal Server Error"), null);
  assert.equal(classifyStartFailure(502, text, noInstanceText), null);
  assert.equal(classifyStartFailure(200, text, noInstanceText), null);
  assert.equal(classifyStartFailure(429, "application/json", "{}"), null);
  assert.equal(
    classifyStartFailure(503, text, `  ${noInstanceText}`),
    null,
    "the opening is exact",
  );
});

test("a response is classified without being consumed", async () => {
  const response = new Response(`${noInstanceText}\n${"x".repeat(5_000)}`, {
    status: 503,
    headers: { "content-type": "text/plain;charset=UTF-8" },
  });
  assert.equal(await classifyStartFailureResponse(response), "no_instance_available");
  assert.equal(response.bodyUsed, false);
  assert((await response.text()).startsWith(noInstanceText));

  assert.equal(await classifyStartFailureResponse(new Response("{}", { status: 503 })), null);
  assert.equal(
    await classifyStartFailureResponse(
      new Response(null, { status: 503, headers: { "content-type": "text/plain" } }),
    ),
    null,
  );
  assert.equal(await classifyStartFailureResponse(new Response("ok", { status: 200 })), null);
});

test("the refusal is fixed text, and carries retry guidance only when asked", async () => {
  const retryable = containerUnavailable(true);
  assert.equal(retryable.status, 503);
  assert.equal(retryable.headers.get("retry-after"), "2");
  assert.equal(retryable.headers.get("cache-control"), "no-store");
  assert.equal(retryable.headers.get("content-type"), "text/plain; charset=utf-8");
  assert.equal(await retryable.text(), containerUnavailableText);
  const plain = containerUnavailable(false);
  assert.equal(plain.status, 503);
  assert.equal(plain.headers.get("retry-after"), null);
  assert.equal(await plain.text(), "Cloud container is temporarily unavailable.");
});
