// SPDX-License-Identifier: AGPL-3.0-only
// The PRF.07 foundation scenarios, written once and run against a target the operator names: the
// deployed `proof` environment (explicit local opt-in, never CI) or the local integration harness.
// Every number travels as canonical text; the expectations are computed here with BigInt, not by the
// system under test. Operator and session secrets are never written to the evidence.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

export interface Target {
  baseUrl: string;
  /** Bearer credential of the local harness. A deployment uses `authorize` instead. */
  operatorToken?: string;
  /** Produces the Authorization header value for one operator request (signed requests). */
  authorize?: (method: string, host: string, pathname: string, body: Uint8Array) => Promise<string>;
  /** The exact Origin value the proof environment is configured with. */
  origin: string;
  /** Pause before inspecting a restarted job (milliseconds). */
  pollIntervalMs?: number;
  jobTimeoutMs?: number;
}

type Json = Record<string, unknown>;
export interface Evidence {
  scenario: string;
  ok: boolean;
  detail: Json;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const int64Min = -(2n ** 63n);
const int64Max = 2n ** 63n - 1n;
const uint64Max = 2n ** 64n - 1n;

async function operator(target: Target, operation: string, body: Json) {
  const pathname = `/proof/v1/${operation}`;
  const bodyText = JSON.stringify(body);
  const authorization = target.authorize
    ? await target.authorize(
        "POST",
        new URL(target.baseUrl).host,
        pathname,
        new TextEncoder().encode(bodyText),
      )
    : `Bearer ${target.operatorToken}`;
  const response = await fetch(`${target.baseUrl}${pathname}`, {
    method: "POST",
    headers: { authorization, "content-type": "application/json" },
    body: bodyText,
    redirect: "error",
    signal: AbortSignal.timeout(60_000),
  });
  const text = await response.text();
  let json: Json = {};
  try {
    json = text ? (JSON.parse(text) as Json) : {};
  } catch {
    json = { unparsable: true };
  }
  return { status: response.status, json };
}

export async function readiness(target: Target, manifestHash: string): Promise<Evidence> {
  const reply = await operator(target, "readiness", {});
  assert.equal(reply.status, 200);
  assert.equal(reply.json.ready, true);
  assert.equal(
    reply.json.manifestHash,
    manifestHash,
    "Worker and Container disagree on the plan manifest",
  );
  return {
    scenario: "readiness",
    ok: true,
    detail: { manifestHash, schemaVersion: reply.json.schemaVersion },
  };
}

export async function exactValues(target: Target): Promise<Evidence> {
  const scope = `proof/exact-${randomUUID()}`;
  const vectors = [
    ["-9223372036854775808", "18446744073709551615", "-1234567890123456789.123456789"],
    ["9223372036854775807", "9007199254740993", "9999999999999999999.999999999"],
    ["9007199254740993", "9223372036854775808", "0.000000001"],
    ["-9007199254740993", "0", "-0.000000001"],
  ] as const;
  const results: Json[] = [];
  for (const [index, [signed, unsigned, decimal]] of vectors.entries()) {
    const reply = await operator(target, "exact", {
      scope,
      id: `value-${index}`,
      signed,
      unsigned,
      decimal,
      payloadBase64Url: Buffer.from(Uint8Array.from({ length: 256 }, (_, n) => n)).toString(
        "base64url",
      ),
      expectedRevision: "0",
      commandId: randomUUID(),
    });
    assert.equal(reply.status, 200, JSON.stringify(reply.json));
    assert.equal(reply.json.signed, signed);
    assert.equal(reply.json.unsigned, unsigned);
    assert.equal(reply.json.decimal, decimal);
    assert.equal(reply.json.revision, "1");
    assert.equal(reply.json.roundTripExact, true);
    const arithmetic = reply.json.arithmetic as Record<string, string>;
    const plusOne = BigInt(signed) + 1n;
    assert.equal(arithmetic.signedPlusOne, plusOne > int64Max ? "overflow" : String(plusOne));
    const unsignedPlusOne = BigInt(unsigned) + 1n;
    assert.equal(
      arithmetic.unsignedPlusOne,
      unsignedPlusOne > uint64Max ? "overflow" : String(unsignedPlusOne),
    );
    assert(BigInt(signed) >= int64Min);
    results.push({ signed, unsigned, decimal, revision: reply.json.revision });
  }
  // A stale revision is a conflict, not a silent overwrite.
  const stale = await operator(target, "exact", {
    scope,
    id: "value-0",
    signed: "1",
    unsigned: "1",
    decimal: "1",
    expectedRevision: "0",
    commandId: randomUUID(),
  });
  assert.equal(stale.status, 409);
  // Out-of-range text is refused before it can reach D1.
  const outOfRange = await operator(target, "exact", {
    scope,
    id: "value-x",
    signed: "9223372036854775808",
    unsigned: "1",
    decimal: "1",
    expectedRevision: "0",
    commandId: randomUUID(),
  });
  assert.equal(outOfRange.status, 400);
  return {
    scenario: "exact-values",
    ok: true,
    detail: { vectors: results.length, staleStatus: 409, outOfRangeStatus: 400 },
  };
}

export async function guardedRollback(target: Target): Promise<Evidence> {
  const scope = `proof/guard-${randomUUID()}`;
  const base = { scope, from: "alpha", to: "beta" };
  const committed = await operator(target, "guard", {
    ...base,
    amount: "9223372036854774900",
    seedFrom: "9223372036854775000",
    seedTo: "100",
    commandId: randomUUID(),
  });
  assert.equal(committed.status, 200, JSON.stringify(committed.json));
  assert.equal(committed.json.outcome, "committed");
  const rejected = await operator(target, "guard", {
    ...base,
    amount: "5",
    expectedFromRevisionOverride: "99",
    commandId: randomUUID(),
  });
  assert.equal(rejected.status, 200);
  assert.equal(rejected.json.outcome, "rejected");
  assert.equal(rejected.json.rolledBack, true, "the failed guard left a partial effect");
  const replayCommand = randomUUID();
  const first = await operator(target, "guard", { ...base, amount: "1", commandId: replayCommand });
  assert.equal(first.json.outcome, "committed");
  const replay = await operator(target, "guard", {
    ...base,
    amount: "1",
    commandId: replayCommand,
  });
  assert.equal(replay.json.outcome, "replayed");
  const conflict = await operator(target, "guard", {
    ...base,
    amount: "2",
    commandId: replayCommand,
  });
  assert.equal(conflict.json.outcome, "idempotencyConflict");
  return {
    scenario: "guard-rollback",
    ok: true,
    detail: {
      committed: committed.json.outcome,
      rejected: rejected.json.outcome,
      replay: replay.json.outcome,
      conflict: conflict.json.outcome,
    },
  };
}

function cookieValue(setCookie: string | null) {
  const match = /^__Host-af_session=([^;]*)/u.exec(setCookie ?? "");
  return match?.[1] ?? null;
}

export async function sessionLifecycle(target: Target): Promise<Evidence> {
  const issued = await operator(target, "session/issue", {
    userId: randomUUID(),
    deviceId: randomUUID(),
    workspaceIds: [randomUUID()],
  });
  assert.equal(issued.status, 200, JSON.stringify(issued.json));
  const handle = String(issued.json.handle);
  const cookie = `__Host-af_session=${handle}`;
  const call = (method: string, path: string, headers: Record<string, string>) =>
    fetch(`${target.baseUrl}${path}`, {
      method,
      headers,
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    });
  const bootstrap = await call("GET", "/session/v1/bootstrap", { cookie, origin: target.origin });
  const boot = (await bootstrap.json()) as { authenticated: boolean; csrfToken: string };
  assert.equal(bootstrap.status, 200);
  assert.equal(boot.authenticated, true);
  assert.equal(boot.csrfToken, issued.json.csrfToken);
  const anonymous = await call("GET", "/session/v1/bootstrap", { origin: target.origin });
  assert.equal(((await anonymous.json()) as { authenticated: boolean }).authenticated, false);
  // Unsafe route: every missing or wrong element is refused and the session survives.
  const refusals: [string, Record<string, string>, number][] = [
    ["no csrf", { cookie, origin: target.origin }, 403],
    ["wrong csrf", { cookie, origin: target.origin, "x-af-csrf": "x".repeat(43) }, 403],
    ["no origin", { cookie, "x-af-csrf": boot.csrfToken }, 403],
    ["wrong origin", { cookie, origin: "https://evil.example", "x-af-csrf": boot.csrfToken }, 403],
    ["no cookie", { origin: target.origin, "x-af-csrf": boot.csrfToken }, 401],
  ];
  for (const [label, headers, status] of refusals)
    assert.equal((await call("POST", "/session/v1/logout", headers)).status, status, label);
  const stillAuthenticated = await call("GET", "/session/v1/bootstrap", {
    cookie,
    origin: target.origin,
  });
  assert.equal(
    ((await stillAuthenticated.json()) as { authenticated: boolean }).authenticated,
    true,
  );
  const logout = await call("POST", "/session/v1/logout", {
    cookie,
    origin: target.origin,
    "x-af-csrf": boot.csrfToken,
  });
  assert.equal(logout.status, 200);
  assert.equal(((await logout.json()) as { effect: string }).effect, "happened");
  assert.equal(cookieValue(logout.headers.get("set-cookie")), "", "the cookie must be cleared");
  // Revocation is durable and every Container sees it: the handle no longer authenticates.
  const afterRevoke = await call("GET", "/session/v1/bootstrap", { cookie, origin: target.origin });
  assert.equal(((await afterRevoke.json()) as { authenticated: boolean }).authenticated, false);
  assert.equal(
    (
      await call("POST", "/session/v1/logout", {
        cookie,
        origin: target.origin,
        "x-af-csrf": boot.csrfToken,
      })
    ).status,
    401,
  );
  return {
    scenario: "session-csrf-revoke",
    ok: true,
    detail: { refusals: refusals.length, revokedStatus: 401 },
  };
}

export async function objectRoundTrip(target: Target): Promise<Evidence> {
  const reply = await operator(target, "objects/roundtrip", {
    workspaceId: randomUUID(),
    resourceId: randomUUID(),
    size: 1_048_576,
    seed: 7,
  });
  assert.equal(reply.status, 200, JSON.stringify(reply.json));
  assert.equal(reply.json.fullMatches, true);
  assert.equal(reply.json.rangeMatches, true);
  assert.equal(reply.json.mismatchRejected, true);
  return {
    scenario: "r2-objects",
    ok: true,
    detail: { size: reply.json.size, sha256: reply.json.sha256 },
  };
}

export function expectedJobChecksum(total: number): bigint {
  let sum = 0n;
  for (let index = 0; index < total; index++) sum += BigInt(index + 1) * 4_611_686_018_427n;
  return sum;
}

export async function checkpointRestart(
  target: Target,
  options: { stopContainer: boolean },
): Promise<Evidence> {
  const scope = `proof/job-${randomUUID()}`;
  const total = 250;
  // Start without the automatic wake so the first slice and the restart happen at known points.
  const started = await operator(target, "job/start", { scope, total, autoWake: false });
  assert.equal(started.status, 200, JSON.stringify(started.json));
  assert.equal(started.json.wakeEnqueued, false);
  const jobId = String(started.json.jobId);
  const first = await operator(target, "job/slice", {
    scope,
    jobId,
    eventId: randomUUID(),
    maxItems: 100,
    maxMilliseconds: 20_000,
  });
  assert.equal(first.status, 200, JSON.stringify(first.json));
  assert.equal(first.json.state, "running");
  assert.equal(first.json.cursor, "100", "the first slice must stop at its item bound");
  let status: Json = (await operator(target, "job/status", { scope, jobId })).json;
  assert.equal(status.cursor, "100");
  assert.equal(status.itemCount, "100");
  if (options.stopContainer) {
    // The Container may sleep or be replaced at any time: the rest must resume from the D1 checkpoint.
    const stop = await operator(target, "container/stop", {});
    assert.equal(stop.status, 200, JSON.stringify(stop.json));
  }
  // The remaining slices run through the Queue wake, Durable Object admission and the (restarted) Container.
  const wake = await operator(target, "job/wake", { scope, jobId });
  assert.equal(wake.status, 200, JSON.stringify(wake.json));
  const deadline = Date.now() + (target.jobTimeoutMs ?? 180_000);
  while (Date.now() < deadline) {
    await sleep(target.pollIntervalMs ?? 2_000);
    status = (await operator(target, "job/status", { scope, jobId })).json;
    if (status.state === "complete") break;
  }
  assert.equal(status.state, "complete", "the job did not finish within the time limit");
  assert.equal(status.itemCount, String(total), "items must be written exactly once");
  const expected = String(expectedJobChecksum(total));
  assert.equal(status.checksum, expected);
  assert.equal(status.itemSum, expected, "stored items must sum to the checkpoint checksum");
  assert.equal(status.expectedChecksum, expected);
  assert.equal(status.matches, true);
  return {
    scenario: "checkpoint-restart",
    ok: true,
    detail: {
      total,
      firstSliceCursor: first.json.cursor,
      containerStopped: options.stopContainer,
      fence: status.fence,
    },
  };
}

export async function negatives(target: Target): Promise<Evidence> {
  const wrong = await fetch(`${target.baseUrl}/proof/v1/readiness`, {
    method: "POST",
    headers: { authorization: "Bearer not-the-operator-token", "content-type": "application/json" },
    body: "{}",
  });
  assert.equal(wrong.status, 401);
  const forged = await fetch(`${target.baseUrl}/proof/v1/readiness`, {
    method: "POST",
    headers: {
      authorization: `AF-Operator t=${Math.floor(Date.now() / 1000)},n=${"A".repeat(22)},s=${"A".repeat(86)}`,
      "content-type": "application/json",
    },
    body: "{}",
  });
  assert.equal(forged.status, 401, "an invalid operator signature must be refused");
  const unauthenticated = await fetch(`${target.baseUrl}/proof/v1/readiness`, {
    method: "POST",
    body: "{}",
    headers: { "content-type": "application/json" },
  });
  assert.equal(unauthenticated.status, 401);
  for (const path of [
    "/internal/foundation/v1/readiness",
    "/internal/storage/v1/execute-plan",
    "/internal/objects/v1/probe/x",
  ]) {
    const response = await fetch(`${target.baseUrl}${path}`, {
      method: "POST",
      body: "{}",
      headers: { "content-type": "application/json" },
    });
    assert.equal(response.status, 404, `${path} must not be reachable from the public origin`);
  }
  return {
    scenario: "public-denial",
    ok: true,
    detail: { operatorWrongToken: 401, forgedSignature: 401, anonymous: 401, internalPaths: 404 },
  };
}

export async function runAll(
  target: Target,
  manifestHash: string,
  options: { stopContainer: boolean },
) {
  const evidence: Evidence[] = [];
  for (const step of [
    () => readiness(target, manifestHash),
    () => exactValues(target),
    () => guardedRollback(target),
    () => sessionLifecycle(target),
    () => objectRoundTrip(target),
    () => checkpointRestart(target, options),
    () => negatives(target),
  ])
    evidence.push(await step());
  return evidence;
}
