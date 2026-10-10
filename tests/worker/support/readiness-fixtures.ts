// SPDX-License-Identifier: AGPL-3.0-only
// Shared fixtures of the readiness tests: a complete proof environment whose every binding is a recording fake,
// and the replies the Container host can give.
import type { ReadinessEnv } from "../../../worker/readiness/bindings.ts";
import type { HostReply } from "../../../worker/readiness/transport.ts";
import { base64UrlEncode } from "../../../worker/private/encoding.ts";

export const secretMaterial = {
  c2w: base64UrlEncode(new Uint8Array(32).fill(1)),
  w2c: base64UrlEncode(new Uint8Array(32).fill(2)),
  csrf: "csrf-secret-value-that-must-never-be-reported",
  operator: "operator-token-value-that-must-never-be-reported",
};

export const manifest = "a".repeat(64);
export const otherManifest = "b".repeat(64);

export interface Calls {
  durableObject: string[];
  r2: string[];
  queueSends: number;
}

export function proofEnvironment(overrides: Record<string, unknown> = {}): {
  env: ReadinessEnv;
  calls: Calls;
} {
  const calls: Calls = { durableObject: [], r2: [], queueSends: 0 };
  const env: Record<string, unknown> = {
    FOUNDATION_PROOF: "enabled",
    SOURCE_REVISION: "0123456789abcdef0123456789abcdef01234567",
    ALLOWED_ORIGIN: "https://proof.example.test",
    REALM_ID: "proof",
    CSRF_SECRET: secretMaterial.csrf,
    RECOVERY_GENERATION: "0",
    HMAC_C2W_KEY_ID: "c2w-1",
    HMAC_C2W_SECRET: secretMaterial.c2w,
    HMAC_W2C_KEY_ID: "w2c-1",
    HMAC_W2C_SECRET: secretMaterial.w2c,
    PROOF_OPERATOR_TOKEN: secretMaterial.operator,
    HELLO_RATE_LIMITER: { limit: async () => ({ success: true }) },
    CLOUD_CONTAINER: { getByName: () => ({ fetch: async () => new Response("{}") }) },
    DB: { prepare: () => ({}), batch: async () => [] },
    JOB_COORDINATOR: {
      getByName(name: string) {
        calls.durableObject.push(name);
        return { readPoison: async () => ({ attempts: [], deadLetter: null }) };
      },
    },
    OBJECTS: {
      head: async (key: string) => {
        calls.r2.push(key);
        return null;
      },
      get: async () => null,
      put: async () => null,
      delete: async () => {},
    },
    WAKE_QUEUE: {
      send: async () => {
        calls.queueSends++;
      },
    },
    ...overrides,
  };
  for (const [name, value] of Object.entries(env)) if (value === undefined) delete env[name];
  return { env: env as ReadinessEnv, calls };
}

export function productionEnvironment(): ReadinessEnv {
  return {
    SOURCE_REVISION: "0123456789abcdef0123456789abcdef01234567",
    HELLO_RATE_LIMITER: { limit: async () => ({ success: true }) },
    CLOUD_CONTAINER: { getByName: () => ({ fetch: async () => new Response("{}") }) },
  };
}

/**
 * The complete report the Container host returns for a proof environment, as the C# evaluator judges it. The fixture only states
 * the verdict the host would give for the given D1 state; the judging itself is tested in C# (CLOUD.84 S39(1)).
 */
export function hostReport(
  d1: { state: string; reason?: string } = { state: "ready" },
  overrides: Record<string, unknown> = {},
): string {
  const status =
    d1.state === "misconfigured"
      ? "misconfigured"
      : d1.state === "unavailable"
        ? "unavailable"
        : "ready";
  return JSON.stringify({
    schema: "cloud.readiness.v1",
    status,
    ready: status === "ready",
    environment: "proof",
    workerRevision: "",
    components: {
      ingress: { state: "ready", evidence: "bound" },
      container: { state: "ready", evidence: "probed" },
      d1: { ...d1, evidence: "probed" },
      durableObject: { state: "ready", evidence: "probed", elapsedMs: 3 },
      r2: { state: "ready", evidence: "probed", elapsedMs: 3 },
      queue: { state: "ready", evidence: "bound" },
    },
    host: {
      manifestHash: manifest,
      schemaVersion: "1",
      revision: "fedcba9876543210fedcba9876543210fedcba98",
    },
    ...overrides,
  });
}

/** The reply the host gives for a report: 200 when ready, 503 otherwise. */
export function hostReply(
  d1: { state: string; reason?: string } = { state: "ready" },
  overrides: Record<string, unknown> = {},
): HostReply {
  return reply(d1.state === "ready" ? 200 : 503, hostReport(d1, overrides));
}

export function reply(
  status: number,
  body: string,
  contentType: string | null = "application/json",
): HostReply {
  return { status, contentType, body: new TextEncoder().encode(body) };
}

export const libraryNoInstance = reply(
  503,
  "There is no Container instance available at this time.\nThis is likely because you have reached your max concurrent instance count (set in wrangler config) or are you currently provisioning the Container.",
  "text/plain;charset=UTF-8",
);
export const libraryStartFailed = reply(
  500,
  "Failed to start container: boom",
  "text/plain;charset=UTF-8",
);
