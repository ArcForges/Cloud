// SPDX-License-Identifier: AGPL-3.0-only
// Protected proof deployment's per-deploy test key. Private bytes exist only in this process and the short-lived Wrangler secrets
// file; the public receipt is persisted before registration so an uncertain write can be inspected, never blindly retried.
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  CenterExit,
  centerVariables,
  chooseLiveSlot,
  dockerArguments,
  type CenterRunner,
  type LiveSlots,
  type WranglerReader,
} from "./postgres-deploy.ts";
import { runSensitive, SensitiveProcessError } from "./sensitive-process.ts";

export interface ProofKeyMetadata {
  kid: string;
  binding: string;
  notBefore: string;
  notAfter: string;
  publicSha256: string;
  fingerprint: string;
  /** Bounds computed by the real registry transaction before insertion, absent until registration is verified. */
  proofReplyBytes?: number;
  proofReplyLimit?: number;
  testOnly: true;
}
export type ProofKeyStage =
  "generated" | "registration-started" | "registered" | "upload-started" | "uploaded";
export type ProofKeyReceipt = ProofKeyMetadata & { stage: ProofKeyStage };

const validityMs = 400 * 24 * 60 * 60 * 1000;
const instant = (date: Date) => date.toISOString().replace(".000Z", "Z");

export class ProofCommandKey {
  readonly metadata: ProofKeyMetadata;
  readonly publicDer: Buffer;
  #privateValue: string;

  constructor(now = new Date()) {
    const epoch = Math.floor(now.getTime() / 1000) * 1000;
    if (!Number.isFinite(epoch)) throw new Error("The proof command-key clock is invalid.");
    const id = randomBytes(16).toString("hex");
    const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    this.publicDer = pair.publicKey.export({ format: "der", type: "spki" });
    const privateDer = pair.privateKey.export({ format: "der", type: "pkcs8" });
    this.#privateValue = privateDer.toString("base64");
    privateDer.fill(0);
    const publicSha256 = createHash("sha256").update(this.publicDer).digest("hex");
    this.metadata = {
      kid: `proof-${id}`,
      binding: `ARCFORGES_CENTER_KEY_PROOF_${id.toUpperCase()}`,
      notBefore: instant(new Date(epoch)),
      notAfter: instant(new Date(epoch + validityMs)),
      publicSha256,
      fingerprint: (publicSha256.slice(0, 20).toUpperCase().match(/.{4}/gu) ?? []).join("-"),
      testOnly: true,
    };
  }

  /** The value is handed only to the combined runner-local Wrangler secrets file. */
  secret(): string {
    return this.#privateValue;
  }

  toJSON(): ProofKeyMetadata {
    return this.metadata;
  }
}

type RunSensitive = typeof runSensitive;

/** A live proof version must have a readable, unambiguous runtime slot before registration and again before rotation. */
export function requireKnownProofSlots(live: LiveSlots): LiveSlots {
  if (live.unreadable !== undefined || live.unlabelled !== 0 || live.labelled.length === 0)
    throw new Error(
      "Proof live-version metadata is unavailable or ambiguous; no runtime slot may be rotated.",
    );
  try {
    chooseLiveSlot(live);
  } catch {
    throw new Error(
      "Proof live-version metadata is unavailable or ambiguous; no runtime slot may be rotated.",
    );
  }
  return live;
}

/**
 * Read every listed deployment version without silently dropping malformed or unlabelled entries. An unknown percentage, ID,
 * slot label or total refuses proof before the key registry or runtime password changes.
 */
export async function readProofLiveSlots(
  wrangler: WranglerReader,
  configArguments: readonly string[],
): Promise<LiveSlots> {
  try {
    const status = JSON.parse(
      await wrangler(["deployments", "status", "--json", ...configArguments]),
    ) as {
      versions?: { version_id?: unknown; percentage?: unknown }[];
    };
    if (!Array.isArray(status.versions) || status.versions.length === 0) throw new Error("invalid");
    const idPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
    let total = 0;
    const active: string[] = [];
    const seen = new Set<string>();
    for (const version of status.versions) {
      if (
        typeof version?.version_id !== "string" ||
        !idPattern.test(version.version_id) ||
        typeof version.percentage !== "number" ||
        !Number.isFinite(version.percentage) ||
        version.percentage < 0 ||
        version.percentage > 100
      )
        throw new Error("invalid");
      const id = version.version_id.toLowerCase();
      if (seen.has(id)) throw new Error("invalid");
      seen.add(id);
      total += version.percentage;
      if (version.percentage > 0) active.push(version.version_id);
    }
    if (active.length === 0 || Math.abs(total - 100) > 0.000001) throw new Error("invalid");
    const labelled: ("a" | "b")[] = [];
    for (const id of active) {
      const view = JSON.parse(
        await wrangler(["versions", "view", id, "--json", ...configArguments]),
      ) as {
        annotations?: Record<string, unknown>;
      };
      const message = view.annotations?.["workers/message"];
      if (typeof message !== "string") throw new Error("invalid");
      const labels = [...message.matchAll(/(?:^|\s)runtime-slot=([^\s]+)(?=\s|$)/gu)];
      if (labels.length !== 1 || (labels[0]?.[1] !== "a" && labels[0]?.[1] !== "b"))
        throw new Error("invalid");
      labelled.push(labels[0][1] as "a" | "b");
    }
    return requireKnownProofSlots({ labelled, unlabelled: 0 });
  } catch {
    throw new Error(
      "Proof live-version metadata is unavailable or ambiguous; no runtime slot may be rotated.",
    );
  }
}

/** The existing credential rotation's sealed-image runner, with bounded/discarded child output and its exit-4 meaning intact. */
export function proofRuntimeRunner(run: RunSensitive = runSensitive): CenterRunner {
  return async (image, variables, command, options = {}) => {
    try {
      const value = await run(
        "runtime",
        "docker",
        dockerArguments(image, Object.keys(variables), command, options),
        { ...process.env, ...variables },
        "json",
      );
      if (typeof value !== "object" || value === null || Array.isArray(value))
        throw new Error("invalid response");
      return value as Record<string, unknown>;
    } catch (error) {
      throw new CenterExit(
        "Protected proof runtime command failed.",
        error instanceof SensitiveProcessError ? error.exitCode : null,
      );
    }
  };
}
export const protectedProofRuntimeRunner = proofRuntimeRunner();

/** Validate and copy only public runtime metadata; never trust an arbitrary child response as log or artifact text. */
export function proofRotationReceipt(rotation: Record<string, unknown>): Record<string, unknown> {
  const slot = rotation.slot;
  if (
    (slot !== "a" && slot !== "b") ||
    rotation.database !== "arcforges_acceptance" ||
    rotation.runtimeRole !== "arcforges_acceptance_runtime" ||
    rotation.loginRole !== `arcforges_acceptance_runtime_${slot}` ||
    !["scram-sha-256-verifier", "neon-plaintext"].includes(String(rotation.passwordForm)) ||
    rotation.slotSource !== "live-version" ||
    !Number.isSafeInteger(rotation.serverVersionNum) ||
    (rotation.serverVersionNum as number) < 1
  )
    throw new Error("The proof runtime rotation returned invalid public metadata.");
  const raw = rotation.probe;
  if (typeof raw !== "object" || raw === null || Array.isArray(raw))
    throw new Error("The proof runtime rotation returned invalid public metadata.");
  const probe = raw as Record<string, unknown>;
  const required = [
    "connectsUnpooled",
    "connectedAsLoginRole",
    "readsGrantedTable",
    "cannotCreateTables",
    "cannotReadUngrantedTables",
    "cannotCreateTemporaryTables",
  ];
  if (typeof probe.pooledEndpoint !== "boolean" || required.some((name) => probe[name] !== true))
    throw new Error("The proof runtime rotation returned invalid public metadata.");
  return {
    database: "arcforges_acceptance",
    runtimeRole: "arcforges_acceptance_runtime",
    loginRole: `arcforges_acceptance_runtime_${slot}`,
    slot,
    passwordForm: rotation.passwordForm,
    serverVersionNum: rotation.serverVersionNum,
    slotSource: "live-version",
    probe: Object.fromEntries(["pooledEndpoint", ...required].map((name) => [name, probe[name]])),
  };
}

function matchesRegistration(value: unknown, key: ProofKeyMetadata): boolean {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    record.kid === key.kid &&
    record.purpose === "command" &&
    record.notBefore === key.notBefore &&
    record.notAfter === key.notAfter &&
    record.fingerprint === key.fingerprint &&
    Number.isSafeInteger(record.proofReplyBytes) &&
    Number.isSafeInteger(record.proofReplyLimit) &&
    (record.proofReplyBytes as number) > 0 &&
    (record.proofReplyBytes as number) <= (record.proofReplyLimit as number)
  );
}

function matchesInspection(value: unknown, key: ProofKeyMetadata): boolean {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    record.found === true &&
    record.kid === key.kid &&
    record.purpose === "command" &&
    record.algorithm === "ES256" &&
    record.secretBinding === key.binding &&
    record.notBefore === key.notBefore &&
    record.notAfter === key.notAfter &&
    record.retiredAt === null &&
    record.publicSha256 === key.publicSha256 &&
    record.fingerprint === key.fingerprint
  );
}

/** Register and independently inspect the exact public key in the acceptance database, using the sealed candidate image. */
export async function registerProofCommandKey(
  image: string,
  key: ProofCommandKey,
  options: { environment?: NodeJS.ProcessEnv; run?: RunSensitive } = {},
): Promise<void> {
  const environment = options.environment ?? process.env;
  const runner = options.run ?? runSensitive;
  const directory = await mkdtemp(path.join(os.tmpdir(), "arcforges-proof-public-key-"));
  try {
    await chmod(directory, 0o700);
    await writeFile(path.join(directory, "public.der"), key.publicDer, { mode: 0o600, flag: "wx" });
    const variables = centerVariables("acceptance", environment);
    const user =
      typeof process.getuid === "function" && typeof process.getgid === "function"
        ? `${process.getuid()}:${process.getgid()}`
        : undefined;
    const args = (command: string[]) =>
      dockerArguments(image, Object.keys(variables), command, {
        user,
        secretsDirectory: directory,
      });
    const env = { ...environment, ...variables };
    const meta = key.metadata;
    const registered = await runner(
      "registration",
      "docker",
      args([
        "admin",
        "register-signing-key",
        "--purpose",
        "command",
        "--kid",
        meta.kid,
        "--public-key-file",
        "/secrets/public.der",
        "--secret-binding",
        meta.binding,
        "--not-before",
        meta.notBefore,
        "--not-after",
        meta.notAfter,
      ]),
      env,
      "json",
    );
    if (!matchesRegistration(registered, meta))
      throw new Error("Proof command-key registration returned unexpected public metadata.");
    const budget = registered as { proofReplyBytes: number; proofReplyLimit: number };
    meta.proofReplyBytes = budget.proofReplyBytes;
    meta.proofReplyLimit = budget.proofReplyLimit;
    const inspected = await runner(
      "inspection",
      "docker",
      args(["admin", "inspect-signing-key", "--kid", meta.kid]),
      env,
      "json",
    );
    if (!matchesInspection(inspected, meta))
      throw new Error("Proof command-key inspection returned unexpected public metadata.");
  } catch {
    // A lost reply can conceal a successful registration; do not retry or print the child's text.
    throw new Error(
      "Proof command-key registration could not be verified; inspect its public receipt before any further write.",
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

/**
 * The callback must mark upload immediately before invoking Wrangler. If registration, inspection, upload or its reply is
 * uncertain no write is retried and no older key is retired. The receipt contains public metadata only.
 */
export async function withProofCommandKey(
  register: (key: ProofCommandKey) => Promise<void>,
  publish: (key: ProofCommandKey, beforeUpload: () => Promise<void>) => Promise<void>,
  record: (receipt: ProofKeyReceipt) => Promise<void>,
  now = new Date(),
): Promise<ProofKeyMetadata> {
  const key = new ProofCommandKey(now);
  const save = async (stage: ProofKeyStage) => {
    try {
      await record({ ...key.metadata, stage });
    } catch {
      throw new Error("The public proof command-key receipt could not be saved.");
    }
  };
  await save("generated");
  await save("registration-started");
  try {
    await register(key);
  } catch {
    throw new Error(
      "Proof command-key registration could not be verified; inspect its public receipt before any further write.",
    );
  }
  await save("registered");
  let uploadStarted = false;
  const beforeUpload = async () => {
    if (uploadStarted) throw new Error("The proof upload was already started.");
    await save("upload-started");
    uploadStarted = true;
  };
  try {
    await publish(key, beforeUpload);
  } catch {
    throw new Error(
      "Proof deployment did not complete; inspect its public receipt, active version and runtime credential slot before any further write.",
    );
  }
  if (!uploadStarted) throw new Error("Proof deployment did not start the protected upload.");
  await save("uploaded");
  return key.metadata;
}
