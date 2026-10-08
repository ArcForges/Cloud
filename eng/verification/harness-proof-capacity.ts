// SPDX-License-Identifier: AGPL-3.0-only
// Local opt-in proof 3 of HAR.40 (container capacity): max_instances semantics, sleep with an open stream and the cold start on the
// standard-2 image are measured only on a deployed Container. Locally this driver does two things and labels both honestly:
//   1. reads wrangler.json and records the container launch values beside the Design launch targets (architecture/05 line 74: standard-2,
//      four realm slots, ten-minute idle sleep). The current production values are lite and max_instances 1, so the capacity decision is
//      still open; the configuration check is an observation, never a pass.
//   2. when HARNESS_CAPACITY_URL is set to an https origin of a deployed proof Worker, probes that endpoint: one cold request (run it after
//      the container has slept), then HARNESS_CAPACITY_CONCURRENCY parallel requests, recording each status and latency. No credential is
//      sent and the URL must carry no query or userinfo. Without the URL the live part is recorded as not-run.
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertLocalOptIn,
  check,
  evidence,
  percentile,
  type ProofCheck,
  type ProofEvidence,
  writeEvidence,
} from "./harness-proof-evidence.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

/** Design launch targets for the production CloudContainer (architecture/05-cloud-architecture.md line 74). */
export const launchTarget = {
  instanceType: "standard-2",
  realmSlots: 4,
  sleepAfter: "10m",
} as const;

export interface ContainerLaunchValues {
  readonly className: string;
  readonly maxInstances: number | null;
  readonly instanceType: string | null;
}

export function containerValues(wrangler: unknown): ContainerLaunchValues[] {
  const containers = (wrangler as { containers?: unknown }).containers;
  if (!Array.isArray(containers)) return [];
  return containers.map((entry) => {
    const record = entry as Record<string, unknown>;
    return {
      className: typeof record.class_name === "string" ? record.class_name : "",
      maxInstances: typeof record.max_instances === "number" ? record.max_instances : null,
      instanceType: typeof record.instance_type === "string" ? record.instance_type : null,
    };
  });
}

export function configurationChecks(wrangler: unknown): ProofCheck[] {
  const values = containerValues(wrangler);
  const production = values.find((entry) => entry.className === "CloudContainer");
  const observed = values
    .map(
      (entry) =>
        `${entry.className}: max_instances ${entry.maxInstances ?? "unset"}, instance_type ${entry.instanceType ?? "unset"}`,
    )
    .join("; ");
  // Configuration is an observation, never a pass: a declared value proves nothing about capacity, so the proof stays not-run until the live run.
  return [
    {
      name: "production-container-declared",
      status: "observed",
      expected: "a CloudContainer entry in wrangler.json",
      observed: production === undefined ? "absent" : `present (${observed})`,
    },
    {
      name: "production-launch-target-applied",
      status: "observed",
      expected: `instance_type ${launchTarget.instanceType}, ${launchTarget.realmSlots} realm slots, sleepAfter ${launchTarget.sleepAfter} (Design launch target; needs the capacity proof and L-16/PG-26 approval)`,
      observed: `${observed}; target not yet applied`,
    },
  ];
}

export function validProbeUrl(raw: string): URL {
  const url = new URL(raw);
  if (url.protocol !== "https:") throw new Error("HARNESS_CAPACITY_URL must be an https origin.");
  if (url.search !== "" || url.hash !== "" || url.username !== "" || url.password !== "") {
    throw new Error("HARNESS_CAPACITY_URL must carry no query, fragment or userinfo.");
  }
  return url;
}

interface Probe {
  readonly status: number;
  readonly latencyMs: number;
}

async function probe(url: URL, timeoutMs: number): Promise<Probe> {
  const started = performance.now();
  try {
    const response = await fetch(url, {
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "error",
    });
    await response.arrayBuffer();
    return { status: response.status, latencyMs: performance.now() - started };
  } catch {
    return { status: 0, latencyMs: performance.now() - started };
  }
}

export async function liveChecks(
  env: NodeJS.ProcessEnv,
): Promise<{ checks: ProofCheck[]; notRun: string[]; observed: string[] }> {
  if (env.HARNESS_CAPACITY_URL === undefined || env.HARNESS_CAPACITY_URL === "") {
    return {
      checks: [],
      notRun: [
        "Cold start on the standard-2 image after the container has slept (operator: wait past sleepAfter, then run this driver with HARNESS_CAPACITY_URL).",
        "max_instances semantics and per-instance concurrency (operator: run the parallel probe against the deployed proof Worker and compare the served instance names).",
        "Sleep with an open stream (operator: hold one streamed response open past sleepAfter on the proof environment).",
      ],
      observed: [],
    };
  }
  const url = validProbeUrl(env.HARNESS_CAPACITY_URL);
  const path_ = env.HARNESS_CAPACITY_PATH ?? "/healthz";
  url.pathname = path_.startsWith("/") ? path_ : `/${path_}`;
  const concurrency = Math.min(8, Math.max(1, Number(env.HARNESS_CAPACITY_CONCURRENCY ?? "4")));
  const timeoutMs = Math.min(
    180_000,
    Math.max(1_000, Number(env.HARNESS_CAPACITY_TIMEOUT_MS ?? "120000")),
  );
  if (!Number.isInteger(concurrency))
    throw new Error("HARNESS_CAPACITY_CONCURRENCY must be an integer.");

  const cold = await probe(url, timeoutMs);
  const burst = await Promise.all(Array.from({ length: concurrency }, () => probe(url, timeoutMs)));
  const latencies = burst.map((entry) => entry.latencyMs).sort((left, right) => left - right);
  const answered = burst.filter((entry) => entry.status >= 200 && entry.status < 300).length;
  return {
    checks: [
      check(
        "parallel-burst-all-answered-2xx",
        answered === concurrency,
        `${concurrency} of ${concurrency} parallel requests answered 2xx within ${timeoutMs} ms`,
        `${answered} of ${concurrency} answered 2xx; statuses ${burst.map((entry) => entry.status).join(",")}`,
      ),
    ],
    notRun: [
      "max_instances semantics and per-instance concurrency need the instance identity served by the proof Worker (operator: compare the served instance names across the burst).",
      "Sleep with an open stream needs a held streamed response on the proof environment (operator run).",
    ],
    observed: [
      `cold request status ${cold.status} in ${cold.latencyMs.toFixed(0)} ms (run after the container has slept)`,
      `burst p50 ${percentile(latencies, 0.5).toFixed(0)} ms, p95 ${percentile(latencies, 0.95).toFixed(0)} ms over ${concurrency} requests`,
    ],
  };
}

export async function runCapacityProof(
  env: NodeJS.ProcessEnv = process.env,
  now = new Date(),
): Promise<ProofEvidence> {
  const wrangler = JSON.parse(await readFile(path.join(root, "wrangler.json"), "utf8")) as unknown;
  const config = configurationChecks(wrangler);
  const live = await liveChecks(env);
  const observations = live.observed.map((text, index): ProofCheck => ({
    name: `live-observation-${index + 1}`,
    status: "observed",
    expected: "recorded",
    observed: text,
  }));
  return evidence({
    proof: "container-capacity",
    realness: env.HARNESS_CAPACITY_URL ? "deployed-live" : "not-run",
    checks: [...config, ...live.checks, ...observations],
    liveNotRun: live.notRun,
    notes: [
      "Cloudflare does not document max_instances semantics; the value is observed, never assumed (P2-021, brief section 5 item 6).",
      "CLOUD.71 observed max_instances 2 serving one of two named instances at a time; that observation is history, not this proof.",
    ],
    environment: {
      production: JSON.stringify(
        containerValues(wrangler).find((entry) => entry.className === "CloudContainer") ?? null,
      ),
      probe: env.HARNESS_CAPACITY_URL ? "set (URL not recorded)" : "unset",
    },
    now,
  });
}

export async function main(): Promise<void> {
  assertLocalOptIn();
  const record = await runCapacityProof();
  const file = await writeEvidence(root, record);
  console.log(
    `container-capacity: ${record.status} (${record.checks.length} checks, realness ${record.realness}) -> ${file}`,
  );
  if (record.status === "failed") process.exitCode = 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  await main();
}
