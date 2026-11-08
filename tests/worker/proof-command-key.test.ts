// SPDX-License-Identifier: AGPL-3.0-only
// E3 uses synthetic keys and mocked provider/registry calls. No owner key, account or provider is contacted.
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { access, readFile, readdir, stat } from "node:fs/promises";
import { execFileSync, spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import path from "node:path";
import test from "node:test";
import {
  ProofCommandKey,
  proofRotationReceipt,
  proofRuntimeRunner,
  readProofLiveSlots,
  registerProofCommandKey,
  requireKnownProofSlots,
  withProofCommandKey,
  writeProofKeyReceipt,
  type ProofKeyReceipt,
} from "../../tooling/proof-command-key.ts";
import { withNeonRuntimeSecret } from "../../tooling/neon-runtime.ts";
import {
  proofProcessEnvironment,
  runSensitive,
  SensitiveProcessError,
} from "../../tooling/sensitive-process.ts";
import { CenterExit } from "../../tooling/postgres-deploy.ts";
import { prepareProofCandidate } from "../../tooling/proof-candidate.ts";
import { scratchDirectory } from "./support/scratch.ts";

const migration = "postgres://synthetic:synthetic-password@example.test/database";
const dispatchContext = (revision: string) => ({
  GITHUB_ACTIONS: "true",
  GITHUB_REPOSITORY: "ArcForges/Cloud",
  GITHUB_SHA: revision,
  GITHUB_EVENT_NAME: "workflow_dispatch",
  GITHUB_EVENT_PATH: "/synthetic/event.json",
  GITHUB_RUN_ID: "999",
  GITHUB_RUN_NUMBER: "560",
  GITHUB_RUN_ATTEMPT: "1",
  ARCFORGES_CANDIDATE_RUN_ID: "88",
  ARCFORGES_CANDIDATE_RUN_NUMBER: "123",
  ARCFORGES_CANDIDATE_RUN_ATTEMPT: "1",
});
const asRegistration = (key: ProofCommandKey) => ({
  kid: key.metadata.kid,
  purpose: "command",
  notBefore: key.metadata.notBefore,
  notAfter: key.metadata.notAfter,
  fingerprint: key.metadata.fingerprint,
  proofReplyBytes: 1000,
  proofReplyLimit: 65536,
});
const asInspection = (key: ProofCommandKey) => ({
  ...asRegistration(key),
  found: true,
  algorithm: "ES256",
  secretBinding: key.metadata.binding,
  retiredAt: null,
  publicSha256: key.metadata.publicSha256,
});

test("proof key generation yields unique P-256 public/private pairs and public-only serialization", () => {
  const first = new ProofCommandKey(new Date("2026-11-08T12:00:00.000Z"));
  const second = new ProofCommandKey(new Date("2026-11-08T12:00:00.000Z"));
  assert.notEqual(first.metadata.kid, second.metadata.kid);
  assert.notEqual(first.metadata.binding, second.metadata.binding);
  assert.match(first.metadata.kid, /^proof-[a-f0-9]{32}$/u);
  assert.match(first.metadata.binding, /^ARCFORGES_CENTER_KEY_PROOF_[A-F0-9]{32}$/u);
  assert.equal(
    Date.parse(first.metadata.notAfter) - Date.parse(first.metadata.notBefore),
    400 * 24 * 60 * 60 * 1000,
  );
  const privateKey = createPrivateKey({
    key: Buffer.from(first.secret(), "base64"),
    type: "pkcs8",
    format: "der",
  });
  const publicDer = createPublicKey(privateKey).export({ type: "spki", format: "der" });
  assert.deepEqual(publicDer, first.publicDer);
  assert.equal(JSON.stringify(first).includes(first.secret()), false);
});

test("registration uses the sealed image, public file and exact read-only inspection, with no private bytes in arguments", async () => {
  const key = new ProofCommandKey();
  const stages: string[] = [];
  let directory = "";
  await registerProofCommandKey("sealed-candidate-image", key, {
    environment: {
      NEON_DATABASE_URL_DIRECT: migration,
      GH_TOKEN: "synthetic-gh",
      CLOUDFLARE_API_TOKEN: "synthetic-cloudflare",
    },
    run: async (stage, command, args, env, output) => {
      stages.push(stage);
      assert.equal(command, "docker");
      assert.equal(output, "json");
      assert.equal(env.ARCFORGES_CENTER_MIGRATION_DATABASE_URL, migration);
      assert.equal(env.NEON_DATABASE_URL_DIRECT, undefined);
      assert.equal(env.GH_TOKEN, undefined);
      assert.equal(env.CLOUDFLARE_API_TOKEN, undefined);
      assert(!args.join(" ").includes(key.secret()));
      assert(!args.join(" ").includes(migration));
      const volume = args[args.indexOf("--volume") + 1] as string;
      assert(volume.endsWith(":/secrets"));
      directory = volume.slice(0, -":/secrets".length);
      assert.deepEqual(await readFile(path.join(directory, "public.der")), key.publicDer);
      assert(args.includes("sealed-candidate-image"));
      return stage === "registration" ? asRegistration(key) : asInspection(key);
    },
  });
  assert.deepEqual(stages, ["registration", "inspection"]);
  await assert.rejects(access(directory));
});

test("uncertain or mismatching registry replies refuse promotion and clean the public temporary directory", async () => {
  for (const failure of ["registration", "binding", "hash", "retired"] as const) {
    const key = new ProofCommandKey();
    let directory = "";
    let calls = 0;
    await assert.rejects(
      registerProofCommandKey("candidate", key, {
        environment: { NEON_DATABASE_URL_DIRECT: migration },
        run: async (stage, _command, args) => {
          calls++;
          const volume = args[args.indexOf("--volume") + 1] as string;
          directory = volume.slice(0, -":/secrets".length);
          if (stage === "registration") {
            if (failure === "registration") throw new Error(`synthetic child: ${key.secret()}`);
            return asRegistration(key);
          }
          return {
            ...asInspection(key),
            ...(failure === "binding" ? { secretBinding: "WRONG" } : {}),
            ...(failure === "hash" ? { publicSha256: "0".repeat(64) } : {}),
            ...(failure === "retired" ? { retiredAt: "2026-01-01T00:00:00Z" } : {}),
          };
        },
      }),
      (error: Error) =>
        /could not be verified/u.test(error.message) && !error.message.includes(key.secret()),
    );
    assert.equal(calls, failure === "registration" ? 1 : 2);
    await assert.rejects(access(directory));
  }
});

test("the protected flow records public stages, combines runtime and command secrets once, and cleans up on both outcomes", async () => {
  for (const fail of [false, true]) {
    const stages: ProofKeyReceipt[] = [];
    let file = "";
    let registered = false;
    let registeredSecret = "";
    const flow = withProofCommandKey(
      async (key) => {
        registered = true;
        registeredSecret = key.secret();
      },
      async (key, beforeUpload) => {
        assert(registered);
        await withNeonRuntimeSecret(
          {
            ARCFORGES_CENTER_DATABASE_URL: "synthetic-runtime",
            [key.metadata.binding]: key.secret(),
          },
          async (args) => {
            assert.equal(args[0], "--secrets-file");
            file = args[1] as string;
            const values = JSON.parse(await readFile(file, "utf8")) as Record<string, string>;
            assert.equal(values.ARCFORGES_CENTER_DATABASE_URL, "synthetic-runtime");
            assert.equal(values[key.metadata.binding], key.secret());
            if (process.platform !== "win32") assert.equal((await stat(file)).mode & 0o777, 0o600);
            await beforeUpload();
            if (fail) throw new Error(`provider error ${key.secret()}`);
          },
        );
      },
      async (receipt) => {
        stages.push(receipt);
      },
    );
    if (fail) {
      await assert.rejects(
        flow,
        (error: Error) =>
          /inspect its public receipt/u.test(error.message) &&
          !error.message.includes(registeredSecret),
      );
    } else {
      const meta = await flow;
      assert.equal(meta.testOnly, true);
    }
    await assert.rejects(access(file));
    assert.deepEqual(
      stages.map((entry) => entry.stage),
      fail
        ? ["generated", "registration-started", "registered", "upload-started"]
        : ["generated", "registration-started", "registered", "upload-started", "uploaded"],
    );
    assert(!JSON.stringify(stages).includes(registeredSecret));
  }
});

test("atomic public stage receipts preserve the last complete state on write or replace failure", async (t) => {
  for (const stage of ["registered", "upload-started"] as const) {
    for (const fault of ["write", "replace"] as const) {
      const directory = scratchDirectory("e3-proof-receipt-", t);
      const file = path.join(directory, "receipt.json");
      let prior = "",
        privateKey = "",
        uploads = 0;
      const flow = withProofCommandKey(
        async (key) => {
          privateKey = key.secret();
          key.metadata.proofReplyBytes = 1000;
          key.metadata.proofReplyLimit = 65536;
        },
        async (_key, beforeUpload) => {
          await beforeUpload();
          uploads++;
        },
        async (receipt) => {
          const options =
            receipt.stage !== stage
              ? {}
              : fault === "write"
                ? {
                    write: async (handle: import("node:fs/promises").FileHandle, text: string) => {
                      await handle.writeFile(text.slice(0, 16));
                      throw new Error(`synthetic write failure ${privateKey}`);
                    },
                  }
                : {
                    replace: async () => {
                      throw new Error(`synthetic rename failure ${privateKey}`);
                    },
                  };
          await writeProofKeyReceipt(
            file,
            { ...receipt, unexpected: privateKey } as ProofKeyReceipt,
            options,
          );
          prior = await readFile(file, "utf8");
        },
      );
      await assert.rejects(flow, (error: Error) => !error.message.includes(privateKey));
      const after = await readFile(file, "utf8");
      assert.equal(after, prior, `${stage}/${fault} keeps the exact previous receipt`);
      assert.equal(
        JSON.parse(after).stage,
        stage === "registered" ? "registration-started" : "registered",
      );
      assert(!after.includes(privateKey));
      assert.equal(uploads, 0);
      assert.deepEqual(await readdir(directory), ["receipt.json"]);
    }
  }
  const directory = scratchDirectory("e3-proof-receipt-ok-", t);
  const file = path.join(directory, "receipt.json");
  let privateKey = "";
  await withProofCommandKey(
    async (key) => {
      privateKey = key.secret();
      key.metadata.proofReplyBytes = 1000;
      key.metadata.proofReplyLimit = 65536;
    },
    async (_key, beforeUpload) => {
      await beforeUpload();
    },
    async (receipt) =>
      writeProofKeyReceipt(file, { ...receipt, unexpected: privateKey } as ProofKeyReceipt),
  );
  const completed = await readFile(file, "utf8");
  assert.equal(JSON.parse(completed).stage, "uploaded");
  assert(!completed.includes(privateKey));
  const invalid = {
    ...JSON.parse(completed),
    binding: "synthetic-private-sentinel",
  } as ProofKeyReceipt;
  await assert.rejects(
    writeProofKeyReceipt(file, invalid),
    (error: Error) => !error.message.includes("synthetic-private-sentinel"),
  );
  assert.equal(await readFile(file, "utf8"), completed);
  assert.deepEqual(await readdir(directory), ["receipt.json"]);
});

test("registration failure never uploads, unknown upload is not retried, and caller errors are sanitized", async () => {
  const stages: ProofKeyReceipt[] = [];
  let publishes = 0;
  let sentinel = "";
  await assert.rejects(
    withProofCommandKey(
      async (key) => {
        sentinel = key.secret();
        throw new Error(sentinel);
      },
      async () => {
        publishes++;
      },
      async (receipt) => {
        stages.push(receipt);
      },
    ),
    (error: Error) =>
      /could not be verified/u.test(error.message) && !error.message.includes(sentinel),
  );
  assert.equal(publishes, 0);
  assert.equal(stages.at(-1)?.stage, "registration-started");
  let registrations = 0;
  await assert.rejects(
    withProofCommandKey(
      async () => {
        registrations++;
      },
      async (_key, beforeUpload) => {
        publishes++;
        await beforeUpload();
        throw new Error("unknown");
      },
      async () => {},
    ),
  );
  assert.equal(registrations, 1);
  assert.equal(publishes, 1);
});

test("sensitive child output, failure text and oversized JSON never escape to parent logs", () => {
  const sentinel = "synthetic-private-sentinel-3c7";
  const moduleUrl = new URL("../../tooling/sensitive-process.ts", import.meta.url).href;
  const child = `
    import { runSensitive } from ${JSON.stringify(moduleUrl)};
    const command = "process.stdout.write(process.env.SENTINEL); process.stderr.write(process.env.SENTINEL); process.exit(7)";
    try { await runSensitive("upload", process.execPath, ["-e", command], process.env, "discard"); }
    catch (error) { console.log(error.message); }
  `;
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", child], {
    env: { ...process.env, SENTINEL: sentinel },
    encoding: "utf8",
  });
  assert.equal(result.status, 0);
  assert.doesNotMatch(result.stdout + result.stderr, new RegExp(sentinel, "u"));
  assert.match(result.stdout, /outcome may be unknown/u);
});

test("sensitive JSON reader enforces a fixed memory bound and reports only a fixed error", async () => {
  await assert.rejects(
    runSensitive(
      "registration",
      process.execPath,
      [
        "-e",
        "process.stdout.write('x'.repeat(131072)); process.stderr.write(process.env.SENTINEL)",
      ],
      { ...process.env, SENTINEL: "synthetic-private-sentinel" },
      "json",
    ),
    (error: Error) =>
      /outcome may be unknown/u.test(error.message) &&
      !error.message.includes("synthetic-private-sentinel"),
  );
});

test(
  "a timed-out sensitive child and inherited-pipe descendant cannot hold the secret file open",
  { skip: process.platform !== "linux" && "Linux process-group semantics", timeout: 8000 },
  async (t) => {
    const directory = scratchDirectory("e3-sensitive-deadline-", t);
    const pidsFile = path.join(directory, "owned-pids.json");
    const sentinel = "synthetic-deadline-secret";
    let secretFile = "";
    const descendant = `process.on("SIGTERM", () => {}); setInterval(() => {}, 1000);`;
    const child = `
      import { spawn } from "node:child_process";
      import { readFileSync, writeFileSync } from "node:fs";
      process.on("SIGTERM", () => {});
      const descendant = spawn(process.execPath, ["-e", process.env.DESCENDANT], { stdio: "inherit" });
      const identity = (pid) => { const stat = readFileSync('/proc/'+pid+'/stat', 'utf8'); return {pid, start:stat.slice(stat.lastIndexOf(')')+2).split(' ')[19]}; };
      writeFileSync(process.env.PIDS, JSON.stringify([identity(process.pid), identity(descendant.pid)]));
      process.stdout.write(process.env.SENTINEL);
      process.stderr.write(process.env.SENTINEL);
      setInterval(() => {}, 1000);
    `;
    const started = Date.now();
    const flow = withNeonRuntimeSecret({ synthetic: sentinel }, async (args) => {
      secretFile = args[1] as string;
      await runSensitive(
        "upload",
        process.execPath,
        ["--input-type=module", "-e", child],
        { ...process.env, PIDS: pidsFile, DESCENDANT: descendant, SENTINEL: sentinel },
        "discard",
        { deadlineMs: 1000, killGraceMs: 100 },
      );
    }).then(
      () => ({ kind: "success", message: "" }),
      (error: Error) => ({ kind: "error", message: error.message }),
    );
    let guardTimer: ReturnType<typeof setTimeout> | undefined;
    const guard = new Promise<{ kind: string; message: string }>((resolve) => {
      guardTimer = setTimeout(() => resolve({ kind: "timeout", message: "" }), 3000);
    });
    const outcome = await Promise.race([flow, guard]);
    clearTimeout(guardTimer);
    const identities = JSON.parse(await readFile(pidsFile, "utf8")) as {
      pid: number;
      start: string;
    }[];
    const current = async ({ pid, start }: { pid: number; start: string }) => {
      const stat = await readFile(`/proc/${pid}/stat`, "utf8").catch(() => "");
      if (!stat) return { same: false, zombie: false };
      const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
      return { same: fields[19] === start, zombie: fields[0] === "Z" };
    };
    if (outcome.kind === "timeout") {
      // Only kill a still-running PID with the exact start identity created by this test.
      for (const identity of identities) {
        const state = await current(identity);
        if (state.same && !state.zombie)
          try {
            process.kill(identity.pid, "SIGKILL");
          } catch {
            /* already gone */
          }
      }
      await flow;
    }
    assert.equal(outcome.kind, "error", "the protected flow must settle on its deadline");
    assert(Date.now() - started < 3000);
    assert(!outcome.message.includes(sentinel));
    assert.match(outcome.message, /outcome may be unknown/u);
    await assert.rejects(access(secretFile));
    for (const identity of identities) {
      let stopped = false;
      for (let attempt = 0; attempt < 100; attempt++) {
        const state = await current(identity);
        if (!state.same || state.zombie) {
          stopped = true;
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      assert(stopped, `owned child ${identity.pid} still runs after the bounded termination wait`);
    }
  },
);

test(
  "a protected child deadline bounds cleanup on each supported host",
  { timeout: 8000 },
  async (t) => {
    const directory = scratchDirectory("e3-sensitive-direct-", t);
    const pidFile = path.join(directory, "pid");
    const sentinel = "synthetic-direct-deadline-secret";
    let secretFile = "";
    const child = `require("node:fs").writeFileSync(process.env.OWNED_PID, String(process.pid)); process.stderr.write(process.env.SENTINEL); setInterval(() => {}, 1000);`;
    const flow = withNeonRuntimeSecret({ synthetic: sentinel }, async (args) => {
      secretFile = args[1] as string;
      await runSensitive(
        "upload",
        process.execPath,
        ["-e", child],
        { ...process.env, OWNED_PID: pidFile, SENTINEL: sentinel },
        "discard",
        { deadlineMs: 1000, killGraceMs: 200 },
      );
    }).then(
      () => ({ kind: "success", message: "" }),
      (error: Error) => ({ kind: "error", message: error.message }),
    );
    let guardTimer: ReturnType<typeof setTimeout> | undefined;
    const guard = new Promise<{ kind: string; message: string }>((resolve) => {
      guardTimer = setTimeout(() => resolve({ kind: "timeout", message: "" }), 4000);
    });
    const outcome = await Promise.race([flow, guard]);
    clearTimeout(guardTimer);
    if (outcome.kind === "timeout") {
      const pid = Number(await readFile(pidFile, "utf8"));
      try {
        process.kill(pid, "SIGKILL");
      } catch {
        /* our child already exited */
      }
      await flow;
    }
    assert.equal(outcome.kind, "error");
    assert.match(outcome.message, /outcome may be unknown/u);
    assert(!outcome.message.includes(sentinel));
    await assert.rejects(access(secretFile));
  },
);

test("proof live-version reader validates every traffic share and label before choosing a slot", async () => {
  const a = "11111111-1111-1111-1111-111111111111";
  const b = "22222222-2222-2222-2222-222222222222";
  const secret = "synthetic-provider-secret";
  type Version = { version_id?: unknown; percentage?: unknown };
  const run = async (versions: Version[], messages: Record<string, unknown>) => {
    const calls: string[][] = [];
    const result = await readProofLiveSlots(
      async (args) => {
        calls.push(args);
        if (args[0] === "deployments") return JSON.stringify({ versions });
        const id = args[2] as string;
        if (messages[id] === secret) throw new Error(secret);
        return JSON.stringify({ annotations: { "workers/message": messages[id] } });
      },
      ["--env", "proof"],
    );
    return { result, calls };
  };
  const single = await run([{ version_id: a, percentage: 100 }], { [a]: "runtime-slot=a" });
  assert.deepEqual(single.result, { labelled: ["a"], unlabelled: 0 });
  assert.deepEqual(single.calls, [
    ["deployments", "status", "--json", "--env", "proof"],
    ["versions", "view", a, "--json", "--env", "proof"],
  ]);
  assert.deepEqual(
    (
      await run(
        [
          { version_id: a, percentage: 30 },
          { version_id: b, percentage: 70 },
        ],
        { [a]: "runtime-slot=b", [b]: "other runtime-slot=b proof-command-key=public" },
      )
    ).result,
    { labelled: ["b", "b"], unlabelled: 0 },
  );
  const badCases: [Version[], Record<string, unknown>][] = [
    [[], {}],
    [
      [
        { version_id: a, percentage: 100 },
        { version_id: b, percentage: "unknown" },
      ],
      { [a]: "runtime-slot=a" },
    ],
    [
      [
        { version_id: a, percentage: 100 },
        { version_id: b, percentage: null },
      ],
      { [a]: "runtime-slot=a" },
    ],
    [
      [
        { version_id: a, percentage: -1 },
        { version_id: b, percentage: 101 },
      ],
      {},
    ],
    [[{ version_id: a, percentage: 99 }], {}],
    [
      [
        { version_id: "bad", percentage: 0 },
        { version_id: a, percentage: 100 },
      ],
      {},
    ],
    [
      [
        { version_id: a, percentage: 0 },
        { version_id: a, percentage: 100 },
      ],
      {},
    ],
    [[{ version_id: a, percentage: 100 }], { [a]: "" }],
    [[{ version_id: a, percentage: 100 }], { [a]: "runtime-slot=a runtime-slot=a" }],
    [[{ version_id: a, percentage: 100 }], { [a]: secret }],
    [
      [
        { version_id: a, percentage: 50 },
        { version_id: b, percentage: 50 },
      ],
      { [a]: "runtime-slot=a", [b]: "runtime-slot=b" },
    ],
  ];
  for (const [versions, messages] of badCases) {
    await assert.rejects(
      run(versions, messages),
      (error: Error) =>
        /unavailable or ambiguous/u.test(error.message) && !error.message.includes(secret),
    );
  }
});

test("protected candidate orchestration narrows every child environment and verifies identity before a push", async () => {
  const account = "0".repeat(32),
    revision = "a".repeat(40),
    id = `sha256:${"b".repeat(64)}`;
  const candidate = {
    revision,
    dirty: false,
    image: "arcforges-cloud:0.1.0-ci.123.1",
    imageId: id,
    version: "0.1.0-ci.123.1",
  };
  const digest = `registry.cloudflare.com/${account}/arcforges-cloud@sha256:${"c".repeat(64)}`;
  const environment = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    ...dispatchContext(revision),
    GH_TOKEN: "synthetic-gh-token",
    CLOUDFLARE_API_TOKEN: "synthetic-cf-token",
    CLOUDFLARE_ACCOUNT_ID: account,
    NEON_DATABASE_URL_DIRECT: "synthetic-neon-url",
    PROOF_BOOTSTRAP_SHA256: "synthetic-bootstrap",
    NODE_OPTIONS: "synthetic-node-options",
  };
  const calls: string[] = [];
  const run: typeof runSensitive = async (stage, command, args, childEnv, mode) => {
    const step =
      stage === "image" && args[0] === "load"
        ? "load"
        : stage === "image" && args[2] === candidate.image
          ? "inspect"
          : stage === "image"
            ? "digest"
            : stage;
    calls.push(step);
    assert.equal(childEnv.NEON_DATABASE_URL_DIRECT, undefined);
    assert.equal(childEnv.PROOF_BOOTSTRAP_SHA256, undefined);
    assert.equal(childEnv.NODE_OPTIONS, undefined);
    assert.equal(childEnv.GH_TOKEN, stage === "head" ? environment.GH_TOKEN : undefined);
    assert.equal(
      childEnv.CLOUDFLARE_API_TOKEN,
      stage === "push" ? environment.CLOUDFLARE_API_TOKEN : undefined,
    );
    if (stage === "candidate") {
      assert.equal(childEnv.GITHUB_ACTIONS, "true");
      assert.equal(childEnv.ARCFORGES_CANDIDATE_RUN_ID, "88");
      assert.equal(command, process.execPath);
      assert.equal(mode, "json");
      return candidate;
    }
    if (stage === "head") {
      assert.equal(command, "gh");
      return { sha: revision };
    }
    if (step === "load") {
      assert.equal(mode, "discard");
      return undefined;
    }
    if (step === "inspect") return id;
    if (step === "digest") return [digest];
    if (stage === "push") {
      assert.equal(mode, "discard");
      return undefined;
    }
    throw new Error("unexpected stage");
  };
  const result = await prepareProofCandidate(
    account,
    async (value) => {
      calls.push("gate");
      assert.equal(value, revision);
    },
    { environment, run },
  );
  assert.deepEqual(result, { candidate, imageDigest: digest });
  assert.deepEqual(calls, ["candidate", "head", "gate", "load", "inspect", "push", "digest"]);

  for (const bad of ["candidate", "head", "gate", "load", "inspect", "push", "digest"] as const) {
    const observed: string[] = [];
    const broken: typeof runSensitive = async (stage, command, args, childEnv, mode) => {
      const step =
        stage === "image" && args[0] === "load"
          ? "load"
          : stage === "image" && args[2] === candidate.image
            ? "inspect"
            : stage === "image"
              ? "digest"
              : stage;
      observed.push(step);
      if (step === bad) {
        if (bad === "candidate") return { ...candidate, revision: "synthetic-private-sentinel" };
        if (bad === "head") return { sha: "synthetic-private-sentinel" };
        if (bad === "inspect") return "synthetic-private-sentinel";
        if (bad === "digest") return ["synthetic-private-sentinel"];
        throw new Error("synthetic-private-sentinel");
      }
      return run(stage, command, args, childEnv, mode);
    };
    await assert.rejects(
      prepareProofCandidate(
        account,
        async () => {
          observed.push("gate");
          if (bad === "gate") throw new Error("synthetic-private-sentinel");
        },
        { environment, run: broken },
      ),
      (error: Error) => !error.message.includes("synthetic-private-sentinel"),
    );
    if (["candidate", "head", "gate", "load", "inspect"].includes(bad))
      assert(!observed.includes("push"));
  }
});

test(
  "the protected dispatch child verifies a main-push producer identity with the real source identity code",
  { timeout: 60000 },
  async (t) => {
    const scratch = scratchDirectory("e3-ci-identity-", t);
    const repository = path.join(scratch, "repository");
    mkdirSync(repository);
    const sourceRoot = path.resolve(import.meta.dirname, "../..");
    for (const name of [
      "tooling/build-identity.ts",
      "tooling/process.ts",
      "eng/version-sources.json",
      "eng/generated/contracts-identity.json",
      "Directory.Packages.props",
      "src/ArcForges.Cloud/packages.lock.json",
      "package-lock.json",
    ]) {
      const target = path.join(repository, name);
      mkdirSync(path.dirname(target), { recursive: true });
      copyFileSync(path.join(sourceRoot, name), target);
    }
    writeFileSync(path.join(repository, "package.json"), '{"type":"module"}\n');
    const hooks = path.join(scratch, "empty-hooks");
    mkdirSync(hooks);
    const gitEnv = proofProcessEnvironment(process.env);
    const git = (...args: string[]) =>
      execFileSync(
        "git",
        ["-c", `core.hooksPath=${hooks}`, "-c", "commit.gpgSign=false", ...args],
        { cwd: repository, env: gitEnv, encoding: "utf8", windowsHide: true },
      ).trim();
    git("init", "--quiet");
    git("add", ".");
    git(
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.test",
      "commit",
      "--quiet",
      "-m",
      "synthetic identity fixture",
    );
    const commit = git("rev-parse", "HEAD");
    const moduleUrl = pathToFileURL(path.join(repository, "tooling/build-identity.ts")).href;
    const version = "0.1.0-ci.547.2";
    const pushEnvironment = {
      ...gitEnv,
      GITHUB_ACTIONS: "true",
      GITHUB_REPOSITORY: "ArcForges/Cloud",
      GITHUB_SHA: commit,
      GITHUB_EVENT_NAME: "push",
      GITHUB_RUN_ID: "88",
      GITHUB_RUN_NUMBER: "547",
      GITHUB_RUN_ATTEMPT: "2",
    };
    const produce = `import {expectedIdentity} from ${JSON.stringify(moduleUrl)};process.stdout.write(JSON.stringify(expectedIdentity(${JSON.stringify(version)})));`;
    const created = spawnSync(process.execPath, ["--input-type=module", "-e", produce], {
      cwd: repository,
      env: pushEnvironment,
      encoding: "utf8",
      windowsHide: true,
      timeout: 30000,
    });
    assert.equal(created.status, 0, "synthetic main-push identity must be produced");
    const identity = JSON.parse(created.stdout) as { build: { buildId: string } };
    assert.equal(identity.build.buildId, "88.2");
    const identityPath = path.join(scratch, "synthetic-main-push-identity.json");
    writeFileSync(identityPath, JSON.stringify(identity));
    const eventPath = path.join(scratch, "event.json");
    writeFileSync(eventPath, "{}\n");
    const account = "0".repeat(32),
      imageId = `sha256:${"b".repeat(64)}`;
    const candidate = {
      revision: commit,
      dirty: false,
      image: "arcforges-cloud:0.1.0-ci.547.2",
      imageId,
      version,
    };
    const digest = `registry.cloudflare.com/${account}/arcforges-cloud@sha256:${"c".repeat(64)}`;
    const sentinel = "synthetic-ci-secret-sentinel";
    const dispatch = {
      ...gitEnv,
      GITHUB_ACTIONS: "true",
      GITHUB_REPOSITORY: "ArcForges/Cloud",
      GITHUB_SHA: commit,
      GITHUB_EVENT_NAME: "workflow_dispatch",
      GITHUB_EVENT_PATH: eventPath,
      GITHUB_RUN_ID: "999",
      GITHUB_RUN_NUMBER: "560",
      GITHUB_RUN_ATTEMPT: "1",
      ARCFORGES_CANDIDATE_RUN_ID: "88",
      ARCFORGES_CANDIDATE_RUN_NUMBER: "547",
      ARCFORGES_CANDIDATE_RUN_ATTEMPT: "2",
      GH_TOKEN: sentinel,
      GITHUB_TOKEN: sentinel,
      CLOUDFLARE_API_TOKEN: sentinel,
      NEON_DATABASE_URL_DIRECT: sentinel,
      NEON_DATABASE_URL: sentinel,
      PROOF_BOOTSTRAP_SHA256: sentinel,
      PROOF_BOOTSTRAP_EXPIRES_AT: sentinel,
      NODE_OPTIONS: sentinel,
    };
    const check = `import {readFileSync} from 'node:fs';import {verifyIdentity} from ${JSON.stringify(moduleUrl)};
    for(const name of ['GH_TOKEN','GITHUB_TOKEN','CLOUDFLARE_API_TOKEN','NEON_DATABASE_URL_DIRECT','NEON_DATABASE_URL','PROOF_BOOTSTRAP_SHA256','PROOF_BOOTSTRAP_EXPIRES_AT','NODE_OPTIONS'])
      if(process.env[name]!==undefined)throw new Error('unexpected secret environment');
    JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH,'utf8'));
    verifyIdentity(JSON.parse(readFileSync(process.argv[1],'utf8')),process.argv[2]);
    process.stdout.write(JSON.stringify(${JSON.stringify(candidate)}));`;
    const observed: string[] = [];
    const fakeRunner: typeof runSensitive = async (stage, command, args, childEnv, mode) => {
      observed.push(stage);
      if (stage === "candidate")
        return runSensitive(
          stage,
          process.execPath,
          ["--input-type=module", "-e", check, identityPath, version],
          childEnv,
          mode,
        );
      if (stage === "head") return { sha: commit };
      if (stage === "image" && args[0] === "load") return undefined;
      if (stage === "image" && args[2] === candidate.image) return imageId;
      if (stage === "image") return [digest];
      if (stage === "push") return undefined;
      throw new Error(`unexpected synthetic stage ${command}`);
    };
    const verify = (environment: NodeJS.ProcessEnv) =>
      prepareProofCandidate(
        account,
        async (revision) => {
          assert.equal(revision, commit);
        },
        { environment, run: fakeRunner },
      );
    assert.deepEqual(await verify(dispatch), { candidate, imageDigest: digest });
    // A later retry of the same producer run may legitimately consume an earlier candidate attempt.
    assert.deepEqual(await verify({ ...dispatch, ARCFORGES_CANDIDATE_RUN_ATTEMPT: "3" }), {
      candidate,
      imageDigest: digest,
    });
    for (const name of [
      "GITHUB_ACTIONS",
      "GITHUB_REPOSITORY",
      "GITHUB_SHA",
      "GITHUB_EVENT_NAME",
      "GITHUB_EVENT_PATH",
      "GITHUB_RUN_ID",
      "GITHUB_RUN_NUMBER",
      "GITHUB_RUN_ATTEMPT",
      "ARCFORGES_CANDIDATE_RUN_ID",
      "ARCFORGES_CANDIDATE_RUN_NUMBER",
      "ARCFORGES_CANDIDATE_RUN_ATTEMPT",
    ] as const) {
      const badValues =
        name === "GITHUB_EVENT_PATH"
          ? [undefined, "", path.join(scratch, "missing-event.json")]
          : [undefined, "", sentinel];
      for (const bad of badValues) {
        observed.length = 0;
        await assert.rejects(
          verify({ ...dispatch, [name]: bad }),
          (error: Error) => !error.message.includes(sentinel),
          name,
        );
        assert(!observed.includes("head") && !observed.includes("push"), name);
      }
    }
    for (const name of [
      "GITHUB_RUN_ID",
      "GITHUB_RUN_NUMBER",
      "GITHUB_RUN_ATTEMPT",
      "ARCFORGES_CANDIDATE_RUN_ID",
      "ARCFORGES_CANDIDATE_RUN_NUMBER",
      "ARCFORGES_CANDIDATE_RUN_ATTEMPT",
    ] as const) {
      for (const bad of ["0", "-1", "1.0", "01", "1e3", "1".repeat(17)]) {
        observed.length = 0;
        await assert.rejects(verify({ ...dispatch, [name]: bad }));
        assert.deepEqual(observed, [], `invalid ${name} must fail before any child`);
      }
    }
    for (const change of [
      { GITHUB_SHA: "a".repeat(40) },
      { GITHUB_REPOSITORY: "Other/Repo" },
      { GITHUB_EVENT_NAME: "push" },
      { ARCFORGES_CANDIDATE_RUN_ID: "89" },
      { ARCFORGES_CANDIDATE_RUN_NUMBER: "548" },
      { ARCFORGES_CANDIDATE_RUN_ATTEMPT: "1" },
    ]) {
      observed.length = 0;
      await assert.rejects(verify({ ...dispatch, ...change }));
      assert(!observed.includes("head") && !observed.includes("push"));
    }
    const wrongIdentity = structuredClone(identity);
    wrongIdentity.build.buildId = "89.2";
    writeFileSync(identityPath, JSON.stringify(wrongIdentity));
    observed.length = 0;
    await assert.rejects(verify(dispatch));
    assert(!observed.includes("head") && !observed.includes("push"));
  },
);

test("protected candidate subprocess output and provider error sentinels are never printed", () => {
  const sentinel = "synthetic-proof-child-secret-47";
  const moduleUrl = new URL("../../tooling/proof-candidate.ts", import.meta.url).href;
  const runnerUrl = new URL("../../tooling/sensitive-process.ts", import.meta.url).href;
  const script = `
    import { prepareProofCandidate } from ${JSON.stringify(moduleUrl)};
    import { runSensitive } from ${JSON.stringify(runnerUrl)};
    const account="0".repeat(32), revision="a".repeat(40), imageId="sha256:"+"b".repeat(64);
    const candidate={revision,dirty:false,image:"arcforges-cloud:0.1.0-ci.123.1",imageId,version:"0.1.0-ci.123.1"};
    const digest="registry.cloudflare.com/"+account+"/arcforges-cloud@sha256:"+"c".repeat(64);
    const environment={...process.env,GH_TOKEN:process.env.SYNTHETIC, CLOUDFLARE_API_TOKEN:process.env.SYNTHETIC,
      CLOUDFLARE_ACCOUNT_ID:account,NEON_DATABASE_URL_DIRECT:process.env.SYNTHETIC,
      GITHUB_ACTIONS:"true",GITHUB_REPOSITORY:"ArcForges/Cloud",GITHUB_SHA:revision,GITHUB_EVENT_NAME:"workflow_dispatch",
      GITHUB_EVENT_PATH:"/synthetic/event.json",GITHUB_RUN_ID:"999",GITHUB_RUN_NUMBER:"560",GITHUB_RUN_ATTEMPT:"1",
      ARCFORGES_CANDIDATE_RUN_ID:"88",ARCFORGES_CANDIDATE_RUN_NUMBER:"123",ARCFORGES_CANDIDATE_RUN_ATTEMPT:"1"};
    let inspections=0;
    const run=async(stage,_command,args,env,mode)=>{
      const value=stage==="candidate"?candidate:stage==="head"?{sha:revision}:
        stage==="image"&&args[0]!=="load"?(inspections++===0?imageId:[digest]):undefined;
      const child='process.stderr.write(process.env.GH_TOKEN || process.env.CLOUDFLARE_API_TOKEN || "");'+
        (mode==="json"?'process.stdout.write(process.env.REPLY)':'process.stdout.write(process.env.CLOUDFLARE_API_TOKEN || "")');
      return runSensitive(stage,process.execPath,["-e",child],{...env,REPLY:JSON.stringify(value)},mode);
    };
    const result=await prepareProofCandidate(account,async()=>{},{environment,run});
    console.log(result.candidate.revision.length);
  `;
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    env: { ...process.env, SYNTHETIC: sentinel },
    encoding: "utf8",
    timeout: 15_000,
  });
  assert.equal(result.status, 0);
  assert.doesNotMatch(result.stdout + result.stderr, new RegExp(sentinel, "u"));
  assert.match(result.stdout, /40/u);
});

test("candidate preparation refuses oversized and failed real child output without advancing", async () => {
  const environment = {
    ...process.env,
    ...dispatchContext("a".repeat(40)),
    GH_TOKEN: "synthetic-gh",
    CLOUDFLARE_API_TOKEN: "synthetic-cf",
  };
  for (const kind of ["oversized", "failure"] as const) {
    let calls = 0;
    const run: typeof runSensitive = async (stage, _command, _args, env, mode) => {
      calls++;
      const code =
        kind === "oversized"
          ? "process.stdout.write('x'.repeat(131072)); process.stderr.write('synthetic-private-sentinel')"
          : "process.stderr.write('synthetic-private-sentinel'); process.exit(7)";
      return runSensitive(stage, process.execPath, ["-e", code], env, mode);
    };
    await assert.rejects(
      prepareProofCandidate(
        "0".repeat(32),
        async () => {
          throw new Error("gate should not run");
        },
        { environment, run },
      ),
      (error: Error) => !error.message.includes("synthetic-private-sentinel"),
    );
    assert.equal(calls, 1);
  }
});

test("protected runtime forwards only the database alias and necessary environment", async () => {
  const runner = proofRuntimeRunner(
    async (_stage, _command, _args, environment) => {
      assert.equal(environment.ARCFORGES_CENTER_MIGRATION_DATABASE_URL, migration);
      assert.equal(environment.NEON_DATABASE_URL_DIRECT, undefined);
      assert.equal(environment.GH_TOKEN, undefined);
      assert.equal(environment.CLOUDFLARE_API_TOKEN, undefined);
      return { ok: true };
    },
    {
      PATH: process.env.PATH,
      GH_TOKEN: "synthetic-gh",
      CLOUDFLARE_API_TOKEN: "synthetic-cf",
      NEON_DATABASE_URL_DIRECT: migration,
    },
  );
  assert.deepEqual(
    await runner("sealed", { ARCFORGES_CENTER_MIGRATION_DATABASE_URL: migration }, [
      "admin",
      "inspect",
    ]),
    { ok: true },
  );
});

test("proof slot preflight refuses missing, unreadable, mixed and unlabelled live versions", () => {
  assert.deepEqual(requireKnownProofSlots({ labelled: ["a"], unlabelled: 0 }), {
    labelled: ["a"],
    unlabelled: 0,
  });
  for (const live of [
    { labelled: [], unlabelled: 0, unreadable: "synthetic-provider-secret" },
    { labelled: [], unlabelled: 0 },
    { labelled: ["a" as const], unlabelled: 1 },
    { labelled: ["a" as const, "b" as const], unlabelled: 0 },
  ]) {
    assert.throws(
      () => requireKnownProofSlots(live),
      (error: Error) =>
        /unavailable or ambiguous/u.test(error.message) &&
        !error.message.includes("synthetic-provider-secret"),
    );
  }
});

test("proof runtime runner hides child errors and preserves the existing unknown-slot exit code", async () => {
  const runner = proofRuntimeRunner(async () => {
    throw new SensitiveProcessError("runtime", 4);
  });
  await assert.rejects(
    runner("image", {}, ["admin", "confirm-runtime-credential"]),
    (error: Error) =>
      error instanceof CenterExit &&
      error.status === 4 &&
      /Protected proof runtime/u.test(error.message),
  );
  const bad = proofRuntimeRunner(async () => {
    throw new Error("synthetic-runtime-secret");
  });
  await assert.rejects(
    bad("image", {}, ["admin", "rotate-runtime-credential"]),
    (error: Error) =>
      error instanceof CenterExit &&
      error.status === null &&
      !error.message.includes("synthetic-runtime-secret"),
  );
});

test("only validated public runtime fields reach the proof receipt", () => {
  const rotation = {
    database: "arcforges_acceptance",
    runtimeRole: "arcforges_acceptance_runtime",
    loginRole: "arcforges_acceptance_runtime_a",
    slot: "a",
    passwordForm: ["scram", "sha", "256", "verifier"].join("-"),
    serverVersionNum: 180000,
    slotSource: "live-version",
    logging: { arbitrary: "synthetic-private-sentinel" },
    probe: {
      pooledEndpoint: true,
      connectsUnpooled: true,
      connectedAsLoginRole: true,
      readsGrantedTable: true,
      cannotCreateTables: true,
      cannotReadUngrantedTables: true,
      cannotCreateTemporaryTables: true,
      extra: "synthetic-private-sentinel",
    },
    unexpected: "synthetic-private-sentinel",
  };
  assert(!JSON.stringify(proofRotationReceipt(rotation)).includes("synthetic-private-sentinel"));
  for (const changed of [
    { slot: "synthetic-private-sentinel" },
    { database: "synthetic-private-sentinel" },
    { loginRole: "arcforges_acceptance_runtime_b" },
    { passwordForm: "synthetic-private-sentinel" },
    { serverVersionNum: "synthetic-private-sentinel" },
    { slotSource: "record" },
    { probe: { ...rotation.probe, cannotCreateTables: false } },
  ]) {
    assert.throws(
      () => proofRotationReceipt({ ...rotation, ...changed }),
      (error: Error) =>
        /invalid public metadata/u.test(error.message) &&
        !error.message.includes("synthetic-private-sentinel"),
    );
  }
});
