// SPDX-License-Identifier: AGPL-3.0-only
// E3 uses synthetic keys and mocked provider/registry calls. No owner key, account or provider is contacted.
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { access, readFile, stat } from "node:fs/promises";
import { spawnSync } from "node:child_process";
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
  type ProofKeyReceipt,
} from "../../tooling/proof-command-key.ts";
import { withNeonRuntimeSecret } from "../../tooling/neon-runtime.ts";
import { runSensitive, SensitiveProcessError } from "../../tooling/sensitive-process.ts";
import { CenterExit } from "../../tooling/postgres-deploy.ts";

const migration = "postgres://synthetic:synthetic-password@example.test/database";
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
    environment: { NEON_DATABASE_URL_DIRECT: migration },
    run: async (stage, command, args, env, output) => {
      stages.push(stage);
      assert.equal(command, "docker");
      assert.equal(output, "json");
      assert.equal(env.ARCFORGES_CENTER_MIGRATION_DATABASE_URL, migration);
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
