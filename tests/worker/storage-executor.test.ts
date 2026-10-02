// SPDX-License-Identifier: AGPL-3.0-only
// Argument validation, exactness, deadline and failure mapping of the named-plan executor.
import assert from "node:assert/strict";
import test from "node:test";
import type { D1Like, D1PreparedStatement, D1RunResult } from "../../worker/storage/d1.ts";
import { classifyError, parseDeadline } from "../../worker/storage/execute-plan.ts";
import { manifestHash } from "../../worker/storage/plans.generated.ts";
import { createSqliteD1 } from "./support/sqlite-d1.ts";
import {
  bytes,
  deadline,
  dec,
  i64,
  nul,
  planRequest,
  run,
  sc,
  txt,
  u64,
  uuid,
} from "./support/plan-calls.ts";
import { executePlan } from "../../worker/storage/execute-plan.ts";
import { depsFor } from "./support/plan-calls.ts";

const load = [[sc(), txt("x")]];

test("unknown plans, versions and manifest mismatches are invalid and run nothing", async () => {
  const db = createSqliteD1();
  assert.deepEqual(await run(db, "foundation.nope", load), { ok: false, failure: "invalidPlan" });
  assert.deepEqual(await run(db, "foundation.account-load", load, { planVersion: 2 }), {
    ok: false,
    failure: "invalidPlan",
  });
  const flipped = `${manifestHash.slice(0, 63)}${manifestHash.endsWith("0") ? "1" : "0"}`;
  assert.deepEqual(await run(db, "foundation.account-load", load, { manifestHash: flipped }), {
    ok: false,
    failure: "invalidPlan",
  });
});

test("a stale recovery generation is refused before any SQL", async () => {
  const db = createSqliteD1();
  assert.deepEqual(await run(db, "foundation.account-load", load, { recoveryGeneration: "1" }), {
    ok: false,
    failure: "staleGeneration",
  });
  assert.deepEqual(
    await run(
      db,
      "foundation.account-load",
      load,
      { recoveryGeneration: "7" },
      { recoveryGeneration: "7" },
    ),
    { ok: true, rows: [], changes: "0" },
  );
});

test("the argument arrays must match the plan statement by statement, kind by kind", async () => {
  const db = createSqliteD1();
  const cases: [string, ReturnType<typeof sc>[][]][] = [
    ["no statements", []],
    ["extra statement", [[sc(), txt("x")], []]],
    ["missing argument", [[sc()]]],
    ["extra argument", [[sc(), txt("x"), txt("y")]]],
    ["wrong kind", [[sc(), i64("1")]]],
    ["null for a non-nullable parameter", [[sc(), nul()]]],
    ["text where scope is declared with another value", [[txt("proof/other"), txt("x")]]],
  ];
  for (const [label, args] of cases)
    assert.deepEqual(
      await run(db, "foundation.account-load", args),
      { ok: false, failure: "invalidPlan" },
      label,
    );
});

test("every exact kind refuses malformed or out-of-range values", async () => {
  const db = createSqliteD1();
  const store = (
    signed: ReturnType<typeof i64>,
    unsigned: ReturnType<typeof u64>,
    decimal: ReturnType<typeof dec>,
    payload = nul(),
  ) => [
    [txt(uuid()), sc(), txt("x"), i64("0")],
    [sc(), txt("x"), signed, unsigned, decimal, payload, i64("0")],
    [sc(), txt(uuid()), txt("h"), txt("{}")],
    [txt(uuid())],
  ];
  const refused = [
    store(i64("01"), u64("1"), dec("1")),
    store(i64("-0"), u64("1"), dec("1")),
    store(i64("1.5"), u64("1"), dec("1")),
    store(i64("+1"), u64("1"), dec("1")),
    store(i64("1"), u64("-1"), dec("1")),
    store(i64("1"), u64("1"), dec("1e3")),
    store(i64("1"), u64("1"), dec("1.0000000001")),
    store(i64("1"), u64("1"), dec("-0")),
    store(i64("1"), u64("1"), dec("12345678901234567890123456789")),
    store(i64("1"), u64("1"), dec("1"), { kind: "bytes", value: "AA==" }),
    store(i64("1"), u64("1"), dec("1"), { kind: "bytes", value: "AB" }),
    store(i64("1"), u64("1"), dec("1"), { kind: "bytes", value: "A" }),
    store(i64("1"), u64("1"), dec("1"), { kind: "bytes", value: "a+b/" }),
    store(i64("1"), u64("1"), dec("1"), { kind: "boolean", value: true } as never),
  ];
  for (const args of refused)
    assert.deepEqual(await run(db, "foundation.exact-store", args), {
      ok: false,
      failure: "invalidPlan",
    });
  assert.deepEqual(await db.prepare("SELECT COUNT(*) FROM probe_exact").raw(), [[0]]);
});

test("64-bit values reach D1 only as exact text and every binding is typed", async () => {
  const recorded: unknown[][] = [];
  const inner = createSqliteD1();
  const spy: D1Like = {
    prepare(sql) {
      const statement = inner.prepare(sql);
      return {
        bind(...values: unknown[]) {
          recorded.push(values);
          return statement.bind(...values);
        },
        raw: () => statement.raw(),
      } as D1PreparedStatement;
    },
    batch: (statements) => inner.batch(statements),
  };
  const result = await run(spy, "foundation.exact-store", [
    [txt("c1"), sc(), txt("x"), i64("0")],
    [
      sc(),
      txt("x"),
      i64("9223372036854775807"),
      u64("18446744073709551615"),
      dec("1.5"),
      bytes(Uint8Array.of(1, 2)),
      i64("0"),
    ],
    [sc(), txt("c1"), txt("h"), txt("{}")],
    [txt("c1")],
  ]);
  assert.equal(result.ok, true);
  const flat = recorded.flat();
  assert(
    !flat.some((value) => typeof value === "number" || typeof value === "bigint"),
    "no numeric binding",
  );
  assert(flat.includes("9223372036854775807"));
  assert(flat.includes("18446744073709551615"));
  assert(flat.some((value) => value instanceof ArrayBuffer && value.byteLength === 2));
});

test("a bind failure is an invalid plan, not an unhandled exception", async () => {
  const db: D1Like = {
    prepare: () => ({
      bind: () => {
        throw new Error("unsupported type");
      },
      raw: () => Promise.resolve([]),
    }),
    batch: () => Promise.resolve([]),
  };
  assert.deepEqual(await run(db, "foundation.account-load", load), {
    ok: false,
    failure: "invalidPlan",
  });
});

test("deadlines: parsing is exact, an expired one never reaches D1 and one too far ahead is refused", async () => {
  assert.equal(parseDeadline("2026-10-02T12:00:05.1234567Z"), Date.UTC(2026, 9, 2, 12, 0, 5, 123));
  assert.equal(parseDeadline("2026-10-02T12:00:05Z"), Date.UTC(2026, 9, 2, 12, 0, 5, 0));
  for (const text of [
    "2026-02-30T12:00:00Z",
    "2026-10-02T25:00:00Z",
    "2026-10-02 12:00:00Z",
    "2026-10-02T12:00:00+00:00",
  ])
    assert.equal(parseDeadline(text), null, text);
  let touched = false;
  const db: D1Like = {
    prepare: () => {
      touched = true;
      throw new Error("must not be called");
    },
    batch: () => Promise.reject(new Error("must not be called")),
  };
  assert.deepEqual(await run(db, "foundation.account-load", load, { deadlineUtc: deadline(0) }), {
    ok: false,
    failure: "unavailable",
  });
  assert.deepEqual(await run(db, "foundation.account-load", load, { deadlineUtc: deadline(-1) }), {
    ok: false,
    failure: "unavailable",
  });
  assert.deepEqual(
    await run(db, "foundation.account-load", load, { deadlineUtc: deadline(13_000) }),
    {
      ok: false,
      failure: "invalidPlan",
    },
  );
  assert.equal(touched, false);
  const ok = createSqliteD1();
  assert.equal(
    (await run(ok, "foundation.account-load", load, { deadlineUtc: deadline(11_999) })).ok,
    true,
  );
});

function writeRequest() {
  return planRequest("foundation.account-seed", [[sc(), txt("a"), i64("1")]]);
}

test("a write that outlives its deadline is an unknown outcome, never a safe failure", async () => {
  const db: D1Like = {
    prepare: () =>
      ({
        bind: () => ({}) as D1PreparedStatement,
        raw: () => Promise.resolve([]),
      }) as D1PreparedStatement,
    batch: () => new Promise<D1RunResult[]>(() => {}),
  };
  const started = Date.now();
  const response = await executePlan(
    {
      ...writeRequest(),
      deadlineUtc: new Date(Date.now() + 50).toISOString().replace(/Z$/u, "0000Z"),
    },
    depsFor(db, { nowMs: () => Date.now() }),
  );
  assert.equal("failure" in response && response.failure, "unknownOutcome");
  assert(Date.now() - started < 2_000);
});

test("a read that outlives its deadline is unavailable and has no effect to reconcile", async () => {
  const db: D1Like = {
    prepare: () =>
      ({
        bind: () =>
          ({ raw: () => new Promise<unknown[][]>(() => {}) }) as unknown as D1PreparedStatement,
      }) as unknown as D1PreparedStatement,
    batch: () => Promise.resolve([]),
  };
  const response = await executePlan(
    {
      ...planRequest("foundation.account-load", load),
      deadlineUtc: new Date(Date.now() + 50).toISOString().replace(/Z$/u, "0000Z"),
    },
    depsFor(db, { nowMs: () => Date.now() }),
  );
  assert.equal("failure" in response && response.failure, "unavailable");
});

test("provider errors map conservatively: constraints are definite, unknown write errors are unknown outcomes", () => {
  for (const [message, access, expected] of [
    ["CHECK constraint failed: af_guard_failed", "write", "precondition"],
    [
      "D1_ERROR: CHECK constraint failed: af_guard_failed: SQLITE_CONSTRAINT",
      "write",
      "precondition",
    ],
    ["UNIQUE constraint failed: probe_receipt.command_id", "write", "constraint"],
    ["FOREIGN KEY constraint failed", "write", "constraint"],
    ["CHECK constraint failed: balance >= 0", "write", "constraint"],
    ["cannot store REAL value in INTEGER column probe_account.balance", "write", "constraint"],
    ["NOT NULL constraint failed: probe_account.balance", "write", "constraint"],
    ["D1 DB is overloaded. Requests queued for too long.", "write", "overloaded"],
    ["Network connection lost", "write", "unknownOutcome"],
    ["something unexpected", "write", "unknownOutcome"],
    ["Network connection lost", "read", "unavailable"],
    ["something unexpected", "read", "unavailable"],
  ] as const)
    assert.equal(classifyError(new Error(message), access), expected, message);
  assert.equal(classifyError("text", "write"), "unknownOutcome");
});

test("a result that breaks the exact-value rules is a defect reported as unavailable, never as data", async () => {
  const returning = (row: unknown[]): D1Like => ({
    prepare: () =>
      ({
        bind: () => ({ raw: () => Promise.resolve([row]) }) as unknown as D1PreparedStatement,
      }) as unknown as D1PreparedStatement,
    batch: () => Promise.resolve([]),
  });
  // account-load returns two int64 text columns.
  for (const row of [
    [5, "1"],
    ["1", 2],
    ["9223372036854775808", "1"],
    ["1"],
    ["1", "1", "1"],
    [null, "1"],
    ["01", "1"],
  ])
    assert.deepEqual(
      await run(returning(row), "foundation.account-load", load),
      { ok: false, failure: "unavailable" },
      JSON.stringify(row),
    );
  assert.deepEqual(
    await run(returning(["9223372036854775807", "1"]), "foundation.account-load", load),
    {
      ok: true,
      rows: [["9223372036854775807", "1"]],
      changes: "0",
    },
  );
});

test("a read that returns more rows than its plan allows is overloaded", async () => {
  const db: D1Like = {
    prepare: () =>
      ({
        bind: () =>
          ({
            raw: () =>
              Promise.resolve([
                ["1", "1"],
                ["2", "2"],
              ]),
          }) as unknown as D1PreparedStatement,
      }) as unknown as D1PreparedStatement,
    batch: () => Promise.resolve([]),
  };
  assert.deepEqual(await run(db, "foundation.account-load", load), {
    ok: false,
    failure: "overloaded",
  });
});

test("a write reports the summed change count and never returns rows", async () => {
  const db = createSqliteD1();
  assert.deepEqual(await run(db, "foundation.account-seed", [[sc(), txt("a"), i64("1")]]), {
    ok: true,
    rows: [],
    changes: "1",
  });
  assert.deepEqual(await run(db, "foundation.account-seed", [[sc(), txt("a"), i64("1")]]), {
    ok: true,
    rows: [],
    changes: "0",
  });
});
