// SPDX-License-Identifier: AGPL-3.0-only
// Pins the Go center's start configuration in wrangler.json. Every environment that selects the Go center
// (ARCFORGES_HELLO_RUNTIME=go) must state an explicit ARCFORGES_CENTER_MODE and an https ARCFORGES_CENTER_PUBLIC_BASE_URL:
// the center refuses to start without them (center/internal/config), so a removed or broken value must fail this check
// rather than the deployment. Wrangler does not inherit `vars` into a named environment, so each environment is checked on
// its own.
import assert from "node:assert/strict";
import {
  edgeRateLimitPeriodSeconds,
  surfaceNames,
} from "../../worker/tables/center-tables.generated.ts";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

interface Environment {
  vars?: Record<string, unknown>;
}

interface Wrangler extends Environment {
  env?: Record<string, Environment>;
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const wrangler = JSON.parse(readFileSync(path.join(root, "wrangler.json"), "utf8")) as Wrangler;
const environments: [string, Environment][] = [
  ["production", wrangler],
  ...Object.entries(wrangler.env ?? {}),
];

const modes = new Set(["official-hosted", "self-hosted"]);

// The https form of the center's public base URL rule (ParsePublicBaseURL in center/internal/config/urls.go): an absolute
// https URL with a lowercase DNS host, an optional port from 1 to 65535 that is not the scheme's default 443 (a browser's Origin
// leaves the default port out, so a value that spells it could never equal an origin) and an optional path of clean segments
// without a trailing slash; no user information, query, fragment or percent-encoding. The center's own http exception (a
// loopback host in self-hosted mode) never applies to a deployed Worker environment.
const baseUrl =
  /^https:\/\/([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*)(?::([1-9][0-9]{0,4}))?((?:\/[A-Za-z0-9._~-]+)*)$/u;

function baseUrlProblem(value: unknown): string | undefined {
  if (typeof value !== "string" || value === "") return "is missing";
  if (value.length > 2048) return "is longer than 2048 bytes";
  const match = baseUrl.exec(value);
  if (!match) return "is not an https URL with a lowercase host and a clean path";
  if (match[2] !== undefined && Number(match[2]) > 65535) return "has a port above 65535";
  if (match[2] === "443") return "spells the default port 443";
  const segments = (match[3] ?? "").split("/").slice(1);
  if (segments.some((segment) => segment === "." || segment === ".."))
    return "has a dot segment in its path";
  return undefined;
}

/** The problems of one environment's center configuration; none when the environment does not select the Go center. */
function centerProblems(vars: Record<string, unknown> | undefined): string[] {
  if (vars?.ARCFORGES_HELLO_RUNTIME !== "go") return [];
  const problems: string[] = [];
  const mode = vars.ARCFORGES_CENTER_MODE;
  if (typeof mode !== "string" || !modes.has(mode))
    problems.push("ARCFORGES_CENTER_MODE is not official-hosted or self-hosted");
  const url = baseUrlProblem(vars.ARCFORGES_CENTER_PUBLIC_BASE_URL);
  if (url) problems.push(`ARCFORGES_CENTER_PUBLIC_BASE_URL ${url}`);
  return problems;
}

test("production selects the Go center in explicit official-hosted mode with an https public base URL", () => {
  const vars = wrangler.vars ?? {};
  assert.equal(vars.ARCFORGES_HELLO_RUNTIME, "go");
  assert.equal(vars.ARCFORGES_CENTER_MODE, "official-hosted");
  assert.deepEqual(centerProblems(vars), []);
});

test("every environment that selects the Go center states a valid mode and an https public base URL", () => {
  for (const [name, environment] of environments)
    assert.deepEqual(centerProblems(environment.vars), [], `wrangler.json environment ${name}`);
});

test("the configuration rule refuses a missing or invalid mode or base URL", () => {
  const valid = {
    ARCFORGES_HELLO_RUNTIME: "go",
    ARCFORGES_CENTER_MODE: "official-hosted",
    ARCFORGES_CENTER_PUBLIC_BASE_URL: "https://arcforges.com/api",
  };
  assert.deepEqual(centerProblems(valid), []);
  assert.deepEqual(centerProblems({ ...valid, ARCFORGES_CENTER_MODE: "self-hosted" }), []);
  assert.deepEqual(
    centerProblems({ ...valid, ARCFORGES_CENTER_PUBLIC_BASE_URL: "https://center.example:8443" }),
    [],
  );
  // A runtime other than the Go center needs neither value.
  assert.deepEqual(centerProblems({ ARCFORGES_HELLO_RUNTIME: "csharp" }), []);
  assert.deepEqual(centerProblems(undefined), []);
  for (const mode of [undefined, "", "Official-Hosted", "official", "self_hosted", 1])
    assert.equal(centerProblems({ ...valid, ARCFORGES_CENTER_MODE: mode }).length, 1, String(mode));
  for (const url of [
    undefined,
    "",
    "http://arcforges.com/api",
    "https://arcforges.com/api/",
    "https://arcforges.com/",
    "https://ArcForges.com/api",
    "https://arcforges.com/api?x=1",
    "https://arcforges.com/api#top",
    "https://user@arcforges.com/api",
    "https://arcforges.com/a%20b",
    "https://arcforges.com/a//b",
    "https://arcforges.com/a/../b",
    "https://arcforges.com:0/api",
    "https://arcforges.com:65536/api",
    "https://arcforges.com:443/api",
    "arcforges.com/api",
    " https://arcforges.com/api",
  ])
    assert.equal(
      centerProblems({ ...valid, ARCFORGES_CENTER_PUBLIC_BASE_URL: url }).length,
      1,
      String(url),
    );
  // Removing both values from an environment that selects the Go center reports both.
  assert.equal(centerProblems({ ARCFORGES_HELLO_RUNTIME: "go" }).length, 2);
});

// AF-CTR-03 (PLT-12): the surface switch. Production enables no surface (Hello stays), the acceptance environment enables the
// identity and pages surfaces; FLAGSHIP_SURFACES is exact generated names, comma-separated, in every environment; the pages need
// the identity surface they call; wherever identity is on, the Worker's ALLOWED_ORIGIN is the origin of the center's public base
// URL (the one origin browser sessions are bound to); and no environment carries a bootstrap value (the proof bootstrap's digest and
// expiry are protected-dispatch inputs, never committed).
// The known names are the generated table's, so a surface the center admits is admitted here and a new one is a decision of this test.
const surfaces = new Set<string>(surfaceNames);

function surfaceProblems(vars: Record<string, unknown> | undefined): string[] {
  const value = vars?.FLAGSHIP_SURFACES;
  if (value === undefined || value === "") return [];
  if (typeof value !== "string") return ["FLAGSHIP_SURFACES is not a string"];
  const names = value.split(",");
  if (names.some((name) => !surfaces.has(name)) || new Set(names).size !== names.length)
    return ["FLAGSHIP_SURFACES is not a comma-separated list of known surface names"];
  if (names.includes("pages") && !names.includes("identity"))
    return ["the pages surface needs the identity surface"];
  if (names.includes("operations") && !(names.includes("identity") && names.includes("pages")))
    return ["the operations surface needs the identity and pages surfaces"];
  if (names.includes("identity")) {
    const base = vars?.ARCFORGES_CENTER_PUBLIC_BASE_URL;
    const origin =
      typeof base === "string" && baseUrlProblem(base) === undefined
        ? new URL(base).origin
        : undefined;
    if (vars?.ALLOWED_ORIGIN !== origin)
      return ["ALLOWED_ORIGIN is not the origin of the public base URL"];
    if (vars?.ARCFORGES_HELLO_RUNTIME !== "go")
      return ["the surfaces take effect only with the Go center"];
  }
  return [];
}

test("production enables no surface and the acceptance environment enables identity and pages", () => {
  assert.equal(wrangler.vars?.FLAGSHIP_SURFACES, "");
  assert.equal(wrangler.env?.proof?.vars?.FLAGSHIP_SURFACES, "identity,pages");
  // C1: only the acceptance environment overrides the identity policy, and only with its anonymous-flow ceiling; production keeps
  // the defaults (no global bucket).
  assert.equal(wrangler.vars?.ARCFORGES_CENTER_IDENTITY_POLICY, undefined);
  assert.deepEqual(
    JSON.parse(String(wrangler.env?.proof?.vars?.ARCFORGES_CENTER_IDENTITY_POLICY)),
    {
      anonymousFlowsLimit: 600,
      anonymousFlowsWindow: "1h",
    },
  );
  assert.equal(wrangler.env?.proof?.vars?.ALLOWED_ORIGIN, "https://proof.arcforges.com");
  for (const [name, environment] of environments) {
    assert.deepEqual(surfaceProblems(environment.vars), [], `wrangler.json environment ${name}`);
    for (const key of Object.keys(environment.vars ?? {}))
      assert(!/BOOTSTRAP/u.test(key), `wrangler.json environment ${name} carries ${key}`);
  }
});

test("the surface rule refuses unknown names, a wrong origin and the C# runtime", () => {
  const valid = {
    ARCFORGES_HELLO_RUNTIME: "go",
    ARCFORGES_CENTER_PUBLIC_BASE_URL: "https://proof.arcforges.com/api",
    ALLOWED_ORIGIN: "https://proof.arcforges.com",
    FLAGSHIP_SURFACES: "identity",
  };
  assert.deepEqual(surfaceProblems(valid), []);
  for (const value of [
    "Identity",
    "identity,",
    "identity,identity",
    " identity",
    "operations",
    "operations,identity",
    "operations,pages",
    "operations,x",
    "none",
  ])
    assert.equal(surfaceProblems({ ...valid, FLAGSHIP_SURFACES: value }).length, 1, value);
  for (const origin of [
    undefined,
    "https://arcforges.com",
    "https://proof.arcforges.com/",
    "http://proof.arcforges.com",
  ])
    assert.equal(surfaceProblems({ ...valid, ALLOWED_ORIGIN: origin }).length, 1, String(origin));
  assert.equal(surfaceProblems({ ...valid, ARCFORGES_HELLO_RUNTIME: "csharp" }).length, 1);
  // The pages call the identity surface in process: one without the other is refused, both are accepted in either order.
  assert.deepEqual(surfaceProblems({ ...valid, FLAGSHIP_SURFACES: "identity,pages" }), []);
  assert.deepEqual(surfaceProblems({ ...valid, FLAGSHIP_SURFACES: "pages,identity" }), []);
  assert.equal(surfaceProblems({ ...valid, FLAGSHIP_SURFACES: "pages" }).length, 1);
  // The operations surface (the operator grant's page) needs both; it is accepted with them, in any order, and is the only name that
  // is not enabled in a checked-in environment (production carries none, the acceptance environment keeps identity,pages).
  assert.deepEqual(
    surfaceProblems({ ...valid, FLAGSHIP_SURFACES: "identity,pages,operations" }),
    [],
  );
  assert.deepEqual(
    surfaceProblems({ ...valid, FLAGSHIP_SURFACES: "operations,pages,identity" }),
    [],
  );
  assert.deepEqual([...surfaces].sort(), ["identity", "operations", "pages"]);
  for (const [name, environment] of environments)
    assert(
      !String(environment.vars?.FLAGSHIP_SURFACES ?? "")
        .split(",")
        .includes("operations"),
      `wrangler.json environment ${name} enables the operations surface`,
    );
});

// AF-CTR-03 (F17): the Worker's rate_limited reply advises a retry after the generated edge period, which must be the surface
// limiter's own period in every environment, so the advised instant is never inside the limiter's window.
test("the surface limiter's period is the generated edge period in every environment", () => {
  for (const [name, environment] of environments) {
    const limiters =
      (environment as { ratelimits?: { name?: string; simple?: { period?: unknown } }[] })
        .ratelimits ?? [];
    const identity = limiters.filter((limiter) => limiter.name === "IDENTITY_RATE_LIMITER");
    assert.equal(identity.length, 1, `wrangler.json environment ${name}`);
    assert.equal(
      identity[0]?.simple?.period,
      edgeRateLimitPeriodSeconds,
      `wrangler.json environment ${name}`,
    );
  }
});
