// SPDX-License-Identifier: AGPL-3.0-only
// Pins the Go center's start configuration in wrangler.json. Every environment that selects the Go center
// (ARCFORGES_HELLO_RUNTIME=go) must state an explicit ARCFORGES_CENTER_MODE and an https ARCFORGES_CENTER_PUBLIC_BASE_URL:
// the center refuses to start without them (center/internal/config), so a removed or broken value must fail this check
// rather than the deployment. Wrangler does not inherit `vars` into a named environment, so each environment is checked on
// its own.
import assert from "node:assert/strict";
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
// https URL with a lowercase DNS host, an optional port from 1 to 65535 and an optional path of clean segments without a
// trailing slash; no user information, query, fragment or percent-encoding. The center's own http exception (a loopback host
// in self-hosted mode) never applies to a deployed Worker environment.
const baseUrl =
  /^https:\/\/([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*)(?::([1-9][0-9]{0,4}))?((?:\/[A-Za-z0-9._~-]+)*)$/u;

function baseUrlProblem(value: unknown): string | undefined {
  if (typeof value !== "string" || value === "") return "is missing";
  if (value.length > 2048) return "is longer than 2048 bytes";
  const match = baseUrl.exec(value);
  if (!match) return "is not an https URL with a lowercase host and a clean path";
  if (match[2] !== undefined && Number(match[2]) > 65535) return "has a port above 65535";
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
