// SPDX-License-Identifier: AGPL-3.0-only
// The public method table, its agreement with the C# host's policies, and the static shape of the
// deployment configuration that keeps the Container reachable only through the Worker.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { edgeCredentials } from "../../worker/ingress/edge-caller.ts";
import {
  findRoute,
  healthPath,
  helloPath,
  productionRoutes,
  proofRoutes,
  streamLifetimeMs,
  type ApiRoute,
} from "../../worker/ingress/routes.ts";

const root = path.resolve(import.meta.dirname, "../..");
const namePattern =
  /^\/[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*\.[A-Z][A-Za-z0-9]*\/[A-Z][A-Za-z0-9]*$/u;

test("production serves exactly the anonymous Hello method and the health route", () => {
  assert.deepEqual(
    productionRoutes.map((route) => `/api${route.path}`),
    [helloPath],
  );
  const hello = productionRoutes[0] as ApiRoute;
  assert.equal(hello.auth, "anonymous");
  assert.equal(hello.kind, "unary");
  assert.equal(hello.instance, "hello");
  assert.equal(findRoute({}, healthPath), undefined, "health is the pipeline's own plain route");
});

test("every route is a well-formed method path with sane bounds, and none is an internal path", () => {
  for (const route of [...productionRoutes, ...proofRoutes]) {
    assert.match(route.path, namePattern);
    assert.doesNotMatch(route.path, /internal/iu);
    assert.ok(route.maxRequestBytes >= 1 && route.maxRequestBytes <= 262_144, route.path);
    assert.ok(route.maxFrameBytes >= 1 && route.maxFrameBytes <= 1_048_576, route.path);
    assert.ok(route.maxDurationMs >= 1 && route.maxDurationMs <= streamLifetimeMs, route.path);
    if (route.auth === "anonymous") assert.equal(route.kind, "unary", "no anonymous stream");
  }
  const paths = [...productionRoutes, ...proofRoutes].map((route) => route.path);
  assert.equal(new Set(paths).size, paths.length, "no duplicate method");
});

test("proof routes exist only for the exact enabled value", () => {
  for (const route of proofRoutes) {
    const pathname = `/api${route.path}`;
    assert.equal(findRoute({ FOUNDATION_PROOF: "enabled" }, pathname), route);
    for (const value of [undefined, "", "disabled", "Enabled", "true", "1"])
      assert.equal(findRoute({ FOUNDATION_PROOF: value }, pathname), undefined);
  }
});

test("the edge credential check needs a whole Origin match and never reads a cookie as a bearer", () => {
  const request = (headers: Record<string, string>) =>
    new Request("https://x.test/api/a", { method: "POST", headers });
  const cookie = `__Host-af_session=${"A".repeat(43)}`;
  assert.equal(edgeCredentials(request({}), "https://o.test").ok, false);
  assert.equal(
    edgeCredentials(
      request({ cookie, origin: "https://o.test", "x-af-csrf": "B".repeat(43) }),
      "https://o.test",
    ).ok,
    true,
  );
  assert.equal(
    edgeCredentials(
      request({ cookie, origin: "https://o.test", "x-af-csrf": "B".repeat(43) }),
      undefined,
    ).ok,
    false,
  );
  assert.equal(edgeCredentials(request({ authorization: cookie }), "https://o.test").ok, false);
});

// ---- agreement with the C# host ----

function csharpSources(directory: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && !["bin", "obj"].includes(entry.name))
      found.push(...csharpSources(path.join(directory, entry.name)));
    else if (entry.isFile() && entry.name.endsWith(".cs"))
      found.push(path.join(directory, entry.name));
  }
  return found;
}

interface HostPolicy {
  kind: "unary" | "serverStream";
  auth: "anonymous" | "session";
  maxRequestBytes: number;
}

function hostPolicies(): Map<string, HostPolicy> {
  const source = csharpSources(path.join(root, "src/ArcForges.Cloud"))
    .map((file) => readFileSync(file, "utf8"))
    .join("\n");
  const constants = new Map<string, string>();
  for (const match of source.matchAll(/const string (\w+) = "(\/[^"]+)";/gu))
    constants.set(match[1] as string, match[2] as string);
  const policies = new Map<string, HostPolicy>();
  const call =
    /RpcPolicy\.(Unary|ServerStream)\(\s*("[^"]+"|\w+)\s*,\s*RpcAuthentication\.(Anonymous|Session)\s*,\s*RpcScope\.(\w+)\s*(?:,\s*(\d+)\s*)?\)/gu;
  for (const match of source.matchAll(call)) {
    const name = match[2] as string;
    const resolved = name.startsWith('"') ? name.slice(1, -1) : constants.get(name);
    assert.ok(resolved, `unresolved policy name ${name}`);
    assert.equal(policies.has(resolved), false, `duplicate host policy ${resolved}`);
    policies.set(resolved, {
      kind: match[1] === "Unary" ? "unary" : "serverStream",
      auth: match[3] === "Anonymous" ? "anonymous" : "session",
      maxRequestBytes: match[5] ? Number(match[5]) : 4096,
    });
  }
  return policies;
}

test("the Worker method table and the host policies list the same methods with the same shape", () => {
  const host = hostPolicies();
  const worker = new Map([...productionRoutes, ...proofRoutes].map((route) => [route.path, route]));
  assert.deepEqual([...worker.keys()].sort(), [...host.keys()].sort());
  for (const [name, route] of worker) {
    const policy = host.get(name) as HostPolicy;
    assert.equal(policy.kind, route.kind, name);
    assert.equal(policy.auth, route.auth, name);
    assert.equal(policy.maxRequestBytes, route.maxRequestBytes, name);
  }
});

test("a workspace-scoped host method is always a session method", () => {
  const source = csharpSources(path.join(root, "src/ArcForges.Cloud"))
    .map((file) => readFileSync(file, "utf8"))
    .join("\n");
  for (const match of source.matchAll(/RpcAuthentication\.Anonymous\s*,\s*RpcScope\.Workspace/gu))
    assert.fail(`anonymous method with an owner scope: ${match[0]}`);
});

// ---- deployment configuration: the Container is reachable only through the Worker ----

interface Wrangler {
  workers_dev?: boolean;
  preview_urls?: boolean;
  routes?: { pattern: string; zone_name?: string; custom_domain?: boolean }[];
  containers?: Record<string, unknown>[];
  vars?: Record<string, string>;
  env?: Record<string, Wrangler>;
}

const wrangler = JSON.parse(readFileSync(path.join(root, "wrangler.json"), "utf8")) as Wrangler;

test("production is one Worker route under /api and exposes no other ingress", () => {
  assert.equal(wrangler.workers_dev, false);
  assert.equal(wrangler.preview_urls, false);
  assert.deepEqual(wrangler.routes, [
    { pattern: "arcforges.com/api/*", zone_name: "arcforges.com" },
  ]);
  assert.equal(wrangler.vars?.FOUNDATION_PROOF, undefined);
  assert.equal(wrangler.vars?.ALLOWED_ORIGIN, undefined);
});

test("the proof environment is one custom domain of its own Worker and also keeps every direct URL off", () => {
  const proof = wrangler.env?.proof as Wrangler;
  assert.equal(proof.workers_dev, false);
  assert.equal(proof.preview_urls, false);
  assert.deepEqual(proof.routes, [{ pattern: "proof.arcforges.com", custom_domain: true }]);
});

test("no container declaration publishes a port or an ingress of its own", () => {
  const declarations = [...(wrangler.containers ?? []), ...(wrangler.env?.proof?.containers ?? [])];
  assert.ok(declarations.length >= 2);
  for (const container of declarations)
    assert.deepEqual(Object.keys(container).sort(), [
      "class_name",
      "image",
      "instance_type",
      "max_instances",
    ]);
});

test("the Worker reaches the Container only through its binding, at the private virtual host", () => {
  const ingress = path.join(root, "worker/ingress");
  for (const file of readdirSync(ingress)) {
    const source = readFileSync(path.join(ingress, file), "utf8");
    for (const match of source.matchAll(/https?:\/\/[^"'`\s)]+/gu))
      assert.ok(
        match[0] === "http://container" ||
          /^https?:\/\/\$\{?/u.test(match[0]) ||
          /\.(?:test|example)/u.test(match[0]),
        `${file} names a network location: ${match[0]}`,
      );
    assert.doesNotMatch(
      source,
      /\bfetch\(\s*["'`]https?:/u,
      `${file} calls fetch with a literal URL`,
    );
  }
});
