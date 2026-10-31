// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test, { mock } from "node:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { coldStartBudgetMs, healthPath } from "../../worker/ingress/routes.ts";
import { trailerFrame } from "../../worker/ingress/io.ts";
import { proofRouteTable } from "../../worker/ingress/proof-table.ts";
import { routeRequest as routeWith, type CloudBindings } from "../../worker/router.ts";
import { platformFetch } from "./support/platform-fetch.ts";

// The proof methods are routed by the proof entry's table, and only when the proof flag is set (CLOUD.84 D1).
const routeRequest = (
  request: Request,
  env: CloudBindings,
  context?: { waitUntil(promise: Promise<unknown>): void },
) =>
  routeWith(
    request,
    env,
    context,
    env.FOUNDATION_PROOF === "enabled" ? proofRouteTable : undefined,
  );

const origin = "https://proof.example.test";
const whoami = "/api/arcforges.proof.v1.PipelineProbe/Whoami";
const stream = "/api/arcforges.proof.v1.PipelineProbe/Stream";
const hello = "/api/arcforges.hello.v1.HelloService/SayHello";
const handle = "A".repeat(43);
const csrf = "B".repeat(43);
const grpcWeb = "application/grpc-web+proto";

function frame(payload: number[]): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(5 + payload.length);
  new DataView(bytes.buffer).setUint32(1, payload.length);
  bytes.set(payload, 5);
  return bytes;
}
function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}
const okReply = concat(frame([1, 2]), trailerFrame(0));

interface Seen {
  names: string[];
  requests: Request[];
}

function bindings(
  respond: (request: Request) => Promise<Response>,
  overrides: Partial<CloudBindings> = {},
): { env: CloudBindings; seen: Seen } {
  const seen: Seen = { names: [], requests: [] };
  const env: CloudBindings = {
    SOURCE_REVISION: "candidate",
    BUILD_IDENTITY: '{"buildId":"fixture.1"}',
    FOUNDATION_PROOF: "enabled",
    ALLOWED_ORIGIN: origin,
    CLOUD_CONTAINER: {
      getByName(name) {
        seen.names.push(name);
        return {
          fetch(request) {
            seen.requests.push(request);
            return respond(request);
          },
        };
      },
    },
    HELLO_RATE_LIMITER: { limit: async () => ({ success: true }) },
    ...overrides,
  };
  return { env, seen };
}

function call(path: string, headers: Record<string, string> = {}, init: RequestInit = {}) {
  return new Request(`https://proof.example.test${path}`, {
    method: "POST",
    headers: { "content-type": grpcWeb, ...headers },
    body: frame([10, 0]),
    ...init,
  });
}

const cookieHeaders = {
  cookie: `__Host-af_session=${handle}`,
  origin,
  "x-af-csrf": csrf,
};

function status(bytes: Uint8Array): { code: number; message: string } {
  assert.equal(bytes[0], 0x80, "a trailer frame");
  const text = new TextDecoder().decode(bytes.subarray(5));
  const code = /^grpc-status: (\d+)\r\n/u.exec(text)?.[1];
  const message = /grpc-message: ([^\r]*)\r\n/u.exec(text)?.[1] ?? "";
  return { code: Number(code), message: decodeURIComponent(message) };
}

async function refused(response: Response, code: number, message?: string): Promise<void> {
  assert.equal(response.status, 200);
  const result = status(new Uint8Array(await response.arrayBuffer()));
  assert.equal(result.code, code);
  if (message !== undefined) assert.equal(result.message, message);
}

// ---- credentials: refused at the edge before any Container wakes ----

test("a session method without a credential is UNAUTHENTICATED and wakes nothing", async () => {
  const { env, seen } = bindings(async () => new Response(okReply));
  await refused(await routeRequest(call(whoami), env), 16, "auth.unauthenticated");
  assert.equal(seen.requests.length, 0);
});

test("a cookie needs the exact Origin and a well-formed CSRF token at the edge", async () => {
  const { env, seen } = bindings(async () => new Response(okReply));
  const wrong: Record<string, string>[] = [
    { ...cookieHeaders, origin: "https://evil.example" },
    { ...cookieHeaders, origin: `${origin}/` },
    { ...cookieHeaders, origin: origin.toUpperCase() },
    { cookie: cookieHeaders.cookie, "x-af-csrf": csrf },
    { cookie: cookieHeaders.cookie, origin },
    { ...cookieHeaders, "x-af-csrf": "short" },
    { ...cookieHeaders, "x-af-csrf": `${csrf}=` },
  ];
  for (const headers of wrong) await refused(await routeRequest(call(whoami, headers), env), 7);
  assert.equal(seen.requests.length, 0);
  const unconfigured = bindings(async () => new Response(okReply), { ALLOWED_ORIGIN: undefined });
  await refused(await routeRequest(call(whoami, cookieHeaders), unconfigured.env), 7);
  assert.equal(unconfigured.seen.requests.length, 0);
});

test("a malformed, repeated or ambiguous credential never reaches the Container", async () => {
  const { env, seen } = bindings(async () => new Response(okReply));
  const bad: Record<string, string>[] = [
    { ...cookieHeaders, cookie: "__Host-af_session=short" },
    {
      ...cookieHeaders,
      cookie: `__Host-af_session=${handle}; __Host-af_session=${"C".repeat(43)}`,
    },
    { ...cookieHeaders, cookie: `other=${handle}` },
    { authorization: "Bearer short" },
    { authorization: `Basic ${"a".repeat(40)}` },
    { authorization: `Bearer ${"a".repeat(40)} extra` },
    { authorization: `Bearer ${"a".repeat(4097)}` },
    { ...cookieHeaders, authorization: `Bearer ${"a".repeat(40)}` },
  ];
  for (const headers of bad) await refused(await routeRequest(call(whoami, headers), env), 16);
  assert.equal(seen.requests.length, 0);
});

test("only the validated credential headers reach the Container, built by the Worker", async () => {
  const { env, seen } = bindings(async () => new Response(okReply));
  const response = await routeRequest(
    call(whoami, {
      ...cookieHeaders,
      cookie: `analytics=1; __Host-af_session=${handle}; theme=dark`,
      "x-af-signature": "forged",
      "x-af-key-id": "c2w-1",
      "x-forwarded-for": "10.0.0.1",
      "cf-connecting-ip": "203.0.113.9",
    }),
    env,
  );
  assert.equal(response.status, 200);
  const forwarded = seen.requests[0];
  assert.ok(forwarded);
  assert.deepEqual(seen.names, ["foundation"]);
  assert.deepEqual([...forwarded.headers.keys()].sort(), [
    "content-type",
    "cookie",
    "grpc-timeout",
    "origin",
    "traceparent",
    "x-af-csrf",
    "x-grpc-web",
  ]);
  assert.equal(forwarded.headers.get("cookie"), `__Host-af_session=${handle}`);
  assert.equal(forwarded.headers.get("origin"), origin);
  assert.equal(forwarded.headers.get("x-af-csrf"), csrf);
  assert.equal(new URL(forwarded.url).pathname, whoami.slice(4));

  const bearer = bindings(async () => new Response(okReply));
  await routeRequest(
    call(whoami, { authorization: `Bearer ${"t".repeat(40)}`, origin: "https://other.example" }),
    bearer.env,
  );
  const native = bearer.seen.requests[0];
  assert.ok(native);
  assert.equal(native.headers.get("authorization"), `Bearer ${"t".repeat(40)}`);
  assert.equal(native.headers.get("cookie"), null);
  assert.equal(native.headers.get("origin"), null, "a native client needs and sends no Origin");
});

test("an anonymous method never reads or forwards a credential", async () => {
  const { env, seen } = bindings(async () => new Response(okReply));
  await routeRequest(
    call(hello, { ...cookieHeaders, authorization: `Bearer ${"t".repeat(40)}` }),
    env,
  );
  const forwarded = seen.requests[0];
  assert.ok(forwarded);
  for (const name of ["cookie", "authorization", "origin", "x-af-csrf"])
    assert.equal(forwarded.headers.get(name), null, name);
  assert.deepEqual(seen.names, ["hello"]);
});

// ---- deny by default ----

test("outside the proof environment the probe methods do not exist and nothing wakes a Container", async () => {
  for (const proof of [undefined, "", "disabled", "ENABLED", "Enabled", "true", "1"]) {
    const { env, seen } = bindings(async () => new Response(okReply), { FOUNDATION_PROOF: proof });
    for (const path of [whoami, stream, "/api/arcforges.proof.v1.PipelineProbe/Observation"]) {
      const response = await routeRequest(call(path, cookieHeaders), env);
      assert.equal(response.status, 404, `${proof}: ${path}`);
    }
    assert.equal(seen.requests.length, 0);
  }
});

test("no path outside the exact method table is ever forwarded", async () => {
  const { env, seen } = bindings(async () => new Response(okReply));
  for (const path of [
    "/internal/storage/v1/execute-plan",
    "/api/internal/storage/v1/execute-plan",
    "/internal/foundation/v1/readiness",
    "/api/internal/foundation/v1/readiness",
    "/session/v1/bootstrap",
    "/api/arcforges.hello.v1.HelloService/SayHello/",
    "/api/arcforges.hello.v1.HelloService/SayHello/extra",
    "/api/arcforges.hello.v1.HelloService/sayhello",
    "/api/arcforges.hello.v1.HelloService",
    "/api/",
    "/api",
    "/",
    "//api/arcforges.hello.v1.HelloService/SayHello",
    "/api/%2e%2e/internal/storage/v1/execute-plan",
    "/api/arcforges.hello.v1.HelloService/SayHello%00",
    // A contract method no surface serves (AF-CTR-03 serves sign-in, the account and its devices, not AF-ID-02's recovery).
    "/api/arcforges.publicapi.v1.IdentityService/BeginRecovery",
    "/api/arcforges.publicapi.v1.IdentityService/GetProfile/",
    // Non-canonical variants of a registered method never match the exact table.
    "/api/arcforges.hello.v1.HelloService/SayHello/.",
    "/api/arcforges.hello.v1.HelloService//SayHello",
    "/api/ARCFORGES.HELLO.V1.HELLOSERVICE/SAYHELLO",
    "/API/arcforges.hello.v1.HelloService/SayHello",
    "/api/arcforges.hello.v1.HelloService/Say%48ello",
    "/api/arcforges.hello.v1.HelloService%2FSayHello",
    "/api/arcforges.hello.v1.HelloService/SayHello%2F",
    "/api/%61rcforges.hello.v1.HelloService/SayHello",
    "/api/./arcforges.hello.v1.HelloService/SayHello/",
    "/api/arcforges.proof.v1.PipelineProbe/Observation/",
    "/api/arcforges.proof.v1.PipelineProbe/Whoami/",
    "/API/arcforges.proof.v1.PipelineProbe/Whoami",
    "/api/arcforges.proof.v1.PipelineProbe/Stream%2F",
  ]) {
    const response = await routeRequest(call(path, cookieHeaders), env);
    assert.equal(response.status, 404, path);
  }
  assert.equal(seen.requests.length, 0);
});

// ---- the reply contract ----

test("only status headers and the Worker's own headers are returned from the Container", async () => {
  const { env } = bindings(
    async () =>
      new Response(okReply, {
        headers: {
          "content-type": "application/grpc-web",
          "set-cookie": "__Host-af_session=x",
          "x-internal": "secret",
          "content-length": "9999",
          "access-control-allow-origin": "*",
        },
      }),
  );
  const response = await routeRequest(call(hello), env);
  assert.equal(response.status, 200);
  assert.deepEqual([...response.headers.keys()].sort(), [
    "cache-control",
    "content-type",
    "x-arcforges-worker-build",
    "x-arcforges-worker-revision",
    "x-content-type-options",
  ]);
  assert.equal(response.headers.get("content-type"), "application/grpc-web");
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), okReply);
});

test("the Container request of an API call says redirect manual: a redirect is refused, never followed to what it leads to (H-1)", async () => {
  // Hello is the unary route that needs no credential; the proof entry's table is not what is under test.
  const followedReply = new Response(okReply, {
    headers: { "content-type": "application/grpc-web" },
  });
  const platform = platformFetch(
    () => new Response(null, { status: 303, headers: { location: "http://container/elsewhere" } }),
    () => followedReply.clone(),
  );
  const { env, seen } = bindings(async (request) => platform(request));
  const response = await routeRequest(call(hello), env);
  assert.equal(seen.requests.length, 1);
  assert.equal(seen.requests[0]?.redirect, "manual");
  // The 303 is a non-200 reply of the Container: the call is refused. The 200 of the address it leads to never reaches the client.
  const bytes = new Uint8Array(await response.arrayBuffer());
  assert.notDeepEqual(bytes, okReply);
  // A health read (the same code path) says it as well, and a redirect answered to it is refused like any other non-200 reply, never
  // followed to the 200 of the address it names.
  const health = bindings(async (request) =>
    platformFetch(
      () =>
        new Response(null, { status: 302, headers: { location: "http://container/elsewhere" } }),
      () => new Response("{}", { headers: { "content-type": "application/json" } }),
    )(request),
  );
  const healthReply = await routeRequest(
    new Request(`${origin}${healthPath}`, { headers: { "cf-connecting-ip": "203.0.113.7" } }),
    health.env,
  );
  assert.equal(health.seen.requests.length, 1);
  assert.equal(health.seen.requests[0]?.redirect, "manual");
  assert.equal(
    new URL(health.seen.requests[0]?.url ?? "").pathname,
    healthPath.replace(/^\/api/u, ""),
  );
  assert.equal(healthReply.status, 503);
  assert.equal(await healthReply.text(), "Cloud container is temporarily unavailable.");
  const unary = bindings(async () => new Response(okReply));
  await (await routeRequest(call(hello), unary.env)).arrayBuffer();
  assert.equal(unary.seen.requests[0]?.redirect, "manual");
});

// The source text without its comments (strings and template literals are kept whole, so an address such as http://container is not
// mistaken for a comment): a comment that spells `redirect: "manual"` must not stand in for the option.
const withoutComments = (text: string): string => {
  let out = "";
  for (let index = 0; index < text.length;) {
    const char = text[index] ?? "";
    const next = text[index + 1];
    if (char === "/" && next === "/") {
      while (index < text.length && text[index] !== "\n") index++;
    } else if (char === "/" && next === "*") {
      const end = text.indexOf("*/", index + 2);
      index = end < 0 ? text.length : end + 2;
      out += " ";
    } else if (char === '"' || char === "'" || char === "`") {
      let end = index + 1;
      while (end < text.length && text[end] !== char) end += text[end] === "\\" ? 2 : 1;
      out += text.slice(index, end + 1);
      index = end + 1;
    } else {
      out += char;
      index++;
    }
  }
  return out;
};

// The index just after the parenthesis that closes the one opened at `open`.
const closing = (text: string, open: number): number => {
  let depth = 0;
  for (let index = open; index < text.length; index++) {
    const char = text[index];
    if (char === "(") depth++;
    else if (char === ")" && --depth === 0) return index + 1;
  }
  throw new Error("an unbalanced parenthesis");
};

// Every place the Worker obtains a Container stub, and what it does with it: a request (.fetch) must say redirect manual in its own
// arguments, whatever address it builds; anything else is a stub the file only stops.
const containerSites = (text: string): { request: boolean; manual: boolean }[] => {
  const code = withoutComments(text);
  const sites: { request: boolean; manual: boolean }[] = [];
  for (const match of code.matchAll(/CLOUD_CONTAINER\s*\.getByName\s*\(/gu)) {
    const afterStub = closing(code, match.index + match[0].length - 1);
    const fetch = /^\s*\.fetch\s*\(/u.exec(code.slice(afterStub));
    if (!fetch) {
      sites.push({ request: false, manual: false });
      continue;
    }
    const open = afterStub + fetch[0].length - 1;
    const requestArguments = code.slice(open, closing(code, open));
    sites.push({ request: true, manual: /\bredirect\s*:\s*"manual"/u.test(requestArguments) });
  }
  return sites;
};

test("every request the Worker makes to the Container says redirect manual (H-1): a new request site must say it too", () => {
  const root = new URL("../../", import.meta.url).pathname;
  const sources: string[] = [];
  const walk = (directory: string) => {
    for (const entry of readdirSync(directory)) {
      const file = path.join(directory, entry);
      if (statSync(file).isDirectory()) walk(file);
      else if (file.endsWith(".ts") && !file.endsWith(".generated.ts")) sources.push(file);
    }
  };
  walk(path.join(root, "worker"));
  assert(sources.length > 20, "the Worker sources were found");
  // The scan is keyed on the call that reaches the Container, not on an address: a request whose URL comes from a constant is seen,
  // and a comment is not an option. The list is the sites of this task: a sixth must be added here on purpose.
  const requests = new Map<string, number>();
  const stubs = new Map<string, number>();
  for (const file of sources) {
    const text = readFileSync(file, "utf8");
    const name = path.relative(root, file);
    for (const site of containerSites(text)) {
      if (!site.request) {
        stubs.set(name, (stubs.get(name) ?? 0) + 1);
        continue;
      }
      assert(site.manual, `${name} makes a Container request without redirect manual`);
      requests.set(name, (requests.get(name) ?? 0) + 1);
    }
  }
  assert.deepEqual(
    [...requests.entries()].sort(([a], [b]) => a.localeCompare(b)),
    [
      ["worker/foundation/container-client.ts", 1],
      ["worker/foundation/proof-routes.ts", 1],
      ["worker/harness/run-alarm.ts", 1],
      ["worker/ingress/pages.ts", 1],
      ["worker/ingress/pipeline.ts", 1],
    ],
  );
  // The one stub that is not a request is stopped, never fetched.
  assert.deepEqual([...stubs.entries()], [["worker/foundation/proof-routes.ts", 1]]);
  assert(
    !/\bstub\s*\.fetch\s*\(/u.test(
      withoutComments(readFileSync(path.join(root, "worker/foundation/proof-routes.ts"), "utf8")),
    ),
  );
});

test("the scan of the Container requests sees a request without the option, a constant address and a comment standing in for it", () => {
  const request = (options: string, comment = "") =>
    `${comment}\nconst r = await env.CLOUD_CONTAINER.getByName(name).fetch(new Request(target, { method: "POST"${options} }));`;
  assert.deepEqual(containerSites(request(', redirect: "manual"')), [
    { request: true, manual: true },
  ]);
  assert.deepEqual(containerSites(request("")), [{ request: true, manual: false }]);
  assert.deepEqual(containerSites(request("", '// redirect: "manual"')), [
    { request: true, manual: false },
  ]);
  assert.deepEqual(containerSites(request("", '/* redirect: "manual" */')), [
    { request: true, manual: false },
  ]);
  assert.deepEqual(containerSites(request("", 'const note = "redirect manual";')), [
    { request: true, manual: false },
  ]);
  // An address held in a constant, another receiver spelling and a stub kept in a variable are all sites.
  assert.deepEqual(
    containerSites("const u = SHARED; await env.CLOUD_CONTAINER\n  .getByName(a)\n  .fetch(u);"),
    [{ request: true, manual: false }],
  );
  assert.deepEqual(
    containerSites(
      'const stub = env.CLOUD_CONTAINER.getByName(a); await stub.fetch(new Request(u, { redirect: "manual" }));',
    ),
    [{ request: false, manual: false }],
  );
  assert.deepEqual(containerSites('const url = "http://container/x"; // not a site'), []);
});

test("a unary reply that is not exactly one message and a status is never passed on", async () => {
  const cases: [string, Uint8Array<ArrayBuffer> | null, ResponseInit?][] = [
    ["two messages", concat(frame([1]), frame([2]), trailerFrame(0))],
    ["oversized", concat(frame(new Array(9000).fill(1)), trailerFrame(0))],
    ["unknown flag", new Uint8Array([2, 0, 0, 0, 0])],
    ["a truncated frame", frame([1, 2, 3]).subarray(0, 6)],
    ["data after the trailer", concat(trailerFrame(0), frame([1]))],
    ["not found", okReply, { status: 404 }],
    ["server error", okReply, { status: 500 }],
    ["no body and no status", null],
  ];
  for (const [name, body, init] of cases) {
    const { env } = bindings(async () => new Response(body, init));
    const response = await routeRequest(call(hello), env);
    assert.equal(response.status, 503, name);
    assert.equal(await response.text(), "Cloud container is temporarily unavailable.", name);
  }
});

test("a unary reply missing its trailer carries an explicit UNAVAILABLE status", async () => {
  const { env } = bindings(async () => new Response(frame([1, 2, 3])));
  const response = await routeRequest(call(hello), env);
  assert.equal(response.status, 200);
  const bytes = new Uint8Array(await response.arrayBuffer());
  assert.deepEqual(bytes.subarray(0, 8), frame([1, 2, 3]));
  assert.equal(status(bytes.subarray(8)).code, 14);
});

test("a status carried in the headers of a bodyless reply is a complete trailers-only reply", async () => {
  const { env } = bindings(
    async () => new Response(null, { headers: { "grpc-status": "3", "grpc-message": "bad" } }),
  );
  const response = await routeRequest(call(hello), env);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("grpc-status"), "3");
  assert.equal((await response.arrayBuffer()).byteLength, 0);
});

// ---- server streams: never buffered, cancel, deadline, cold start ----

function gate() {
  let open!: () => void;
  const promise = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { promise, open };
}

test("a server stream reaches the client frame by frame, not after it completes", async () => {
  const release = gate();
  const first = frame([1, 1, 1]);
  const second = frame([2, 2]);
  const { env } = bindings(async () => {
    return new Response(
      new ReadableStream<Uint8Array>({
        async start(controller) {
          controller.enqueue(first);
          await release.promise;
          controller.enqueue(second);
          controller.enqueue(trailerFrame(0, undefined));
          controller.close();
        },
      }),
      { headers: { "content-type": grpcWeb } },
    );
  });
  const response = await routeRequest(call(stream, cookieHeaders), env);
  assert.equal(response.status, 200);
  const reader = (response.body as ReadableStream<Uint8Array>).getReader();
  const one = await reader.read();
  assert.deepEqual(
    one.value,
    first,
    "the first frame arrives while the Container is still producing",
  );
  release.open();
  const parts: Uint8Array[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
  }
  const rest = concat(...parts);
  assert.deepEqual(rest.subarray(0, second.length), second);
  assert.equal(status(rest.subarray(second.length)).code, 0);
});

test("a stream is not subject to the unary reply bounds and may carry many frames", async () => {
  const frames = Array.from({ length: 200 }, (_, i) => frame(new Array(64).fill(i % 256)));
  const { env } = bindings(async () => new Response(concat(...frames, trailerFrame(0))));
  const response = await routeRequest(call(stream, cookieHeaders), env);
  const bytes = new Uint8Array(await response.arrayBuffer());
  assert.equal(bytes.length, 200 * (5 + 64) + trailerFrame(0).length);
});

test("closing the client's response cancels the Container request and its body", async () => {
  let upstreamAborted = false;
  let bodyCanceled = false;
  const { env, seen } = bindings(async (request) => {
    request.signal.addEventListener("abort", () => {
      upstreamAborted = true;
    });
    return new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(frame([1]));
        },
        cancel() {
          bodyCanceled = true;
        },
      }),
    );
  });
  const response = await routeRequest(call(stream, cookieHeaders), env);
  const reader = (response.body as ReadableStream<Uint8Array>).getReader();
  await reader.read();
  await reader.cancel();
  assert.equal(upstreamAborted, true, "the Container request signal aborted");
  assert.equal(bodyCanceled, true, "the Container body was released");
  assert.equal(seen.requests.length, 1);
});

test("the client's own deadline ends a stalled stream with DEADLINE_EXCEEDED, not an EOF", async () => {
  let bodyCanceled = false;
  const { env, seen } = bindings(
    async () =>
      new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(frame([1]));
          },
          cancel() {
            bodyCanceled = true;
          },
        }),
      ),
  );
  const response = await routeRequest(
    call(stream, { ...cookieHeaders, "grpc-timeout": "80m" }),
    env,
  );
  assert.match(seen.requests[0]?.headers.get("grpc-timeout") ?? "", /^\d+m$/u);
  const bytes = new Uint8Array(await response.arrayBuffer());
  assert.deepEqual(bytes.subarray(0, 6), frame([1]));
  assert.equal(status(bytes.subarray(6)).code, 4);
  assert.equal(bodyCanceled, true);
});

test("a stream whose Container fails mid-frame errors the client's read instead of ending", async () => {
  const { env } = bindings(
    async () =>
      new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(frame([1, 2, 3, 4]).subarray(0, 7));
            controller.error(new Error("container reset"));
          },
        }),
      ),
  );
  const response = await routeRequest(call(stream, cookieHeaders), env);
  await assert.rejects(response.arrayBuffer());
});

test("a stream ended by the Container without a status carries an explicit UNAVAILABLE", async () => {
  const { env } = bindings(async () => new Response(frame([1, 2])));
  const response = await routeRequest(call(stream, cookieHeaders), env);
  const bytes = new Uint8Array(await response.arrayBuffer());
  assert.equal(status(bytes.subarray(7)).code, 14);
});

test("the cold start of a stream is bounded on its own, whatever the stream's lifetime", async () => {
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    const { env, seen } = bindings(() => new Promise<Response>(() => {}));
    const pending = routeRequest(call(stream, cookieHeaders), env);
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(seen.requests.length, 1);
    mock.timers.tick(coldStartBudgetMs - 1);
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(seen.requests[0]?.signal.aborted, false, "still within the cold start budget");
    mock.timers.tick(2);
    const response = await pending;
    assert.equal(response.status, 503);
    assert.equal(seen.requests[0]?.signal.aborted, true);
  } finally {
    mock.timers.reset();
  }
});

const libraryText = "text/plain;charset=UTF-8";
const noInstance =
  "There is no Container instance available at this time.\nThis is likely because you have reached your max concurrent instance count.";

test("a Container the platform could not start is a retryable 503 with fixed text, never the library's", async () => {
  const cases: [string, ResponseInit & { body: string }][] = [
    ["no instance", { status: 503, body: noInstance, headers: { "content-type": libraryText } }],
    [
      "start failed",
      {
        status: 500,
        body: "Failed to start container: secret detail",
        headers: { "content-type": libraryText },
      },
    ],
    ["rate limited", { status: 429, body: "slow", headers: { "content-type": "text/plain" } }],
  ];
  for (const path of [hello, whoami, stream]) {
    for (const [name, init] of cases) {
      const { env, seen } = bindings(async () => new Response(init.body, init));
      const response = await routeRequest(call(path, path === hello ? {} : cookieHeaders), env);
      assert.equal(response.status, 503, `${path} ${name}`);
      assert.equal(response.headers.get("retry-after"), "2", `${path} ${name}`);
      const text = await response.text();
      assert.equal(text, "Cloud container is temporarily unavailable.", `${path} ${name}`);
      assert.equal(seen.requests.length, 1, "one attempt, no replay");
    }
  }
});

test("a non-200 reply the host may have produced carries no retry guidance", async () => {
  for (const init of [
    {
      status: 503,
      body: '{"error":"unavailable"}',
      headers: { "content-type": "application/json" },
    },
    { status: 503, body: noInstance, headers: { "content-type": "application/json" } },
    {
      status: 500,
      body: "Failed to start container: x",
      headers: { "content-type": "application/json" },
    },
    { status: 502, body: "bad gateway", headers: { "content-type": libraryText } },
  ]) {
    const { env } = bindings(async () => new Response(init.body, init));
    const response = await routeRequest(call(whoami, cookieHeaders), env);
    assert.equal(response.status, 503);
    assert.equal(response.headers.get("retry-after"), null, `${init.status} ${init.body}`);
  }
});

test("a Container that throws is an unavailable refusal without retry guidance and without the error text", async () => {
  const { env } = bindings(async () => {
    throw new Error("Network connection lost with internal detail");
  });
  const response = await routeRequest(call(whoami, cookieHeaders), env);
  assert.equal(response.status, 503);
  assert.equal(response.headers.get("retry-after"), null);
  assert.equal(await response.text(), "Cloud container is temporarily unavailable.");
});

test("a stream that ends at the cold-start bound carries no retry guidance: the call may have been forwarded", async () => {
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    // A running Container that received the call but is slow to send its first byte looks exactly like this.
    const { env, seen } = bindings(() => new Promise<Response>(() => {}));
    const pending = routeRequest(call(stream, cookieHeaders), env);
    await new Promise<void>((resolve) => setImmediate(resolve));
    mock.timers.tick(coldStartBudgetMs + 1);
    const response = await pending;
    assert.equal(seen.requests.length, 1);
    assert.equal(response.status, 503);
    assert.equal(response.headers.get("retry-after"), null);
  } finally {
    mock.timers.reset();
  }
});

test("the rate limit applies to session and stream methods before a credential is read", async () => {
  const { env, seen } = bindings(async () => new Response(okReply), {
    HELLO_RATE_LIMITER: { limit: async () => ({ success: false }) },
  });
  assert.equal((await routeRequest(call(stream, cookieHeaders), env)).status, 429);
  assert.equal((await routeRequest(call(whoami), env)).status, 429);
  assert.equal(seen.requests.length, 0);
});

test("a request body over the method bound or a compressed message is refused before the Container", async () => {
  const { env, seen } = bindings(async () => new Response(okReply));
  const big = call(whoami, cookieHeaders, { body: new Uint8Array(4097) });
  assert.equal((await routeRequest(big, env)).status, 413);
  const compressed = call(whoami, cookieHeaders, { body: new Uint8Array([1, 0, 0, 0, 0]) });
  assert.equal((await routeRequest(compressed, env)).status, 415);
  assert.equal(seen.requests.length, 0);
});
