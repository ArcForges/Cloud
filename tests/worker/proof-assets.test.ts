// SPDX-License-Identifier: AGPL-3.0-only
// Offline checks of the proof origin's static profile assets (CLOUD.71): route precedence, the pinned digest, the
// strict bundle reader, the headers and the staging. No network, no deployment and no Cloudflare call.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { isProofPath } from "../../worker/foundation/proof-routes.ts";
import {
  buildProofConfig,
  profileBundleAssetName,
  profileBundlePin,
  proofAssetsDirName,
  parsePolicy,
  readBundleArchive,
  stageProfileAssets,
  verifyProfileBundle,
  workerFirst,
  type CandidateConfig,
} from "../../eng/verification/proof-deploy.ts";

const wrangler = JSON.parse(
  readFileSync(path.resolve(import.meta.dirname, "../../wrangler.json"), "utf8"),
) as CandidateConfig;
const sha = (value: Uint8Array | string) => createHash("sha256").update(value).digest("hex");

// ---- A bundle writer that follows the Web build's format exactly, so each test can damage one thing. ----
function octal(value: number, length: number) {
  return `${value.toString(8).padStart(length - 1, "0")}\0`;
}
function header(entryPath: string, size: number, options: { uid?: number; type?: string } = {}) {
  const head = Buffer.alloc(512);
  Buffer.from(entryPath, "ascii").copy(head, 0);
  head.write(octal(0o644, 8), 100, "ascii");
  head.write(octal(options.uid ?? 0, 8), 108, "ascii");
  head.write(octal(0, 8), 116, "ascii");
  head.write(octal(size, 12), 124, "ascii");
  head.write(octal(0, 12), 136, "ascii");
  head.fill(0x20, 148, 156);
  head.write(options.type ?? "0", 156, "ascii");
  head.write("ustar\0", 257, "ascii");
  head.write("00", 263, "ascii");
  let sum = 0;
  for (const byte of head) sum += byte;
  head.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
  return head;
}
function tar(
  entries: { path: string; bytes: Uint8Array }[],
  options: { uid?: number; type?: string } = {},
) {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    parts.push(header(entry.path, entry.bytes.byteLength, options), Buffer.from(entry.bytes));
    const pad = (512 - (entry.bytes.byteLength % 512)) % 512;
    if (pad > 0) parts.push(Buffer.alloc(pad));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

function page(profile: string, extra = "") {
  return `<!DOCTYPE html><html><head><link rel="modulepreload" href="/assets/entry.js"/></head><body>${extra}<script>window.p="${profile}";</script><script type="module" src="/assets/entry.js"></script></body></html>`;
}
const csp = (profile: string, tail = "") =>
  `default-src 'self'; script-src 'self' '${`sha256-${createHash("sha256").update(`window.p="${profile}";`).digest("base64")}`}'; style-src 'self'${tail}; connect-src 'self'; object-src 'none'`;

interface Spec {
  pages?: Record<string, string>;
  headers?: string;
  extra?: Record<string, string>;
  csp?: Record<string, string>;
  tamper?: (entries: { path: string; bytes: Uint8Array }[]) => void;
  manifest?: (manifest: Record<string, unknown>) => void;
  tarOptions?: { uid?: number; type?: string };
}
function bundle(spec: Spec = {}) {
  const policies = { account: csp("account"), chat: csp("chat"), ...spec.csp };
  const headers =
    spec.headers ??
    `/*\n  X-Content-Type-Options: nosniff\n/account/*\n  Content-Security-Policy: ${policies.account}\n/chat/*\n  Content-Security-Policy: ${policies.chat}\n/assets/*\n  ! Cache-Control\n  Cache-Control: public, max-age=31536000, immutable\n`;
  const files: Record<string, string> = {
    "account/index.html": page("account"),
    "chat/index.html": page("chat"),
    "assets/entry.js": "export const entry = 1;",
    "favicon.svg": "<svg/>",
    "robots.txt": "User-agent: *\n",
    _headers: headers,
    ...spec.pages,
    ...spec.extra,
  };
  const names = Object.keys(files).sort();
  const manifest: Record<string, unknown> = {
    schema: 1,
    profiles: {
      account: { page: "account/index.html", buildDigest: sha("a"), csp: policies.account },
      chat: { page: "chat/index.html", buildDigest: sha("c"), csp: policies.chat },
    },
    files: Object.fromEntries(
      names.map((name) => [
        name,
        { sha256: sha(files[name] as string), bytes: Buffer.byteLength(files[name] as string) },
      ]),
    ),
  };
  spec.manifest?.(manifest);
  const entries = [
    { path: "manifest.json", bytes: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`) },
    ...names.map((name) => ({ path: name, bytes: Buffer.from(files[name] as string) })),
  ];
  spec.tamper?.(entries);
  const archive = tar(entries, spec.tarOptions);
  return { archive, digest: sha(archive) };
}
const refuses = (spec: Spec, pattern: RegExp) => {
  const built = bundle(spec);
  assert.throws(() => verifyProfileBundle(built.archive, built.digest), pattern);
};

test("the Worker answers every one of its own route families before any asset", () => {
  const assets = (wrangler.env.proof as { assets?: Record<string, unknown> }).assets;
  assert(assets);
  assert.deepEqual(assets.run_worker_first, workerFirst);
  assert.deepEqual(workerFirst, ["/api/*", "/session/v1/*", "/proof/v1/*"]);
  assert.equal(assets.not_found_handling, "none");
  assert.equal(assets.html_handling, "auto-trailing-slash");
  assert.equal(assets.binding, undefined, "no new binding: the Worker code is unchanged");
  const matches = (pathname: string) =>
    workerFirst.some((pattern) => pathname.startsWith(pattern.slice(0, -1)));
  for (const pathname of [
    "/session/v1/bootstrap",
    "/session/v1/logout",
    "/proof/v1/readiness",
    "/proof/v1/session/issue",
    "/api/arcforges.hello.v1.HelloService/SayHello",
    "/api/healthz",
  ])
    assert(matches(pathname), pathname);
  // Every path the proof entry itself claims is inside a Worker-first pattern.
  for (const pathname of ["/proof/v1/x", "/session/v1/bootstrap", "/session/v1/logout"])
    assert(isProofPath(pathname) && matches(pathname));
  // No profile asset path is Worker-first, so the profiles are not shadowed by the Worker.
  for (const pathname of ["/account/", "/chat/", "/assets/entry.js", "/favicon.svg"])
    assert(!matches(pathname), pathname);
});

test("only the proof environment gains assets; production and the other bindings are unchanged", () => {
  const top = wrangler as unknown as Record<string, unknown>;
  assert.equal(top.assets, undefined);
  assert.equal(wrangler.env.proof.workers_dev, false);
  assert.equal(wrangler.env.proof.preview_urls, false);
  assert.deepEqual(wrangler.env.proof.routes, [
    { pattern: "proof.arcforges.com", custom_domain: true },
  ]);
});

test("the generated proof config points the assets at the staged directory and keeps the route order", () => {
  const options = {
    account: "0".repeat(32),
    imageDigest: `registry.example/arcforges-cloud@sha256:${"a".repeat(64)}`,
    revision: "b".repeat(40),
    main: "./candidate/worker.js",
  };
  const before = JSON.stringify(wrangler);
  const config = buildProofConfig(wrangler, options);
  assert.equal(config.env.proof.assets?.directory, `./${proofAssetsDirName}`);
  assert.deepEqual(config.env.proof.assets?.run_worker_first, workerFirst);
  assert.equal(JSON.stringify(wrangler), before, "the input is not mutated");
  assert.equal(
    buildProofConfig(wrangler, { ...options, assetsDir: "../elsewhere" }).env.proof.assets
      ?.directory,
    "../elsewhere",
  );
  // A configuration that lets assets answer a Worker route family is refused.
  for (const order of [undefined, true, [], ["/api/*"], ["/session/v1/*", "/api/*", "/proof/v1/*"]])
    assert.throws(
      () =>
        buildProofConfig(
          {
            ...wrangler,
            env: {
              proof: {
                ...wrangler.env.proof,
                assets: { ...wrangler.env.proof.assets, run_worker_first: order },
              },
            },
          },
          options,
        ),
      /route families first/u,
    );
  const noAssets = structuredClone(wrangler);
  delete noAssets.env.proof.assets;
  assert.throws(() => buildProofConfig(noAssets, options), /no static assets/u);
});

test("the pin names a Web release asset by its own digest", () => {
  assert.equal(profileBundlePin.repository, "ArcForges/Web");
  assert.match(profileBundlePin.release, /^web-0\.1\.0-ci\.[1-9]\d*\.[1-9]\d*$/u);
  assert.match(profileBundlePin.digest, /^[0-9a-f]{64}$/u);
  assert.equal(
    profileBundleAssetName(profileBundlePin.digest),
    `web-profiles-${profileBundlePin.digest}.tar`,
  );
});

test("a well-formed bundle verifies and a digest that is not the pin is refused first", () => {
  const built = bundle();
  const verified = verifyProfileBundle(built.archive, built.digest);
  assert.equal(verified.digest, built.digest);
  assert.deepEqual(
    verified.files.map((file) => file.path),
    [
      "_headers",
      "account/index.html",
      "assets/entry.js",
      "chat/index.html",
      "favicon.svg",
      "robots.txt",
    ],
  );
  assert.throws(() => verifyProfileBundle(built.archive, sha("other")), /pinned digest/u);
  assert.throws(() => verifyProfileBundle(built.archive, "abc"), /not a SHA-256/u);
  // One flipped byte anywhere changes the digest and is refused before any parsing.
  const flipped = Buffer.from(built.archive);
  flipped[flipped.length - 2000] = (flipped[flipped.length - 2000] ?? 0) ^ 1;
  assert.throws(() => verifyProfileBundle(flipped, built.digest), /pinned digest/u);
});

test("content that disagrees with the manifest is refused even when the digest is the new one", () => {
  refuses(
    {
      tamper: (entries) => {
        const entry = entries.find((item) => item.path === "assets/entry.js");
        assert(entry);
        entry.bytes = Buffer.from("export const entry = 2;");
      },
    },
    /Content of assets\/entry\.js/u,
  );
  refuses(
    {
      tamper: (entries) => {
        const entry = entries.find((item) => item.path === "assets/entry.js");
        assert(entry);
        entry.bytes = Buffer.from("export const entry = 22;");
      },
    },
    /Size of assets\/entry\.js/u,
  );
  refuses({ tamper: (entries) => entries.splice(2, 1) }, /exactly the manifest's files/u);
  refuses(
    { tamper: (entries) => entries.push({ path: "assets/zz.js", bytes: Buffer.from("x") }) },
    /exactly the manifest's files/u,
  );
  refuses(
    { tamper: (entries) => entries.unshift(entries.splice(1, 1)[0] as (typeof entries)[0]) },
    /manifest must be the first/u,
  );
  refuses({ manifest: (manifest) => (manifest.schema = 2) }, /schema/u);
});

test("the archive reader accepts only plain regular files with the canonical header", () => {
  const entries = [{ path: "a.txt", bytes: Buffer.from("hello") }];
  assert.equal(readBundleArchive(tar(entries)).length, 1);
  // The owner field is pinned: a different uid is not the Web build's header.
  assert.throws(() => readBundleArchive(tar(entries, { uid: 1000 })), /canonical header/u);
  // A symbolic link, a hard link or a directory entry is refused.
  for (const type of ["1", "2", "5"])
    assert.throws(() => readBundleArchive(tar(entries, { type })), /canonical header/u);
  const good = tar(entries);
  assert.throws(() => readBundleArchive(good.subarray(0, good.length - 512)));
  assert.throws(() => readBundleArchive(Buffer.concat([good, Buffer.alloc(512)])), /follows/u);
  assert.throws(() => readBundleArchive(Buffer.concat([good, Buffer.alloc(512, 1)])));
  assert.throws(() => readBundleArchive(Buffer.alloc(100)), /Not a profile bundle/u);
  assert.throws(() => readBundleArchive(Buffer.alloc(30 * 1024 * 1024)), /larger than the limit/u);
  for (const bad of ["../x", "/abs", "a//b", "a b", "a/../b", ".hidden", "a/"])
    assert.throws(
      () => readBundleArchive(tar([{ path: bad, bytes: Buffer.alloc(0) }])),
      /plain relative path/u,
      bad,
    );
  const tooMany = Array.from({ length: 401 }, (_, index) => ({
    path: `f${index}`,
    bytes: Buffer.alloc(0),
  }));
  assert.throws(() => readBundleArchive(tar(tooMany)), /Too many/u);
});

test("a file outside the served layout, a source map or a missing page refuses the bundle", () => {
  for (const extra of [
    "assets/sub/deep.js",
    "other/index.html",
    "index.html",
    "account/extra.html",
    "server.js",
  ])
    refuses({ extra: { [extra]: "x" } }, /outside the served layout/u);
  refuses({ extra: { "assets/entry.js.map": "{}" } }, /source map/u);
  refuses(
    {
      tamper: (entries) =>
        entries.splice(
          entries.findIndex((e) => e.path === "chat/index.html"),
          1,
        ),
    },
    /exactly the manifest's files/u,
  );
});

test("pages use LF line ends and reference only their own origin", () => {
  refuses(
    { pages: { "chat/index.html": page("chat").replaceAll("><", ">\r\n<") } },
    /LF line ends/u,
  );
  refuses({ headers: "/*\r\n  X: y\r\n" }, /LF line ends/u);
  refuses(
    {
      pages: {
        "account/index.html": page("account", '<img src="https://cdn.example.test/a.png"/>'),
      },
    },
    /another origin/u,
  );
  refuses(
    { pages: { "account/index.html": page("account", '<a href="//cdn.example.test/">x</a>') } },
    /another origin/u,
  );
  refuses(
    {
      pages: {
        "account/index.html": page("account", '<link href="assets/x.css" rel="stylesheet"/>'),
      },
    },
    /another origin/u,
  );
});

test("each profile's policy must cover its own inline scripts and stay restrictive", () => {
  // The Chat policy applied to the Account page does not cover the Account inline script.
  refuses({ csp: { account: csp("chat") } }, /does not cover an inline script/u);
  // An inline script in any letter case or with a spaced closing tag must be covered as well.
  refuses(
    { pages: { "chat/index.html": page("chat", "<script>window.other = 1;</script junk>") } },
    /does not cover an inline script/u,
  );
  for (const tag of ["SCRIPT", "Script"])
    refuses(
      { pages: { "chat/index.html": page("chat", `<${tag}>window.other = 1;</${tag} >`) } },
      /does not cover an inline script/u,
    );
  refuses({ csp: { account: csp("account", " 'unsafe-inline'") } }, /not restrictive/u);
  refuses({ csp: { chat: csp("chat", " *") } }, /not restrictive/u);
  refuses(
    { csp: { chat: csp("chat").replace("connect-src 'self'", "connect-src https:") } },
    /connect-src/u,
  );
  refuses({ csp: { chat: csp("chat").replace("default-src 'self'; ", "") } }, /default-src/u);
  refuses(
    {
      manifest: (manifest) => {
        const profiles = manifest.profiles as Record<string, { csp: string }>;
        profiles.chat = { csp: "x" };
      },
    },
    /manifest policy of chat differs/u,
  );
  refuses(
    { headers: "/*\n  X: y\n/chat/*\n  Content-Security-Policy: x\n" },
    /No headers rule for \/account/u,
  );
});

test("the site-wide and asset rules never carry a policy and every rule is unique", () => {
  const rules = (extra: string) =>
    `${extra}/account/*\n  Content-Security-Policy: ${csp("account")}\n/chat/*\n  Content-Security-Policy: ${csp("chat")}\n`;
  refuses(
    { headers: rules("/*\n  Content-Security-Policy: default-src *\n") },
    /\/\* rule must not carry a policy/u,
  );
  refuses(
    { headers: rules("/assets/*\n  Content-Security-Policy: default-src *\n") },
    /\/assets\/\* rule must not carry a policy/u,
  );
  refuses({ headers: `${rules("")}/chat/*\n  X: y\n` }, /Duplicate headers rule/u);
});

test("staging writes the verified files without the manifest into a fresh directory of the fixed name", async () => {
  const parent = await mkdtemp(path.join(tmpdir(), "cloud71-"));
  try {
    const target = path.join(parent, proofAssetsDirName);
    await writeFile(path.join(parent, "keep.txt"), "kept");
    const built = bundle();
    const verified = verifyProfileBundle(built.archive, built.digest);
    // Stale content of an earlier staging never survives.
    await stageProfileAssets(verified, target);
    await writeFile(path.join(target, "stale.txt"), "stale");
    assert.equal(await stageProfileAssets(verified, target), 6);
    assert.deepEqual((await readdir(target)).sort(), [
      "_headers",
      "account",
      "assets",
      "chat",
      "favicon.svg",
      "robots.txt",
    ]);
    assert.equal(await readFile(path.join(target, "account/index.html"), "utf8"), page("account"));
    await assert.rejects(stat(path.join(target, "manifest.json")));
    assert.equal(await readFile(path.join(parent, "keep.txt"), "utf8"), "kept");
    await assert.rejects(
      stageProfileAssets(verified, path.join(parent, "elsewhere")),
      /Unexpected staging/u,
    );
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("an inline script is found in every start-tag form and must be covered in script-src itself", () => {
  const uncovered = /does not cover an inline script/u;
  refuses(
    { pages: { "chat/index.html": page("chat", "<script/x>window.other = 1;</script>") } },
    uncovered,
  );
  refuses(
    { pages: { "chat/index.html": page("chat", "<script\n>window.other = 1;</script>") } },
    uncovered,
  );
  // A src that only appears inside another attribute value or in a slash-separated form is not an external script.
  refuses(
    {
      pages: {
        "chat/index.html": page("chat", '<script data-x="src=1">window.other = 1;</script>'),
      },
    },
    uncovered,
  );
  // An external script (a real src attribute, in any form) needs no hash; its body text is not executed inline.
  for (const external of [
    "<script src=/assets/a.js></script>",
    "<script/src=/assets/a.js></script>",
  ]) {
    const built = bundle({ pages: { "chat/index.html": page("chat", external) } });
    assert.equal(verifyProfileBundle(built.archive, built.digest).digest, built.digest);
  }
  // The hash must be in script-src: the same hash in style-src does not cover the script.
  const hash = `'sha256-${createHash("sha256").update('window.p="chat";').digest("base64")}'`;
  refuses(
    {
      csp: {
        chat: `default-src 'self'; script-src 'self'; style-src 'self' ${hash}; connect-src 'self'; object-src 'none'`,
      },
    },
    uncovered,
  );
  refuses(
    {
      csp: {
        chat: `default-src 'self'; x-script-src 'self' ${hash}; connect-src 'self'; object-src 'none'`,
      },
    },
    uncovered,
  );
});

test("default-src and connect-src must be exactly 'self' and a directive may not repeat", () => {
  const hash = `'sha256-${createHash("sha256").update('window.p="chat";').digest("base64")}'`;
  const policy = (extra: string) => `${extra}; script-src 'self' ${hash}; object-src 'none'`;
  const good = policy("default-src 'self'; connect-src 'self'");
  const built = bundle({ csp: { chat: good } });
  assert.equal(verifyProfileBundle(built.archive, built.digest).digest, built.digest);
  for (const bad of [
    "default-src 'self' https:; connect-src 'self'",
    "default-src 'self'; connect-src 'self' https://other.example.test",
    "default-src 'self'; x-connect-src 'self'",
    "default-src 'self'; connect-src 'self'; connect-src 'self'",
    "x-default-src 'self'; connect-src 'self'",
    "default-src 'none'; connect-src 'self'",
  ])
    refuses({ csp: { chat: policy(bad) } }, /exactly 'self'|repeats the/u);
  assert.deepEqual(
    [...parsePolicy("a 'self' b; ;C  x y;")],
    [
      ["a", ["'self'", "b"]],
      ["c", ["x", "y"]],
    ],
  );
  assert.throws(() => parsePolicy("a x; A y"), /repeats the a directive/u);
});

test("page references are refused unless they are plain same-origin paths, in every quoting form", () => {
  const other = /another origin/u;
  for (const tag of [
    "<a href='https://cdn.example.test/x'>x</a>",
    "<img src=https://cdn.example.test/x.png>",
    "<img src=//cdn.example.test/x.png>",
    "<a href='//cdn.example.test/'>x</a>",
    '<a href = "https://cdn.example.test/">x</a>',
    '<A HREF="https://cdn.example.test/">x</A>',
    '<a href="/\\cdn.example.test/x">x</a>',
    "<a href=/\\cdn.example.test/x>x</a>",
    '<a href="\\\\cdn.example.test/x">x</a>',
    '<a href="/ok/\\x">x</a>',
    '<a href="/\tcdn.example.test/">x</a>',
    '<a href="data:text/html,x">x</a>',
    '<a href="javascript:void(0)">x</a>',
  ])
    refuses({ pages: { "account/index.html": page("account", tag) } }, other);
  // Plain absolute paths, fragments and all three quoting forms of them pass.
  const ok = `<a href="/a">1</a><a href='/b'>2</a><a href=/c>3</a><a href="#x">4</a>`;
  const built = bundle({ pages: { "account/index.html": page("account", ok) } });
  assert.equal(verifyProfileBundle(built.archive, built.digest).digest, built.digest);
});
