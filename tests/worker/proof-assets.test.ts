// SPDX-License-Identifier: AGPL-3.0-only
// Offline checks of the proof origin's static assets: the route precedence and the generated proof configuration
// (CLOUD.71), and the WEB.40 profile bundle: the pinned digest, the strict reader, the served layout, the pages, the
// policies and the headers. No network, no deployment and no release download.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { brotliCompressSync, gzipSync } from "node:zlib";
import { isProofPath } from "../../worker/foundation/proof-routes.ts";
import {
  buildProofConfig,
  composeHeaders,
  composeProofAssets,
  expectedProfileHeaders,
  expectedSiteHeaders,
  expectedSitePolicy,
  expectedProfilePolicy,
  parsePolicy,
  profileBundleAssetName,
  profileBundlePin,
  proofAssetsDirName,
  readBundleArchive,
  stageProfileAssets,
  stageProofAssets,
  verifyProfileBundle,
  verifySiteArchive,
  workerFirst,
  type CandidateConfig,
} from "../../eng/verification/proof-deploy.ts";

// ---- Synthetic WEB.40-shaped fixtures: the Web writers' formats, so that each test can damage one thing. ----
const sha = (value: Uint8Array | string) =>
  createHash("sha256").update(value).digest("hex");

function octal(value: number, length: number): string {
  return `${value.toString(8).padStart(length - 1, "0")}\0`;
}

/** One canonical ustar header: mode 0644, owner and time 0, a regular file with no names (the Web writer). */
function tarHeader(
  entryPath: string,
  size: number,
  options: { uid?: number; type?: string } = {},
): Buffer {
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

interface TarEntry {
  path: string;
  bytes: Uint8Array;
}

/** A ustar archive of the entries in the order given, closed by two zero blocks. */
function tarArchive(
  entries: TarEntry[],
  options: { uid?: number; type?: string } = {},
): Buffer {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    parts.push(tarHeader(entry.path, entry.bytes.byteLength, options), Buffer.from(entry.bytes));
    const pad = (512 - (entry.bytes.byteLength % 512)) % 512;
    if (pad > 0) parts.push(Buffer.alloc(pad));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

/** The application shell the Web publish writes (src/ArcForges.Web.App/wwwroot/index.html). */
const profileShell = [
  "<!DOCTYPE html>",
  '<html lang="en">',
  "<head>",
  '    <meta charset="utf-8" />',
  '    <meta name="viewport" content="width=device-width, initial-scale=1" />',
  '    <meta name="robots" content="noindex, nofollow" />',
  '    <meta name="theme-color" content="#f4f3ed" />',
  '    <link rel="icon" href="favicon.svg" type="image/svg+xml" />',
  "    <title>ArcForges</title>",
  '    <base href="/" />',
  '    <link rel="stylesheet" href="app.css" />',
  "</head>",
  "<body>",
  '    <div id="app">Loading…</div>',
  '    <div id="blazor-error-ui">',
  '        <span role="alert">An unhandled error has occurred. <a href="" class="reload">Reload</a></span>',
  '        <button type="button" class="dismiss" aria-label="Dismiss">&times;</button>',
  "    </div>",
  '    <script src="_framework/blazor.webassembly.js"></script>',
  "</body>",
  "</html>",
  "",
].join("\n");

/** The root files that the App publish and the Site share, byte for byte (the merge rule of the proof tree). */
const sharedFavicon = "<svg/>";
const sharedRobots = "User-agent: *\n";

interface ManifestDocument {
  schema: number;
  profiles: Record<string, { page: string; buildDigest: string; csp: string }>;
  files: Record<string, { sha256: string; bytes: number }>;
}

interface ProfileSpec {
  shell?: string;
  /** Files added to or replaced in the bundle, by path. */
  files?: Record<string, string | Uint8Array>;
  /** The headers file, when it is not the reviewed one. */
  headers?: string;
  /** The policy of a profile, when it is not the one its page derives. */
  csp?: Partial<Record<"account" | "chat", string>>;
  tamper?: (entries: TarEntry[]) => void;
  manifest?: (manifest: ManifestDocument) => void;
  tarOptions?: { uid?: number; type?: string };
}

const bytesOf = (value: string | Uint8Array): Buffer =>
  typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value);

/** A profile bundle with the WEB.40 layout, built from the reviewed writer's rules. */
function profileBundle(spec: ProfileSpec = {}): { archive: Buffer; digest: string } {
  const shell = spec.shell ?? profileShell;
  const policy = expectedProfilePolicy(shell);
  const policies = { account: spec.csp?.account ?? policy, chat: spec.csp?.chat ?? policy };
  const files: Record<string, string | Uint8Array> = {
    "account/index.html": shell,
    "chat/index.html": shell,
    "_framework/blazor.webassembly.js": "// loader",
    "_framework/blazor.webassembly.js.gz": gzipSync("// loader"),
    "_framework/dotnet.js": "// dotnet loader",
    "_framework/dotnet.runtime.a1b2c3d4e5.js": "export {};",
    "_framework/ArcForges.Web.App.w1s8cjv5ju.wasm": "\0asm",
    "_framework/ArcForges.Web.App.w1s8cjv5ju.wasm.br": brotliCompressSync("\0asm"),
    "_framework/ArcForges.Web.App.w1s8cjv5ju.wasm.gz": gzipSync("\0asm"),
    "app.css": "body{margin:0}",
    "favicon.svg": sharedFavicon,
    "robots.txt": sharedRobots,
    _headers: spec.headers ?? expectedProfileHeaders(policies),
    ...spec.files,
  };
  const names = Object.keys(files).sort();
  const manifest: ManifestDocument = {
    schema: 1,
    profiles: {
      account: { page: "account/index.html", buildDigest: sha("build"), csp: policies.account },
      chat: { page: "chat/index.html", buildDigest: sha("build"), csp: policies.chat },
    },
    files: Object.fromEntries(
      names.map((name) => {
        const bytes = bytesOf(files[name] ?? "");
        return [name, { sha256: sha(bytes), bytes: bytes.byteLength }];
      }),
    ),
  };
  spec.manifest?.(manifest);
  const entries: TarEntry[] = [
    { path: "manifest.json", bytes: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`) },
    ...names.map((name) => ({ path: name, bytes: bytesOf(files[name] ?? "") })),
  ];
  spec.tamper?.(entries);
  const archive = tarArchive(entries, spec.tarOptions);
  return { archive, digest: sha(archive) };
}

const wrangler = JSON.parse(
  readFileSync(path.resolve(import.meta.dirname, "../../wrangler.json"), "utf8"),
) as CandidateConfig;

const refuses = (spec: ProfileSpec, pattern: RegExp) => {
  const built = profileBundle(spec);
  assert.throws(() => verifyProfileBundle(built.archive, built.digest), pattern);
};
const accepts = (spec: ProfileSpec = {}) => {
  const built = profileBundle(spec);
  return verifyProfileBundle(built.archive, built.digest);
};
/** A bundle whose shell is changed; its policy follows the page, so only the change under test can fail. */
const withShell = (replace: (html: string) => string): ProfileSpec => ({
  shell: replace(profileShell),
});
const policyOf = (shell = profileShell) => expectedProfilePolicy(shell);

test("the Worker answers every one of its own route families before any asset", () => {
  const assets = (wrangler.env.proof as { assets?: Record<string, unknown> }).assets;
  assert(assets);
  assert.deepEqual(assets.run_worker_first, workerFirst);
  assert.deepEqual(workerFirst, ["/api/*", "/session/v1/*", "/proof/v1/*"]);
  assert.equal(assets.not_found_handling, "404-page");
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
  for (const pathname of ["/account/", "/chat/", "/_framework/blazor.webassembly.js", "/favicon.svg"])
    assert(!matches(pathname), pathname);
});

test("only the proof environment gains assets; production and the other bindings are unchanged", () => {
  const top = wrangler as unknown as Record<string, unknown>;
  assert.equal(top.assets, undefined);
  assert.equal(wrangler.env.proof.workers_dev, false);
  assert.equal(wrangler.env.proof.preview_urls, false);
  // The proof origin serves the Site 404 page for unknown paths, as production Web does; no other environment changes.
  assert.equal(wrangler.env.proof.assets?.not_found_handling, "404-page");
  assert.equal((wrangler as unknown as Record<string, unknown>).assets, undefined);
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

test("a well-formed WEB.40 bundle verifies and a digest that is not the pin is refused first", () => {
  const built = profileBundle();
  const verified = accepts();
  assert.equal(verified.digest, built.digest);
  assert.deepEqual(
    verified.files.map((file) => file.path).sort(),
    Object.keys(verified.manifest.files).sort(),
  );
  for (const served of [
    "_headers",
    "account/index.html",
    "chat/index.html",
    "app.css",
    "favicon.svg",
    "robots.txt",
    "_framework/blazor.webassembly.js",
    "_framework/ArcForges.Web.App.w1s8cjv5ju.wasm.br",
  ])
    assert(verified.files.some((file) => file.path === served), served);
  assert.equal(verified.files.some((file) => file.path === "manifest.json"), false);
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
        const entry = entries.find((item) => item.path === "app.css");
        assert(entry);
        entry.bytes = Buffer.from("body{margin:1}");
      },
    },
    /Content of app\.css/u,
  );
  refuses(
    {
      tamper: (entries) => {
        const entry = entries.find((item) => item.path === "app.css");
        assert(entry);
        entry.bytes = Buffer.from("body{margin:1px 2px}");
      },
    },
    /Size of app\.css/u,
  );
  refuses({ tamper: (entries) => entries.splice(1, 1) }, /exactly the manifest's files/u);
  refuses(
    { tamper: (entries) => entries.push({ path: "zz.txt", bytes: Buffer.from("x") }) },
    /exactly the manifest's files/u,
  );
  refuses(
    { tamper: (entries) => entries.unshift(entries.splice(1, 1)[0] as TarEntry) },
    /manifest must be the first/u,
  );
  refuses(
    {
      manifest: (manifest) => {
        manifest.schema = 2;
      },
    },
    /schema/u,
  );
  refuses(
    {
      manifest: (manifest) => {
        delete manifest.profiles.chat;
      },
    },
    /exactly the account and chat profiles/u,
  );
});

test("the archive reader accepts only plain regular files with the canonical header", () => {
  const good = tarArchive([{ path: "a.txt", bytes: Buffer.from("x") }]);
  assert.equal(readBundleArchive(good).length, 1);
  assert.throws(() => readBundleArchive(tarArchive([{ path: "a", bytes: Buffer.from("x") }], { uid: 1000 })), /canonical header/u);
  for (const type of ["5", "1", "2"])
    assert.throws(
      () => readBundleArchive(tarArchive([{ path: "a", bytes: Buffer.from("x") }], { type })),
      /canonical header/u,
    );
  assert.throws(() => readBundleArchive(good.subarray(0, good.length - 512)));
  assert.throws(() => readBundleArchive(Buffer.concat([good, Buffer.alloc(512)])), /follows/u);
  assert.throws(() => readBundleArchive(Buffer.concat([good, Buffer.alloc(512, 1)])));
  assert.throws(() => readBundleArchive(Buffer.alloc(100)), /Not a profile bundle/u);
  assert.throws(
    () => readBundleArchive(Buffer.alloc(25 * 1024 * 1024)),
    /larger than the limit/u,
  );
  for (const bad of ["../x", "/abs", "a//b", "a/../b", "with space"])
    assert.throws(
      () => readBundleArchive(tarArchive([{ path: bad, bytes: Buffer.alloc(0) }])),
      /plain relative path|canonical header/u,
      bad,
    );
  const tooMany = Array.from({ length: 401 }, (_, index) => ({
    path: `f${index}.txt`,
    bytes: Buffer.alloc(0),
  }));
  assert.throws(() => readBundleArchive(tarArchive(tooMany)), /Too many/u);
});

test("the served layout admits only the reviewed WEB.40 files and their own encodings", () => {
  refuses({ files: { "assets/entry.js": "export {};" } }, /outside the served layout/u);
  refuses({ files: { "_framework/app.js": "x" } }, /outside the served layout/u);
  refuses(
    { files: { "_framework/ArcForges.Web.App.w1s8cjv5j.wasm": "x" } },
    /outside the served layout/u,
  );
  refuses({ files: { "index.html": profileShell } }, /outside the served layout/u);
  refuses(
    { files: { "_framework/dotnet.runtime.a1b2c3d4e5.js.map": "{}" } },
    /outside the served layout/u,
  );
  refuses(
    { files: { "index.html.br": brotliCompressSync(profileShell) } },
    /encoded file without its plain file/u,
  );
  refuses(
    { files: { "_framework/x.abcdefghij.js.gz": gzipSync("x") } },
    /encoded file without its plain file/u,
  );
  refuses(
    { files: { "_framework/ArcForges.Web.App.w1s8cjv5ju.wasm.br": "not brotli" } },
    /does not decode to its plain file/u,
  );
  refuses(
    { files: { "app.css.gz": gzipSync("body{margin:1px}") } },
    /does not decode to its plain file/u,
  );
  refuses(
    {
      manifest: (manifest) => {
        delete manifest.files["account/index.html"];
      },
      tamper: (entries) => {
        entries.splice(entries.findIndex((entry) => entry.path === "account/index.html"), 1);
      },
    },
    /The bundle has no account\/index\.html/u,
  );
  // The encodings of the root app files and the framework are served as the Web publish writes them.
  const verified = accepts({
    files: {
      "app.css.br": brotliCompressSync("body{margin:0}"),
      "favicon.svg.gz": gzipSync(Buffer.from("<svg/>")),
    },
  });
  assert(verified.files.some((file) => file.path === "app.css.br"));
});

test("the two profile pages are one shell and every reference stays on the root", () => {
  refuses({ files: { "chat/index.html": profileShell.replace("Loading", "Wait") } }, /one application shell/u);
  refuses(withShell((html) => html.replace(/\n/gu, "\r\n")), /must use LF line ends/u);
  refuses(withShell((html) => html.replace('<base href="/" />', "")), /must set exactly one base/u);
  refuses(
    withShell((html) => html.replace('<base href="/" />', '<base href="/" /><base href="/" />')),
    /must set exactly one base/u,
  );
  refuses(withShell((html) => html.replace('<base href="/" />', '<base href="/account/" />')), /sets a base other than/u);
  refuses(
    withShell((html) => html.replace("_framework/blazor.webassembly.js", "https://cdn.example.com/b.js")),
    /references another origin/u,
  );
  refuses(
    withShell((html) => html.replace("_framework/blazor.webassembly.js", "//cdn.example.com/b.js")),
    /references another origin/u,
  );
  refuses(
    withShell((html) => html.replace("_framework/blazor.webassembly.js", "../_framework/blazor.webassembly.js")),
    /climbs out of the root/u,
  );
  refuses(
    withShell((html) => html.replace('<a href="" class="reload">', '<a href="javascript:void(0)" class="reload">')),
    /references another origin/u,
  );
  refuses(
    withShell((html) => html.replace('<a href="" class="reload">', '<a href="\\\\evil" class="reload">')),
    /control character, a backslash or an entity/u,
  );
  refuses(
    withShell((html) => html.replace('<a href="" class="reload">', '<a href="&#47;evil" class="reload">')),
    /control character, a backslash or an entity/u,
  );
  refuses(
    withShell((html) => html.replace("_framework/blazor.webassembly.js", "_framework/missing.js")),
    /references a file the bundle does not hold/u,
  );
  refuses(
    withShell((html) => html.replace("<title>", '<meta http-equiv="refresh" content="0;url=/x" /><title>')),
    /has a meta http-equiv/u,
  );
  // Empty and fragment references, relative references and the root base are the reviewed shape: accepted.
  assert.equal(accepts().digest.length, 64);
});

test("each profile's policy is the one its page derives, with the exact WebAssembly token set", () => {
  const derived = policyOf();
  assert.equal(
    derived,
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  );
  // An inline script of the page is covered by its hash in script-src, and by nothing else.
  const inline = profileShell.replace("</body>", "<script>window.p=1;</script></body>");
  assert.match(expectedProfilePolicy(inline), /script-src 'self' 'wasm-unsafe-eval' 'sha256-/u);
  accepts(withShell((html) => html.replace("</body>", "<script>window.p=1;</script></body>")));
  refuses(
    { shell: inline, csp: { account: derived, chat: derived } },
    /does not match its page/u,
  );
  // A policy that drops WebAssembly, adds unsafe-eval or widens a directive is refused.
  refuses({ csp: { account: derived.replace(" 'wasm-unsafe-eval'", "") } }, /does not match its page/u);
  refuses(
    { csp: { account: derived.replace("'wasm-unsafe-eval'", "'wasm-unsafe-eval' 'unsafe-eval'") } },
    /does not match its page/u,
  );
  refuses(
    { csp: { account: derived.replace("connect-src 'self'", "connect-src *") } },
    /does not match its page/u,
  );
  refuses(
    { csp: { chat: derived.replace("default-src 'self'", "default-src 'self' https:") } },
    /does not match its page/u,
  );
  refuses(
    {
      manifest: (manifest: ManifestDocument) => {
        const row = manifest.profiles.account;
        assert(row);
        row.csp = "default-src 'self'";
      },
    },
    /manifest policy of account differs from its rule/u,
  );
  // The policy is parsed as directives, and a repeated directive is refused.
  assert.deepEqual(
    [...parsePolicy("a 'self' b; ;C  x y;")],
    [
      ["a", ["'self'", "b"]],
      ["c", ["x", "y"]],
    ],
  );
  assert.throws(() => parsePolicy("a x; A y"), /repeats the a directive/u);
});

test("a policy over the Cloudflare header line budget is refused", () => {
  const scripts = Array.from(
    { length: 40 },
    (_, index) => `<script>window.n${index}=${index};</script>`,
  ).join("");
  refuses(withShell((html) => html.replace("</body>", `${scripts}</body>`)), /exceeds the header line budget/u);
});

test("the headers file is the reviewed one: rules unique, no policy on the shared rules, LF only", () => {
  const expected = accepts().headers;
  refuses({ headers: `${expected}/account/*\n  X-A: b\n` }, /Duplicate headers rule \/account\/\*/u);
  refuses(
    { headers: expected.replace("/*\n  X-Content-Type-Options", "/*\n  Content-Security-Policy: default-src 'self'\n  X-Content-Type-Options") },
    /must not carry a policy/u,
  );
  refuses({ headers: `${expected}/extra/*\n  X-A: b\n` }, /differs from the reviewed rules/u);
  refuses({ headers: expected.replace(/\n/gu, "\r\n") }, /headers file must use LF/u);
});

test("stylesheets of the bundle import only paths that stay on the root", () => {
  refuses({ files: { "app.css": '@import "https://cdn.example.com/x.css";' } }, /violates the same-origin rules/u);
  accepts({ files: { "app.css": '@import "/fonts.css";' } });
});

test("staging writes the verified files without the manifest into a fresh directory of the fixed name", async () => {
  const verified = accepts();
  const parent = await mkdtemp(path.join(tmpdir(), "arcforges-proof-"));
  try {
    const target = path.join(parent, proofAssetsDirName);
    assert.equal(await stageProfileAssets(verified, target), verified.files.length);
    assert.equal(await stageProfileAssets(verified, target), verified.files.length);
    assert((await stat(path.join(target, "_headers"))).isFile());
    await assert.rejects(stat(path.join(target, "manifest.json")));
    await assert.rejects(
      stageProfileAssets(verified, path.join(parent, "elsewhere")),
      /Unexpected staging directory/u,
    );
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

// ---- The Site (WEB.40 web-site-<sha256>.tar): the Site builder's members, pages and headers, as synthetic bytes. ----
const siteCss = "body{margin:0}";
const siteStylesheetPath = `assets/site.${sha(siteCss).slice(0, 16)}.css`;
const sourceLink = `https://github.com/ArcForges/Web/tree/${"a".repeat(40)}`;
const sitePage = (title: string, body: string) =>
  [
    "<!DOCTYPE html>",
    '<html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><meta name="robots" content="noindex, nofollow" /><meta name="theme-color" content="#f4f3ed" /><link rel="icon" href="/favicon.svg" type="image/svg+xml" />',
    `<title>${title}</title><link rel="stylesheet" href="/${siteStylesheetPath}" /></head><body>`,
    `<div class="site-shell"><a class="skip-link" href="#main">Skip to content</a><header><a class="brand" href="/">ArcForges</a><nav><a href="/hello">Hello example</a><a class="source-link" href="${sourceLink}">Source</a></nav></header>`,
    `<main id="main" tabindex="-1">${body}</main><footer><a href="/license.txt">AGPL-3.0-only</a></footer></div></body></html>`,
  ].join("");
const sitePageNames = ["index.html", "hello/index.html", "cloud-hello/index.html"];
const sitePages = (): Record<string, string> => ({
  "index.html": sitePage("Hello, world. — ArcForges", "<h1>Hello, world.</h1>"),
  "hello/index.html": sitePage("Your hello — ArcForges", "<h1>Your hello</h1>"),
  "cloud-hello/index.html": sitePage("Server connection — ArcForges", "<h1>Server connection</h1>"),
});
const notFoundPage =
  '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" /><link rel="stylesheet" href="/404.css" /><link rel="icon" href="/favicon.svg" /><title>Not found</title></head><body><a href="/">← Back home</a></body></html>';

export interface SiteSpec {
  /** Members added to or replaced in the Site, by path (the pages and the policy follow them). */
  files?: Record<string, string>;
  headers?: string;
  tamper?: (entries: TarEntry[]) => void;
  tarOptions?: { uid?: number; type?: string };
}

/** A Site archive with the Site builder's members, pages, policy and headers. */
function siteArchive(spec: SiteSpec = {}): { archive: Buffer; digest: string } {
  const members: Record<string, string> = {
    "404.css": siteCss,
    "404.html": notFoundPage,
    "favicon.svg": sharedFavicon,
    "robots.txt": sharedRobots,
    [siteStylesheetPath]: siteCss,
    ...sitePages(),
    ...spec.files,
  };
  const policy = expectedSitePolicy(sitePageNames.map((name) => members[name] ?? ""));
  members._headers = spec.headers ?? expectedSiteHeaders(policy);
  const entries: TarEntry[] = Object.keys(members)
    .sort()
    .map((entryPath) => ({ path: entryPath, bytes: Buffer.from(members[entryPath] ?? "") }));
  spec.tamper?.(entries);
  const archive = tarArchive(entries, spec.tarOptions);
  return { archive, digest: sha(archive) };
}
const acceptsSite = (spec: SiteSpec = {}) => {
  const built = siteArchive(spec);
  return verifySiteArchive(built.archive, built.digest);
};
const refusesSite = (spec: SiteSpec, pattern: RegExp) => {
  const built = siteArchive(spec);
  assert.throws(() => verifySiteArchive(built.archive, built.digest), pattern);
};

test("the Site archive verifies against its pinned digest with its exact members, policy and headers", () => {
  const built = siteArchive();
  const site = verifySiteArchive(built.archive, built.digest);
  assert.equal(site.digest, built.digest);
  assert.deepEqual(site.files.map((file) => file.path), [
    "404.css",
    "404.html",
    "_headers",
    siteStylesheetPath,
    "cloud-hello/index.html",
    "favicon.svg",
    "hello/index.html",
    "index.html",
    "robots.txt",
  ]);
  assert.equal(
    site.policy,
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  );
  assert.throws(() => verifySiteArchive(built.archive, sha("other")), /pinned digest/u);
  assert.throws(() => verifySiteArchive(built.archive, "abc"), /not a SHA-256/u);
});

test("the Site archive is refused for a non-canonical header, an order, a member set or a stylesheet count", () => {
  refusesSite({ tarOptions: { uid: 1000 } }, /canonical header/u);
  refusesSite({ tamper: (entries) => entries.reverse() }, /ordinal path order/u);
  refusesSite({ files: { "extra.txt": "x" } }, /members other than the reviewed Site/u);
  refusesSite(
    { tamper: (entries) => entries.splice(entries.findIndex((entry) => entry.path === "404.html"), 1) },
    /members other than the reviewed Site/u,
  );
  refusesSite(
    { files: { "assets/site.0123456789abcdef.css": "x" } },
    /exactly one content-hashed stylesheet/u,
  );
});

test("the Site policy never carries WebAssembly, and its headers file is the reviewed one", () => {
  const policy = acceptsSite().policy;
  refusesSite(
    { headers: expectedSiteHeaders(policy.replace("script-src 'self'", "script-src 'self' 'wasm-unsafe-eval'")) },
    /WebAssembly token/u,
  );
  refusesSite({ headers: `${expectedSiteHeaders(policy)}/extra/*\n  X-A: b\n` }, /differs from the reviewed rules/u);
  refusesSite({ headers: expectedSiteHeaders(policy).replace(/\n/gu, "\r\n") }, /headers file must use LF/u);
});

test("the Site pages are same-origin: no base, no foreign link but its source, every script covered", () => {
  refusesSite(
    { files: { "index.html": sitePage("x", "<p>x</p>").replace("<head>", "<head><base href=\"/\" />") } },
    /violates the Site's same-origin rules/u,
  );
  refusesSite(
    { files: { "index.html": sitePage("x", '<a href="https://evil.example/">x</a>') } },
    /violates the Site's same-origin rules/u,
  );
  refusesSite(
    { files: { "hello/index.html": sitePage("x", '<a href="hello">x</a>') } },
    /violates the Site's same-origin rules/u,
  );
  refusesSite(
    { files: { "index.html": sitePage("x", '<link rel="stylesheet" href="/assets/missing.css" />') } },
    /violates the Site's same-origin rules/u,
  );
  refusesSite(
    { files: { "404.html": notFoundPage.replace("</body>", "<script>window.x=1;</script></body>") } },
    /does not cover an inline script/u,
  );
  refusesSite(
    { files: { "index.html": `${sitePage("x", "<p>x</p>")}\r` } },
    /must use LF line ends/u,
  );
  refusesSite(
    { tamper: (entries) => {
      const entry = entries.find((item) => item.path === siteStylesheetPath);
      assert(entry);
      entry.bytes = Buffer.from('@import "https://cdn.example.com/x.css";');
    } },
    /violates the Site's same-origin rules/u,
  );
});

test("the profile and the Site are one proof tree with one headers file", () => {
  const profile = accepts();
  const site = acceptsSite();
  const assets = composeProofAssets(profile, site);
  const paths = assets.files.map((file) => file.path);
  assert.equal(new Set(paths).size, paths.length);
  assert.equal(paths.filter((entryPath) => entryPath === "_headers").length, 1);
  for (const served of [
    "index.html",
    "404.html",
    siteStylesheetPath,
    "account/index.html",
    "chat/index.html",
    "_framework/blazor.webassembly.js",
    "app.css",
    "favicon.svg",
    "robots.txt",
  ])
    assert(paths.includes(served), served);
  assert.equal(paths.includes("manifest.json"), false);
  assert.deepEqual(paths, [...paths].sort());
  const union = new Set([...profile.files, ...site.files].map((file) => file.path));
  assert.equal(paths.length, union.size);
  assert.equal(assets.profileDigest, profile.digest);
  assert.equal(assets.siteDigest, site.digest);
  assert.deepEqual(composeProofAssets(accepts(), acceptsSite()).files, assets.files, "deterministic");
});

test("identical shared root files merge, and a differing one refuses the tree", () => {
  assert.equal(
    composeProofAssets(accepts(), acceptsSite()).files.filter((file) => file.path === "favicon.svg")
      .length,
    1,
  );
  assert.throws(
    () =>
      composeProofAssets(accepts({ files: { "favicon.svg": "<svg/><!-- other -->" } }), acceptsSite()),
    /different bytes at favicon\.svg/u,
  );
  assert.throws(
    () => composeProofAssets(accepts(), acceptsSite({ files: { "robots.txt": "User-agent: x\n" } })),
    /different bytes at robots\.txt/u,
  );
});

test("the Site may not hold a file under a profile route", () => {
  const site = acceptsSite();
  const forged = { ...site, files: [...site.files, { path: "chat/index.html", bytes: Buffer.from("x") }] };
  assert.throws(
    () => composeProofAssets(accepts(), forged),
    /path the profiles serve: chat\/index\.html/u,
  );
});

test("the composed headers keep each surface's rules and unset the Site policy under the profiles", () => {
  const site = acceptsSite();
  const accountPolicy = expectedProfilePolicy(profileShell);
  const expected = [
    "/*",
    `  Content-Security-Policy: ${site.policy}`,
    "  X-Content-Type-Options: nosniff",
    "  Referrer-Policy: no-referrer",
    "  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
    "  X-Frame-Options: DENY",
    "  X-Robots-Tag: noindex, nofollow",
    "  Cache-Control: public, no-cache, no-transform",
    "/assets/*",
    "  ! Cache-Control",
    "  Cache-Control: public, max-age=31536000, immutable, no-transform",
    "/__build.json",
    "  ! Cache-Control",
    "  Cache-Control: no-store, no-transform",
    "/__build-info.json",
    "  ! Cache-Control",
    "  Cache-Control: no-store, no-transform",
    "/account/*",
    "  ! Content-Security-Policy",
    `  Content-Security-Policy: ${accountPolicy}`,
    "/chat/*",
    "  ! Content-Security-Policy",
    `  Content-Security-Policy: ${accountPolicy}`,
    "/_framework/*",
    "  ! Cache-Control",
    "  Cache-Control: public, max-age=31536000, immutable, no-transform",
    "/_framework/blazor.webassembly.js",
    "  ! Cache-Control",
    "  Cache-Control: public, no-cache, no-transform",
    "/_framework/dotnet.js",
    "  ! Cache-Control",
    "  Cache-Control: public, no-cache, no-transform",
  ];
  assert.equal(composeProofAssets(accepts(), site).headers, `${expected.join("\n")}\n`);
});

test("the header merge keeps one line, refuses a conflict and unsets an inherited value", () => {
  assert.equal(composeHeaders("/*\n  X-A: 1\n", "/*\n  X-A: 1\n"), "/*\n  X-A: 1\n");
  assert.throws(() => composeHeaders("/*\n  X-A: 1\n", "/*\n  X-A: 2\n"), /differently on \/\*/u);
  assert.equal(composeHeaders("/*\n  X-A: 1\n", "/x/*\n  X-A: 1\n"), "/*\n  X-A: 1\n");
  assert.equal(
    composeHeaders("/*\n  X-A: 1\n", "/x/*\n  X-A: 2\n"),
    "/*\n  X-A: 1\n/x/*\n  ! X-A\n  X-A: 2\n",
  );
  assert.equal(
    composeHeaders("/*\n  X-A: 1\n", "/x/*\n  ! X-A\n  X-A: 1\n"),
    "/*\n  X-A: 1\n/x/*\n  ! X-A\n  X-A: 1\n",
  );
  assert.throws(() => composeHeaders("/*\n  X-A: 1\n", ""), /LF line ends/u);
  assert.throws(() => composeHeaders("/*\n  X-A 1\n", "/x/*\n  X-A: 1\n"), /not a plain header/u);
  assert.throws(() => composeHeaders("/*\n  X-A: 1\n/*\n  X-B: 2\n", "/x/*\n  X-A: 1\n"), /Duplicate headers rule/u);
});

test("the composed proof tree stages into the fixed directory with its one headers file", async () => {
  const assets = composeProofAssets(accepts(), acceptsSite());
  const parent = await mkdtemp(path.join(tmpdir(), "arcforges-proof-tree-"));
  try {
    const target = path.join(parent, proofAssetsDirName);
    assert.equal(await stageProofAssets(assets, target), assets.files.length);
    assert.equal(await readFile(path.join(target, "_headers"), "utf8"), assets.headers);
    assert.equal(await readFile(path.join(target, siteStylesheetPath), "utf8"), siteCss);
    await assert.rejects(
      stageProofAssets(assets, path.join(parent, "elsewhere")),
      /Unexpected staging directory/u,
    );
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});
