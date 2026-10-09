// SPDX-License-Identifier: AGPL-3.0-only
// Offline checks of the proof origin's static assets: the route precedence and the generated proof configuration
// (CLOUD.71), and the WEB.40 profile bundle: the pinned digest, the strict reader, the served layout, the pages, the
// policies and the headers. No network, no deployment and no release download.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
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
  siteArchiveAssetName,
  siteArchivePin,
  stageProofAssets,
  verifyProfileBundle,
  verifySiteArchive,
  workerFirst,
  type CandidateConfig,
} from "../../eng/verification/proof-deploy.ts";

// ---- Synthetic WEB.40-shaped fixtures: the Web writers' formats, so that each test can damage one thing. ----
const sha = (value: Uint8Array | string) => createHash("sha256").update(value).digest("hex");

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
function tarArchive(entries: TarEntry[], options: { uid?: number; type?: string } = {}): Buffer {
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
  for (const pathname of [
    "/account/",
    "/chat/",
    "/_framework/blazor.webassembly.js",
    "/favicon.svg",
  ])
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

test("the pins name the WEB.40 release assets by their own digests, one release for both", () => {
  assert.equal(profileBundlePin.repository, "ArcForges/Web");
  assert.equal(profileBundlePin.release, "web-0.1.0-ci.111.1");
  assert.equal(
    profileBundlePin.digest,
    "4afc8f285a7a64202ce221bc4e3011a9f8b6de641d50eef0a537677e80eaef9a",
  );
  assert.equal(
    profileBundleAssetName(profileBundlePin.digest),
    `web-profiles-${profileBundlePin.digest}.tar`,
  );
  assert.equal(siteArchivePin.repository, profileBundlePin.repository);
  assert.equal(siteArchivePin.release, profileBundlePin.release);
  assert.equal(
    siteArchivePin.digest,
    "573575617dec11d2d3678bf5ccd92728190b64a79e7907e050764fd8a1d131ac",
  );
  assert.equal(
    siteArchiveAssetName(siteArchivePin.digest),
    `web-site-${siteArchivePin.digest}.tar`,
  );
});

test("the retired React pin is no longer referenced by the proof sources", () => {
  for (const rel of [
    "eng/verification/proof-deploy.ts",
    "eng/verification/proof-cloudflare.ts",
    "wrangler.json",
  ]) {
    const source = readFileSync(path.resolve(import.meta.dirname, "../..", rel), "utf8");
    assert(!source.includes("web-0.1.0-ci.90.1"), rel);
    assert(
      !source.includes("67956d7f4b3d2909625585ca68f19f3f8a9ea27a5a08958659b9d9841871f996"),
      rel,
    );
  }
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
    assert(
      verified.files.some((file) => file.path === served),
      served,
    );
  assert.equal(
    verified.files.some((file) => file.path === "manifest.json"),
    false,
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
  assert.throws(
    () => readBundleArchive(tarArchive([{ path: "a", bytes: Buffer.from("x") }], { uid: 1000 })),
    /canonical header/u,
  );
  for (const type of ["5", "1", "2"])
    assert.throws(
      () => readBundleArchive(tarArchive([{ path: "a", bytes: Buffer.from("x") }], { type })),
      /canonical header/u,
    );
  assert.throws(() => readBundleArchive(good.subarray(0, good.length - 512)));
  assert.throws(() => readBundleArchive(Buffer.concat([good, Buffer.alloc(512)])), /follows/u);
  assert.throws(() => readBundleArchive(Buffer.concat([good, Buffer.alloc(512, 1)])));
  assert.throws(() => readBundleArchive(Buffer.alloc(100)), /Not a profile bundle/u);
  assert.throws(() => readBundleArchive(Buffer.alloc(25 * 1024 * 1024)), /larger than the limit/u);
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
        entries.splice(
          entries.findIndex((entry) => entry.path === "account/index.html"),
          1,
        );
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
  refuses(
    { files: { "chat/index.html": profileShell.replace("Loading", "Wait") } },
    /one application shell/u,
  );
  refuses(
    withShell((html) => html.replace(/\n/gu, "\r\n")),
    /must use LF line ends/u,
  );
  refuses(
    withShell((html) => html.replace('<base href="/" />', "")),
    /must set exactly one base/u,
  );
  refuses(
    withShell((html) => html.replace('<base href="/" />', '<base href="/" /><base href="/" />')),
    /must set exactly one base/u,
  );
  refuses(
    withShell((html) => html.replace('<base href="/" />', '<base href="/account/" />')),
    /sets a base other than/u,
  );
  refuses(
    withShell((html) =>
      html.replace("_framework/blazor.webassembly.js", "https://cdn.example.com/b.js"),
    ),
    /references another origin/u,
  );
  refuses(
    withShell((html) => html.replace("_framework/blazor.webassembly.js", "//cdn.example.com/b.js")),
    /references another origin/u,
  );
  refuses(
    withShell((html) =>
      html.replace("_framework/blazor.webassembly.js", "../_framework/blazor.webassembly.js"),
    ),
    /climbs out of the root/u,
  );
  refuses(
    withShell((html) =>
      html.replace('<a href="" class="reload">', '<a href="javascript:void(0)" class="reload">'),
    ),
    /references another origin/u,
  );
  refuses(
    withShell((html) =>
      html.replace('<a href="" class="reload">', '<a href="\\\\evil" class="reload">'),
    ),
    /control character, a backslash or an entity/u,
  );
  refuses(
    withShell((html) =>
      html.replace('<a href="" class="reload">', '<a href="&#47;evil" class="reload">'),
    ),
    /control character, a backslash or an entity/u,
  );
  // A leading or trailing space is not a control character, but browsers strip it from a URL attribute before
  // resolving, so " //host" and " javascript:" would leave the origin. Every padded form is refused as written.
  for (const padded of [
    " //evil.example.test/x",
    " javascript:alert(1)",
    "//evil.example.test/x ",
  ]) {
    refuses(
      withShell((html) =>
        html.replace('<a href="" class="reload">', `<a href="${padded}" class="reload">`),
      ),
      /has leading or trailing whitespace/u,
    );
    refuses(
      withShell((html) =>
        html.replace(
          '<script src="_framework/blazor.webassembly.js"></script>',
          `<script src="${padded}"></script>`,
        ),
      ),
      /has leading or trailing whitespace/u,
    );
    refuses(
      withShell((html) =>
        html.replace('<div id="app">', `<form action="${padded}"></form><div id="app">`),
      ),
      /has leading or trailing whitespace/u,
    );
  }
  refuses(
    withShell((html) =>
      html.replace(
        '<a href="" class="reload">',
        '<a href="\t//evil.example.test/x" class="reload">',
      ),
    ),
    /control character, a backslash or an entity/u,
  );
  refuses(
    { files: { "app.css": '@import " //evil.example.test/x.css";' } },
    /violates the same-origin rules/u,
  );
  refuses(
    { files: { "app.css": '@import url( "javascript:alert(1)");' } },
    /violates the same-origin rules/u,
  );
  refuses(
    withShell((html) => html.replace("_framework/blazor.webassembly.js", "_framework/missing.js")),
    /references a file the bundle does not hold/u,
  );
  refuses(
    withShell((html) =>
      html.replace("<title>", '<meta http-equiv="refresh" content="0;url=/x" /><title>'),
    ),
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
  refuses({ shell: inline, csp: { account: derived, chat: derived } }, /does not match its page/u);
  // A policy that drops WebAssembly, adds unsafe-eval or widens a directive is refused.
  refuses(
    { csp: { account: derived.replace(" 'wasm-unsafe-eval'", "") } },
    /does not match its page/u,
  );
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
  refuses(
    withShell((html) => html.replace("</body>", `${scripts}</body>`)),
    /exceeds the header line budget/u,
  );
});

test("the headers file is the reviewed one: rules unique, no policy on the shared rules, LF only", () => {
  const expected = accepts().headers;
  refuses(
    { headers: `${expected}/account/*\n  X-A: b\n` },
    /Duplicate headers rule \/account\/\*/u,
  );
  refuses(
    {
      headers: expected.replace(
        "/*\n  X-Content-Type-Options",
        "/*\n  Content-Security-Policy: default-src 'self'\n  X-Content-Type-Options",
      ),
    },
    /must not carry a policy/u,
  );
  refuses({ headers: `${expected}/extra/*\n  X-A: b\n` }, /differs from the reviewed rules/u);
  refuses({ headers: expected.replace(/\n/gu, "\r\n") }, /headers file must use LF/u);
});

test("stylesheets of the bundle import only paths that stay on the root", () => {
  refuses(
    { files: { "app.css": '@import "https://cdn.example.com/x.css";' } },
    /violates the same-origin rules/u,
  );
  accepts({ files: { "app.css": '@import "/fonts.css";' } });
});

// ---- Refusals of the CLOUD.71 verifier, restated for the WEB.40 shell. Each probe changes one thing. ----
/** The reviewed shell with one fragment before </body>; its policy is derived from the probed page. */
const shellWith = (fragment: string) => profileShell.replace("</body>", `${fragment}</body>`);
/** Both profile pages hold the same probe bytes, while the policies stay the reviewed shell's. */
const samePages = (html: string): ProfileSpec => ({
  files: { "account/index.html": html, "chat/index.html": html },
});
/** The reviewed shell with one fragment at the start of the application root; the policy follows the page. */
const withFragment = (fragment: string): ProfileSpec =>
  withShell((html) => html.replace('<div id="app">', `${fragment}<div id="app">`));
const derivedPolicy = () => policyOf();
const manifestRow = (manifest: ManifestDocument, name: string) => {
  const row = manifest.profiles[name];
  assert(row);
  return row;
};

test("an inline script is found in every start-tag form and must be covered in script-src itself", () => {
  const uncovered = /does not match its page/u;
  // Whatever its start tag looks like, an inline script is found, and the policy of the shell does not cover it.
  for (const tag of [
    "<script/x>window.other = 1;</script>",
    "<script\n>window.other = 1;</script>",
    '<script data-x="src=1">window.other = 1;</script>',
    "<SCRIPT>window.other = 1;</SCRIPT >",
    "<Script type=module>window.other = 1;</script\n>",
  ])
    refuses(samePages(shellWith(tag)), uncovered);
  // An external script (a real src attribute in either form) needs no hash, and its body text is not executed inline.
  for (const external of [
    "<script src=/_framework/dotnet.js></script>",
    "<script/src=/_framework/dotnet.js></script>",
    "<script src=/_framework/dotnet.js>not executed</script>",
  ])
    accepts({ shell: shellWith(external) });
  // The hash must be in script-src itself: the same hash in style-src does not cover the script.
  const probe = shellWith('<script>window.p="probe";</script>');
  const hash = `'sha256-${createHash("sha256").update('window.p="probe";').digest("base64")}'`;
  const policy = derivedPolicy();
  refuses(
    {
      ...samePages(probe),
      csp: {
        account: policy.replace("style-src 'self'", `style-src 'self' ${hash}`),
        chat: policy,
      },
    },
    uncovered,
  );
  refuses(
    {
      ...samePages(probe),
      csp: {
        account: policy.replace("script-src", "x-script-src"),
        chat: policy.replace("script-src", "x-script-src"),
      },
    },
    uncovered,
  );
});

test("page references are refused unless they are plain same-origin paths, in every quoting form", () => {
  const other = /another origin/u;
  const control = /control character, a backslash or an entity/u;
  for (const [tag, pattern] of [
    ["<a href='https://cdn.example.test/x'>x</a>", other],
    ["<img src=https://cdn.example.test/x.png>", other],
    ["<img src=//cdn.example.test/x.png>", other],
    ["<a href='//cdn.example.test/'>x</a>", other],
    ['<a href = "https://cdn.example.test/">x</a>', other],
    ['<A HREF="https://cdn.example.test/">x</A>', other],
    ['<a href="/\\cdn.example.test/x">x</a>', control],
    ["<a href=/\\cdn.example.test/x>x</a>", control],
    ['<a href="\\\\cdn.example.test/x">x</a>', control],
    ['<a href="/ok/\\x">x</a>', control],
    ['<a href="/\tcdn.example.test/">x</a>', control],
    ['<a href="data:text/html,x">x</a>', other],
    ['<a href="javascript:void(0)">x</a>', other],
  ] as const)
    refuses(withFragment(tag), pattern);
  // Plain absolute paths, fragments and all three quoting forms of them pass.
  accepts(withFragment(`<a href="/a">1</a><a href='/b'>2</a><a href=/c>3</a><a href="#x">4</a>`));
});

test("slash-separated attributes, entities and every other url-bearing form stay on this origin", () => {
  const other = /violates the same-origin rules/u;
  const evil = "https://evil.example.test/x";
  for (const tag of [
    `<script/src=${evil}.js></script>`,
    `<link/href=${evil}.css rel=stylesheet>`,
    `<img/src=${evil}.png>`,
    `<img\n/src=${evil}.png>`,
    `<img / src='${evil}.png'>`,
    `<a title="a>b" href="${evil}">x</a>`,
    '<a href="/&#x2F;evil.example.test">x</a>',
    '<a href="/&#92;evil.example.test">x</a>',
    '<a href="/&sol;evil.example.test">x</a>',
    '<a href="/a&amp;b">x</a>',
    '<a href="#a&b">x</a>',
    `<img srcset="${evil}.png 1x, /b.png 2x">`,
    '<img srcset="/a.png 1x, //evil.example.test/b.png 2x">',
    '<img srcset="/a&#x2F;b.png 1x">',
    `<meta http-equiv=refresh content="0;url=${evil}">`,
    '<meta http-equiv="Refresh" content="0;url=/ok">',
    `<form action="${evil}"></form>`,
    `<form><button formaction="${evil}">x</button></form>`,
    `<object data="${evil}"></object>`,
    `<video poster="${evil}.png"></video>`,
    `<html manifest=${evil}></html>`,
    `<a ping="${evil}">x</a>`,
    `<blockquote cite="${evil}">x</blockquote>`,
    `<table background="${evil}.png"></table>`,
    // The first of two equal attributes is the one a browser uses.
    `<img src=${evil}.png src=/ok.png>`,
    `<style>@import url(${evil}.css);</style>`,
    `<style>@import "${evil}.css";</style>`,
    "<style>@import url('//evil.example.test/x.css');</style>",
    '<STYLE>@IMPORT URL("https://evil.example.test/x.css")</STYLE >',
  ])
    refuses(withFragment(tag), other);
  // A second base is refused by the one-base rule before any reference is read.
  refuses(withFragment('<base href="/ok/">'), /must set exactly one base/u);
  const ok = [
    '<img src="/a.png" srcset="/a.png 1x, /b.png 2x"><form action="/ok"></form>',
    "<style>@import url('/assets/x.css');</style>",
    "<SCRIPT SRC=/_framework/dotnet.js></SCRIPT>",
    // An external script's body text is not executed inline and needs no hash.
    "<script src=/_framework/dotnet.js>not executed</script>",
    // Text in a script body is not markup; the shell's policy covers the body by its hash.
    '<script type="module">const x = "<img src=https://evil.example.test/y.png>";</script>',
  ];
  for (const tag of ok) accepts({ shell: shellWith(tag) });
});

test("the codebase, archive and imagesrcset attributes refuse a foreign entry in any position", () => {
  const other = /violates the same-origin rules/u;
  const evil = "https://evil.example.test";
  for (const tag of [
    `<object codebase="${evil}/"></object>`,
    '<applet codebase="//evil.example.test/" code="x.class"></applet>',
    '<object codebase=" //evil.example.test/"></object>',
    `<object archive="${evil}/a.jar"></object>`,
    // archive is a space-separated list, so a foreign second entry is refused as well.
    `<object archive="/a.jar ${evil}/b.jar"></object>`,
    '<applet archive="/a.jar //evil.example.test/b.jar" code="x.class"></applet>',
    `<link rel="preload" as="image" href="/a.png" imagesrcset="${evil}/a.png 1x">`,
    // imagesrcset is a candidate list, so a foreign second candidate is refused as well.
    `<link rel="preload" as="image" href="/a.png" imagesrcset="/a.png 1x, ${evil}/b.png 2x">`,
    '<link rel="preload" as="image" href="/a.png" imagesrcset="/a.png 1x, //evil.example.test/b.png 2x">',
  ])
    refuses(withFragment(tag), other);
  const ok = [
    '<object archive="/a.jar /b.jar" codebase="/"></object>',
    '<link rel="preload" as="image" href="/a.png" imagesrcset="/a.png 1x, /b.png 2x">',
  ];
  for (const tag of ok) accepts({ shell: shellWith(tag) });
});

test("script-src allows only 'self', 'wasm-unsafe-eval' and sha256 hashes", () => {
  const derived = derivedPolicy();
  for (const source of [
    "https:",
    "data:",
    "https://cdn.example.test",
    "'strict-dynamic'",
    "'nonce-abc123'",
    "'sha256-short'",
    `'sha384-${"A".repeat(64)}'`,
    "blob:",
    "'self'x",
  ])
    refuses(
      { csp: { chat: derived.replace("script-src 'self'", `script-src 'self' ${source}`) } },
      /does not match its page/u,
    );
  // The legitimate policy still passes (its own hash is a sha256 source).
  accepts();
});

test("a tag-like text in a covered script body neither hides a real tag after it nor counts as one", () => {
  const body = "if (a<b) { run(); }";
  const script = `<script>${body}</script>`;
  refuses(
    { shell: shellWith(`${script}<img src=https://evil.example.test/y.png>`) },
    /another origin/u,
  );
  accepts({ shell: shellWith(`${script}<img src=/y.png>`) });
});

test("each profile's policy must cover its own inline scripts and stay restrictive", () => {
  const uncovered = /does not match its page/u;
  const derived = derivedPolicy();
  // An inline script in any letter case or with a spaced closing tag must be covered as well.
  refuses(samePages(shellWith("<script>window.other = 1;</script junk>")), uncovered);
  for (const tag of ["SCRIPT", "Script"])
    refuses(samePages(shellWith(`<${tag}>window.other = 1;</${tag} >`)), uncovered);
  // A page whose inline script the policy of its shell does not cover is refused, in both profiles.
  refuses(samePages(shellWith('<script>window.p="account";</script>')), uncovered);
  refuses(
    { csp: { account: derived.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'") } },
    uncovered,
  );
  refuses({ csp: { chat: derived.replace("style-src 'self'", "style-src 'self' *") } }, uncovered);
  refuses(
    { csp: { chat: derived.replace("connect-src 'self'", "connect-src https:") } },
    uncovered,
  );
  refuses({ csp: { chat: derived.replace("default-src 'self'; ", "") } }, uncovered);
  refuses(
    {
      manifest: (manifest) => {
        manifestRow(manifest, "chat").csp = "x";
      },
    },
    /manifest policy of chat differs/u,
  );
  refuses(
    { headers: "/*\n  X: y\n/chat/*\n  Content-Security-Policy: x\n" },
    /No headers rule for \/account/u,
  );
});

test("default-src and connect-src must be exactly 'self' and a directive may not repeat", () => {
  const derived = derivedPolicy();
  for (const bad of [
    derived.replace("default-src 'self'", "default-src 'self' https:"),
    derived.replace("default-src 'self'", "default-src 'none'"),
    derived.replace("connect-src 'self'", "connect-src 'self' https://other.example.test"),
    derived.replace("connect-src 'self'", "x-connect-src 'self'"),
    derived.replace("connect-src 'self'", "connect-src 'self'; connect-src 'self'"),
  ])
    refuses({ csp: { chat: bad } }, /does not match its page/u);
  assert.throws(() => parsePolicy("a x; A y"), /repeats the a directive/u);
});

test("the site-wide and asset rules never carry a policy and every rule is unique", () => {
  const expected = accepts().headers;
  refuses(
    {
      headers: expected.replace(
        "/assets/*\n  ! Cache-Control",
        "/assets/*\n  Content-Security-Policy: default-src *\n  ! Cache-Control",
      ),
    },
    /\/assets\/\* rule must not carry a policy/u,
  );
  refuses({ headers: `${expected}/chat/*\n  X: y\n` }, /Duplicate headers rule \/chat\/\*/u);
});

test("the manifest names each profile's own page, and a build digest is a SHA-256", () => {
  refuses(
    {
      manifest: (manifest) => {
        manifestRow(manifest, "account").page = "chat/index.html";
      },
    },
    /manifest names another page for account/u,
  );
  refuses(
    {
      manifest: (manifest) => {
        manifestRow(manifest, "chat").page = "index.html";
      },
    },
    /manifest names another page for chat/u,
  );
  for (const digest of ["A".repeat(64), "f".repeat(63), ""])
    refuses(
      {
        manifest: (manifest) => {
          manifestRow(manifest, "chat").buildDigest = digest;
        },
      },
      /build digest of chat is not a SHA-256/u,
    );
});

test("only the root app files and the framework may have precompressed siblings", () => {
  refuses(
    { files: { "account/index.html.br": brotliCompressSync(profileShell) } },
    /encoded file without its plain file/u,
  );
  refuses(
    { files: { "chat/index.html.gz": gzipSync(profileShell) } },
    /encoded file without its plain file/u,
  );
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
  assert.deepEqual(
    site.files.map((file) => file.path),
    [
      "404.css",
      "404.html",
      "_headers",
      siteStylesheetPath,
      "cloud-hello/index.html",
      "favicon.svg",
      "hello/index.html",
      "index.html",
      "robots.txt",
    ],
  );
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
    {
      tamper: (entries) =>
        entries.splice(
          entries.findIndex((entry) => entry.path === "404.html"),
          1,
        ),
    },
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
    {
      headers: expectedSiteHeaders(
        policy.replace("script-src 'self'", "script-src 'self' 'wasm-unsafe-eval'"),
      ),
    },
    /WebAssembly token/u,
  );
  refusesSite(
    { headers: `${expectedSiteHeaders(policy)}/extra/*\n  X-A: b\n` },
    /differs from the reviewed rules/u,
  );
  refusesSite(
    { headers: expectedSiteHeaders(policy).replace(/\n/gu, "\r\n") },
    /headers file must use LF/u,
  );
});

test("the Site pages are same-origin: no base, no foreign link but its source, every script covered", () => {
  refusesSite(
    {
      files: {
        "index.html": sitePage("x", "<p>x</p>").replace("<head>", '<head><base href="/" />'),
      },
    },
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
    {
      files: {
        "index.html": sitePage("x", '<link rel="stylesheet" href="/assets/missing.css" />'),
      },
    },
    /violates the Site's same-origin rules/u,
  );
  refusesSite(
    {
      files: { "404.html": notFoundPage.replace("</body>", "<script>window.x=1;</script></body>") },
    },
    /does not cover an inline script/u,
  );
  refusesSite(
    { files: { "index.html": `${sitePage("x", "<p>x</p>")}\r` } },
    /must use LF line ends/u,
  );
  refusesSite(
    {
      tamper: (entries) => {
        const entry = entries.find((item) => item.path === siteStylesheetPath);
        assert(entry);
        entry.bytes = Buffer.from('@import "https://cdn.example.com/x.css";');
      },
    },
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
  assert.deepEqual(
    composeProofAssets(accepts(), acceptsSite()).files,
    assets.files,
    "deterministic",
  );
});

test("identical shared root files merge, and a differing one refuses the tree", () => {
  assert.equal(
    composeProofAssets(accepts(), acceptsSite()).files.filter((file) => file.path === "favicon.svg")
      .length,
    1,
  );
  assert.throws(
    () =>
      composeProofAssets(
        accepts({ files: { "favicon.svg": "<svg/><!-- other -->" } }),
        acceptsSite(),
      ),
    /different bytes at favicon\.svg/u,
  );
  assert.throws(
    () =>
      composeProofAssets(accepts(), acceptsSite({ files: { "robots.txt": "User-agent: x\n" } })),
    /different bytes at robots\.txt/u,
  );
});

test("the Site may not hold a file under a profile route", () => {
  const site = acceptsSite();
  const forged = {
    ...site,
    files: [...site.files, { path: "chat/index.html", bytes: Buffer.from("x") }],
  };
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
  assert.throws(
    () => composeHeaders("/*\n  X-A: 1\n/*\n  X-B: 2\n", "/x/*\n  X-A: 1\n"),
    /Duplicate headers rule/u,
  );
});

test("the composed proof tree stages into the fixed directory with its one headers file", async () => {
  const assets = composeProofAssets(accepts(), acceptsSite());
  const parent = await mkdtemp(path.join(tmpdir(), "arcforges-proof-tree-"));
  try {
    const target = path.join(parent, proofAssetsDirName);
    assert.equal(await stageProofAssets(assets, target), assets.files.length);
    assert.equal(await readFile(path.join(target, "_headers"), "utf8"), assets.headers);
    assert.equal(await readFile(path.join(target, siteStylesheetPath), "utf8"), siteCss);
    await assert.rejects(stat(path.join(target, "manifest.json")));
    await assert.rejects(
      stageProofAssets(assets, path.join(parent, "elsewhere")),
      /Unexpected staging directory/u,
    );
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("staging replaces the stale content of an earlier staging and leaves the directory beside it alone", async () => {
  const assets = composeProofAssets(accepts(), acceptsSite());
  const parent = await mkdtemp(path.join(tmpdir(), "arcforges-proof-stale-"));
  try {
    const target = path.join(parent, proofAssetsDirName);
    await writeFile(path.join(parent, "keep.txt"), "kept");
    assert.equal(await stageProofAssets(assets, target), assets.files.length);
    await writeFile(path.join(target, "stale.txt"), "stale");
    // Stale content of an earlier staging never survives a second staging of the same tree.
    assert.equal(await stageProofAssets(assets, target), assets.files.length);
    await assert.rejects(stat(path.join(target, "stale.txt")));
    assert.equal(await readFile(path.join(parent, "keep.txt"), "utf8"), "kept");
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});
