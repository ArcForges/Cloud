// SPDX-License-Identifier: AGPL-3.0-only
// Pure helpers of the proof-environment deployment: the isolated Wrangler configuration and the
// deployment secrets. The deployment itself runs only in the manually dispatched CI job
// (eng/verification/proof-cloudflare.ts); secrets are generated there at deploy time, handed to
// Wrangler through a runner-local file and never printed, committed or sent anywhere else.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { brotliDecompressSync, gunzipSync } from "node:zlib";
import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";

export const proofWorkerName = "arcforges-cloud-proof";
export const proofDatabaseName = "arcforges-proof-business";
export const proofBucketName = "arcforges-proof-objects";
export const proofQueueNames = ["arcforges-proof-wake", "arcforges-proof-wake-dlq"] as const;
export const proofHostname = "proof.arcforges.com";
/** The route families that the Worker answers before any static asset. */
export const workerFirst = ["/api/*", "/session/v1/*", "/proof/v1/*"];
/** Where the verified bundle is staged, beside the generated configuration (artifacts/). */
export const proofAssetsDirName = "proof-assets";

/**
 * The Web profile bundle served from the proof origin (CLOUD.71, moved to the WEB.40 release by CLOUD.85): the
 * immutable release asset that the Web main-push build publishes as `web-profiles-<digest>.tar`. Moving the pin is
 * a reviewed change; nothing is rebuilt here.
 */
export const profileBundlePin = {
  repository: "ArcForges/Web",
  release: "web-0.1.0-ci.111.1",
  digest: "4afc8f285a7a64202ce221bc4e3011a9f8b6de641d50eef0a537677e80eaef9a",
} as const;
export const profileBundleAssetName = (digest: string) => `web-profiles-${digest}.tar`;
/**
 * The Site archive of the same Web release (CLOUD.85 D2 option A): the C# public Site, a deterministic ustar whose
 * name is the digest of its own bytes. Moving the pin is a reviewed change, as for the profile bundle.
 */
export const siteArchivePin = {
  repository: "ArcForges/Web",
  release: "web-0.1.0-ci.111.1",
  digest: "573575617dec11d2d3678bf5ccd92728190b64a79e7907e050764fd8a1d131ac",
} as const;
export const siteArchiveAssetName = (digest: string) => `web-site-${digest}.tar`;

interface ProofEnvironment {
  name?: string;
  assets?: Record<string, unknown>;
  containers: { image: string; [key: string]: unknown }[];
  vars: Record<string, string>;
  d1_databases: { database_id?: string; [key: string]: unknown }[];
  [key: string]: unknown;
}
export interface CandidateConfig {
  name: string;
  main: string;
  env: { proof: ProofEnvironment };
  [key: string]: unknown;
}

/** The standalone config to deploy with `--env proof`: only the proof environment is customized. */
export function buildProofConfig(
  candidate: CandidateConfig,
  options: {
    account: string;
    imageDigest: string;
    revision: string;
    databaseId?: string;
    main: string;
    /** Relative to the directory of the generated configuration file; defaults to the staged profile assets. */
    assetsDir?: string;
    /** Relative to the directory of the generated configuration file. */
    migrationsDir?: string;
  },
): CandidateConfig {
  assert.match(
    options.account,
    /^[0-9a-f]{32}$/u,
    "Set CLOUDFLARE_ACCOUNT_ID to the 32-character account id.",
  );
  assert.match(
    options.imageDigest,
    /^[^\s@]+@sha256:[0-9a-f]{64}$/u,
    "A pinned registry image digest is required.",
  );
  assert(candidate.env?.proof, "The candidate has no proof environment.");
  assert.equal(candidate.env.proof.name, proofWorkerName);
  // workers.dev and preview URLs stay disabled, and the only ingress is the dedicated custom domain;
  // the production route arcforges.com/api/* belongs to the production Worker alone.
  assert.equal(candidate.env.proof.workers_dev, false, "workers.dev must stay disabled.");
  assert.equal(candidate.env.proof.preview_urls, false, "Preview URLs must stay disabled.");
  assert.deepEqual(candidate.env.proof.routes, [{ pattern: proofHostname, custom_domain: true }]);
  const config = structuredClone(candidate);
  config.main = options.main;
  (config as Record<string, unknown>).account_id = options.account;
  const proof = config.env.proof;
  assert.equal(proof.containers.length, 1);
  (proof.containers[0] as { image: string }).image = options.imageDigest;
  // Wrangler validates the top-level container image of the file even for `--env proof`; the
  // production definition is never deployed from this file, so it carries the same registry digest
  // instead of a Dockerfile path.
  const top = (config as Record<string, unknown>).containers as { image: string }[] | undefined;
  if (top?.[0]) top[0].image = options.imageDigest;
  proof.vars = { ...proof.vars, SOURCE_REVISION: options.revision };
  // The static profile assets: the directory staged from the verified bundle, with the Worker answering its own
  // route families first. Nothing else about the assets configuration is taken from the options.
  const assets = proof.assets;
  assert(assets, "The proof environment declares no static assets.");
  assert.deepEqual(
    assets.run_worker_first,
    workerFirst,
    "The Worker must answer its route families first.",
  );
  assets.directory = options.assetsDir ?? `./${proofAssetsDirName}`;
  if (options.databaseId !== undefined) {
    assert.match(
      options.databaseId,
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
    );
    (proof.d1_databases[0] as { database_id?: string }).database_id = options.databaseId;
  }
  if (options.migrationsDir !== undefined)
    (proof.d1_databases[0] as { migrations_dir?: string }).migrations_dir = options.migrationsDir;
  return config;
}

const base64Url = /^[A-Za-z0-9_-]{43}$/u;
/** Deployment secrets by Worker name; the pattern is the shape every consumer expects. */
export const secretSources = [
  { worker: "HMAC_C2W_SECRET", pattern: base64Url },
  { worker: "HMAC_W2C_SECRET", pattern: base64Url },
  { worker: "CSRF_SECRET", pattern: base64Url },
] as const;

/**
 * Fresh random proof secrets (256 bits each, unpadded base64url). The operator credential is not a
 * secret: the Worker trusts an operator public key (see proof-operator.ts), so no operator token exists.
 */
export function generateSecrets(
  random: (bytes: number) => Uint8Array = randomBytes,
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const source of secretSources) {
    const value = Buffer.from(random(32)).toString("base64url");
    // Messages name the secret and never echo a value.
    assert(source.pattern.test(value), `${source.worker} was not generated in the required shape.`);
    result[source.worker] = value;
  }
  assert.equal(
    new Set(Object.values(result)).size,
    secretSources.length,
    "Proof secrets must be distinct.",
  );
  return result;
}

// ---------------------------------------------------------------------------------------------------------------
// The profile bundle: strict reader and verification. The bundle is a plain POSIX ustar written by the Web build
// (tools/ArcForges.Web.Tooling/Profiles/ProfileBundle.cs, WEB.40); this reader accepts exactly that shape and refuses
// everything else. The served layout is the Web's: the shells at /account/ and /chat/ under base href "/", the framework
// at the root, and the root app files.

const block = 512;
const sha256Hex = (value: Uint8Array) => createHash("sha256").update(value).digest("hex");
const maxFiles = 400;
const maxBundleBytes = 24 * 1024 * 1024;
const headerLineBudget = 1800;
const profileNames = ["account", "chat"] as const;
const manifestName = "manifest.json";
const headersName = "_headers";
/** The unfingerprinted framework loaders, revalidated on every load (ProfileBundle.UnfingerprintedFrameworkLoaders). */
const frameworkLoaders = ["_framework/blazor.webassembly.js", "_framework/dotnet.js"];
/** The root files of the App publish that the bundle serves. The application shell itself is not served at the root. */
const appRootFiles = ["app.css", "favicon.svg", "robots.txt"];
/** A fingerprinted framework file: ten lower-case characters before the extension, as the SDK names them. */
const fingerprintedFramework = /^_framework\/[^/]+\.[a-z0-9]{10}\.(?:js|wasm|dat)$/u;
/** The suffix of a precompressed sibling of a plain file: Brotli (.br) or gzip (.gz). */
const encodingSuffix = /\.(?:br|gz)$/u;

export interface BundleEntry {
  path: string;
  bytes: Uint8Array;
}
export interface BundleManifest {
  schema: 1;
  profiles: Record<string, { page: string; buildDigest: string; csp: string }>;
  files: Record<string, { sha256: string; bytes: number }>;
}

function octal(value: number, length: number): string {
  const text = value.toString(8);
  assert(text.length < length, "Value does not fit its tar field");
  return `${text.padStart(length - 1, "0")}\0`;
}

/** The only header a bundle entry may have: regular file, mode 0644, owner 0, time 0, no names, no link. */
function canonicalHeader(entryPath: string, size: number): Buffer {
  const name = Buffer.from(entryPath, "ascii");
  const head = Buffer.alloc(block);
  name.copy(head, 0);
  head.write(octal(0o644, 8), 100, "ascii");
  head.write(octal(0, 8), 108, "ascii");
  head.write(octal(0, 8), 116, "ascii");
  head.write(octal(size, 12), 124, "ascii");
  head.write(octal(0, 12), 136, "ascii");
  head.fill(0x20, 148, 156);
  head.write("0", 156, "ascii");
  head.write("ustar\0", 257, "ascii");
  head.write("00", 263, "ascii");
  let sum = 0;
  for (const byte of head) sum += byte;
  head.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
  return head;
}

const safePath = /^[A-Za-z0-9_][A-Za-z0-9._-]*(?:\/[A-Za-z0-9_][A-Za-z0-9._-]*)*$/u;

export function readBundleArchive(archive: Uint8Array): BundleEntry[] {
  assert(archive.byteLength <= maxBundleBytes, "The bundle is larger than the limit.");
  const data = Buffer.from(archive);
  assert(data.length % block === 0 && data.length >= block * 2, "Not a profile bundle archive.");
  const entries: BundleEntry[] = [];
  let offset = 0;
  for (;;) {
    assert(offset + block <= data.length, "The archive ends without its terminator.");
    const head = data.subarray(offset, offset + block);
    if (head.every((byte) => byte === 0)) {
      assert(offset + block * 2 === data.length, "Data follows the archive terminator.");
      assert(
        data.subarray(offset + block).every((byte) => byte === 0),
        "Bad archive terminator.",
      );
      return entries;
    }
    assert(entries.length < maxFiles, "Too many entries.");
    const end = head.indexOf(0);
    const entryPath = head.subarray(0, end < 0 || end > 100 ? 100 : end).toString("ascii");
    assert(
      safePath.test(entryPath) && !entryPath.includes(".."),
      "An entry path is not a plain relative path.",
    );
    const size = Number.parseInt(head.subarray(124, 135).toString("ascii"), 8);
    assert(Number.isSafeInteger(size) && size >= 0, "An entry has a bad size.");
    assert(
      Buffer.compare(head, canonicalHeader(entryPath, size)) === 0,
      `Entry ${entryPath} is not a plain regular file with the canonical header.`,
    );
    const start = offset + block;
    assert(start + size <= data.length, `Entry ${entryPath} is truncated.`);
    entries.push({ path: entryPath, bytes: data.subarray(start, start + size) });
    offset = start + Math.ceil(size / block) * block;
  }
}

export interface VerifiedBundle {
  digest: string;
  manifest: BundleManifest;
  /** Every served file, including the headers file; the manifest is not served. */
  files: BundleEntry[];
  /** The headers file as the bundle writes it. */
  headers: string;
}

interface StartTag {
  name: string;
  /** Attribute names (lower case) to their raw values; a valueless attribute has the empty string. */
  attributes: Map<string, string>;
  /** Where the tag ends, so a script body can be read from there. */
  end: number;
}

/**
 * Every start tag of a document with its attributes, by one tokenizer for all checks. A tag name ends at
 * whitespace, a slash or the closing bracket; attributes are separated by whitespace or slashes, so
 * `<script/src=x>` has a src attribute; quoted values may contain `>`.
 */
function startTags(html: string): StartTag[] {
  const tags: StartTag[] = [];
  const pattern = /<([A-Za-z][^\s/>]*)((?:"[^"]*"|'[^']*'|[^>"'])*)>/gu;
  for (let tag = pattern.exec(html); tag !== null; tag = pattern.exec(html)) {
    const attributes = new Map<string, string>();
    for (const attribute of (tag[2] ?? "").matchAll(
      /([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/gu,
    )) {
      const name = (attribute[1] ?? "").toLowerCase();
      // The first occurrence of an attribute wins, as in a browser.
      if (!attributes.has(name))
        attributes.set(name, attribute[2] ?? attribute[3] ?? attribute[4] ?? "");
    }
    const name = (tag[1] ?? "").toLowerCase();
    const end = tag.index + tag[0].length;
    tags.push({ name, attributes, end });
    if (name === "script" || name === "style") {
      // The body is text, not markup: continue after its closing tag so `a<b` in a script cannot start a phantom tag.
      const close = new RegExp(`</${name}[^>]*>`, "giu");
      close.lastIndex = end;
      const found = close.exec(html);
      pattern.lastIndex = found ? found.index + found[0].length : html.length;
    }
  }
  return tags;
}

/** The sha256 source of every non-empty inline script body of a page (the Web's policy derivation). */
function inlineScriptHashes(html: string): string[] {
  const hashes: string[] = [];
  for (const tag of startTags(html)) {
    if (tag.name !== "script" || tag.attributes.has("src")) continue;
    const close = /<\/script[^>]*>/giu;
    close.lastIndex = tag.end;
    const found = close.exec(html);
    const body = html.slice(tag.end, found?.index ?? html.length);
    if (body === "") continue;
    hashes.push(`'sha256-${createHash("sha256").update(body).digest("base64")}'`);
  }
  return hashes;
}

/** The inline script sources of pages: unique and sorted, as the Web's SortedSet holds them. */
function inlineHashSet(pages: string[]): string[] {
  const hashes = new Set<string>();
  for (const html of pages) for (const hash of inlineScriptHashes(html)) hashes.add(hash);
  return [...hashes].sort();
}

/** The policy text that follows the script sources (WasmContentSecurityPolicy.FromHostPages). */
function policyText(scriptSources: string[]): string {
  return `default-src 'self'; script-src ${scriptSources.join(" ")}; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`;
}

/** The App profile policy the Web build derives from its shell: 'self', 'wasm-unsafe-eval' and the inline hashes. */
export function expectedProfilePolicy(page: string): string {
  return policyText(["'self'", "'wasm-unsafe-eval'", ...inlineHashSet([page])]);
}

/** The headers file the Web build writes for the two App profiles (ProfileBundle.HeadersText), byte for byte. */
export function expectedProfileHeaders(policies: Record<string, string | undefined>): string {
  const immutable = "  Cache-Control: public, max-age=31536000, immutable, no-transform";
  const lines = [
    "/*",
    "  X-Content-Type-Options: nosniff",
    "  Referrer-Policy: no-referrer",
    "  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
    "  X-Robots-Tag: noindex, nofollow",
  ];
  for (const name of profileNames)
    lines.push(
      `/${name}/*`,
      `  Content-Security-Policy: ${policies[name] ?? ""}`,
      "  X-Frame-Options: DENY",
      "  Cache-Control: public, no-cache, no-transform",
    );
  lines.push("/assets/*", "  ! Cache-Control", immutable, "/_framework/*", "  ! Cache-Control", immutable);
  for (const loader of frameworkLoaders)
    lines.push(`/${loader}`, "  ! Cache-Control", "  Cache-Control: public, no-cache, no-transform");
  return `${lines.join("\n")}\n`;
}

/** Why a reference leaves the root, or null when it stays on this origin. Relative references resolve to the root. */
function referenceProblem(reference: string, relative: boolean): string | null {
  const controlOrEntity =
    reference.includes("\\") ||
    reference.includes("&") ||
    [...reference].some((character) => character.charCodeAt(0) < 0x20 || character === "\x7f");
  if (controlOrEntity) return "uses a control character, a backslash or an entity";
  if (reference === "" || reference.startsWith("#")) return null;
  if (reference.startsWith("//") || /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(reference))
    return "references another origin";
  const pathPart = reference.split(/[?#]/u, 1)[0] ?? "";
  if (pathPart.split("/").includes("..")) return "climbs out of the root";
  if (!relative && !reference.startsWith("/")) return "uses a relative reference";
  return null;
}

/** The url attributes whose value must stay on this origin. */
const urlAttributes = [
  "src",
  "href",
  "action",
  "formaction",
  "poster",
  "data",
  "ping",
  "cite",
  "background",
  "manifest",
];

/** The served file a script, stylesheet or icon tag names (the root is the base), or undefined when it names none. */
function loadedFile(tag: StartTag): string | undefined {
  const rel = tag.attributes.get("rel") ?? "";
  const loads = /(?:^|\s)(?:stylesheet|icon)(?:\s|$)/iu.test(rel);
  const value =
    tag.name === "script"
      ? tag.attributes.get("src")
      : tag.name === "link" && loads
        ? tag.attributes.get("href")
        : undefined;
  if (value === undefined || value.startsWith("#")) return undefined;
  return value.startsWith("/") ? value.slice(1) : value;
}

interface PageRules {
  /** Whether relative references are allowed (the App shells, with base href "/"). */
  relative: boolean;
  /** Whether a base element is allowed; when it is, it must be exactly <base href="/">. */
  base: boolean;
  /** Whether a page may link to its own source repository (the public Site's shell only). */
  sourceLink: boolean;
  /** The files of the bundle that scripts, stylesheets and icons may load. */
  files: ReadonlySet<string>;
}

/** Everything in a page that could reach another origin, change its base or load a file the bundle does not hold. */
function pageViolations(html: string, rules: PageRules): string[] {
  const problems: string[] = [];
  const check = (attribute: string, value: string) => {
    const problem = referenceProblem(value, rules.relative);
    if (problem !== null) problems.push(`${problem}: ${attribute}=${value}`);
  };
  for (const tag of startTags(html)) {
    for (const attribute of urlAttributes) {
      const value = tag.attributes.get(attribute);
      if (value === undefined) continue;
      const repository =
        rules.sourceLink && tag.name === "a" && attribute === "href" && sourceRepository.test(value);
      if (!repository) check(attribute, value);
    }
    const srcset = tag.attributes.get("srcset");
    if (srcset !== undefined)
      for (const candidate of srcset.split(","))
        check("srcset", candidate.trim().split(/\s+/u)[0] ?? "");
    if (tag.name === "base") {
      if (!rules.base) problems.push("sets a base");
      else if (tag.attributes.size !== 1 || tag.attributes.get("href") !== "/")
        problems.push("sets a base other than /");
    }
    if (tag.name === "meta" && tag.attributes.has("http-equiv"))
      problems.push(`has a meta http-equiv: ${tag.attributes.get("http-equiv")}`);
    const file = loadedFile(tag);
    if (file !== undefined && !rules.files.has(file))
      problems.push(`references a file the bundle does not hold: ${file}`);
  }
  for (const style of html.matchAll(/<style[^>]*>([\s\S]*?)<\/style[^>]*>/giu))
    problems.push(...cssViolations(style[1] ?? "", rules.relative));
  return problems;
}

/** A stylesheet may import only paths that stay on this origin. */
function cssViolations(css: string, relative: boolean): string[] {
  const problems: string[] = [];
  for (const rule of css.matchAll(
    /@import\s*(?:url\(\s*)?(?:"([^"]*)"|'([^']*)'|([^\s)"';]*))/giu,
  )) {
    const target = rule[1] ?? rule[2] ?? rule[3] ?? "";
    const problem = referenceProblem(target, relative);
    if (problem !== null) problems.push(`imports: ${problem}: ${target}`);
  }
  return problems;
}

/** A policy as directives (name to sources); a repeated directive name is refused. */
export function parsePolicy(policy: string): Map<string, string[]> {
  const directives = new Map<string, string[]>();
  for (const part of policy.split(";")) {
    const [name = "", ...sources] = part.trim().split(/\s+/u);
    if (name === "") continue;
    const key = name.toLowerCase();
    assert(!directives.has(key), `The policy repeats the ${key} directive.`);
    directives.set(key, sources);
  }
  return directives;
}

/** The `_headers` rules by path pattern (a rule starts at a line that begins with "/"). */
function headerRules(headers: string): Map<string, string> {
  const rules = new Map<string, string>();
  for (const rule of headers.split(/\n(?=\/)/u)) {
    const [pattern = "", ...lines] = rule.split("\n");
    assert(!rules.has(pattern), `Duplicate headers rule ${pattern}.`);
    rules.set(pattern, lines.join("\n"));
  }
  return rules;
}

/** The policy of one App profile: a restrictive set whose script sources are exactly its page's sources. */
function checkProfilePolicy(name: string, policy: string, html: string): void {
  const directives = parsePolicy(policy);
  assert.deepEqual(directives.get("default-src"), ["'self'"], `${name} default-src must be exactly 'self'.`);
  assert.deepEqual(directives.get("connect-src"), ["'self'"], `${name} connect-src must be exactly 'self'.`);
  assert.deepEqual(directives.get("style-src"), ["'self'"], `${name} style-src must be exactly 'self'.`);
  for (const [directive, sources] of directives)
    for (const source of sources)
      assert(
        source !== "'unsafe-inline'" && source !== "'unsafe-eval'" && !source.includes("*"),
        `${name} policy is not restrictive: ${directive} ${source}`,
      );
  const scriptSources = directives.get("script-src") ?? [];
  assert(
    scriptSources.includes("'wasm-unsafe-eval'"),
    `${name} script-src must allow WebAssembly compilation.`,
  );
  for (const source of scriptSources)
    assert(
      source === "'self'" ||
        source === "'wasm-unsafe-eval'" ||
        /^'sha256-[A-Za-z0-9+/]{43}='$/u.test(source),
      `${name} script-src allows a source other than 'self', 'wasm-unsafe-eval' and sha256 hashes: ${source}`,
    );
  for (const hash of inlineHashSet([html]))
    assert(
      scriptSources.includes(hash),
      `${name} policy does not cover an inline script of its page in script-src.`,
    );
}

/** Whether a precompressed file decodes to exactly its plain file. */
function decodesTo(bytes: Uint8Array, encoding: string, plain: Uint8Array): boolean {
  try {
    const decoded = encoding === ".br" ? brotliDecompressSync(bytes) : gunzipSync(bytes);
    return Buffer.compare(decoded, plain) === 0;
  } catch {
    return false;
  }
}

/** The plain files the profile bundle serves. Anything else is refused. */
function servedPlain(entryPath: string): boolean {
  return (
    entryPath === headersName ||
    profileNames.some((name) => entryPath === `${name}/index.html`) ||
    appRootFiles.includes(entryPath) ||
    frameworkLoaders.includes(entryPath) ||
    fingerprintedFramework.test(entryPath)
  );
}

/** Only the root app files and the framework may have precompressed siblings. */
function encodable(entryPath: string): boolean {
  return appRootFiles.includes(entryPath) || entryPath.startsWith("_framework/");
}

/**
 * Verifies the bundle bytes against the pinned digest, then the archive, the manifest, every file, the served layout,
 * the pages, the policies and the headers. Anything unexpected refuses the bundle; nothing is repaired or skipped.
 */
export function verifyProfileBundle(archive: Uint8Array, pinnedDigest: string): VerifiedBundle {
  assert.match(pinnedDigest, /^[0-9a-f]{64}$/u, "The pinned digest is not a SHA-256.");
  const digest = sha256Hex(archive);
  assert.equal(digest, pinnedDigest, "The profile bundle does not match the pinned digest.");
  const [first, ...files] = readBundleArchive(archive);
  assert(first?.path === manifestName, "The manifest must be the first entry.");
  const manifest = JSON.parse(Buffer.from(first.bytes).toString("utf8")) as BundleManifest;
  assert.equal(manifest.schema, 1, "Unknown bundle manifest schema.");
  assert.deepEqual(
    Object.keys(manifest.profiles ?? {}).sort(),
    [...profileNames],
    "The manifest must name exactly the account and chat profiles.",
  );
  assert.deepEqual(
    files.map((entry) => entry.path),
    Object.keys(manifest.files).sort(),
    "The archive does not hold exactly the manifest's files in order.",
  );
  const byPath = new Map(files.map((entry) => [entry.path, entry]));
  for (const entry of files) {
    const row = manifest.files[entry.path];
    assert(row, `Unlisted file ${entry.path}`);
    assert.equal(row.bytes, entry.bytes.byteLength, `Size of ${entry.path}`);
    assert.equal(row.sha256, sha256Hex(entry.bytes), `Content of ${entry.path}`);
  }
  for (const entry of files) {
    const encoding = encodingSuffix.exec(entry.path)?.[0];
    if (encoding === undefined) {
      assert(servedPlain(entry.path), `The bundle holds a file outside the served layout: ${entry.path}`);
    } else {
      const plainPath = entry.path.slice(0, -encoding.length);
      const plain = byPath.get(plainPath);
      assert(
        plain !== undefined && servedPlain(plainPath) && encodable(plainPath),
        `The bundle holds an encoded file without its plain file: ${entry.path}`,
      );
      assert(
        decodesTo(entry.bytes, encoding, plain.bytes),
        `${entry.path} does not decode to its plain file.`,
      );
    }
    assert(!entry.path.endsWith(".map"), `A source map is in the bundle: ${entry.path}`);
  }
  const text = (name: string) => {
    const entry = byPath.get(name);
    assert(entry, `The bundle has no ${name}.`);
    return Buffer.from(entry.bytes).toString("utf8");
  };
  // Both profiles are one application shell, so the two pages are the same bytes.
  assert.equal(
    text("account/index.html"),
    text("chat/index.html"),
    "The two profile pages must be one application shell.",
  );
  assert(byPath.has("_framework/blazor.webassembly.js"), "The bundle has no WebAssembly loader.");
  const headers = text(headersName);
  assert(!headers.includes("\r"), "The headers file must use LF line ends.");
  const rules = headerRules(headers);
  for (const pattern of ["/*", "/assets/*"])
    assert(
      !(rules.get(pattern) ?? "").includes("Content-Security-Policy"),
      `The ${pattern} rule must not carry a policy.`,
    );
  const plainNames = new Set(files.map((entry) => entry.path).filter((p) => !encodingSuffix.test(p)));
  const policies: Record<string, string> = {};
  for (const name of profileNames) {
    const html = text(`${name}/index.html`);
    // The policy hashes are of the bytes a browser executes: CRLF in a page would invalidate them.
    assert(!html.includes("\r"), `${name}/index.html must use LF line ends.`);
    assert.equal(
      startTags(html).filter((tag) => tag.name === "base").length,
      1,
      `${name}/index.html must set exactly one base.`,
    );
    assert.deepEqual(
      pageViolations(html, {
        relative: true,
        base: true,
        sourceLink: false,
        files: plainNames,
      }),
      [],
      `${name} page violates the same-origin rules`,
    );
    const rule = rules.get(`/${name}/*`);
    assert(rule, `No headers rule for /${name}/*.`);
    const policy = /^ {2}Content-Security-Policy: (.+)$/mu.exec(rule)?.[1] ?? "";
    assert.equal(
      manifest.profiles[name]?.csp,
      policy,
      `The manifest policy of ${name} differs from its rule.`,
    );
    assert.equal(
      manifest.profiles[name]?.page,
      `${name}/index.html`,
      `The manifest names another page for ${name}.`,
    );
    assert.match(
      manifest.profiles[name]?.buildDigest ?? "",
      /^[0-9a-f]{64}$/u,
      `The build digest of ${name} is not a SHA-256.`,
    );
    assert.equal(policy, expectedProfilePolicy(html), `${name} policy does not match its page.`);
    assert(policy.length < headerLineBudget, `${name} policy exceeds the header line budget.`);
    checkProfilePolicy(name, policy, html);
    policies[name] = policy;
  }
  assert.equal(
    headers,
    expectedProfileHeaders(policies),
    "The headers file differs from the reviewed rules.",
  );
  for (const entry of files)
    if (entry.path.endsWith(".css"))
      assert.deepEqual(
        cssViolations(Buffer.from(entry.bytes).toString("utf8"), true),
        [],
        `${entry.path} violates the same-origin rules`,
      );
  return { digest, manifest, files, headers };
}

// ---------------------------------------------------------------------------------------------------------------
// The Site archive (WEB.40 release asset web-site-<sha256>.tar): the C# public Site, verified against its pinned
// digest and composed with the profile bundle into one proof tree and one headers file (CLOUD.85 D2 option A, D4, D5).

/** The Site's pages, as the Site builder renders them (SitePages.All). */
const sitePages = ["index.html", "hello/index.html", "cloud-hello/index.html"];
/** The Site's other members, written beside its pages (SiteBuilder.BuildAsync). */
const siteRootFiles = ["404.css", "404.html", "favicon.svg", "robots.txt"];
/** The one content-hashed stylesheet the Site links from its pages. */
const siteStylesheet = /^assets\/site\.[0-9a-f]{16}\.css$/u;
/** The one outbound link a Site page may carry: its own source repository (the shell's SourceUrl). */
const sourceRepository = /^https:\/\/github\.com\/ArcForges\/Web(?:\/tree\/[0-9a-f]{40})?$/u;
/** The root paths that the profile routes own; the Site may not hold a file under them. */
const profileOwnedPath = /^(?:account|chat|_framework)(?:\/|$)/u;

/** The Site policy the Site builder derives from its pages (SiteContentSecurityPolicy.FromPages). */
export function expectedSitePolicy(pages: string[]): string {
  return policyText(["'self'", ...inlineHashSet(pages)]);
}

/** The headers file of the public Site (SiteSecurityHeaders.Render), byte for byte. */
export function expectedSiteHeaders(policy: string): string {
  const lines = [
    "/*",
    `  Content-Security-Policy: ${policy}`,
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
  ];
  return `${lines.join("\n")}\n`;
}

export interface VerifiedSite {
  digest: string;
  /** Every member, including the Site's own headers file. */
  files: BundleEntry[];
  /** The Site's headers file as the Site writes it. */
  headers: string;
  /** The Site policy, derived from its pages and matched by its headers file. */
  policy: string;
}

/**
 * Verifies the Site archive against its pinned digest, then its strict layout, its exact member set and order, its pages
 * (same-origin, no base, every inline script covered by its policy) and its headers. A Site policy never carries a
 * WebAssembly token: the public pages need no WebAssembly.
 */
export function verifySiteArchive(archive: Uint8Array, pinnedDigest: string): VerifiedSite {
  assert.match(pinnedDigest, /^[0-9a-f]{64}$/u, "The pinned digest is not a SHA-256.");
  const digest = sha256Hex(archive);
  assert.equal(digest, pinnedDigest, "The Site archive does not match the pinned digest.");
  const files = readBundleArchive(archive);
  const names = files.map((entry) => entry.path);
  for (let index = 1; index < names.length; index += 1)
    assert((names[index - 1] ?? "") < (names[index] ?? ""), "The Site archive is not in ordinal path order.");
  const stylesheets = names.filter((name) => siteStylesheet.test(name));
  assert.equal(stylesheets.length, 1, "The Site must hold exactly one content-hashed stylesheet.");
  assert.deepEqual(
    names,
    [...sitePages, ...siteRootFiles, ...stylesheets, headersName].sort(),
    "The Site holds members other than the reviewed Site.",
  );
  const byPath = new Map(files.map((entry) => [entry.path, entry] as const));
  const text = (name: string) => {
    const entry = byPath.get(name);
    assert(entry, `The Site has no ${name}.`);
    return Buffer.from(entry.bytes).toString("utf8");
  };
  const pages = [...sitePages, "404.html"];
  const policy = expectedSitePolicy(sitePages.map((name) => text(name)));
  const headers = text(headersName);
  assert(!headers.includes("\r"), "The Site headers file must use LF line ends.");
  assert(!headers.includes("wasm-unsafe-eval"), "The Site policy carries a WebAssembly token.");
  assert.equal(headers, expectedSiteHeaders(policy), "The Site headers file differs from the reviewed rules.");
  const siteFiles = new Set(names);
  for (const name of pages) {
    const html = text(name);
    assert(!html.includes("\r"), `${name} must use LF line ends.`);
    assert.deepEqual(
      pageViolations(html, { relative: false, base: false, files: siteFiles, sourceLink: true }),
      [],
      `${name} violates the Site's same-origin rules`,
    );
    const scriptSources = parsePolicy(policy).get("script-src") ?? [];
    for (const hash of inlineScriptHashes(html))
      assert(
        scriptSources.includes(hash),
        `${name} policy does not cover an inline script of its page in script-src.`,
      );
  }
  for (const name of [...stylesheets, "404.css"])
    assert.deepEqual(
      cssViolations(text(name), false),
      [],
      `${name} violates the Site's same-origin rules`,
    );
  return { digest, files, headers, policy };
}

interface HeaderBlock {
  pattern: string;
  lines: string[];
}
const unsetLine = /^ {2}! ([A-Za-z-]+)$/u;
const setLine = /^ {2}([A-Za-z-]+): (.+)$/u;
/** The header a line sets or unsets, or the line itself when it is neither. */
const headerName = (line: string): string =>
  unsetLine.exec(line)?.[1] ?? setLine.exec(line)?.[1] ?? line;

/** The rule blocks of a headers file in order; a line is one header set or one header unset. */
function headerBlocks(headers: string): HeaderBlock[] {
  assert(
    headers.endsWith("\n") && !headers.includes("\r"),
    "A headers file must use LF line ends and end with a newline.",
  );
  const blocks: HeaderBlock[] = [];
  for (const rule of headers.slice(0, -1).split(/\n(?=\/)/u)) {
    const [pattern = "", ...lines] = rule.split("\n");
    assert(
      !blocks.some((block) => block.pattern === pattern),
      `Duplicate headers rule ${pattern}.`,
    );
    for (const line of lines)
      assert(
        unsetLine.test(line) || setLine.test(line),
        `A headers line is not a plain header: ${line}`,
      );
    blocks.push({ pattern, lines });
  }
  return blocks;
}

/**
 * One headers file for the proof origin. The Site's rules come first, unchanged. A profile rule with the same path
 * pattern merges by line: an identical line is kept once, and a different value for the same header refuses the merge.
 * A profile rule for another path keeps only what differs from the Site's global rule, and where the Site sets the same
 * header to another value it unsets that header first, so the Site's policy never reaches /account/* or /chat/*.
 */
export function composeHeaders(siteText: string, profileText: string): string {
  const merged = new Map<string, string[]>();
  for (const block of headerBlocks(siteText)) merged.set(block.pattern, [...block.lines]);
  const inherited = new Map<string, string>();
  for (const line of merged.get("/*") ?? []) {
    const set = setLine.exec(line);
    if (set !== null) inherited.set(set[1] ?? "", set[2] ?? "");
  }
  for (const block of headerBlocks(profileText)) {
    const existing = merged.get(block.pattern);
    if (existing !== undefined) {
      for (const line of block.lines) {
        if (existing.includes(line)) continue;
        const name = headerName(line);
        assert(
          !existing.some((other) => headerName(other) === name),
          `The Site and the profile set ${name} differently on ${block.pattern}.`,
        );
        existing.push(line);
      }
      continue;
    }
    const unset = new Set(
      block.lines.map((line) => unsetLine.exec(line)?.[1]).filter((name) => name !== undefined),
    );
    const lines: string[] = [];
    for (const line of block.lines) {
      const set = setLine.exec(line);
      if (set === null) {
        lines.push(line);
        continue;
      }
      const name = set[1] ?? "";
      const value = set[2] ?? "";
      if (unset.has(name)) {
        lines.push(line);
        continue;
      }
      const parent = inherited.get(name);
      if (parent === value) continue;
      if (parent !== undefined) lines.push(`  ! ${name}`);
      lines.push(line);
    }
    if (lines.length > 0) merged.set(block.pattern, lines);
  }
  return `${[...merged].map(([pattern, lines]) => [pattern, ...lines].join("\n")).join("\n")}\n`;
}

export interface ProofAssets {
  /** Every file of the one proof tree, sorted by path, including the composed headers file. */
  files: BundleEntry[];
  headers: string;
  profileDigest: string;
  siteDigest: string;
}

/**
 * The profile bundle and the Site as one proof tree. A path that both hold merges only when the bytes are identical
 * (favicon.svg and robots.txt today); a different byte refuses. The Site may not hold a file under a profile route.
 */
export function composeProofAssets(profile: VerifiedBundle, site: VerifiedSite): ProofAssets {
  const tree = new Map<string, Uint8Array>();
  for (const entry of site.files) {
    assert(!profileOwnedPath.test(entry.path), `The Site holds a path the profiles serve: ${entry.path}`);
    if (entry.path !== headersName) tree.set(entry.path, entry.bytes);
  }
  for (const entry of profile.files) {
    if (entry.path === headersName) continue;
    const shared = tree.get(entry.path);
    if (shared === undefined) tree.set(entry.path, entry.bytes);
    else
      assert(
        Buffer.compare(shared, entry.bytes) === 0,
        `The Site and the profile hold different bytes at ${entry.path}.`,
      );
  }
  const headers = composeHeaders(site.headers, profile.headers);
  tree.set(headersName, Buffer.from(headers, "utf8"));
  const files = [...tree]
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([entryPath, bytes]) => ({ path: entryPath, bytes }));
  return { files, headers, profileDigest: profile.digest, siteDigest: site.digest };
}

async function writeTree(files: BundleEntry[], directory: string): Promise<number> {
  assert.equal(path.basename(directory), proofAssetsDirName, "Unexpected staging directory.");
  const resolved = path.resolve(directory);
  await rm(resolved, { recursive: true, force: true });
  for (const entry of files) {
    const target = path.resolve(resolved, ...entry.path.split("/"));
    assert(target.startsWith(`${resolved}${path.sep}`), "A staged path escapes its directory.");
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, entry.bytes);
  }
  return files.length;
}

/** Writes the composed proof tree into a fresh staging directory named for the proof assets. */
export async function stageProofAssets(assets: ProofAssets, directory: string): Promise<number> {
  return writeTree(assets.files, directory);
}
