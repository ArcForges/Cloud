// SPDX-License-Identifier: AGPL-3.0-only
// Pure helpers of the proof-environment deployment: the isolated Wrangler configuration and the
// deployment secrets. The deployment itself runs only in the manually dispatched CI job
// (eng/verification/proof-cloudflare.ts); secrets are generated there at deploy time, handed to
// Wrangler through a runner-local file and never printed, committed or sent anywhere else.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
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
 * The Web profile bundle served from the proof origin (CLOUD.71): the immutable release asset that the Web main-push
 * build publishes as `web-profiles-<digest>.tar`. Moving the pin is a reviewed change; nothing is rebuilt here.
 */
export const profileBundlePin = {
  repository: "ArcForges/Web",
  release: "web-0.1.0-ci.90.1",
  digest: "67956d7f4b3d2909625585ca68f19f3f8a9ea27a5a08958659b9d9841871f996",
} as const;
export const profileBundleAssetName = (digest: string) => `web-profiles-${digest}.tar`;

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
// The profile bundle: strict reader and verification. The bundle is a plain POSIX ustar written by the Web
// build (apps/app/scripts/bundle.ts); this reader accepts exactly that shape and refuses everything else.

const block = 512;
const sha256Hex = (value: Uint8Array) => createHash("sha256").update(value).digest("hex");
const maxFiles = 400;
const maxBundleBytes = 24 * 1024 * 1024;
const profileNames = ["account", "chat"] as const;
const manifestName = "manifest.json";
const headersName = "_headers";

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
  /** Every file to stage (the manifest is not served). */
  files: BundleEntry[];
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

/** True for a plain same-origin absolute path (or a fragment); entities, backslashes and control characters never are. */
function samePath(reference: string): boolean {
  if (reference.startsWith("#")) return !/[&\\\t\n\r]/u.test(reference);
  return (
    reference.startsWith("/") && !reference.startsWith("//") && !/[&\\\t\n\r]/u.test(reference)
  );
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

/** Everything in a page that could reach another origin or change its base; one message per violation. */
function pageViolations(html: string): string[] {
  const problems: string[] = [];
  for (const tag of startTags(html)) {
    for (const attribute of urlAttributes) {
      const value = tag.attributes.get(attribute);
      if (value !== undefined && !samePath(value))
        problems.push(`references another origin: ${attribute}=${value}`);
    }
    const srcset = tag.attributes.get("srcset");
    if (srcset !== undefined)
      for (const candidate of srcset.split(",")) {
        const url = candidate.trim().split(/\s+/u)[0] ?? "";
        if (!samePath(url)) problems.push(`references another origin: srcset ${url}`);
      }
    if (tag.name === "base") problems.push("sets a base");
    if (tag.name === "meta" && tag.attributes.has("http-equiv"))
      problems.push(`has a meta http-equiv: ${tag.attributes.get("http-equiv")}`);
  }
  for (const style of html.matchAll(/<style[^>]*>([\s\S]*?)<\/style[^>]*>/giu))
    problems.push(...cssViolations(style[1] ?? ""));
  return problems;
}

/** A stylesheet may import only same-origin paths. */
function cssViolations(css: string): string[] {
  const problems: string[] = [];
  for (const rule of css.matchAll(
    /@import\s*(?:url\(\s*)?(?:"([^"]*)"|'([^']*)'|([^\s)"';]*))/giu,
  )) {
    const target = rule[1] ?? rule[2] ?? rule[3] ?? "";
    if (!samePath(target)) problems.push(`imports another origin: ${target}`);
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

/**
 * Verifies the bundle bytes against the pinned digest, then the archive, the manifest, every file, the layout, the
 * pages and the headers. Anything unexpected refuses the bundle; nothing is repaired or skipped.
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
    files.map((entry) => entry.path),
    Object.keys(manifest.files).sort(),
    "The archive does not hold exactly the manifest's files in order.",
  );
  for (const entry of files) {
    const row = manifest.files[entry.path];
    assert(row, `Unlisted file ${entry.path}`);
    assert.equal(row.bytes, entry.bytes.byteLength, `Size of ${entry.path}`);
    assert.equal(row.sha256, sha256Hex(entry.bytes), `Content of ${entry.path}`);
  }
  const pages = profileNames.map((name) => `${name}/index.html`);
  for (const entry of files) {
    const allowed =
      entry.path === headersName ||
      entry.path === "favicon.svg" ||
      entry.path === "robots.txt" ||
      pages.includes(entry.path) ||
      /^assets\/[A-Za-z0-9_][A-Za-z0-9._-]*$/u.test(entry.path);
    assert(allowed, `The bundle holds a file outside the served layout: ${entry.path}`);
    assert(!entry.path.endsWith(".map"), `A source map is in the bundle: ${entry.path}`);
  }
  const text = (name: string) => {
    const entry = files.find((candidate) => candidate.path === name);
    assert(entry, `The bundle has no ${name}.`);
    return Buffer.from(entry.bytes).toString("utf8");
  };
  const headers = text(headersName);
  assert(!headers.includes("\r"), "The headers file must use LF line ends.");
  const rules = headerRules(headers);
  for (const pattern of ["/*", "/assets/*"])
    assert(
      !(rules.get(pattern) ?? "").includes("Content-Security-Policy"),
      `The ${pattern} rule must not carry a policy.`,
    );
  for (const name of profileNames) {
    const html = text(`${name}/index.html`);
    // The policy hashes are of the bytes a browser executes: CRLF in a page would invalidate them.
    assert(!html.includes("\r"), `${name}/index.html must use LF line ends.`);
    const rule = rules.get(`/${name}/*`);
    assert(rule, `No headers rule for /${name}/*.`);
    const policy = /^ {2}Content-Security-Policy: (.+)$/mu.exec(rule)?.[1] ?? "";
    assert.equal(
      manifest.profiles[name]?.csp,
      policy,
      `The manifest policy of ${name} differs from its rule.`,
    );
    const directives = parsePolicy(policy);
    assert.deepEqual(
      directives.get("default-src"),
      ["'self'"],
      `${name} default-src must be exactly 'self'.`,
    );
    assert.deepEqual(
      directives.get("connect-src"),
      ["'self'"],
      `${name} connect-src must be exactly 'self'.`,
    );
    assert(!/unsafe-inline|unsafe-eval|\*/u.test(policy), `${name} policy is not restrictive.`);
    const scriptSources = directives.get("script-src") ?? [];
    for (const source of scriptSources)
      assert(
        source === "'self'" || /^'sha256-[A-Za-z0-9+/]{43}='$/u.test(source),
        `${name} script-src allows a source other than 'self' and sha256 hashes: ${source}`,
      );
    for (const hash of inlineScriptHashes(html))
      assert(
        scriptSources.includes(hash),
        `${name} policy does not cover an inline script of its page in script-src.`,
      );
    assert.deepEqual(pageViolations(html), [], `${name} page violates the same-origin rules`);
  }
  for (const entry of files)
    if (entry.path.endsWith(".css"))
      assert.deepEqual(
        cssViolations(Buffer.from(entry.bytes).toString("utf8")),
        [],
        `${entry.path} violates the same-origin rules`,
      );
  return { digest, manifest, files };
}

/** Writes the verified files (not the manifest) into a fresh staging directory named for the proof assets. */
export async function stageProfileAssets(
  bundle: VerifiedBundle,
  directory: string,
): Promise<number> {
  assert.equal(path.basename(directory), proofAssetsDirName, "Unexpected staging directory.");
  const resolved = path.resolve(directory);
  await rm(resolved, { recursive: true, force: true });
  for (const entry of bundle.files) {
    const target = path.resolve(resolved, ...entry.path.split("/"));
    assert(target.startsWith(`${resolved}${path.sep}`), "A staged path escapes its directory.");
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, entry.bytes);
  }
  return bundle.files.length;
}
