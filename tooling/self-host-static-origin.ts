// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import {
  type BundleEntry,
  type VerifiedBundle,
  profileBundleAssetName,
  verifyProfileBundle,
} from "../eng/verification/proof-deploy.ts";

const maxArchiveBytes = 24 * 1024 * 1024;
const stagePrefix = ".static-origin-stage-";

async function readFileBounded(file: string, limit: number): Promise<Buffer> {
  const expected = await lstat(file, { bigint: true });
  assert(expected.isFile(), `${file} must be a regular file.`);
  const flags =
    process.platform === "win32"
      ? constants.O_RDONLY
      : constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
  const input = await open(file, flags);
  try {
    const stat = await input.stat({ bigint: true });
    assert(
      stat.isFile() &&
        stat.dev === expected.dev &&
        stat.ino === expected.ino &&
        stat.size === expected.size,
      `${file} changed while opening.`,
    );
    assert(stat.size <= BigInt(limit), `${file} exceeds its byte limit.`);
    const size = Number(stat.size);
    const data = Buffer.alloc(size + 1);
    let offset = 0;
    while (offset < data.length) {
      const { bytesRead } = await input.read(data, offset, data.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    assert(offset === size, `${file} changed while reading.`);
    return data.subarray(0, offset);
  } finally {
    await input.close();
  }
}

function caddyValue(value: string): string {
  assert(!/["\\{}\p{Cc}]/u.test(value), "A static origin value is not safe in a Caddyfile.");
  return `"${value}"`;
}

function routeFragment(bundle: VerifiedBundle, site: string): string {
  const root = caddyValue(site.split(path.sep).join("/"));
  const headers = new Map<string, string[]>();
  for (const block of bundle.headers.trimEnd().split(/\n(?=\/)/u)) {
    const [pattern = "", ...rows] = block.split("\n");
    const settings: string[] = [];
    for (const row of rows) {
      if (row.startsWith("  ! ")) continue;
      const setting = /^ {2}([A-Za-z0-9-]+): (.+)$/u.exec(row);
      assert(setting?.[1] && setting[2], "A verified response header could not be adapted.");
      settings.push(`${setting[1]} ${caddyValue(setting[2])}`);
    }
    headers.set(pattern, settings);
  }

  const routes = [`# Web profile archive SHA-256 ${bundle.digest}`];
  function addRoute(name: string, paths: string[], settings: string[], page?: string) {
    if (paths.length === 0) return;
    // Compare the original escaped request target to its decoded canonical path and query.
    // Caddy's regular path matcher also accepts normalized and case-folded paths.
    const exact = paths.map(caddyValue).join(", ");
    routes.push(
      `@${name} {`,
      "  method GET HEAD",
      `  expression \`{orig_uri} == {orig_path} + {orig_?query} && {orig_path} in [${exact}]\``,
      "}",
      `route @${name} {`,
      '  header Cache-Control "no-store"',
      "  header {",
      "    match status 2xx 304",
      ...[...(headers.get("/*") ?? []), ...settings].map((value) => `    ${value}`),
      "  }",
    );
    if (page) routes.push(`  rewrite * ${page}`);
    routes.push(
      "  file_server {",
      `    root ${root}`,
      "    disable_canonical_uris",
      "    precompressed br gzip",
      "  }",
      "}",
      "",
    );
  }

  const shellPages = new Set<string>();
  for (const [name, profile] of Object.entries(bundle.manifest.profiles)) {
    const page = `/${profile.page}`;
    shellPages.add(page);
    addRoute(
      `af_static_${name}`,
      [`/${name}`, `/${name}/`, page],
      headers.get(`/${name}/*`) ?? [],
      page,
    );
  }

  const immutable: string[] = [];
  const revalidated: string[] = [];
  for (const entry of bundle.files) {
    const url = `/${entry.path}`;
    if (entry.path === "_headers" || /\.(?:br|gz)$/u.test(entry.path) || shellPages.has(url))
      continue;
    if (url.startsWith("/_framework/") && !headers.has(url)) immutable.push(url);
    else revalidated.push(url);
  }
  addRoute("af_static_fingerprinted", immutable, headers.get("/_framework/*") ?? []);
  addRoute(
    "af_static_revalidated",
    revalidated,
    headers.get("/_framework/blazor.webassembly.js") ?? [],
  );
  return routes.join("\n");
}

function releaseEntries(bundle: VerifiedBundle, release: string): BundleEntry[] {
  const publicEntries = bundle.files.filter((entry) => entry.path !== "_headers");
  if (process.platform === "win32") {
    for (const entry of publicEntries)
      assert(
        !entry.path
          .split("/")
          .some((part) => /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iu.test(part)),
        `The asset cannot be stored as a Windows file: ${entry.path}.`,
      );
  }
  return [
    { path: "manifest.json", bytes: Buffer.from(`${JSON.stringify(bundle.manifest, null, 2)}\n`) },
    { path: "_headers", bytes: Buffer.from(bundle.headers) },
    {
      path: "static-origin.caddy",
      bytes: Buffer.from(routeFragment(bundle, path.join(release, "site"))),
    },
    ...publicEntries.map((entry) => ({ path: `site/${entry.path}`, bytes: entry.bytes })),
  ];
}

function expectedDirectories(entries: BundleEntry[]): Set<string> {
  const directories = new Set<string>();
  for (const entry of entries) {
    for (
      let parent = path.posix.dirname(entry.path);
      parent !== ".";
      parent = path.posix.dirname(parent)
    )
      directories.add(parent);
  }
  return directories;
}

async function verifyRelease(directory: string, entries: BundleEntry[]): Promise<void> {
  assert((await lstat(directory)).isDirectory(), "The release root must be a real directory.");
  const files = new Map(entries.map(({ path: name, bytes }) => [name, bytes]));
  const directories = expectedDirectories(entries);
  async function checkDirectory(current: string): Promise<void> {
    for (const entry of await readdir(path.join(directory, current), { withFileTypes: true })) {
      const name = path.posix.join(current, entry.name);
      if (entry.isDirectory()) {
        assert(directories.delete(name), `Unexpected release directory: ${name}.`);
        await checkDirectory(name);
      } else {
        const expected = files.get(name);
        assert(
          entry.isFile() && expected && files.delete(name),
          `Unexpected release entry: ${name}.`,
        );
        const actual = await readFileBounded(path.join(directory, name), expected.byteLength);
        assert(Buffer.compare(actual, expected) === 0, `Staged bytes differ: ${name}.`);
      }
    }
  }
  await checkDirectory("");
  assert(files.size === 0 && directories.size === 0, "The release is missing expected entries.");
}

/** Verify a trusted archive pin and stage a selectable release on the same filesystem. */
export async function selfHostStaticOrigin(
  command: "stage" | "verify",
  archive: string,
  digest: string,
  releasesDirectory: string,
): Promise<string> {
  assert.match(digest, /^[0-9a-f]{64}$/u, "The reviewed digest must be a SHA-256.");
  assert.equal(
    path.basename(archive),
    profileBundleAssetName(digest),
    "Unexpected profile archive name.",
  );
  const bundle = verifyProfileBundle(await readFileBounded(archive, maxArchiveBytes), digest);
  const directory = await realpath(releasesDirectory);
  assert((await lstat(directory)).isDirectory(), "The releases parent must be a real directory.");
  const release = path.join(directory, digest);
  const entries = releaseEntries(bundle, release);
  const present = await lstat(release).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") throw error;
    return undefined;
  });
  if (present || command === "verify") {
    await verifyRelease(release, entries);
    return release;
  }

  const stage = await mkdtemp(path.join(directory, stagePrefix));
  assert(path.dirname(stage) === directory && path.basename(stage).startsWith(stagePrefix));
  try {
    const directories = expectedDirectories(entries);
    for (const current of directories) {
      const target = path.join(stage, current);
      await mkdir(target, { recursive: true });
      await chmod(target, 0o755);
    }
    for (const entry of entries) {
      const target = path.join(stage, entry.path);
      await writeFile(target, entry.bytes, { flag: "wx" });
      await chmod(target, 0o644);
    }
    await verifyRelease(stage, entries);
    await chmod(stage, 0o755);
    try {
      await rename(stage, release);
    } catch (error) {
      if (!["EEXIST", "ENOTEMPTY", "EPERM"].includes((error as NodeJS.ErrnoException).code ?? ""))
        throw error;
      await verifyRelease(release, entries);
    }
    return release;
  } finally {
    await rm(stage, { recursive: true, force: true });
  }
}

if (import.meta.main) {
  const [command, archive, digest, directory, ...extra] = process.argv.slice(2);
  if (
    (command !== "stage" && command !== "verify") ||
    !archive ||
    !digest ||
    !directory ||
    extra.length > 0
  ) {
    console.error(
      "Usage: node tooling/self-host-static-origin.ts stage|verify <archive> <digest> <releases-directory>",
    );
    process.exitCode = 2;
  } else {
    try {
      console.log(await selfHostStaticOrigin(command, archive, digest, directory));
    } catch (error) {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    }
  }
}
