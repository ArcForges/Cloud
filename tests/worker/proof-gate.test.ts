// SPDX-License-Identifier: AGPL-3.0-only
// The proof deployment gate (owner decision of 2026-11-04): the gate logic against recorded GitHub API answers, the fetch of the
// gated candidate, and the workflow wiring (which jobs run for each event, the gate's permissions, and the main-push path).
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  candidateArtifactName,
  checkEntries,
  evaluateGate,
  type FetchInput,
  type FetchPorts,
  fetchCandidate,
  fetchInput,
  GateRefusal,
  type Get,
  gateOutputs,
  maxStatusPages,
  requireDispatch,
  trustedPoster,
} from "../../eng/verification/proof-gate.ts";
import { candidateEnvironment } from "../../tooling/build-identity.ts";
import { scratchDirectory } from "./support/scratch.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const recorded = JSON.parse(
  readFileSync(path.join(root, "tests/worker/fixtures/proof-gate-9085b12.json"), "utf8"),
) as { sha: string; responses: Record<string, unknown> };

// The recorded merge: PR #137 (head 21ab8ea, verified by both host legs) merged as 9085b12, built by the main push run 41866820816.
const merge = recorded.sha;
const head = "21ab8eafba702fcf6109ec91f9457d3f0eaa341b";
const tree = "963af282e91567ef5940f498082fb6db3c6eb279";
const runId = 41866820816;
const artifactId = 13343345828;
const repo = "repos/ArcForges/Cloud";
const key = {
  main: `${repo}/git/ref/heads/main`,
  merge: `${repo}/git/commits/${merge}`,
  pulls: `${repo}/commits/${merge}/pulls?per_page=100`,
  head: `${repo}/git/commits/${head}`,
  statuses: (commit: string, page = 1) =>
    `${repo}/commits/${commit}/statuses?per_page=100&page=${page}`,
  runs: `${repo}/actions/workflows/ci.yml/runs?event=push&branch=main&head_sha=${merge}&exclude_pull_requests=true&per_page=100`,
  jobs: `${repo}/actions/runs/${runId}/jobs?filter=latest&per_page=100`,
  artifacts: `${repo}/actions/runs/${runId}/artifacts?per_page=100`,
  run: `${repo}/actions/runs/${runId}`,
  artifact: `${repo}/actions/artifacts/${artifactId}`,
};

interface Status {
  id: number;
  state: string;
  context: string;
  description: string;
  target_url: string | null;
  created_at: string;
  updated_at: string;
  creator: { login: string; id: number; type: string };
}
type Responses = Record<string, unknown>;
type Mutable = Record<string, unknown>;

function field(value: unknown, ...names: string[]): Mutable {
  let current = value;
  for (const name of names) current = (current as Mutable)[name];
  return current as Mutable;
}

function api(mutate?: (responses: Responses) => void): { get: Get; calls: string[] } {
  const responses = structuredClone(recorded.responses);
  mutate?.(responses);
  const calls: string[] = [];
  return {
    calls,
    get: (endpoint) => {
      calls.push(endpoint);
      assert.ok(endpoint in responses, `unrecorded endpoint ${endpoint}`);
      return structuredClone(responses[endpoint]);
    },
  };
}

function statuses(responses: Responses, commit = head): Status[] {
  return responses[key.statuses(commit)] as Status[];
}

function hostStatus(overrides: Partial<Status>): Status {
  return {
    id: 58070000000,
    state: "success",
    context: "arcforges/linux",
    description: "12 steps passed in 600s on linux-host (profile full)",
    target_url: null,
    created_at: "2026-11-04T16:30:00Z",
    updated_at: "2026-11-04T16:30:00Z",
    creator: { ...trustedPoster },
    ...overrides,
  };
}

function refused(mutate: (responses: Responses) => void, message: RegExp, sha = merge) {
  const { get } = api(mutate);
  assert.throws(
    () => evaluateGate(get, sha),
    (error: unknown) => error instanceof GateRefusal && message.test(error.message),
  );
}

test("the recorded merge of PR #137 passes the gate with the host-verified tree and the main-push candidate", () => {
  const { get, calls } = api();
  const result = evaluateGate(get, merge);
  assert.deepEqual(result, {
    sha: merge,
    tree,
    verifiedCommit: head,
    kind: "merge",
    pullRequest: 137,
    statuses: [
      { context: "arcforges/linux", id: 58061930671, createdAt: "2026-11-04T16:23:10Z" },
      { context: "arcforges/windows", id: 58061125352, createdAt: "2026-11-04T16:15:15Z" },
    ],
    run: { id: runId, number: 547, attempt: 1 },
    candidateAttempt: 1,
    artifact: {
      id: artifactId,
      name: "cloud-candidate-41866820816-1",
      digest: "sha256:c6cbb21b0973676a76d455baaa70be7c094ff22dd562b866e0a5a61276f74daf",
      size: (recorded.responses[key.artifact] as { size_in_bytes: number }).size_in_bytes,
    },
  });
  assert.deepEqual(gateOutputs(result), {
    sha: merge,
    tree,
    "verified-commit": head,
    "run-id": String(runId),
    "run-number": "547",
    "run-attempt": "1",
    "candidate-attempt": "1",
    "artifact-id": String(artifactId),
    "artifact-digest": result.artifact.digest,
  });
  // Every answer the gate relied on was read through the API; it never trusts the dispatch's own inputs.
  assert.deepEqual(calls, [
    key.merge,
    key.main,
    key.pulls,
    key.head,
    key.statuses(head),
    key.runs,
    key.jobs,
    key.artifacts,
  ]);
});

test("1a: the dispatched commit must be main's head and the merge commit of the merged PR", () => {
  refused((r) => {
    field(r[key.main], "object").sha = head;
  }, /is not the head of main/u);
  // The second parent is the PR head; swapped parents, a squash (one parent) or another head is not the verified tree.
  refused((r) => {
    const parents = field(r[key.merge]).parents as { sha: string }[];
    parents.reverse();
  }, /is not the merge commit of PR #137/u);
  refused((r) => {
    field(r[key.merge]).parents = [{ sha: "41c8a72dbbd63efdb6967f71c23610ae2f73fae1" }];
  }, /is not the merge commit of PR #137/u);
  refused((r) => {
    field((r[key.pulls] as unknown[])[0], "head").sha = "41c8a72dbbd63efdb6967f71c23610ae2f73fae1";
  }, /is not the merge commit of PR #137/u);
  // Two PRs naming this merge commit: the gate does not guess.
  refused((r) => {
    const pulls = r[key.pulls] as unknown[];
    pulls.push(structuredClone(pulls[0]));
  }, /2 pull requests name/u);
  // An unmerged PR, a PR into another base or of another repository does not count, and then the commit needs its own statuses.
  for (const edit of [
    (pull: Mutable) => {
      pull.merged_at = null;
    },
    (pull: Mutable) => {
      field(pull, "base").ref = "release";
    },
    (pull: Mutable) => {
      field(pull, "base", "repo").full_name = "someone/Cloud";
    },
  ])
    refused((r) => {
      edit(field((r[key.pulls] as unknown[])[0]));
      r[key.statuses(merge)] = [];
    }, /has no arcforges\/linux status/u);
});

test("1a: a fast-forward is gated on the statuses of the commit itself", () => {
  // The PR head is the dispatched commit (fast-forward merge): the statuses are read on it.
  const { get } = api((r) => {
    field((r[key.pulls] as unknown[])[0], "head").sha = merge;
    r[key.statuses(merge)] = statuses(r);
  });
  const forward = evaluateGate(get, merge);
  assert.equal(forward.kind, "fast-forward");
  assert.equal(forward.verifiedCommit, merge);
  assert.equal(forward.pullRequest, 137);
  // No PR merged as this commit: the commit itself must carry both statuses.
  const direct = api((r) => {
    r[key.pulls] = [];
    r[key.statuses(merge)] = statuses(r);
  });
  assert.equal(evaluateGate(direct.get, merge).pullRequest, null);
  refused((r) => {
    r[key.pulls] = [];
    r[key.statuses(merge)] = [];
  }, /has no arcforges\/linux status/u);
});

test("1b: the merged tree must be the tree the host legs verified", () => {
  refused((r) => {
    field(r[key.head], "tree").sha = "0".repeat(40);
  }, /is not the tree the host legs verified at 21ab8ea/u);
  refused((r) => {
    field(r[key.merge], "tree").sha = "1".repeat(40);
  }, /is not the tree the host legs verified/u);
});

test("1b: the latest status of each context counts, so a later failure, error or pending wins", () => {
  for (const state of ["failure", "error", "pending"])
    for (const context of ["arcforges/linux", "arcforges/windows"])
      refused(
        (r) => {
          statuses(r).unshift(hostStatus({ state, context, description: "x" }));
        },
        new RegExp(`latest ${context} status on ${head} \\(id 58070000000\\) is ${state}`, "u"),
      );
  // At the same second the later id wins.
  refused((r) => {
    statuses(r).unshift(
      hostStatus({ id: 58061930672, state: "failure", created_at: "2026-11-04T16:23:10Z" }),
    );
  }, /is failure, not success/u);
  // A missing context fails.
  refused((r) => {
    r[key.statuses(head)] = statuses(r).filter((status) => status.context !== "arcforges/windows");
  }, /has no arcforges\/windows status/u);
  // Positive control: an earlier failure superseded by the later success passes.
  const { get } = api((r) => {
    statuses(r).push(hostStatus({ id: 1, state: "failure", created_at: "2026-11-04T16:00:00Z" }));
  });
  assert.equal(evaluateGate(get, merge).statuses[0]?.id, 58061930671);
});

test("1b: the statuses are read page by page, and a later failure on the second page still wins", () => {
  const filler = (index: number) =>
    hostStatus({ id: 1000 + index, context: `other/${index}`, created_at: "2026-11-04T10:00:00Z" });
  const { get, calls } = api((r) => {
    r[key.statuses(head, 2)] = statuses(r);
    r[key.statuses(head)] = Array.from({ length: 100 }, (_, index) => filler(index));
    (r[key.statuses(head, 2)] as Status[]).push(hostStatus({ state: "failure" }));
  });
  assert.throws(() => evaluateGate(get, merge), /is failure, not success/u);
  assert.ok(calls.includes(key.statuses(head, 2)));
  // A list longer than the gate reads is refused, never half-read.
  refused((r) => {
    for (let page = 1; page <= maxStatusPages; page++)
      r[key.statuses(head, page)] = Array.from({ length: 100 }, (_, index) => filler(index));
  }, /has more than 1000 statuses/u);
});

test("1c: a status counts only from the host legs' account and in the shape eng/verify.py writes", () => {
  for (const creator of [
    { login: "someone", id: 1, type: "User" },
    { login: trustedPoster.login, id: 1, type: "User" },
    { login: trustedPoster.login, id: trustedPoster.id, type: "Bot" },
    { login: "github-actions[bot]", id: 41898282, type: "Bot" },
  ])
    refused((r) => {
      statuses(r).unshift(hostStatus({ creator }));
    }, /was not created by the host legs' account deku2026/u);
  refused((r) => {
    statuses(r).unshift(hostStatus({ target_url: "https://example.com/run" }));
  }, /has a target URL/u);
  for (const description of [
    "no Linux steps apply to 21ab8eafba70 (profile 'full')",
    "12 steps passed in 600s on linux-host (profile docs)",
    "12 steps passed in 600s on linux-host (profile full) and more",
    "0 steps passed in 1s on linux-host (profile full)",
    "verifying on linux-host",
  ])
    refused((r) => {
      statuses(r).unshift(hostStatus({ description }));
    }, /does not have the description eng\/verify.py writes/u);
});

test("1d: the candidate is the artifact of the successful main-push run of the same commit, or the dispatch fails", () => {
  refused((r) => {
    r[key.runs] = { total_count: 0, workflow_runs: [] };
  }, /No main-push run of .github\/workflows\/ci.yml exists for 9085b12/u);
  for (const edit of [
    (run: Mutable) => {
      run.event = "workflow_dispatch";
    },
    (run: Mutable) => {
      run.head_sha = head;
    },
    (run: Mutable) => {
      run.path = ".github/workflows/other.yml";
    },
    (run: Mutable) => {
      run.head_branch = "task/x";
    },
    (run: Mutable) => {
      field(run, "head_repository").full_name = "someone/Cloud";
    },
  ])
    refused((r) => {
      edit(field(field(r[key.runs]).workflow_runs, "0"));
    }, /No main-push run/u);
  refused((r) => {
    field(field(r[key.runs]).workflow_runs, "0").conclusion = "failure";
  }, /concluded failure, not success/u);
  refused((r) => {
    const run = field(field(r[key.runs]).workflow_runs, "0");
    run.status = "in_progress";
    run.conclusion = null;
  }, /is in_progress; dispatch again after it completed/u);
  refused((r) => {
    const listing = field(r[key.runs]);
    (listing.workflow_runs as unknown[]).push(
      structuredClone((listing.workflow_runs as unknown[])[0]),
    );
    listing.total_count = 2;
  }, /2 main-push runs exist/u);
  refused((r) => {
    const jobs = field(r[key.jobs]).jobs as Mutable[];
    const job = jobs.find((entry) => entry.name === "Native AOT image and Worker build");
    assert.ok(job);
    job.conclusion = "failure";
  }, /The candidate job of run 41866820816 did not succeed/u);
  refused((r) => {
    const jobs = field(r[key.jobs]).jobs as Mutable[];
    const job = jobs.find((entry) => entry.name === "Native AOT image and Worker build");
    assert.ok(job);
    job.head_sha = head;
  }, /the candidate job does not belong to run 41866820816 of 9085b12/u);
  const candidate = (r: Responses) => {
    const found = (field(r[key.artifacts]).artifacts as Mutable[]).find(
      (entry) => entry.name === candidateArtifactName(runId, 1),
    );
    assert.ok(found);
    return found;
  };
  refused((r) => {
    field(candidate(r), "workflow_run").head_sha = head;
  }, /was not uploaded by the main-push run 41866820816 of 9085b12/u);
  refused((r) => {
    field(candidate(r), "workflow_run").id = 41835733994;
  }, /was not uploaded by the main-push run/u);
  for (const name of ["repository_id", "head_repository_id"])
    refused((r) => {
      field(candidate(r), "workflow_run")[name] = 1;
    }, /was not uploaded by the main-push run/u);
  refused((r) => {
    candidate(r).expired = true;
  }, /has expired/u);
  refused((r) => {
    candidate(r).name = "cloud-candidate-41866820816-2";
  }, /holds no artifact cloud-candidate-41866820816-1/u);
  refused((r) => {
    candidate(r).digest = null;
  }, /digest/u);
});

test("any API failure fails the gate", () => {
  const { calls } = api();
  evaluateGate(api().get, merge);
  const read: string[] = [];
  evaluateGate((endpoint) => {
    read.push(endpoint);
    return api().get(endpoint);
  }, merge);
  assert.equal(calls.length, 0);
  for (const failing of read) {
    const { get } = api();
    assert.throws(() =>
      evaluateGate((endpoint) => {
        if (endpoint === failing) throw new Error("HTTP 502");
        return get(endpoint);
      }, merge),
    );
  }
  assert.throws(() => evaluateGate(api().get, "main"), /not a commit SHA/u);
});

test("both phases run on a manual dispatch of main in ArcForges/Cloud only", () => {
  const good = {
    GITHUB_ACTIONS: "true",
    GITHUB_REPOSITORY: "ArcForges/Cloud",
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_REF: "refs/heads/main",
    GITHUB_SHA: merge,
  };
  assert.equal(requireDispatch(good), merge);
  for (const [name, value] of [
    ["GITHUB_ACTIONS", undefined],
    ["GITHUB_REPOSITORY", "someone/Cloud"],
    ["GITHUB_EVENT_NAME", "push"],
    ["GITHUB_EVENT_NAME", "pull_request"],
    ["GITHUB_REF", "refs/heads/task/x"],
    ["GITHUB_SHA", "main"],
  ] as const)
    assert.throws(() => requireDispatch({ ...good, [name]: value }), GateRefusal);
});

// The fetch phase of the deploy job, with an archive built here: the API answers are the recorded ones with this archive's digest.
const members = {
  "docker-image.tar": "image bytes",
  "worker.js": "export default {};\n",
  "image-provenance.json": JSON.stringify({ revision: merge, imageId: `sha256:${"a".repeat(64)}` }),
  "build-identity.json": JSON.stringify({
    artifact: { id: "Cloud", version: "0.1.0-ci.547.1" },
    build: {
      sourceCommit: merge,
      dirty: false,
      kind: "ci",
      buildId: `${runId}.1`,
      runId: String(runId),
      runAttempt: 1,
      pipelineRun: `https://github.com/ArcForges/Cloud/actions/runs/${runId}`,
      sourceDateEpoch: 1,
    },
  }),
} as Record<string, string>;

function sealed(edit?: (files: Record<string, string>, manifest: Mutable) => void) {
  const files = structuredClone(members);
  const manifest: Mutable = {
    schema: 1,
    revision: merge,
    dirty: false,
    version: "0.1.0-ci.547.1",
    image: "arcforges-cloud:0.1.0-ci.547.1",
    imageId: `sha256:${"a".repeat(64)}`,
  };
  const digests = () =>
    Object.fromEntries(
      Object.entries(files).map(([name, body]) => [
        name,
        createHash("sha256").update(body).digest("hex"),
      ]),
    );
  manifest.files = digests();
  edit?.(files, manifest);
  return { ...files, "manifest.json": JSON.stringify(manifest) };
}

const input: FetchInput = {
  sha: merge,
  tree,
  runId,
  runNumber: 547,
  runAttempt: 1,
  candidateAttempt: 1,
  artifactId,
  artifactDigest: "",
};

function fetchWith(
  t: { after(fn: () => void): void },
  archive: Record<string, string>,
  options: {
    bytes?: string;
    entries?: string[];
    headTree?: string;
    responses?: (r: Responses) => void;
    extra?: (directory: string) => void;
  } = {},
) {
  const directory = scratchDirectory("proof-gate-", t);
  const bytes = JSON.stringify(archive);
  const digest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  const { get } = api((r) => {
    field(r[key.artifact]).digest = digest;
    options.responses?.(r);
  });
  let extracted = false;
  const ports: FetchPorts = {
    get,
    download: (_id, file) => writeFileSync(file, options.bytes ?? bytes),
    entries: () => options.entries ?? Object.keys(archive),
    extract: (_file, target) => {
      extracted = true;
      for (const [name, body] of Object.entries(archive))
        writeFileSync(path.join(target, name), body);
      options.extra?.(target);
    },
    head: () => ({ sha: merge, tree: options.headTree ?? tree }),
  };
  const run = () => fetchCandidate(ports, { ...input, artifactDigest: digest }, directory);
  return { run, directory, extracted: () => extracted };
}

test("the deploy job fetches the gated artifact, checks its digest and its sealed manifest, and unpacks it", (t) => {
  const fetch = fetchWith(t, sealed());
  assert.deepEqual(fetch.run(), { version: "0.1.0-ci.547.1" });
  const candidate = path.join(fetch.directory, "artifacts", "candidate");
  assert.equal(readFileSync(path.join(candidate, "worker.js"), "utf8"), members["worker.js"]);
  assert.ok(
    !existsSync(path.join(fetch.directory, "artifacts", "cloud-candidate-41866820816-1.zip")),
  );
});

test("the fetch refuses another digest, a changed artifact, a non-flat archive and a wrong checkout", (t) => {
  const refusedFetch = (fetch: ReturnType<typeof fetchWith>, message: RegExp) =>
    assert.throws(
      fetch.run,
      (error: unknown) => error instanceof GateRefusal && message.test(error.message),
    );
  const tampered = fetchWith(t, sealed(), { bytes: "other bytes" });
  refusedFetch(tampered, /has the digest sha256:[0-9a-f]{64}, not the API's/u);
  assert.equal(tampered.extracted(), false);
  refusedFetch(
    fetchWith(t, sealed(), {
      responses: (r) => {
        field(r[key.artifact]).digest = `sha256:${"b".repeat(64)}`;
      },
    }),
    /changed since the gate read it/u,
  );
  refusedFetch(
    fetchWith(t, sealed(), {
      responses: (r) => {
        field(r[key.artifact], "workflow_run").head_sha = head;
      },
    }),
    /was not uploaded by the main-push run/u,
  );
  refusedFetch(
    fetchWith(t, sealed(), {
      responses: (r) => {
        field(r[key.run]).event = "workflow_dispatch";
      },
    }),
    /is not the successful main push of 9085b12/u,
  );
  // Re-run between the gate and the fetch: the run must still be the completed, successful main push.
  for (const edit of [
    (run: Mutable) => {
      run.status = "in_progress";
    },
    (run: Mutable) => {
      run.conclusion = "failure";
    },
  ])
    refusedFetch(
      fetchWith(t, sealed(), {
        responses: (r) => {
          edit(field(r[key.run]));
        },
      }),
      /is not the successful main push of 9085b12/u,
    );
  // A candidate directory that exists before the fetch (another source of bytes) is refused.
  const occupied = fetchWith(t, sealed());
  mkdirSync(path.join(occupied.directory, "artifacts", "candidate"), { recursive: true });
  refusedFetch(occupied, /artifacts\/candidate exists before the gated candidate was fetched/u);
  assert.equal(occupied.extracted(), false);
  for (const entry of ["../worker.js", "nested/worker.js", ".hidden", "/etc/passwd"]) {
    const nested = fetchWith(t, sealed(), { entries: [...Object.keys(sealed()), entry] });
    refusedFetch(nested, /not a plain file name/u);
    assert.equal(nested.extracted(), false);
  }
  refusedFetch(
    fetchWith(t, sealed(), { headTree: "0".repeat(40) }),
    /is not the tree .* the gate proved/u,
  );
});

test("the fetch refuses a sealed manifest that names another commit, run, version or member", (t) => {
  const manifestOf = (edit: (manifest: Mutable) => void) =>
    sealed((_, manifest) => {
      edit(manifest);
    });
  const cases: [Record<string, string>, RegExp][] = [
    [
      manifestOf((m) => {
        m.revision = head;
      }),
      /does not name the clean commit/u,
    ],
    [
      manifestOf((m) => {
        m.dirty = true;
      }),
      /does not name the clean commit/u,
    ],
    [
      manifestOf((m) => {
        m.version = "0.1.0-ci.546.1";
      }),
      /version is not 0.1.0-ci.547.1/u,
    ],
    [
      sealed((files) => {
        files["worker.js"] = "changed";
      }),
      /worker.js does not match its manifest digest/u,
    ],
  ];
  const identity = (edit: (build: Mutable) => void) =>
    sealed((files, m) => {
      const value = JSON.parse(files["build-identity.json"] ?? "") as { build: Mutable };
      edit(value.build);
      files["build-identity.json"] = JSON.stringify(value);
      field(m, "files")["build-identity.json"] = createHash("sha256")
        .update(files["build-identity.json"])
        .digest("hex");
    });
  for (const [name, value] of [
    ["runId", "41835733994"],
    ["sourceCommit", head],
    ["buildId", "41835733994.1"],
    ["kind", "local"],
    ["runAttempt", 2],
    ["pipelineRun", "https://github.com/ArcForges/Cloud/actions/runs/41835733994"],
  ] as const) {
    const edit = (build: Mutable) => {
      build[name] = value;
    };
    cases.push([identity(edit), /build identity does not name 9085b12/u]);
  }
  cases.push([
    sealed((files, m) => {
      files["image-provenance.json"] = JSON.stringify({ revision: head, imageId: m.imageId });
      field(m, "files")["image-provenance.json"] = createHash("sha256")
        .update(files["image-provenance.json"])
        .digest("hex");
    }),
    /image provenance does not name 9085b12/u,
  ]);
  for (const [archive, message] of cases)
    assert.throws(
      fetchWith(t, archive).run,
      (error: unknown) => error instanceof GateRefusal && message.test(error.message),
    );
  // A member that the manifest does not list, or a link instead of a file.
  assert.throws(
    fetchWith(t, { ...sealed(), "extra.js": "x" }).run,
    /not exactly the manifest's files/u,
  );
  assert.throws(
    fetchWith(t, sealed(), {
      extra: (target) => {
        mkdirSync(path.join(target, "..", "elsewhere"), { recursive: true });
        symlinkSync(path.join(target, "..", "elsewhere"), path.join(target, "link"));
      },
    }).run,
    /link is not a regular file/u,
  );
});

test("the deploy job takes the gate's outputs only in their exact shapes", () => {
  const good = {
    GITHUB_SHA: merge,
    PROOF_GATE_TREE: tree,
    ARCFORGES_CANDIDATE_RUN_ID: String(runId),
    ARCFORGES_CANDIDATE_RUN_NUMBER: "547",
    ARCFORGES_CANDIDATE_RUN_ATTEMPT: "2",
    PROOF_GATE_CANDIDATE_ATTEMPT: "1",
    PROOF_GATE_ARTIFACT_ID: String(artifactId),
    PROOF_GATE_ARTIFACT_DIGEST: `sha256:${"c".repeat(64)}`,
  };
  assert.equal(fetchInput(good).runAttempt, 2);
  for (const name of Object.keys(good))
    for (const value of [undefined, "", "x", "0", "-1"])
      assert.throws(
        () => fetchInput({ ...good, [name]: value }),
        GateRefusal,
        `${name}=${String(value)}`,
      );
  assert.throws(
    () => fetchInput({ ...good, PROOF_GATE_CANDIDATE_ATTEMPT: "3" }),
    /later than its run's/u,
  );
  assert.deepEqual(checkEntries(["worker.js", "manifest.json"]), ["manifest.json", "worker.js"]);
  assert.throws(() => checkEntries(["worker.js", "worker.js", "manifest.json"]), /twice/u);
  assert.throws(() => checkEntries(["worker.js"]), /no manifest.json/u);
});

test("the build identity accepts the producer run the gate named, on a dispatch only", () => {
  const dispatch = {
    GITHUB_ACTIONS: "true",
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_RUN_ID: "41900000000",
    GITHUB_RUN_NUMBER: "560",
    GITHUB_RUN_ATTEMPT: "1",
    ARCFORGES_CANDIDATE_RUN_ID: String(runId),
    ARCFORGES_CANDIDATE_RUN_NUMBER: "547",
    ARCFORGES_CANDIDATE_RUN_ATTEMPT: "1",
  };
  const producer = candidateEnvironment("0.1.0-ci.547.1", dispatch);
  assert.equal(producer.GITHUB_RUN_ID, String(runId));
  assert.equal(producer.GITHUB_RUN_NUMBER, "547");
  assert.equal(producer.GITHUB_RUN_ATTEMPT, "1");
  assert.equal(dispatch.GITHUB_RUN_ID, "41900000000", "the environment itself is not changed");
  // The candidate must still be the named run's.
  assert.throws(() => candidateEnvironment("0.1.0-ci.560.1", dispatch));
  assert.throws(() => candidateEnvironment("0.1.0-ci.547.2", dispatch));
  // A main push (production) never deploys another run's candidate, and the three names go together.
  assert.throws(
    () => candidateEnvironment("0.1.0-ci.547.1", { ...dispatch, GITHUB_EVENT_NAME: "push" }),
    /Only the proof dispatch/u,
  );
  for (const name of [
    "ARCFORGES_CANDIDATE_RUN_ID",
    "ARCFORGES_CANDIDATE_RUN_NUMBER",
    "ARCFORGES_CANDIDATE_RUN_ATTEMPT",
  ])
    for (const value of ["", "x", "0"])
      assert.throws(
        () => candidateEnvironment("0.1.0-ci.547.1", { ...dispatch, [name]: value }),
        /together/u,
      );
  // Without the names, the run's own identity as before.
  const own = candidateEnvironment("0.1.0-ci.560.1", {
    GITHUB_ACTIONS: "true",
    GITHUB_EVENT_NAME: "push",
    GITHUB_RUN_ID: "41900000000",
    GITHUB_RUN_NUMBER: "560",
    GITHUB_RUN_ATTEMPT: "1",
  });
  assert.equal(own.GITHUB_RUN_ID, "41900000000");
});

// The workflow: which jobs run for each event, evaluated from the jobs' own `if:` and `needs:` the way GitHub Actions does.
const workflow = readFileSync(path.join(root, ".github/workflows/ci.yml"), "utf8");

function jobsOf(text: string): Map<string, string> {
  const after = text.split(/^jobs:\n/mu)[1] ?? "";
  const parts = after.split(/^ {2}([a-z][a-z-]*):\n/mu);
  const jobs = new Map<string, string>();
  for (let index = 1; index + 1 < parts.length; index += 2)
    jobs.set(parts[index] ?? "", parts[index + 1] ?? "");
  return jobs;
}

const jobs = jobsOf(workflow);

function condition(body: string): string | null {
  const folded = /^ {4}if: >-\n((?: {6}.*\n)+)/mu.exec(body);
  if (folded?.[1])
    return folded[1]
      .split("\n")
      .map((line) => line.trim())
      .join(" ")
      .trim();
  const single = /^ {4}if: (.+)$/mu.exec(body);
  return single?.[1]?.trim() ?? null;
}

function needsOf(body: string): string[] {
  const listed = /^ {4}needs: \[(.*)\]$/mu.exec(body);
  if (listed?.[1] !== undefined)
    return listed[1]
      .split(",")
      .map((name) => name.trim())
      .filter(Boolean);
  const single = /^ {4}needs: ([a-z-]+)$/mu.exec(body);
  return single?.[1] ? [single[1]] : [];
}

type Value = string | boolean;
interface Scenario {
  event: string;
  ref: string;
  proof?: string;
  author?: string;
  failing?: string[];
}

/** A small evaluator of the expression subset ci.yml uses: ! && || == != ( ), 'strings', contexts and the status functions. */
function evaluate(
  expression: string,
  lookup: (name: string) => Value,
  status: (fn: string) => boolean,
): Value {
  const tokens =
    expression.match(
      /\s*(\(|\)|!=|==|!|&&|\|\||'[^']*'|[A-Za-z_][A-Za-z0-9_.-]*\(\)|[A-Za-z_][A-Za-z0-9_.-]*)/gu,
    ) ?? [];
  assert.equal(
    tokens.join("").replace(/\s/gu, ""),
    expression.replace(/\s/gu, ""),
    `unparsed: ${expression}`,
  );
  const queue = tokens.map((token) => token.trim());
  let position = 0;
  const peek = () => queue[position];
  const take = () => queue[position++] ?? "";
  const truthy = (value: Value) => value !== false && value !== "";
  const primary = (): Value => {
    const token = take();
    if (token === "(") {
      const value = or();
      assert.equal(take(), ")");
      return value;
    }
    if (token.startsWith("'")) return token.slice(1, -1);
    if (token.endsWith("()")) return status(token.slice(0, -2));
    return lookup(token);
  };
  const comparison = (): Value => {
    const left = primary();
    if (peek() === "==" || peek() === "!=") {
      const operator = take();
      const right = primary();
      return operator === "==" ? left === right : left !== right;
    }
    return left;
  };
  const unary = (): Value => {
    if (peek() === "!") {
      take();
      return !truthy(unary());
    }
    return comparison();
  };
  const and = (): Value => {
    let value = unary();
    while (peek() === "&&") {
      take();
      const right = unary();
      value = truthy(value) && truthy(right);
    }
    return value;
  };
  const or = (): Value => {
    let value = and();
    while (peek() === "||") {
      take();
      const right = and();
      value = truthy(value) || truthy(right);
    }
    return value;
  };
  const result = or();
  assert.equal(position, queue.length, `trailing tokens in ${expression}`);
  return truthy(result);
}

/** The jobs that run for a scenario (a job that runs succeeds unless the scenario names it as failing). */
function running(scenario: Scenario): Map<string, string> {
  const results = new Map<string, string>();
  const resolve = (name: string): string => {
    const known = results.get(name);
    if (known !== undefined) return known;
    const body = jobs.get(name);
    assert.ok(body !== undefined, `no job ${name}`);
    const needs = needsOf(body);
    const needed = needs.map(resolve);
    const lookup = (context: string): Value => {
      if (context === "github.event_name") return scenario.event;
      if (context === "github.ref") return scenario.ref;
      if (context === "inputs.proof")
        return scenario.event === "workflow_dispatch" ? (scenario.proof ?? "none") : "";
      if (context === "github.event.pull_request.user.login")
        return scenario.event === "pull_request" ? (scenario.author ?? "") : "";
      const need = /^needs\.([a-z-]+)\.result$/u.exec(context);
      if (need?.[1] && needs.includes(need[1])) return resolve(need[1]);
      assert.fail(`${name}: unknown context ${context}`);
    };
    const status = (fn: string) => {
      if (fn === "always") return true;
      if (fn === "cancelled") return false;
      if (fn === "success") return needed.every((result) => result === "success");
      if (fn === "failure") return needed.some((result) => result === "failure");
      assert.fail(`${name}: unknown function ${fn}`);
    };
    const expression = condition(body);
    const explicit =
      expression !== null && /\b(always|cancelled|success|failure)\(\)/u.test(expression);
    const runs =
      (explicit || needed.every((result) => result === "success")) &&
      (expression === null ||
        evaluate(expression.replace(/^\$\{\{|\}\}$/gu, ""), lookup, status) === true);
    const result = runs ? (scenario.failing?.includes(name) ? "failure" : "success") : "skipped";
    results.set(name, result);
    return result;
  };
  for (const name of jobs.keys()) resolve(name);
  return new Map([...results].filter(([, result]) => result !== "skipped"));
}

const ran = (scenario: Scenario) => [...running(scenario).keys()].sort();
const main = "refs/heads/main";
const validation = ["candidate", "codeql", "quality", "source", "verify"];

test("the proof deployment dispatch runs only the gate, the access job and the deployment: no hosted validation, no candidate", () => {
  assert.deepEqual(ran({ event: "workflow_dispatch", ref: main, proof: "deploy" }), [
    "deploy-proof",
    "proof-access",
    "proof-gate",
  ]);
  // The deployment needs the gate: a failed gate (or access job) deploys nothing.
  assert.deepEqual(
    ran({ event: "workflow_dispatch", ref: main, proof: "deploy", failing: ["proof-gate"] }),
    ["proof-access", "proof-gate"],
  );
  assert.deepEqual(
    ran({ event: "workflow_dispatch", ref: main, proof: "deploy", failing: ["proof-access"] }),
    ["proof-access", "proof-gate"],
  );
  const deploy = jobs.get("deploy-proof") ?? "";
  assert.ok(needsOf(deploy).includes("proof-gate"), "deploy-proof needs the gate");
  assert.match(condition(deploy) ?? "", /&& needs\.proof-gate\.result == 'success'/u);
  // Off main nothing of the proof environment runs, and the full hosted validation runs exactly as before the gate: a dispatch
  // can never put a skipped (passing) Verify on a branch head.
  assert.deepEqual(
    ran({ event: "workflow_dispatch", ref: "refs/heads/task/x", proof: "deploy" }),
    validation,
  );
});

test("every other event keeps its jobs: main push delivery, PR validation, schedule security, other dispatches", () => {
  assert.deepEqual(ran({ event: "push", ref: main }), ["candidate", "deploy"]);
  assert.deepEqual(ran({ event: "push", ref: main, failing: ["candidate"] }), ["candidate"]);
  assert.deepEqual(
    ran({ event: "pull_request", ref: "refs/pull/1/merge", author: "dependabot[bot]" }),
    [...validation.slice(0, 2), "dependency-review", ...validation.slice(2)],
  );
  assert.deepEqual(
    ran({ event: "pull_request", ref: "refs/pull/1/merge", author: "deku2026" }),
    [],
  );
  assert.deepEqual(ran({ event: "schedule", ref: main }), ["codeql", "quality"]);
  assert.deepEqual(ran({ event: "workflow_dispatch", ref: main, proof: "none" }), validation);
  for (const proof of ["access", "provision", "observe"])
    assert.deepEqual(ran({ event: "workflow_dispatch", ref: main, proof }), [
      ...validation.slice(0, 2),
      "proof-access",
      ...validation.slice(2),
    ]);
});

test("the gate job holds no secret and reads only: contents, statuses, actions and pull requests", () => {
  const gate = jobs.get("proof-gate") ?? "";
  const permissions = /^ {4}permissions:\n((?: {6}.*\n)+)/mu.exec(gate)?.[1] ?? "";
  assert.deepEqual(
    permissions
      .trim()
      .split("\n")
      .map((line) => line.trim())
      .sort(),
    ["actions: read", "contents: read", "pull-requests: read", "statuses: read"],
  );
  assert.doesNotMatch(gate, /secrets\.|environment:|CLOUDFLARE|NEON|inputs\.bootstrap/u);
  assert.match(gate, /^ {8}run: node eng\/verification\/proof-gate\.ts gate$/mu);
  assert.match(gate, /^ {10}GH_TOKEN: \$\{\{ github\.token \}\}$/mu);
  // Its outputs are the gate script's outputs, all of which the deployment job uses.
  const outputs = [
    ...gate.matchAll(/^ {6}([a-z-]+): \$\{\{ steps\.gate\.outputs\.([a-z-]+) \}\}$/gmu),
  ];
  assert.ok(outputs.length >= 7);
  for (const [, name, from] of outputs) {
    assert.equal(name, from);
    assert.match(
      jobs.get("deploy-proof") ?? "",
      new RegExp(`needs\\.proof-gate\\.outputs\\.${name} `, "u"),
    );
  }
});

test("the deployment job fetches the gated candidate before it migrates or deploys, and builds or downloads nothing else", () => {
  const deploy = jobs.get("deploy-proof") ?? "";
  assert.doesNotMatch(deploy, /needs\.candidate|download-artifact|npm run candidate/u);
  const fetch = deploy.indexOf("run: node eng/verification/proof-gate.ts fetch");
  assert.ok(fetch > 0);
  for (const later of [
    "run: node eng/migrations/deploy.ts deploy --target proof",
    "run: node tooling/postgres-deploy.ts migrate --target acceptance",
    "run: npm run deploy:proof",
  ])
    assert.ok(deploy.indexOf(later) > fetch, later);
  assert.match(deploy, /^ {4}permissions:\n {6}contents: read\n {6}actions: read\n/mu);
  for (const name of ["run-id", "run-number", "run-attempt"])
    assert.match(
      deploy,
      new RegExp(
        `^ {6}ARCFORGES_CANDIDATE_${name.replace("-", "_").toUpperCase()}: \\$\\{\\{ needs\\.proof-gate\\.outputs\\.${name} \\}\\}$`,
        "mu",
      ),
    );
  // Every action of the workflow is pinned by its full commit SHA.
  const actions = [...workflow.matchAll(/^ +(?:- )?uses: (\S+)/gmu)].map((match) => match[1] ?? "");
  assert.ok(actions.length > 20);
  for (const action of actions)
    assert.match(action, /^[a-z-]+\/[a-z-]+(?:\/[a-z-]+)?@[0-9a-f]{40}$/u);
});

test("the main-push path and the reviewed proof deployment steps remain pinned", () => {
  // Candidate and production deployment retain the pre-gate pins (Cloud main 9085b12). E3 adds only the public
  // proof-key-registration.json evidence artifact to the proof steps, which receive their own reviewed pin below.
  // Any future change here is a reviewed delivery-path change, never an incidental effect of the gate.
  const digest = (value: string) => createHash("sha256").update(value).digest("hex");
  const deploy = jobs.get("deploy-proof") ?? "";
  const candidate = jobs.get("candidate") ?? "";
  const pins = {
    candidate: digest(candidate.slice(candidate.indexOf("    runs-on:"))),
    deploy: digest(jobs.get("deploy") ?? ""),
    proofSteps: digest(
      deploy.slice(deploy.indexOf("      # CLOUD.70: the same gated D1 migration step")),
    ),
  };
  assert.match(deploy, /artifacts\/proof-key-registration\.json/u);
  assert.deepEqual(pins, {
    candidate: "e9304d0b4ed9b27272acf3bf654ee7271e924a214e243212930321b6699a8b00",
    deploy: "63df864296382e2a0e9c44211af75ee4f7396dad874d53f418f2b61e718c7fe3",
    proofSteps: "809f00adb5ec26e565dd3a1273a1fd61e43faf0f19dfe3166337a678910dda1a",
  });
});
