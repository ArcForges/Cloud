// SPDX-License-Identifier: AGPL-3.0-only
// Scheduling holds no business permission or progress: the production Platform D1 lease does.
export interface CapacityOwner {
  realmId: string;
  workspaceId: string | null;
  kind: string;
  ownerId: string;
}
export interface CapacityWake {
  wakeId: string;
  owner: CapacityOwner;
  jobId: string;
  holder: string;
  claimCommandId: string;
  checkpointCommandId: string;
}
export interface CapacityPacerState {
  wake: CapacityWake;
  dueAt: number;
  failures: number;
  paused: boolean;
}
export interface CapacityPacerStorage {
  get(): Promise<CapacityPacerState | undefined>;
  put(state: CapacityPacerState): Promise<void>;
  delete(): Promise<void>;
  alarm(at: number | null): Promise<void>;
  exclusive<T>(action: () => Promise<T>): Promise<T>;
}
export type CapacityReply = {
  status: "Complete" | "Reschedule" | "Busy" | "Refused" | "Unavailable" | "UnknownOutcome";
  availableAtMicros?: string | null;
};
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const nil = "00000000-0000-0000-0000-000000000000";
const id = (value: unknown): value is string =>
  typeof value === "string" && uuid.test(value) && value !== nil;
export function validWake(value: unknown): value is CapacityWake {
  if (value === null || typeof value !== "object") return false;
  const w = value as CapacityWake;
  return (
    Object.keys(w).sort().join(",") ===
      "checkpointCommandId,claimCommandId,holder,jobId,owner,wakeId" &&
    id(w.wakeId) &&
    id(w.jobId) &&
    id(w.claimCommandId) &&
    id(w.checkpointCommandId) &&
    new Set([w.wakeId, w.claimCommandId, w.checkpointCommandId]).size === 3 &&
    w.holder === `capacity-${w.wakeId}` &&
    w.owner !== null &&
    typeof w.owner === "object" &&
    Object.keys(w.owner).sort().join(",") === "kind,ownerId,realmId,workspaceId" &&
    id(w.owner.realmId) &&
    id(w.owner.ownerId) &&
    (w.owner.workspaceId === null || id(w.owner.workspaceId)) &&
    typeof w.owner.kind === "string" &&
    /^[A-Za-z0-9._:/-]{1,64}$/u.test(w.owner.kind)
  );
}
export function freshWake(owner: CapacityOwner, jobId: string, newId: () => string): CapacityWake {
  const wakeId = newId();
  const wake = {
    owner,
    jobId,
    wakeId,
    holder: `capacity-${wakeId}`,
    claimCommandId: newId(),
    checkpointCommandId: newId(),
  };
  if (!validWake(wake)) throw new Error("Invalid capacity wake identity");
  return wake;
}
const sameJob = (a: CapacityWake, b: CapacityWake) =>
  a.jobId === b.jobId &&
  a.owner.realmId === b.owner.realmId &&
  a.owner.workspaceId === b.owner.workspaceId &&
  a.owner.kind === b.owner.kind &&
  a.owner.ownerId === b.owner.ownerId;

/** One durable object per realm/job. A failed dispatch retains the same immutable wake for bounded
 * transport replay; a definite continuation receives new command IDs. A crash after a successful
 * call replays its D1 command receipts; no queue delivery count becomes business completion. */
export class CapacityPacer {
  private running = false;
  private readonly storage: CapacityPacerStorage;
  private readonly call: (wake: CapacityWake) => Promise<CapacityReply>;
  private readonly now: () => number;
  private readonly newId: () => string;
  constructor(
    storage: CapacityPacerStorage,
    call: (wake: CapacityWake) => Promise<CapacityReply>,
    now: () => number = Date.now,
    newId: () => string = () => crypto.randomUUID(),
  ) {
    this.storage = storage;
    this.call = call;
    this.now = now;
    this.newId = newId;
  }

  async schedule(
    wake: CapacityWake,
    dueAt: number,
  ): Promise<"scheduled" | "duplicate" | "conflict"> {
    if (!validWake(wake) || !Number.isSafeInteger(dueAt) || dueAt < 0)
      throw new Error("Invalid capacity schedule");
    return this.storage.exclusive(async () => {
      const old = await this.storage.get();
      if (old && !sameJob(old.wake, wake)) return "conflict";
      if (old && !old.paused) {
        // Another caller cannot discard a dispatched command identity or extend its deadline.
        if (dueAt < old.dueAt) {
          await this.storage.put({ ...old, dueAt });
          await this.storage.alarm(Math.max(this.now(), dueAt));
        }
        return "duplicate";
      }
      const state = { wake, dueAt, failures: 0, paused: false };
      await this.storage.put(state);
      await this.storage.alarm(Math.max(this.now(), dueAt));
      return "scheduled";
    });
  }

  async run(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      await this.runOnce();
    } finally {
      this.running = false;
    }
  }

  private async runOnce(): Promise<void> {
    const selected = await this.storage.exclusive(async () => {
      const state = await this.storage.get();
      if (!state || state.paused) return null;
      if (state.dueAt > this.now()) {
        await this.storage.alarm(state.dueAt);
        return null;
      }
      // Persist a recovery alarm before network I/O; an evicted object cannot lose its only wake.
      await this.storage.alarm(this.now() + 60_000);
      return state;
    });
    if (!selected) return;
    let reply: CapacityReply;
    try {
      reply = await this.call(selected.wake);
    } catch {
      reply = { status: "Unavailable" };
    }
    await this.storage.exclusive(async () => {
      const current = await this.storage.get();
      if (!current || current.wake.wakeId !== selected.wake.wakeId || current.paused) return;
      if (reply.status === "Complete") {
        await this.storage.delete();
        await this.storage.alarm(null);
        return;
      }
      if (reply.status === "Refused") {
        await this.storage.put({ ...current, paused: true });
        await this.storage.alarm(null);
        return;
      }
      if (reply.status === "Busy" || reply.status === "Reschedule") {
        // Integer microseconds are wire strings; never lose a large fence/time through JSON numbers.
        if (
          typeof reply.availableAtMicros === "string" &&
          /^(0|[1-9][0-9]{0,18})$/u.test(reply.availableAtMicros)
        ) {
          const micros = BigInt(reply.availableAtMicros);
          const millis = Number((micros + 999n) / 1000n);
          if (Number.isSafeInteger(millis) && millis >= this.now()) {
            const state = {
              wake: freshWake(current.wake.owner, current.wake.jobId, this.newId),
              dueAt: Math.max(this.now() + 100, millis),
              failures: 0,
              paused: false,
            };
            await this.storage.put(state);
            await this.storage.alarm(state.dueAt);
            return;
          }
        }
      }
      const failures = current.failures + 1;
      const state = {
        ...current,
        failures,
        dueAt: this.now() + Math.min(60_000, 1000 * 2 ** Math.min(failures - 1, 6)),
        paused: failures >= 20,
      };
      await this.storage.put(state);
      await this.storage.alarm(state.paused ? null : state.dueAt);
    });
  }
}
