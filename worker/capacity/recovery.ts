// SPDX-License-Identifier: AGPL-3.0-only
import {
  callCapacityRecovery,
  validRecoveryCursor,
  type CapacityClientEnv,
  type CapacityRecoveryCursor,
} from "./container-client.ts";

export interface RecoveryState {
  cursor: CapacityRecoveryCursor | null;
  holder: string | null;
  until: number;
}
export interface RecoveryStorage {
  get(): Promise<RecoveryState | undefined>;
  put(value: RecoveryState): Promise<void>;
  exclusive<T>(action: () => Promise<T>): Promise<T>;
}
/** Cursor/lease are scheduling hints only. Persisted keyset progress prevents a refused job at the
 * start of a large backlog starving later jobs. D1 owner/generation/lease authority remains intact. */
export class CapacityRecoveryCoordinator {
  private readonly storage: RecoveryStorage;
  private readonly now: () => number;
  constructor(storage: RecoveryStorage, now: () => number = Date.now) {
    this.storage = storage;
    this.now = now;
  }
  async begin(holder: string): Promise<{ cursor: CapacityRecoveryCursor | null } | null> {
    if (
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(holder) ||
      holder === "00000000-0000-0000-0000-000000000000"
    )
      throw new Error("Invalid recovery holder");
    return this.storage.exclusive(async () => {
      const old = await this.storage.get();
      if (old?.holder && old.until > this.now()) return null;
      if (old?.cursor && !validRecoveryCursor(old.cursor))
        throw new Error("Invalid recovery cursor");
      const cursor = old?.cursor ?? null;
      await this.storage.put({ cursor, holder, until: this.now() + 30_000 });
      return { cursor };
    });
  }
  async advance(
    holder: string,
    cursor: CapacityRecoveryCursor | null,
    complete: boolean,
  ): Promise<boolean> {
    if (cursor !== null && !validRecoveryCursor(cursor)) throw new Error("Invalid recovery cursor");
    return this.storage.exclusive(async () => {
      const old = await this.storage.get();
      if (!old || old.holder !== holder || old.until <= this.now()) return false;
      await this.storage.put({
        cursor,
        holder: complete ? null : holder,
        until: complete ? 0 : old.until,
      });
      return true;
    });
  }
}

export interface RecoveryNamespace {
  getByName(name: string): {
    recoveryBegin(holder: string): Promise<{ cursor: CapacityRecoveryCursor | null } | null>;
    recoveryAdvance(
      holder: string,
      cursor: CapacityRecoveryCursor | null,
      complete: boolean,
    ): Promise<boolean>;
  };
}
export type CapacityRecoveryEnv = CapacityClientEnv & {
  CAPACITY_ENABLED?: string;
  CAPACITY_PACER?: RecoveryNamespace;
};

/** One minute cron repairs at most 100 hints in a total 20 seconds. A transient/unknown response
 * retains the current page cursor, and the next cron retries hints without repeating job effects. */
export async function recoverCapacity(
  env: CapacityRecoveryEnv,
  now: () => number = Date.now,
  newId: () => string = () => crypto.randomUUID(),
): Promise<void> {
  if (env.CAPACITY_ENABLED !== "enabled" || !env.CAPACITY_PACER || !env.CAPACITY_CONTAINER_NAME)
    return;
  const deadline = now() + 20_000;
  const holder = newId();
  const coordinator = env.CAPACITY_PACER.getByName(
    `capacity-recovery:${env.CAPACITY_CONTAINER_NAME}`,
  );
  const admitted = await coordinator.recoveryBegin(holder);
  if (!admitted) return;
  let cursor = admitted.cursor;
  try {
    for (let page = 0; page < 10; page++) {
      const remaining = Math.floor(deadline - now());
      if (remaining <= 0) return;
      const reply = await callCapacityRecovery(
        env,
        newId(),
        cursor,
        Math.min(remaining, 25_000),
        now,
      );
      if (reply.status !== "Succeeded") return;
      if (reply.nextDueAtMicros !== null && reply.nextJobId === null)
        throw new Error("Invalid recovery cursor");
      cursor =
        reply.nextDueAtMicros === null
          ? null
          : { dueAtMicros: reply.nextDueAtMicros, jobId: reply.nextJobId as string };
      if (!(await coordinator.recoveryAdvance(holder, cursor, cursor === null))) return;
      if (cursor === null) return;
    }
  } finally {
    await coordinator.recoveryAdvance(holder, cursor, true);
  }
}
