// SPDX-License-Identifier: AGPL-3.0-only
import { Container } from "@cloudflare/containers";
import type { DurableObject } from "cloudflare:workers";
import { callCapacity, type CapacityClientEnv } from "./container-client.ts";
import { CapacityPacer, type CapacityPacerState, type CapacityWake } from "./pacer.ts";
import { CapacityRecoveryCoordinator, type RecoveryState } from "./recovery.ts";
import type { CapacityRecoveryCursor } from "./container-client.ts";

const DurableObjectBase = Object.getPrototypeOf(Container) as typeof DurableObject;
const stateKey = "capacity-pacer-v1";

/** Scheduling only. Each realm/job has one object; the actual Platform D1 job is the progress,
 * retry-limit, current owner and lease/fence authority. No customer content is stored here. */
export class CapacityJobPacer extends DurableObjectBase {
  private readonly pacer: CapacityPacer;
  private readonly recovery: CapacityRecoveryCoordinator;
  constructor(ctx: DurableObjectState, env: CapacityClientEnv) {
    super(ctx, env);
    this.recovery = new CapacityRecoveryCoordinator({
      get: () => ctx.storage.get<RecoveryState>("capacity-recovery-v1"),
      put: (state) => ctx.storage.put("capacity-recovery-v1", state),
      exclusive: (action) => ctx.blockConcurrencyWhile(action),
    });
    this.pacer = new CapacityPacer(
      {
        get: () => ctx.storage.get<CapacityPacerState>(stateKey),
        put: (state) => ctx.storage.put(stateKey, state),
        delete: async () => {
          await ctx.storage.delete(stateKey);
        },
        alarm: (at) => (at === null ? ctx.storage.deleteAlarm() : ctx.storage.setAlarm(at)),
        exclusive: (action) => ctx.blockConcurrencyWhile(action),
      },
      (wake) => callCapacity(env, wake),
    );
  }
  async schedule(wake: CapacityWake, dueAt: number) {
    return this.pacer.schedule(wake, dueAt);
  }
  async alarm(): Promise<void> {
    await this.pacer.run();
  }
  async recoveryBegin(holder: string) {
    return this.recovery.begin(holder);
  }
  async recoveryAdvance(holder: string, cursor: CapacityRecoveryCursor | null, complete: boolean) {
    return this.recovery.advance(holder, cursor, complete);
  }
}
