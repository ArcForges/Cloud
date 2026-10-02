// SPDX-License-Identifier: AGPL-3.0-only
import { DurableObject } from "cloudflare:workers";
import {
  admitEvent,
  completeEvent,
  emptyState,
  releaseEvent,
  type CoordinatorState,
} from "./coordination.ts";
import type { AdmitResult } from "./types.ts";

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const stateKey = "state";

/**
 * One instance per job (addressed by job id). It owns only coordination state: which wake events were
 * processed and whether a slice is in flight. It has no alarm, no customer data and no authority.
 */
export class FoundationJobCoordinator extends DurableObject {
  private async load(): Promise<CoordinatorState> {
    return (await this.ctx.storage.get<CoordinatorState>(stateKey)) ?? emptyState();
  }

  async admit(eventId: string): Promise<AdmitResult> {
    if (!uuid.test(eventId)) throw new Error("Invalid event id");
    const state = await this.load();
    const next = admitEvent(state, eventId, Date.now());
    if (next.state !== state) await this.ctx.storage.put(stateKey, next.state);
    return next.result;
  }

  async complete(eventId: string): Promise<void> {
    if (!uuid.test(eventId)) throw new Error("Invalid event id");
    const state = await this.load();
    const next = completeEvent(state, eventId);
    if (next !== state) await this.ctx.storage.put(stateKey, next);
  }

  async release(eventId: string): Promise<void> {
    if (!uuid.test(eventId)) throw new Error("Invalid event id");
    const state = await this.load();
    const next = releaseEvent(state, eventId);
    if (next !== state) await this.ctx.storage.put(stateKey, next);
  }
}
