// SPDX-License-Identifier: AGPL-3.0-only
import { Container } from "@cloudflare/containers";
import type { DurableObject } from "cloudflare:workers";
import {
  admitEvent,
  completeEvent,
  emptyState,
  releaseEvent,
  type CoordinatorState,
} from "./coordination.ts";
import { emptyObservation, withAttempt, withDeadLetter } from "./poison.ts";
import type { AdmitResult, PoisonObservation } from "./types.ts";

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const stateKey = "state";
const poisonKey = "poison";

// Container extends DurableObject (its documented base). Deriving the base from it keeps the emitted
// bundle's external `cloudflare:workers` import to the single statement the release profile can bind.
const DurableObjectBase = Object.getPrototypeOf(Container) as typeof DurableObject;

/**
 * One instance per job (addressed by job id). It owns only coordination state: which wake events were
 * processed and whether a slice is in flight. It has no alarm, no customer data and no authority.
 */
export class FoundationJobCoordinator extends DurableObjectBase {
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

  // The proof-only queue retry/dead-letter probe records its deliveries here (one instance per probe id).
  async recordPoisonAttempt(attempt: number): Promise<void> {
    if (!Number.isSafeInteger(attempt) || attempt < 1) throw new Error("Invalid attempt");
    const state = (await this.ctx.storage.get<PoisonObservation>(poisonKey)) ?? emptyObservation();
    await this.ctx.storage.put(poisonKey, withAttempt(state, attempt, Date.now()));
  }

  async recordDeadLetter(attempt: number): Promise<void> {
    if (!Number.isSafeInteger(attempt) || attempt < 1) throw new Error("Invalid attempt");
    const state = (await this.ctx.storage.get<PoisonObservation>(poisonKey)) ?? emptyObservation();
    const next = withDeadLetter(state, attempt, Date.now());
    if (next !== state) await this.ctx.storage.put(poisonKey, next);
  }

  async readPoison(): Promise<PoisonObservation> {
    return (await this.ctx.storage.get<PoisonObservation>(poisonKey)) ?? emptyObservation();
  }
}
