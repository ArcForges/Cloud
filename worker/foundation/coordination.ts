// SPDX-License-Identifier: AGPL-3.0-only
// Per-job coordination state of the FoundationJobCoordinator Durable Object: duplicate-delivery
// admission by event id and single-flight slices. It is a disposable projection: D1 stays the
// authority (lease, fence and inbox), so losing this state can only cause a safe re-check.
import type { AdmitResult } from "./types.ts";

export const maxSeenEvents = 64;
export const inflightLeaseMs = 70_000;

export interface CoordinatorState {
  /** Most recent completed event ids, oldest first, at most maxSeenEvents. */
  seen: string[];
  inflight: { eventId: string; until: number } | null;
}

export const emptyState = (): CoordinatorState => ({ seen: [], inflight: null });

export function admitEvent(
  state: CoordinatorState,
  eventId: string,
  nowMs: number,
): { state: CoordinatorState; result: AdmitResult } {
  if (state.seen.includes(eventId)) return { state, result: { admit: false, reason: "duplicate" } };
  if (state.inflight && state.inflight.until > nowMs)
    return { state, result: { admit: false, reason: "busy" } };
  return {
    state: { seen: state.seen, inflight: { eventId, until: nowMs + inflightLeaseMs } },
    result: { admit: true },
  };
}

/** Marks the in-flight event as processed (its effect is committed in D1). */
export function completeEvent(state: CoordinatorState, eventId: string): CoordinatorState {
  if (state.inflight?.eventId !== eventId) return state;
  return { seen: [...state.seen, eventId].slice(-maxSeenEvents), inflight: null };
}

/** Clears the in-flight event without marking it processed, so a retry of the same message can run. */
export function releaseEvent(state: CoordinatorState, eventId: string): CoordinatorState {
  return state.inflight?.eventId === eventId ? { seen: state.seen, inflight: null } : state;
}
