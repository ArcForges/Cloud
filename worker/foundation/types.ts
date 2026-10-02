// SPDX-License-Identifier: AGPL-3.0-only
// Narrow structural views of the Cloudflare bindings used by the foundation proof. The real bindings
// satisfy them and the offline tests fake them, so the logic modules never import Worker types.
import type { PrivateKeyEnv } from "../private/hmac-settings.ts";
import type { StorageEnv } from "../storage/handler.ts";

export interface R2ObjectLike {
  readonly size: number;
  readonly customMetadata?: Record<string, string>;
}
export interface R2ObjectBodyLike extends R2ObjectLike {
  readonly body: ReadableStream<Uint8Array>;
}
export interface R2Like {
  put(
    key: string,
    value: ReadableStream<Uint8Array>,
    options: {
      sha256: string;
      customMetadata: Record<string, string>;
      onlyIf?: { etagDoesNotMatch: string };
    },
  ): Promise<R2ObjectLike | null>;
  head(key: string): Promise<R2ObjectLike | null>;
  get(
    key: string,
    options?: { range: { offset: number; length: number } },
  ): Promise<R2ObjectBodyLike | null>;
  delete(key: string): Promise<void>;
}

export interface WakeMessage {
  v: 1;
  kind: "job.wake";
  jobId: string;
  scope: string;
  eventId: string;
}
export interface QueueLike {
  send(message: WakeMessage, options?: { delaySeconds?: number }): Promise<void>;
}

export interface CoordinatorLike {
  admit(eventId: string): Promise<AdmitResult>;
  complete(eventId: string): Promise<void>;
  release(eventId: string): Promise<void>;
}
export type AdmitResult = { admit: true } | { admit: false; reason: "duplicate" | "busy" };

export interface ContainerStubLike {
  fetch(request: Request): Promise<Response>;
  stop?(): Promise<void>;
}
export interface ContainerNamespaceLike {
  getByName(name: string): ContainerStubLike;
}
export interface CoordinatorNamespaceLike {
  getByName(name: string): CoordinatorLike;
}

/** Bindings and variables of the isolated proof environment. Absent in production. */
export interface FoundationEnv extends StorageEnv, PrivateKeyEnv {
  FOUNDATION_PROOF?: string;
  REALM_ID?: string;
  ALLOWED_ORIGIN?: string;
  CSRF_SECRET?: string;
  PROOF_OPERATOR_TOKEN?: string;
  OBJECTS: R2Like;
  WAKE_QUEUE: QueueLike;
  JOB_COORDINATOR: CoordinatorNamespaceLike;
  CLOUD_CONTAINER: ContainerNamespaceLike;
}

export const foundationContainerName = "foundation";

export function proofEnabled(env: { FOUNDATION_PROOF?: string }): boolean {
  return env.FOUNDATION_PROOF === "enabled";
}
