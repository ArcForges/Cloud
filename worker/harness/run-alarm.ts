// SPDX-License-Identifier: AGPL-3.0-only
// The Durable Object alarm that wakes a run. It is a thin platform adapter (P2-021 item 1): it holds only a wake handle (a run identifier
// and a time), it never reads or writes run state, and it does not decide whether the run advances. Each alarm sends one signed wake
// to the C# endpoint and reports nothing else; the C# side claims, resumes and records every outcome under its own fence.
// The C# executor arms the wake before it parks a run with a timer, and cancels it best-effort when the parking commit fails. The arming
// request reaches schedule() and cancel() through the harness.internal outbound handler (worker/harness/internal/outbound.ts), on the proof
// Container class only. The live observation of a real alarm wake after a restart is an operator step (docs/harness-proofs.md, Proof 2).
import { Container } from "@cloudflare/containers";
import type { DurableObject } from "cloudflare:workers";
import type { ContainerNamespaceLike } from "../foundation/types.ts";
import { loadKeys, type PrivateKeyEnv } from "../private/hmac-settings.ts";
import { newNonce, sign } from "../private/signing.ts";
import {
  afterFailure,
  harnessContainerName,
  isWorkerVersion,
  parseSchedule,
  readHandle,
  wakeBody,
  wakeBodySha256Hex,
  wakePath,
  type WakeHandle,
} from "./run-alarm-core.ts";

export interface RunAlarmEnv extends PrivateKeyEnv {
  CLOUD_CONTAINER: ContainerNamespaceLike;
  /** The Worker's version metadata binding (wrangler version_metadata); its id is the Worker version identifier of the wake. */
  CF_VERSION_METADATA?: { readonly id: string };
}

/** The only storage key the alarm uses; it holds the wake handle and nothing else. */
const handleKey = "wake";

// The base is the Durable Object base that Container extends (the same derivation as foundation/durable.ts). A value import of
// `cloudflare:workers` here would add a second external import statement to the bundle, which the release profile does not bind.
const DurableObjectBase = Object.getPrototypeOf(Container) as typeof DurableObject;

export class HarnessRunAlarm extends DurableObjectBase<RunAlarmEnv> {
  /** Stores the wake handle and sets the alarm. Anything outside the closed schedule shape is refused and writes nothing. */
  async schedule(input: unknown): Promise<{ scheduled: boolean }> {
    const parsed = parseSchedule(input, Date.now());
    if (!parsed.ok) return { scheduled: false };
    await this.ctx.storage.put(handleKey, parsed.handle);
    await this.ctx.storage.setAlarm(parsed.handle.wakeAtMs);
    return { scheduled: true };
  }

  /** Drops the wake handle and its alarm. */
  async cancel(): Promise<void> {
    await this.ctx.storage.delete(handleKey);
    await this.ctx.storage.deleteAlarm();
  }

  async alarm(): Promise<void> {
    const handle = readHandle(await this.ctx.storage.get(handleKey));
    if (!handle) {
      await this.ctx.storage.delete(handleKey);
      return;
    }

    if (await this.deliver(handle)) {
      await this.ctx.storage.delete(handleKey);
      return;
    }

    // Bounded retries: a failed wake is retried on the backoff schedule, then dropped; the C# side reconciles on its own timer.
    const plan = afterFailure(handle, Date.now());
    if (plan.kind === "drop") {
      await this.ctx.storage.delete(handleKey);
      return;
    }
    await this.ctx.storage.put(handleKey, plan.handle);
    await this.ctx.storage.setAlarm(plan.atMs);
  }

  /**
   * One signed wake to the C# endpoint. The endpoint answers 200 once it has taken the wake; its own decision follows. Without a
   * configured W2C key the wake is not sent at all (fail closed), and a transport failure is reported as not delivered.
   */
  private async deliver(handle: WakeHandle): Promise<boolean> {
    const keys = loadKeys(this.env, "W2C");
    if (!keys) return false;
    // Without the Worker version identifier the wake is not sent; the alarm keeps its handle and retries on the bounded schedule.
    const workerVersion = this.env.CF_VERSION_METADATA?.id;
    if (!isWorkerVersion(workerVersion)) return false;
    const body = wakeBody(handle, workerVersion);
    const headers = await sign(
      {
        method: "POST",
        pathAndQuery: wakePath,
        bodySha256Hex: await wakeBodySha256Hex(body),
        requestId: crypto.randomUUID(),
        time: String(Math.floor(Date.now() / 1000)),
        nonce: newNonce(),
      },
      keys.current,
    );
    try {
      const response = await this.env.CLOUD_CONTAINER.getByName(harnessContainerName).fetch(
        new Request(`http://container${wakePath}`, {
          method: "POST",
          headers: { ...headers, "content-type": "application/json" },
          body: body as BodyInit,
        }),
      );
      await response.body?.cancel().catch(() => {});
      return response.status === 200;
    } catch {
      return false;
    }
  }
}
