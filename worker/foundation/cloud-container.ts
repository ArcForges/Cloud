// SPDX-License-Identifier: AGPL-3.0-only
// ARCFORGES_HELLO_RUNTIME=go selects the Go center (/app/arcforges-center) and passes it its explicit mode, public base URL and
// plan configuration, and the runtime role's pooled PostgreSQL URL of its store; the center refuses to start without a valid
// mode and base URL. It also passes the enabled surfaces the Worker forwards (FLAGSHIP_SURFACES as parsed here, "none" when none)
// and always names the header the Worker sets to the client's address, so the center and the Worker agree on both, and passes the
// identity policy override where an environment sets one (only the acceptance environment's anonymous-flow ceiling) and the owner bootstrap
// (digest and expiry) that a protected proof dispatch sets (never a checked-in value). The Hello's own Neon credential reaches only the C# host, or a Go center without a store. Proof subclasses
// keep their closed outbound policy and their own environment hook.
//
// The start environment follows the deployed Worker version (AF-CTR-03). A Container image rollout restarts a running instance with
// the new image but the environment of its previous start, so a center could keep the previous version's surfaces, client-address
// header and policy until its first idle sleep. Every request therefore first compares the digest of the settings this Worker
// version starts the center with against the digest recorded, in this Durable Object's storage, before the running center's start.
// A center started under another digest is stopped (SIGTERM, then SIGKILL, each bounded) and started again with this version's
// settings before the request is forwarded; one restart serves every request that arrives meanwhile.
import { Container, type OutboundHandler } from "@cloudflare/containers";
import { aiInternalOutbound } from "../ai/internal/outbound.ts";
import { startFailedText } from "../readiness/container.ts";
import { containerSleepAfter } from "../tables/cloud-tables.generated.ts";
import {
  centerStopPollMs,
  staleCenterKillMs,
  staleCenterStopMs,
} from "../tables/center-tables.generated.ts";
import { centerSurfaces, clientIpHeader } from "../ingress/routes.ts";

export interface CenterEnvironment {
  ARCFORGES_NEON_HELLO?: string;
  NEON_DATABASE_URL?: string;
  ARCFORGES_HELLO_RUNTIME?: string;
  ARCFORGES_CENTER_MODE?: string;
  ARCFORGES_CENTER_PUBLIC_BASE_URL?: string;
  ARCFORGES_CENTER_PLAN_CONFIGURATION?: string;
  /** The identity policy override; only the acceptance environment sets one (its anonymous-flow ceiling, C1). */
  ARCFORGES_CENTER_IDENTITY_POLICY?: string;
  ARCFORGES_CENTER_DATABASE_URL?: string;
  /** The owner bootstrap of a protected proof dispatch (AF-CTR-03 A2): the SHA-256 of a one-time token and its expiry. */
  ARCFORGES_CENTER_BOOTSTRAP_SHA256?: string;
  ARCFORGES_CENTER_BOOTSTRAP_EXPIRES_AT?: string;
  FLAGSHIP_SURFACES?: string;
}

/** What the Container runs: the entrypoint (undefined keeps the image's C# default), its environment and TCP egress. */
export interface CenterContainerSettings {
  entrypoint?: string[];
  envVars: Record<string, string>;
  enableInternet: boolean;
}

/** The Container settings of the configured Hello runtime; it throws on an unknown runtime or a missing Hello credential. */
export function centerContainerSettings(center: CenterEnvironment): CenterContainerSettings {
  const runtime = center.ARCFORGES_HELLO_RUNTIME;
  const settings: CenterContainerSettings = { envVars: {}, enableInternet: false };
  const go = runtime === "go";
  if (go) {
    settings.entrypoint = ["/app/arcforges-center"];
    // Passed through unchanged: the center validates them and refuses to start on a missing or invalid value.
    for (const name of [
      "ARCFORGES_CENTER_MODE",
      "ARCFORGES_CENTER_PUBLIC_BASE_URL",
      "ARCFORGES_CENTER_PLAN_CONFIGURATION",
      "ARCFORGES_CENTER_IDENTITY_POLICY",
      "ARCFORGES_CENTER_BOOTSTRAP_SHA256",
      "ARCFORGES_CENTER_BOOTSTRAP_EXPIRES_AT",
    ] as const) {
      const value = center[name];
      if (value !== undefined) settings.envVars[name] = value;
    }
    settings.envVars.ARCFORGES_CENTER_SURFACES = centerSurfaces(center.FLAGSHIP_SURFACES);
    settings.envVars.ARCFORGES_CENTER_CLIENT_IP_HEADER = clientIpHeader;
    if (center.ARCFORGES_CENTER_DATABASE_URL) {
      // Native PostgreSQL TCP is not handled by the HTTP outbound proxy; allowedHosts would NOT restrict TCP port 5432.
      settings.enableInternet = true;
      settings.envVars.ARCFORGES_CENTER_DATABASE_URL = center.ARCFORGES_CENTER_DATABASE_URL;
    }
  } else if (runtime !== undefined && runtime !== "" && runtime !== "csharp")
    throw new Error("Unknown Hello runtime.");
  const enabled = center.ARCFORGES_NEON_HELLO;
  if (enabled !== undefined && enabled !== "" && enabled !== "disabled") {
    // A Go center with a store reads the greeting through its runtime role; only the C# host and a Go center without a store
    // receive the Hello's own Neon credential.
    const store = go && Boolean(center.ARCFORGES_CENTER_DATABASE_URL);
    if (enabled !== "enabled" || (!store && !center.NEON_DATABASE_URL))
      throw new Error("Neon Hello runtime configuration is missing or invalid.");
    settings.enableInternet = true;
    settings.envVars.ARCFORGES_NEON_HELLO = enabled;
    if (!store) settings.envVars.NEON_DATABASE_URL = center.NEON_DATABASE_URL as string;
  }
  return settings;
}

/** Applies the settings to a Container instance. */
export function applyCenterContainer(container: Container, center: CenterEnvironment): void {
  const settings = centerContainerSettings(center);
  if (settings.entrypoint) container.entrypoint = settings.entrypoint;
  container.enableInternet = settings.enableInternet;
  if (Object.keys(settings.envVars).length > 0) container.envVars = settings.envVars;
}

/** The Durable Object storage key of the start digest of the running center (written before every start). */
export const startDigestKey = "arcforges.centerStartDigest";

/**
 * The digest of what a start hands the Container: the Worker's source revision, the entrypoint, the egress switch and every
 * environment variable in name order. Two Worker versions share it only when they would start the same center. It stays in the
 * Durable Object's storage: it covers the runtime credential, so it is never logged or returned.
 */
export async function startDigest(
  revision: string,
  settings: CenterContainerSettings,
): Promise<string> {
  const canonical = JSON.stringify([
    revision,
    settings.entrypoint ?? null,
    settings.enableInternet,
    Object.keys(settings.envVars)
      .sort()
      .map((name) => [name, settings.envVars[name]]),
  ]);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Waits until the Container is no longer running, at most `withinMs`; true when it stopped. */
async function stopped(
  container: { readonly running: boolean },
  withinMs: number,
): Promise<boolean> {
  const deadline = Date.now() + withinMs;
  while (container.running) {
    if (Date.now() >= deadline) return false;
    await new Promise((resolve) => setTimeout(resolve, centerStopPollMs));
  }
  return true;
}

/**
 * The reply to a request that arrived while a center started under another Worker version's settings could not be stopped: the
 * library's own start-failure reply (HTTP 500, plain text), which worker/readiness classifies as a start failure, so the Worker
 * answers it as retryable. The request was never forwarded.
 */
function stillStopping(): Response {
  return new Response(`${startFailedText} the previous start environment is still stopping.`, {
    status: 500,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

export class CloudContainer extends Container {
  override defaultPort = 8080;
  override sleepAfter = containerSleepAfter;
  override enableInternet = false;
  /** How long a stale center may take to stop on SIGTERM: its own shutdown bound and a margin (generated from the center). */
  protected staleStopMs = staleCenterStopMs;
  /** How long the forced stop of a stale center may take before the request is refused as a start failure. */
  protected staleDestroyMs = staleCenterKillMs;
  #digest?: Promise<string>;
  #following?: Promise<boolean>;

  constructor(ctx: ConstructorParameters<typeof Container>[0], env: object) {
    super(ctx, env);
    if (new.target !== CloudContainer) return;
    applyCenterContainer(this, env as CenterEnvironment);
  }

  /**
   * Forwards a request only to a center started with this Worker version's settings. A center that a previous start left running
   * under another digest is restarted first; when it cannot be stopped within the bounds the request is answered with the
   * library's start-failure text, which the Worker classifies as a retryable start failure (the request was never forwarded).
   */
  override async fetch(request: Request): Promise<Response> {
    this.#following ??= this.followWorkerVersion().finally(() => {
      this.#following = undefined;
    });
    if (!(await this.#following)) return stillStopping();
    return super.fetch(request);
  }

  private async followWorkerVersion(): Promise<boolean> {
    // The settings are final once the constructors ran; a Durable Object instance never changes its Worker version.
    this.#digest ??= startDigest((this.env as { SOURCE_REVISION?: string }).SOURCE_REVISION ?? "", {
      entrypoint: this.entrypoint,
      enableInternet: this.enableInternet,
      envVars: this.envVars ?? {},
    });
    const digest = await this.#digest;
    const container = this.ctx.container as { readonly running: boolean };
    if (container.running) {
      if ((await this.ctx.storage.get<string>(startDigestKey)) === digest) return true;
      await this.stop("SIGTERM");
      if (!(await stopped(container, this.staleStopMs))) {
        await Promise.race([
          this.destroy().catch(() => undefined),
          new Promise((resolve) => setTimeout(resolve, this.staleDestroyMs)),
        ]);
        if (!(await stopped(container, 0))) return false;
      }
    }
    // Recorded before the start that follows (super.fetch starts the center with exactly these settings), so a request that
    // arrives while that start is in flight finds the center current and joins it.
    await this.ctx.storage.put(startDigestKey, digest);
    return true;
  }
}

CloudContainer.outboundByHost = {
  "ai.internal": aiInternalOutbound as OutboundHandler,
};
