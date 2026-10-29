// SPDX-License-Identifier: AGPL-3.0-only
// ARCFORGES_HELLO_RUNTIME=go selects the Go center (/app/arcforges-center) and passes it its explicit mode, public base URL and
// plan configuration, and the runtime role's pooled PostgreSQL URL of its store; the center refuses to start without a valid
// mode and base URL. It also passes the enabled surfaces the Worker forwards (FLAGSHIP_SURFACES as parsed here, "none" when none)
// and always names the header the Worker sets to the client's address, so the center and the Worker agree on both, and passes the
// identity policy override where an environment sets one (only the acceptance environment's anonymous-flow ceiling). The Hello's own Neon credential reaches only the C# host, or a Go center without a store. Proof subclasses
// keep their closed outbound policy and their own environment hook.
import { Container, type OutboundHandler } from "@cloudflare/containers";
import { aiInternalOutbound } from "../ai/internal/outbound.ts";
import { containerSleepAfter } from "../tables/cloud-tables.generated.ts";
import { clientIpHeader, enabledSurfaces } from "../ingress/routes.ts";

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
    ] as const) {
      const value = center[name];
      if (value !== undefined) settings.envVars[name] = value;
    }
    const surfaces = [...enabledSurfaces(center.FLAGSHIP_SURFACES)];
    settings.envVars.ARCFORGES_CENTER_SURFACES = surfaces.length > 0 ? surfaces.join(",") : "none";
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

export class CloudContainer extends Container {
  override defaultPort = 8080;
  override sleepAfter = containerSleepAfter;
  override enableInternet = false;

  constructor(ctx: ConstructorParameters<typeof Container>[0], env: object) {
    super(ctx, env);
    if (new.target !== CloudContainer) return;
    applyCenterContainer(this, env as CenterEnvironment);
  }
}

CloudContainer.outboundByHost = {
  "ai.internal": aiInternalOutbound as OutboundHandler,
};
