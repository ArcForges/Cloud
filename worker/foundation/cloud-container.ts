// SPDX-License-Identifier: AGPL-3.0-only
// ARCFORGES_HELLO_RUNTIME=go selects the Go center (/app/arcforges-center) and passes it its explicit mode and public base URL;
// the center refuses to start without them. Only the explicitly enabled production Hello passes a Neon credential and enables
// TCP egress. Proof subclasses keep their closed outbound policy and their own environment hook.
import { Container, type OutboundHandler } from "@cloudflare/containers";
import { aiInternalOutbound } from "../ai/internal/outbound.ts";
import { containerSleepAfter } from "../tables/cloud-tables.generated.ts";

interface CenterEnvironment {
  ARCFORGES_NEON_HELLO?: string;
  NEON_DATABASE_URL?: string;
  ARCFORGES_HELLO_RUNTIME?: string;
  ARCFORGES_CENTER_MODE?: string;
  ARCFORGES_CENTER_PUBLIC_BASE_URL?: string;
}

export class CloudContainer extends Container {
  override defaultPort = 8080;
  override sleepAfter = containerSleepAfter;
  override enableInternet = false;

  constructor(ctx: ConstructorParameters<typeof Container>[0], env: object) {
    super(ctx, env);
    if (new.target !== CloudContainer) return;
    const center = env as CenterEnvironment;
    const runtime = center.ARCFORGES_HELLO_RUNTIME;
    const variables: Record<string, string> = {};
    if (runtime === "go") {
      this.entrypoint = ["/app/arcforges-center"];
      // Passed through unchanged: the center validates them and refuses to start on a missing or invalid value.
      if (center.ARCFORGES_CENTER_MODE !== undefined)
        variables.ARCFORGES_CENTER_MODE = center.ARCFORGES_CENTER_MODE;
      if (center.ARCFORGES_CENTER_PUBLIC_BASE_URL !== undefined)
        variables.ARCFORGES_CENTER_PUBLIC_BASE_URL = center.ARCFORGES_CENTER_PUBLIC_BASE_URL;
    } else if (runtime !== undefined && runtime !== "" && runtime !== "csharp")
      throw new Error("Unknown Hello runtime.");
    const enabled = center.ARCFORGES_NEON_HELLO;
    if (enabled !== undefined && enabled !== "" && enabled !== "disabled") {
      if (enabled !== "enabled" || !center.NEON_DATABASE_URL)
        throw new Error("Neon Hello runtime configuration is missing or invalid.");
      // Native PostgreSQL TCP is not handled by the HTTP outbound proxy. This is a deliberate
      // production-only egress change; allowedHosts would NOT restrict TCP port 5432.
      this.enableInternet = true;
      variables.ARCFORGES_NEON_HELLO = enabled;
      variables.NEON_DATABASE_URL = center.NEON_DATABASE_URL;
    }
    if (Object.keys(variables).length > 0) this.envVars = variables;
  }
}

CloudContainer.outboundByHost = {
  "ai.internal": aiInternalOutbound as OutboundHandler,
};
