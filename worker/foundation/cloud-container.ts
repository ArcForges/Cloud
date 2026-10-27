// SPDX-License-Identifier: AGPL-3.0-only
// Only the explicitly enabled production Hello passes a Neon credential and enables TCP egress.
// Proof subclasses keep their closed outbound policy and their own environment hook.
import { Container, type OutboundHandler } from "@cloudflare/containers";
import { aiInternalOutbound } from "../ai/internal/outbound.ts";
import { containerSleepAfter } from "../tables/cloud-tables.generated.ts";

interface NeonEnvironment {
  ARCFORGES_NEON_HELLO?: string;
  NEON_DATABASE_URL?: string;
}

export class CloudContainer extends Container {
  override defaultPort = 8080;
  override sleepAfter = containerSleepAfter;
  override enableInternet = false;

  constructor(ctx: ConstructorParameters<typeof Container>[0], env: object) {
    super(ctx, env);
    if (new.target !== CloudContainer) return;
    const neon = env as NeonEnvironment;
    const enabled = neon.ARCFORGES_NEON_HELLO;
    if (enabled === undefined || enabled === "" || enabled === "disabled") return;
    if (enabled !== "enabled" || !neon.NEON_DATABASE_URL)
      throw new Error("Neon Hello runtime configuration is missing or invalid.");
    // Native PostgreSQL TCP is not handled by the HTTP outbound proxy. This is a deliberate
    // production-only egress change; allowedHosts would NOT restrict TCP port 5432.
    this.enableInternet = true;
    this.envVars = {
      ARCFORGES_NEON_HELLO: enabled,
      NEON_DATABASE_URL: neon.NEON_DATABASE_URL,
    };
  }
}

CloudContainer.outboundByHost = {
  "ai.internal": aiInternalOutbound as OutboundHandler,
};
