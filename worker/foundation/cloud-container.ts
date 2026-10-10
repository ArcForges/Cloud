// SPDX-License-Identifier: AGPL-3.0-only
// The production Container class (CLOUD.84 D1): the Hello class plus one outbound host, ai.internal, the thin Workers AI transport of
// HAR.40. It is a lifecycle adapter in the foundation folder rather than in an entry, so the production entry (worker/index.ts), which
// exports it, and the proof entry (worker/proof/entry.ts), which extends it, both import it, and nothing imports an entry. It has no
// environment hook, and enableInternet stays false, so the container reaches nothing but the exact virtual host registered below.
import { Container, type OutboundHandler } from "@cloudflare/containers";
import { aiInternalOutbound } from "../ai/internal/outbound.ts";

export class CloudContainer extends Container {
  override defaultPort = 8080;
  override sleepAfter = "60s";
  override enableInternet = false;
}

// Assigned (not declared as a static field) so the base class setter registers the handler under
// the production class name only. The proof class in worker/proof/entry.ts extends this class and
// registers its own handlers under its own name.
CloudContainer.outboundByHost = {
  "ai.internal": aiInternalOutbound as OutboundHandler,
};
