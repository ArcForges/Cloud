// SPDX-License-Identifier: AGPL-3.0-only
// The outbound handler registered for the ai.internal virtual host on the production Container class (HAR.40). It is the only outbound
// registration of that class; the proof class keeps its own storage and objects hosts (worker/index.ts).
import { type AiEnv, handleAiInternal } from "./handler.ts";

export const aiInternalOutbound = (request: Request, env: unknown): Promise<Response> =>
  handleAiInternal(request, env as AiEnv);
