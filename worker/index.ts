// SPDX-License-Identifier: AGPL-3.0-only
import { Container } from "@cloudflare/containers";
import { routeRequest, type CloudBindings } from "./router.ts";

export class CloudContainer extends Container {
  override defaultPort = 8080;
  override sleepAfter = "60s";
  override enableInternet = false;
}

export default {
  fetch(request: Request, env: CloudBindings): Promise<Response> {
    return routeRequest(request, env);
  },
};
