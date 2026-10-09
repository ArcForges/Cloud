// SPDX-License-Identifier: AGPL-3.0-only
// The deny-by-default public method table of the Worker. A request is forwarded to the Container only when its exact /api path is
// listed here; everything else is answered by the Worker and never wakes a Container. The rows, the transport budgets and the bounds
// are generated from the C# host (worker/tables/cloud-tables.generated.ts, CLOUD.84 S34), so this module holds no literal of its own.
import { type ApiRoute, productionRoutes, proofRoutes } from "../tables/cloud-tables.generated.ts";

export {
  type ApiRoute,
  type RouteAuth,
  type RouteKind,
  coldStartBudgetMs,
  healthPath,
  helloPath,
  maxBodyBytes,
  productionRoutes,
  proofRoutes,
  streamLifetimeMs,
} from "../tables/cloud-tables.generated.ts";

const production = new Map(productionRoutes.map((route) => [`/api${route.path}`, route]));
const withProof = new Map([
  ...production,
  ...proofRoutes.map((route) => [`/api${route.path}`, route] as const),
]);

export function findRoute(
  env: { FOUNDATION_PROOF?: string },
  pathname: string,
): ApiRoute | undefined {
  return (env.FOUNDATION_PROOF === "enabled" ? withProof : production).get(pathname);
}
