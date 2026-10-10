// SPDX-License-Identifier: AGPL-3.0-only
// The deny-by-default public method table of the Worker. A request is forwarded to the Container only when its exact /api path is
// listed in the table it is routed with; everything else is answered by the Worker and never wakes a Container. The rows, the transport
// budgets and the bounds are generated from the C# host (worker/tables/cloud-tables.generated.ts, CLOUD.84 S34), so this module holds no
// literal of its own. The production table holds the public Hello method only. The proof table is the production table plus the proof
// methods, and only the isolated proof entry (worker/proof/entry.ts, CLOUD.84 D1) routes with it, so the production bundle carries none of
// the proof rows.
import { type ApiRoute, productionRoutes } from "../tables/cloud-tables.generated.ts";

export {
  type ApiRoute,
  type RouteAuth,
  type RouteKind,
  coldStartBudgetMs,
  healthPath,
  helloPath,
  maxBodyBytes,
  productionRoutes,
  streamLifetimeMs,
} from "../tables/cloud-tables.generated.ts";

/** The public methods of one Worker entry, keyed by the exact /api path. */
export type RouteTable = ReadonlyMap<string, ApiRoute>;

/** The methods the production Worker serves: the anonymous Hello method only. */
export const productionTable: RouteTable = new Map(
  productionRoutes.map((route) => [`/api${route.path}`, route]),
);

/** The route of an exact /api path in a table, or undefined when the table does not list it. */
export function findRoute(
  pathname: string,
  table: RouteTable = productionTable,
): ApiRoute | undefined {
  return table.get(pathname);
}
