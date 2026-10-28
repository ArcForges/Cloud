// SPDX-License-Identifier: AGPL-3.0-only
// The deny-by-default public method table of the Worker. A request is forwarded to the Container only when its exact /api path is
// listed in the table it is routed with; everything else is answered by the Worker and never wakes a Container. The production rows,
// the transport budgets and the bounds are generated from the Go center's registrations (worker/tables/center-tables.generated.ts,
// AF-CTR-02) and the proof rows from the C# host (worker/tables/cloud-tables.generated.ts, CLOUD.84 S34), so this module holds no
// literal of its own. The production table holds the public Hello method only. The proof table is the production table plus the proof
// methods, and only the isolated proof entry (worker/proof/entry.ts, CLOUD.84 D1) routes with it, so the production bundle carries none of
// the proof rows. The switchable surfaces' methods (AF-CTR-03) are a table of their own: a row is forwarded only while FLAGSHIP_SURFACES
// enables its surface, and is otherwise answered by the Worker with the surface's generated not_activated reply.
import {
  type ApiRoute,
  productionRoutes,
  type Surface,
  surfaceNames,
  type SurfaceRoute,
  surfaceRoutes,
} from "../tables/center-tables.generated.ts";

export {
  type ApiRoute,
  type Surface,
  type SurfaceRoute,
  clientIpHeader,
  notActivatedReplies,
  rateLimitedReply,
  type RouteAuth,
  type RouteKind,
  coldStartBudgetMs,
  healthPath,
  helloPath,
  maxBodyBytes,
  productionRoutes,
  streamLifetimeMs,
} from "../tables/center-tables.generated.ts";

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

/** The methods of the switchable surfaces, keyed by the exact /api path. */
export const surfaceTable: ReadonlyMap<string, SurfaceRoute> = new Map(
  surfaceRoutes.map((route) => [`/api${route.path}`, route]),
);

/**
 * The surfaces FLAGSHIP_SURFACES enables: exact generated names, comma-separated, without white space or repetition. Any other
 * value (an unknown name, a space, an empty item, a repeated name) enables none, so a mistyped list never opens a surface.
 */
export function enabledSurfaces(value: string | undefined): ReadonlySet<Surface> {
  if (value === undefined || value === "") return new Set();
  const names = value.split(",");
  const known = new Set<string>(surfaceNames);
  if (names.some((name) => !known.has(name)) || new Set(names).size !== names.length)
    return new Set();
  return new Set(names as Surface[]);
}
