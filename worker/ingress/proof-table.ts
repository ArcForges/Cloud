// SPDX-License-Identifier: AGPL-3.0-only
// The proof method table (CLOUD.84 D1): the production table plus the proof methods. Only the isolated proof entry routes with it, and it
// lives apart from routes.ts and from the entry, so the production bundle never reaches it and the route tests need no Cloudflare stub.
import { proofRoutes } from "../tables/cloud-tables.generated.ts";
import { productionTable, type RouteTable } from "./routes.ts";

export const proofRouteTable: RouteTable = new Map([
  ...productionTable,
  ...proofRoutes.map((route) => [`/api${route.path}`, route] as const),
]);
