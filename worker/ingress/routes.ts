// SPDX-License-Identifier: AGPL-3.0-only
// The deny-by-default public method table of the Worker. A request is forwarded to the Container only
// when its exact /api path is listed here; everything else is answered by the Worker and never wakes
// a Container. Each module appends its own methods in its own section (RES-cloud-host-composition); the
// C# host holds the same methods with its own policies and a test compares the two tables.

export type RouteKind = "unary" | "serverStream";
export type RouteAuth = "anonymous" | "session";

export interface ApiRoute {
  /** The method path without the owned /api prefix: /package.Service/Method. */
  readonly path: string;
  readonly kind: RouteKind;
  /** anonymous: no credential is read or forwarded; session: bearer or origin-bound cookie, checked again by the host. */
  readonly auth: RouteAuth;
  /** Bound of the whole request body, frame header included. Unary and server-streaming requests are one message. */
  readonly maxRequestBytes: number;
  /** Bound of one response frame. */
  readonly maxFrameBytes: number;
  /** Bound of a whole unary response (buffered); a stream has no total bound, only its lifetime. */
  readonly maxUnaryResponseBytes: number;
  /** Cap of the RPC deadline (unary) or of the stream's lifetime (server stream). */
  readonly maxDurationMs: number;
  /** The Container instance (Durable Object name) that serves the method. */
  readonly instance: string;
  /**
   * The request message starts with a RequestMeta (field 1, wire registry 04). Only then does the edge read the client's
   * correlation id from it; a method whose field 1 means something else (the Hello name) is never interpreted.
   */
  readonly requestMeta: boolean;
}

export const helloPath = "/api/arcforges.hello.v1.HelloService/SayHello";
export const healthPath = "/api/healthz";
export const maxBodyBytes = 4096;
/** The Container may take at most this long to start before a stream's response headers arrive. */
export const coldStartBudgetMs = 15_000;
/** A server stream's lifetime when the client states no shorter deadline: the annex 10 server close after five minutes plus slack. */
export const streamLifetimeMs = 310_000;

const helloRoute: ApiRoute = {
  path: helloPath.slice(4),
  kind: "unary",
  auth: "anonymous",
  maxRequestBytes: maxBodyBytes,
  maxFrameBytes: 8192,
  maxUnaryResponseBytes: 8192,
  maxDurationMs: 10_000,
  instance: "hello",
  requestMeta: false,
};

/** The methods the production Worker serves. */
export const productionRoutes: readonly ApiRoute[] = [helloRoute];

// Proof-only pipeline probe (the isolated proof environment, FOUNDATION_PROOF=enabled): an authenticated
// workspace-scoped unary call, a timed server stream and an observation of how the host saw its streams end.
const probeBase = {
  auth: "session",
  maxRequestBytes: 4096,
  maxFrameBytes: 65_536,
  maxUnaryResponseBytes: 8192,
  instance: "foundation",
  requestMeta: true,
} as const;

export const proofRoutes: readonly ApiRoute[] = [
  {
    ...probeBase,
    path: "/arcforges.proof.v1.PipelineProbe/Whoami",
    kind: "unary",
    maxDurationMs: 10_000,
  },
  {
    ...probeBase,
    path: "/arcforges.proof.v1.PipelineProbe/Observation",
    kind: "unary",
    maxDurationMs: 10_000,
  },
  {
    ...probeBase,
    path: "/arcforges.proof.v1.PipelineProbe/Stream",
    kind: "serverStream",
    maxDurationMs: 60_000,
  },
];

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
