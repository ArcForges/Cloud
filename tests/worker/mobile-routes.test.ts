// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { apexTable } from "../../worker/ingress/applink.ts";
import { nativeTable } from "../../worker/ingress/native.ts";
import { routeRequest, type CloudBindings } from "../../worker/router.ts";
import {
  apexRoutes,
  nativeRoutes,
  pageRoutes,
  productionRoutes,
} from "../../worker/tables/center-tables.generated.ts";

const origin = "https://proof.example.test";
const retiredRoutes = [
  ["GET", "/api/mobile/authorize"],
  ["POST", "/api/mobile/authorize/review"],
  ["POST", "/api/mobile/authorize/decision"],
  ["POST", "/api/session/v1/mobile/begin"],
  ["POST", "/api/session/v1/mobile/token"],
  ["GET", "/.well-known/assetlinks.json"],
  ["GET", "/app/callback"],
] as const;

test("the generated Worker tables have no route for standalone mobile authorization", () => {
  assert.deepEqual(nativeRoutes, []);
  assert.deepEqual(apexRoutes, []);
  assert.equal(nativeTable.size, 0);
  assert.equal(apexTable.size, 0);
  assert(!pageRoutes.some((row) => row.path.startsWith("/mobile/")));
});

test("retired mobile routes return 404 without waking the Center or spending a quota", async () => {
  let calls = 0;
  const unexpected = () => {
    calls++;
    throw new Error("retired mobile route was forwarded or admitted");
  };
  const env: CloudBindings = {
    SOURCE_REVISION: "candidate",
    ALLOWED_ORIGIN: origin,
    CLOUD_CONTAINER: { getByName: unexpected },
    HELLO_RATE_LIMITER: { limit: unexpected },
    IDENTITY_RATE_LIMITER: { limit: unexpected },
  };
  for (const surfaces of [
    "",
    "identity,pages,operations,fleet,relay,nodes,commerce",
    "identity,pages,mobile",
  ]) {
    for (const [method, pathname] of retiredRoutes) {
      const reply = await routeRequest(new Request(origin + pathname, { method }), {
        ...env,
        FLAGSHIP_SURFACES: surfaces,
      });
      assert.equal(reply.status, 404, `${surfaces} ${method} ${pathname}`);
    }
  }
  assert.equal(calls, 0);
});

test("the Worker keeps the production API route and proof domain with no mobile activation", () => {
  const wrangler = JSON.parse(
    readFileSync(new URL("../../wrangler.json", import.meta.url), "utf8"),
  ) as {
    routes: unknown;
    vars: Record<string, string>;
    env: { proof: { vars: Record<string, string>; routes: unknown } };
  };
  assert.deepEqual(wrangler.routes, [
    { pattern: "arcforges.com/api/*", zone_name: "arcforges.com" },
  ]);
  assert.deepEqual(wrangler.env.proof.routes, [
    { pattern: "proof.arcforges.com", custom_domain: true },
  ]);
  assert.equal(wrangler.vars.FLAGSHIP_SURFACES, "");
  for (const vars of [wrangler.vars, wrangler.env.proof.vars]) {
    assert(!vars.FLAGSHIP_SURFACES?.split(",").includes("mobile"));
    assert.equal(vars.ARCFORGES_CENTER_ANDROID_APP, undefined);
    assert.equal(vars.ARCFORGES_CENTER_MOBILE_DEBUG_REDIRECT, undefined);
  }
  assert.deepEqual(
    productionRoutes.map((row) => row.path),
    ["/arcforges.hello.v1.HelloService/SayHello"],
  );
});
