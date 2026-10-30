// SPDX-License-Identifier: AGPL-3.0-only
// A Container (or Durable Object) stub's fetch as the Workers platform runs it, for the tests of every Worker request to the
// Container (AF-CTR-03 A2 hotfix 1, H-1). The platform's fetch follows a redirect unless the request says `redirect: "manual"`: the
// caller then gets the reply of the address the redirect leads to, never the redirect. A stand-in that answers the first reply
// whatever the mode lets a Worker that forgets the option pass its tests; this one does what the hosted proof environment did, where
// the center's 303 to the sign-in page became a 404 of a path the center does not serve and the page handler answered its own 503.

const redirectStatuses = new Set([301, 302, 303, 307, 308]);

/** The reply of the address a followed redirect leads to: a path the center does not serve, without any of its headers. */
export function notServed(): Response {
  return new Response("404 page not found\n", {
    status: 404,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

/**
 * Wraps the stand-in's answer in the platform's redirect rule. `followed` is what the address the redirect leads to answers (a path
 * the center does not serve, by default).
 */
export function platformFetch(
  answer: (request: Request) => Response | Promise<Response>,
  followed: (request: Request, redirect: Response) => Response | Promise<Response> = notServed,
): (request: Request) => Promise<Response> {
  return async (request) => {
    const reply = await answer(request);
    if (request.redirect === "manual") return reply;
    if (!redirectStatuses.has(reply.status) || !reply.headers.has("location")) return reply;
    void reply.body?.cancel().catch(() => {});
    return followed(request, reply);
  };
}
