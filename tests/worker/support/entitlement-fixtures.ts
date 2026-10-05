// SPDX-License-Identifier: AGPL-3.0-only
// Argument builders for the Entitlement plans (COM.16), shared by the SQLite oracle tests and the explicit workerd run: the JSON arrays
// the commit plan unpacks, the guarded revision arguments and the canonical commit tail. They mirror D1EntitlementStore in C#.
import type { D1Scalar } from "@arcforges/ai-internal";
import { i64, txt } from "./plan-calls.ts";
import { event, tailArguments } from "./commit-support.ts";

export const workspace = "00000000-0000-4000-8000-0000000000b1";
export const other = "00000000-0000-4000-8000-0000000000b2";
export const id = (n: number) => `00000000-0000-4000-8000-${n.toString(16).padStart(12, "0")}`;

export interface Records {
  grants?: unknown[];
  revocations?: unknown[];
  terms?: unknown[];
  actions?: unknown[];
  activations?: unknown[];
  facts?: unknown[];
  validUntil?: number;
}

export const grant = (n: number, overrides: Record<string, unknown> = {}) => ({
  id: id(n),
  kind: 1,
  subject: "cloud.sync",
  value: {},
  source: 1,
  sourceRef: `order-${n}`,
  from: "0",
  until: null,
  actor: "commerce",
  createdAt: "5",
  reason: null,
  ...overrides,
});

/** The arguments of one commit of the entitlement.commit plan, in statement order, ending with the canonical tail and the release. */
export function commitArguments(
  scope: string,
  command: string,
  expected: number,
  records: Records = {},
): D1Scalar[][] {
  const s = { kind: "text", value: scope } as D1Scalar;
  const json = (value: unknown[] | undefined) => txt(JSON.stringify(value ?? []));
  return [
    [txt(command), s, i64(expected)],
    [s, i64(expected + 1), i64(10), i64(expected)],
    [s, json(records.grants)],
    [json(records.revocations)],
    [s, json(records.terms)],
    [json(records.actions)],
    [s, json(records.activations)],
    [s, json(records.facts)],
    [
      s,
      i64(expected + 1),
      i64(10),
      i64(records.validUntil ?? -1),
      txt(`{"cloud.sync":{"granted":true,"reason":"Available","sourceGrantIds":[]}}`),
      txt("{}"),
      txt(
        `{"features":{},"service":{"state":"None","paidTermActive":false},"allowances":{},"definitionsVersion":"bundle-1","unrecognizedGrantIds":[],"ignoredTermIds":[]}`,
      ),
    ],
    ...tailArguments(scope, {
      commandId: command,
      workspaceId: scope,
      operation: "entitlement.commit",
      resultRevision: expected + 1,
      events: [event()],
    }),
  ];
}
