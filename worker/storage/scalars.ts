// SPDX-License-Identifier: AGPL-3.0-only
// Exact scalar handling for the private D1 bridge. 64-bit integers and decimals are canonical text
// end to end: they are never converted to a JavaScript number, bound with CAST(? AS INTEGER) and
// returned as CAST(column AS TEXT).
import type { D1Scalar } from "@arcforges/ai-internal";
import { base64UrlDecode, base64UrlEncode } from "../private/encoding.ts";
import {
  int64TextPattern as int64Text,
  storageGuards,
  uint64TextPattern as uint64Text,
} from "../tables/cloud-tables.generated.ts";
import type { PlanKind, PlanParam } from "./plan-types.ts";

// The value bounds are generated from the C# declarations in src/ArcForges.Cloud/Generation (CLOUD.84 S40(2)); none is a literal here.
export const int64Min = BigInt(storageGuards.int64Min);
export const int64Max = BigInt(storageGuards.int64Max);
export const uint64Max = BigInt(storageGuards.uint64Max);
export const maxTextLength = storageGuards.maxTextLength;
export const maxBytesLength = storageGuards.maxBytesLength;

/** The longest spelling of a 64-bit integer text: the longest bound, with its sign. */
const maxIntegerTextLength = storageGuards.uint64Max.length;
const decimalText = new RegExp(
  `^-?(?:0|[1-9][0-9]*)(?:\\.[0-9]{1,${storageGuards.maxDecimalFractionDigits}})?$`,
  "u",
);

export function isInt64Text(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length <= maxIntegerTextLength &&
    int64Text.test(value) &&
    BigInt(value) >= int64Min &&
    BigInt(value) <= int64Max
  );
}
export function isUint64Text(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length <= maxIntegerTextLength &&
    uint64Text.test(value) &&
    BigInt(value) <= uint64Max
  );
}
/** At most the generated significant digits and fractional digits; no exponent, no negative zero. */
export function isCanonicalDecimal(value: unknown): value is string {
  if (typeof value !== "string" || !decimalText.test(value)) return false;
  if (
    value.startsWith("-") &&
    ![...value].some((character) => character >= "1" && character <= "9")
  )
    return false;
  return (
    value.replace(/[-.]/gu, "").replace(/^0+/u, "").length <=
    storageGuards.maxDecimalSignificantDigits
  );
}

const scalarKind: Record<PlanKind, string> = {
  int64: "int64",
  uint64: "uint64",
  decimal: "decimal",
  text: "text",
  bytes: "bytes",
  bool: "boolean",
  scope: "text",
};

/** Validates one argument against its declared parameter and returns the exact value to bind. */
export function bindValue(
  scalar: D1Scalar,
  param: PlanParam,
  ownerScope: string,
): { ok: true; value: unknown } | { ok: false } {
  const bad = { ok: false } as const;
  if (scalar.kind === "null") {
    return param.nullable ? { ok: true, value: null } : bad;
  }
  if (scalar.kind !== scalarKind[param.kind]) return bad;
  const value = (scalar as { value: unknown }).value;
  switch (param.kind) {
    case "int64":
      // Bound as the exact decimal text; the plan SQL wraps it as CAST(? AS INTEGER).
      return isInt64Text(value) ? { ok: true, value } : bad;
    case "uint64":
      return isUint64Text(value) ? { ok: true, value } : bad;
    case "decimal":
      return isCanonicalDecimal(value) ? { ok: true, value } : bad;
    case "text":
      return typeof value === "string" && value.length <= maxTextLength ? { ok: true, value } : bad;
    case "scope":
      return value === ownerScope ? { ok: true, value } : bad;
    case "bool":
      return typeof value === "boolean" ? { ok: true, value: value ? 1 : 0 } : bad;
    case "bytes": {
      if (typeof value !== "string") return bad;
      const bytes = base64UrlDecode(value);
      if (!bytes || bytes.length > maxBytesLength) return bad;
      const copy = new ArrayBuffer(bytes.length);
      new Uint8Array(copy).set(bytes);
      return { ok: true, value: copy };
    }
  }
}

/** A plan returned a value that breaks the exact-value rules: a defect, never a client error. */
export class PlanResultError extends Error {}

/**
 * Encodes one D1 result value. A 64-bit integer column must already be text (the plan wraps it in
 * CAST(x AS TEXT)); a JavaScript number there would have lost precision and is refused.
 */
export function encodeResult(raw: unknown, param: PlanParam): D1Scalar {
  if (raw === null || raw === undefined) {
    if (!param.nullable) throw new PlanResultError("Unexpected null result column");
    return { kind: "null" };
  }
  switch (param.kind) {
    case "int64":
      if (!isInt64Text(raw)) throw new PlanResultError("Result column is not an exact int64 text");
      return { kind: "int64", value: raw };
    case "uint64":
      if (!isUint64Text(raw))
        throw new PlanResultError("Result column is not an exact uint64 text");
      return { kind: "uint64", value: raw };
    case "decimal":
      if (!isCanonicalDecimal(raw))
        throw new PlanResultError("Result column is not a canonical decimal");
      return { kind: "decimal", value: raw };
    case "text":
      if (typeof raw !== "string") throw new PlanResultError("Result column is not text");
      return { kind: "text", value: raw };
    case "bool":
      if (raw === 0 || raw === false) return { kind: "boolean", value: false };
      if (raw === 1 || raw === true) return { kind: "boolean", value: true };
      throw new PlanResultError("Result column is not a boolean");
    case "bytes": {
      let bytes: Uint8Array | undefined;
      if (raw instanceof ArrayBuffer) bytes = new Uint8Array(raw);
      else if (ArrayBuffer.isView(raw))
        bytes = new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
      else if (
        Array.isArray(raw) &&
        raw.every((item) => Number.isInteger(item) && item >= 0 && item <= 255)
      )
        bytes = Uint8Array.from(raw as number[]);
      if (!bytes || bytes.length > maxBytesLength)
        throw new PlanResultError("Result column is not bytes");
      return { kind: "bytes", value: base64UrlEncode(bytes) };
    }
    case "scope":
      throw new PlanResultError("A result column cannot be a scope");
  }
}
