// SPDX-License-Identifier: AGPL-3.0-only
// The ai.internal envelope: the closed document the C# harness builds for one Workers AI call (HAR.40, P2-021 item 5). The Worker reads only
// the envelope fields below. The frozen request is forwarded unchanged; the Worker never reads its content, adds to it or holds a token.
//
// The admitted-model set and the size caps come from C# on every call. They are checked here and nowhere else: no catalogue or cap is
// hard-coded in the Worker beyond the hard ceilings that bound any C# value (1 MiB each), so a C# value above a ceiling is refused.

export const aiHost = "ai.internal";
export const aiRunPath = "/v1/run";
export const aiEnvelopeVersion = 1;
/** The hard ceiling of any request or response byte cap C# may supply (1 MiB). */
export const hardByteCap = 1_048_576;
/** The most admitted models one call may name. */
export const maxAdmittedModels = 16;

const modelToken = /^[A-Za-z0-9@/._-]{1,128}$/u;
const envelopeKeys = "admittedModels,maxBodyBytes,maxResponseBytes,model,request,v";

export interface AiEnvelope {
  readonly model: string;
  readonly admittedModels: readonly string[];
  readonly maxBodyBytes: number;
  readonly maxResponseBytes: number;
  /** The frozen Workers AI request, forwarded to the binding exactly as parsed. */
  readonly request: Record<string, unknown>;
  readonly stream: boolean;
}

/** A refusal before the binding is called. Every refusal here is a pre-dispatch refusal for the C# caller. */
export interface EnvelopeRefusal {
  readonly ok: false;
  readonly status: 400 | 403 | 413;
  readonly code: string;
}

export type EnvelopeResult = { readonly ok: true; readonly value: AiEnvelope } | EnvelopeRefusal;

function refuse(status: 400 | 403 | 413, code: string): EnvelopeRefusal {
  return { ok: false, status, code };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isByteCap(value: unknown): value is number {
  return (
    typeof value === "number" && Number.isSafeInteger(value) && value >= 1 && value <= hardByteCap
  );
}

/**
 * Parses one envelope body. The body is refused above the hard ceiling before it is decoded; a malformed or closed-shape violation is a
 * 400; a body over its own C#-supplied cap is a 413; a model outside the C#-supplied admitted set is a 403. Nothing else is checked.
 */
export function parseEnvelope(bytes: Uint8Array): EnvelopeResult {
  if (bytes.byteLength > hardByteCap) return refuse(413, "ai.body_too_large");
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes));
  } catch {
    return refuse(400, "ai.malformed");
  }
  if (!isPlainObject(value)) return refuse(400, "ai.malformed");
  if (Object.keys(value).sort().join(",") !== envelopeKeys) return refuse(400, "ai.envelope_shape");
  if (value.v !== aiEnvelopeVersion) return refuse(400, "ai.envelope_version");

  const { model, admittedModels, maxBodyBytes, maxResponseBytes, request } = value;
  if (typeof model !== "string" || !modelToken.test(model)) return refuse(400, "ai.model_shape");
  if (
    !Array.isArray(admittedModels) ||
    admittedModels.length < 1 ||
    admittedModels.length > maxAdmittedModels ||
    !admittedModels.every((entry) => typeof entry === "string" && modelToken.test(entry))
  )
    return refuse(400, "ai.admitted_set_shape");
  if (!isByteCap(maxBodyBytes) || !isByteCap(maxResponseBytes)) return refuse(400, "ai.cap_shape");
  if (!isPlainObject(request)) return refuse(400, "ai.request_shape");

  if (bytes.byteLength > maxBodyBytes) return refuse(413, "ai.body_over_cap");
  if (!admittedModels.includes(model)) return refuse(403, "ai.model_not_admitted");

  return {
    ok: true,
    value: {
      model,
      admittedModels: [...admittedModels],
      maxBodyBytes,
      maxResponseBytes,
      request,
      stream: request.stream === true,
    },
  };
}
