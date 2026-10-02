// SPDX-License-Identifier: AGPL-3.0-only
// Shape of a reviewed named D1 plan. The plan files are the source; plans.generated.ts is derived.

/** Typed bind/result kinds. `scope` is a text parameter that must equal the request owner scope. */
export type PlanKind = "int64" | "uint64" | "decimal" | "text" | "bytes" | "bool" | "scope";

export interface PlanParam {
  readonly kind: PlanKind;
  readonly nullable: boolean;
}

export interface PlanStatement {
  readonly sql: string;
  readonly params: readonly PlanParam[];
  /** Result columns of the one statement whose rows the plan returns; null for all others. */
  readonly returns: readonly PlanParam[] | null;
}

export interface PlanDefinition {
  readonly id: string;
  readonly version: number;
  readonly access: "read" | "write";
  readonly maxRows: number;
  readonly statements: readonly PlanStatement[];
}
