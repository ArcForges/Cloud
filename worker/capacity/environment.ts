// SPDX-License-Identifier: AGPL-3.0-only
import type { CapacityClientEnv } from "./container-client.ts";
import type { CapacityScheduleEnv } from "./handler.ts";
export type CapacityEnvironment = CapacityClientEnv &
  CapacityScheduleEnv & { CAPACITY_ENABLED?: string };

/** Only the explicit production capability passes signing keys to the host; the Foundation proof
 * switch grants no capacity authority. Missing bindings/configuration cannot silently enable it. */
export function capacityEnvironment(env: CapacityEnvironment): Record<string, string> {
  if (env.CAPACITY_ENABLED !== "enabled") return {};
  if (
    !env.CAPACITY_PACER ||
    !env.CAPACITY_CONTAINER_NAME ||
    !/^[A-Za-z0-9._-]{1,64}$/u.test(env.CAPACITY_CONTAINER_NAME)
  )
    throw new Error("Capacity production binding is missing");
  const result: Record<string, string> = { ARCFORGES_CAPACITY: "enabled" };
  for (const name of [
    "HMAC_C2W_KEY_ID",
    "HMAC_C2W_SECRET",
    "HMAC_W2C_KEY_ID",
    "HMAC_W2C_SECRET",
    "HMAC_W2C_PREVIOUS_KEY_ID",
    "HMAC_W2C_PREVIOUS_SECRET",
  ] as const) {
    const value = env[name];
    if (value !== undefined) result[`AF_${name}`] = value;
  }
  return result;
}
