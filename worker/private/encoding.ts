// SPDX-License-Identifier: AGPL-3.0-only
// Strict byte encodings shared by the private request signing and the exact D1 scalars.
import { hexBytesPattern } from "../tables/cloud-tables.generated.ts";

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const character = (index: number) => alphabet.charAt(index);
const lookup = new Map([...alphabet].map((symbol, index) => [symbol, index]));

/** Unpadded base64url. */
export function base64UrlEncode(bytes: Uint8Array): string {
  let output = "";
  let index = 0;
  for (; index + 2 < bytes.length; index += 3) {
    const value =
      ((bytes[index] ?? 0) << 16) | ((bytes[index + 1] ?? 0) << 8) | (bytes[index + 2] ?? 0);
    output +=
      character((value >> 18) & 63) +
      character((value >> 12) & 63) +
      character((value >> 6) & 63) +
      character(value & 63);
  }
  const remaining = bytes.length - index;
  if (remaining === 1) {
    const value = (bytes[index] ?? 0) << 16;
    output += character((value >> 18) & 63) + character((value >> 12) & 63);
  } else if (remaining === 2) {
    const value = ((bytes[index] ?? 0) << 16) | ((bytes[index + 1] ?? 0) << 8);
    output +=
      character((value >> 18) & 63) + character((value >> 12) & 63) + character((value >> 6) & 63);
  }
  return output;
}

/**
 * Strict unpadded base64url: only the 64 URL-safe characters, no padding, no whitespace and no
 * non-zero trailing bits, so every byte string has exactly one accepted text form.
 */
export function base64UrlDecode(text: string): Uint8Array | null {
  if (text.length % 4 === 1) return null;
  const values: number[] = [];
  for (const character of text) {
    const value = lookup.get(character);
    if (value === undefined) return null;
    values.push(value);
  }
  const bytes: number[] = [];
  for (let index = 0; index < values.length; index += 4) {
    const chunk = values.slice(index, index + 4);
    const packed =
      ((chunk[0] ?? 0) << 18) | ((chunk[1] ?? 0) << 12) | ((chunk[2] ?? 0) << 6) | (chunk[3] ?? 0);
    bytes.push((packed >> 16) & 255);
    if (chunk.length > 2) bytes.push((packed >> 8) & 255);
    if (chunk.length > 3) bytes.push(packed & 255);
    if (chunk.length === 2 && (packed & 0xffff) !== 0) return null;
    if (chunk.length === 3 && (packed & 0xff) !== 0) return null;
  }
  return Uint8Array.from(bytes);
}

export function hexEncode(bytes: Uint8Array): string {
  return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
}

export function hexDecode(text: string): Uint8Array | null {
  if (!hexBytesPattern.test(text)) return null;
  const bytes = new Uint8Array(text.length / 2);
  for (let index = 0; index < bytes.length; index++)
    bytes[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);
  return bytes;
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource));
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return hexEncode(await sha256(bytes));
}
