// SPDX-License-Identifier: AGPL-3.0-only
// The edge rate limits' client key and the surface limit's reply (AF-CTR-03 F7, F17). Their parameters (the IPv6 network that keys
// a client, the limiter's period, the reply template and the places of its instants) are generated from the Go center's
// registrations (worker/tables/center-tables.generated.ts). What is written here is fixed by standards: the IPv6 text form (RFC 4291
// section 2.2, canonicalised by the WHATWG URL host parser) and the protobuf encoding of an instant's seconds (a zigzag sint64 varint).
import {
  edgeIpv6PrefixBits,
  edgeRateLimitPeriodSeconds,
  rateLimitedReply,
  rateLimitedReplyInstantBytes,
  rateLimitedReplyInstantOffsets,
} from "../tables/center-tables.generated.ts";

/** RFC 4291 section 2.2: an IPv6 address is eight groups of sixteen bits. */
const ipv6Groups = 8;
const ipv6GroupBits = 16;
/** The prefix of an IPv4-mapped IPv6 address in its canonical text (RFC 4291 section 2.5.5.2). */
const mappedPrefix = "::ffff:";

/** The canonical host text of an IP literal, or undefined when the URL host parser does not read it as one. */
function canonicalHost(literal: string): string | undefined {
  try {
    return new URL(`http://${literal}/`).hostname;
  } catch {
    return undefined;
  }
}

/** The eight groups of a canonical IPv6 address text (at most one "::", lower-case hexadecimal groups). */
function groupsOf(text: string): number[] | undefined {
  const halves = text.split("::");
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves[1] ? halves[1].split(":") : [];
  const missing = ipv6Groups - head.length - tail.length;
  if (halves.length > 2 || missing < 0 || (halves.length === 1 && missing !== 0)) return undefined;
  const groups = [...head, ...new Array<string>(missing).fill("0"), ...tail].map((group) =>
    Number(`0x${group}`),
  );
  return groups.some((group) => Number.isNaN(group)) ? undefined : groups;
}

/**
 * The key of a client address at the edge rate limits (F7): an IPv4 address, or the IPv4 address of an IPv4-mapped IPv6 address,
 * keys as its whole address; an IPv6 address keys as its network of the generated prefix length, in canonical text with the length
 * (for example 2001:db8:1:2::/64), so one host cannot pass the limit by changing its address within its own network. Without an
 * address the key is "local"; a value the host parser does not read keys as itself. It never throws.
 */
export function edgeClientKey(address: string | null): string {
  if (address === null) return "local";
  if (!address.includes(":")) return address;
  const host = canonicalHost(`[${address}]`);
  if (host === undefined) return address;
  const text = host.slice(1, -1);
  if (text.startsWith(mappedPrefix)) {
    const parts = text.slice(mappedPrefix.length).split(":");
    if (parts.length === 2 && parts.every((part) => part !== ""))
      return canonicalHost(`0x${parts.map((part) => part.padStart(4, "0")).join("")}`) ?? address;
  }
  const groups = groupsOf(text);
  if (groups === undefined) return address;
  let remaining = edgeIpv6PrefixBits;
  const network = groups.map((group) => {
    const kept = Math.min(Math.max(remaining, 0), ipv6GroupBits);
    remaining -= ipv6GroupBits;
    return kept === 0 ? 0 : (group >> (ipv6GroupBits - kept)) << (ipv6GroupBits - kept);
  });
  const prefix = canonicalHost(`[${network.map((group) => group.toString(16)).join(":")}]`);
  return prefix === undefined ? address : `${prefix.slice(1, -1)}/${edgeIpv6PrefixBits}`;
}

/** SI unit: one second is 1000 milliseconds; the instant is written in whole seconds. */
const millisecondsPerSecond = 1000;
/** The protobuf varint: seven-bit groups, least significant first, each but the last with the continuation bit 0x80 (128). */
const varintRadix = 128;
/** The zigzag encoding of a sint64 n >= 0 is 2n. */
const zigzagFactor = 2;

/**
 * The surface limit's reply at a time (F17): the generated RESOURCE/rate_limited template with its retry instant written into each
 * instant (retry.retry_at and limit.recovery_at): the time rounded up to the second, plus the edge limiter's period, an upper bound of
 * the limiter's window. The instant's seconds are a fixed-width zigzag varint, so no length of the template changes.
 */
export function rateLimitedReplyAt(nowMilliseconds: number): Uint8Array<ArrayBuffer> {
  const body = Uint8Array.from(atob(rateLimitedReply), (character) => character.charCodeAt(0));
  const seconds = Math.ceil(nowMilliseconds / millisecondsPerSecond) + edgeRateLimitPeriodSeconds;
  for (const offset of rateLimitedReplyInstantOffsets) {
    let value = seconds * zigzagFactor;
    for (let index = 0; index < rateLimitedReplyInstantBytes; index++) {
      const continuation = index < rateLimitedReplyInstantBytes - 1 ? varintRadix : 0;
      body[offset + index] = (value % varintRadix) + continuation;
      value = Math.floor(value / varintRadix);
    }
  }
  return body;
}
