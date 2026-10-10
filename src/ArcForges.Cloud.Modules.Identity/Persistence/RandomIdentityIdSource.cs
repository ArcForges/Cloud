// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Cloud.Modules.Identity.Core.Application;

namespace ArcForges.Cloud.Modules.Identity.Persistence.Infrastructure;

/// <summary>
/// The production identifier source: 122 bits from the operating system's cryptographic random generator with the RFC 9562 version 4
/// nibble and variant bits, in the canonical lower-case form every identifier column of the physical schema requires. An identifier is
/// never derived from a clock, a counter or another identifier, so it discloses nothing and cannot be guessed from its neighbours; a
/// collision is refused whole by the plan guards and keys, and the service then retries with fresh identifiers.
/// </summary>
internal sealed class RandomIdentityIdSource : IIdentityIdSource
{
    public string NewId()
    {
        Span<byte> bytes = stackalloc byte[16];
        RandomNumberGenerator.Fill(bytes);
        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x40);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);
        return new Guid(bytes, bigEndian: true).ToString("D");
    }
}
