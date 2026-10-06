// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Cloud.Modules.Identity.Core.Application;

namespace ArcForges.Cloud.Modules.Identity.Persistence;

/// <summary>Identifiers contain 122 cryptographically random bits and canonical UUID v4 version/variant bits. Collisions remain guarded by the transaction.</summary>
internal sealed class IdentityIdSource : IIdentityIdSource
{
    public string NewId()
    {
        Span<byte> bytes = stackalloc byte[16];
        RandomNumberGenerator.Fill(bytes);
        bytes[6] = (byte)((bytes[6] & 0x0f) | 0x40);
        bytes[8] = (byte)((bytes[8] & 0x3f) | 0x80);
        return new Guid(bytes, bigEndian: true).ToString("D");
    }
}
