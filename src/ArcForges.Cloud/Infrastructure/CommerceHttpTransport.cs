// SPDX-License-Identifier: AGPL-3.0-only
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace ArcForges.Cloud.Infrastructure;

/// <summary>Dedicated handler trust for the platform's ephemeral per-instance outbound interception CA.
/// It never changes system trust, bypasses hostname validation or imports provider business types.</summary>
internal static class CommerceHttpTransport
{
    internal const string ServiceKey = "commerce-provider-transport";
    internal const string MountedAuthority = "/etc/cloudflare/certs/cloudflare-containers-ca.crt";
    private const int MaxAuthorityBytes = 64 * 1024;

    internal static HttpMessageHandler Create(string? enabled) =>
        enabled == "enabled" ? CreateFromAuthority(MountedAuthority) : throw new InvalidOperationException("Commerce transport is not configured.");

    /// <summary>A fresh handler owns an immutable CA snapshot. The mount is reread for each handler;
    /// Container restart, including its ephemeral-CA replacement, must recreate the owning provider adapter.</summary>
    internal static HttpMessageHandler CreateFromAuthority(string certificatePath)
    {
        X509Certificate2? authority = null;
        var certificates = new X509Certificate2Collection();
        SocketsHttpHandler? sockets = null;
        try
        {
            using var stream = new FileStream(certificatePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length is <= 0 or > MaxAuthorityBytes) throw new InvalidOperationException();
            var pem = new byte[checked((int)stream.Length)];
            stream.ReadExactly(pem);
            if (stream.ReadByte() != -1) throw new InvalidOperationException();
            var text = System.Text.Encoding.ASCII.GetString(pem);
            // Public certificates only: the platform must not expose its signing private key.
            if (text.Contains("PRIVATE KEY", StringComparison.Ordinal)) throw new InvalidOperationException();
            certificates.ImportFromPem(text);
            if (certificates.Count != 1)
            {
                throw new InvalidOperationException();
            }
            authority = certificates[0];
            var constraints = authority.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
            var usage = authority.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
            var now = DateTimeOffset.UtcNow;
            if (authority.HasPrivateKey || constraints?.CertificateAuthority != true
                || usage is not null && (usage.KeyUsages & X509KeyUsageFlags.KeyCertSign) == 0
                || authority.NotBefore.ToUniversalTime() > now.UtcDateTime || authority.NotAfter.ToUniversalTime() <= now.UtcDateTime)
                throw new InvalidOperationException();
            var policy = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                VerificationFlags = X509VerificationFlags.NoFlag,
                // The platform's ephemeral root publishes no revocation service. Chain/name/time checks
                // remain standard; no server validation callback or permissive fallback is installed.
                RevocationMode = X509RevocationMode.NoCheck,
                DisableCertificateDownloads = true,
            };
            policy.CustomTrustStore.Add(authority);
            sockets = new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                UseProxy = false,
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
                ConnectTimeout = TimeSpan.FromSeconds(10),
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
                MaxConnectionsPerServer = 16,
                SslOptions = new SslClientAuthenticationOptions { CertificateChainPolicy = policy },
            };
            return new OwnedAuthorityHandler(sockets, authority);
        }
        catch
        {
            sockets?.Dispose();
            authority?.Dispose();
            foreach (var certificate in certificates) certificate.Dispose();
            // Configuration failures contain no certificate bytes, private material or path diagnostics.
            throw new InvalidOperationException("Commerce transport authority is unavailable or invalid.");
        }
    }

    private sealed class OwnedAuthorityHandler(HttpMessageHandler inner, X509Certificate2 authority) : DelegatingHandler(inner)
    {
        private int disposed;
        protected override void Dispose(bool disposing)
        {
            if (disposing && Interlocked.Exchange(ref disposed, 1) == 0)
            {
                try { base.Dispose(true); }
                finally { authority.Dispose(); }
            }
        }
    }
}
