// SPDX-License-Identifier: AGPL-3.0-only
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ArcForges.Cloud.Composition;
using ArcForges.Cloud.Infrastructure;
using ArcForges.Cloud.Modules.Commerce.Adapters;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace ArcForges.Cloud.Tests;

/// <summary>Actual SocketsHttpHandler TLS handshakes on loopback. Generated certificates replace only
/// the unavailable Cloudflare mounted CA/provider endpoint; this proves neither OS egress isolation nor deployment.</summary>
public sealed class CommerceHttpTransportTests
{
    private const string Suffix = "01grnn4zta5a1mf02jjze7y2ys";
    private const string Credential = "component-transport-credential-only";
    private const string PriceJson = """
        {"data":{"id":"pri_01grnn4zta5a1mf02jjze7y2ys","product_id":"pro_01grnn4zta5a1mf02jjze7y2ys","status":"active","tax_mode":"internal","product":{"id":"pro_01grnn4zta5a1mf02jjze7y2ys","status":"active","tax_category":"standard"},"unit_price":{"amount":"1000","currency_code":"USD"},"billing_cycle":{"interval":"month","frequency":1},"trial_period":null,"unit_price_overrides":[]}}
        """;
    private sealed class Authority : IDisposable
    {
        private readonly RSA key = RSA.Create(2048);
        public X509Certificate2 Certificate { get; }
        public string Path { get; } = System.IO.Path.GetTempFileName();
        public Authority(bool isAuthority = true, bool expired = false)
        {
            var request = new CertificateRequest("CN=Component authority", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(isAuthority, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            var now = DateTimeOffset.UtcNow;
            Certificate = request.CreateSelfSigned(now.AddDays(-3), expired ? now.AddDays(-1) : now.AddDays(3));
            File.WriteAllText(Path, Certificate.ExportCertificatePem());
        }
        public X509Certificate2 Leaf(string host = "localhost", bool expired = false)
        {
            using var leafKey = RSA.Create(2048);
            var request = new CertificateRequest("CN=" + host, leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName(host);
            request.CertificateExtensions.Add(names.Build());
            var now = DateTimeOffset.UtcNow;
            using var publicLeaf = request.Create(Certificate, now.AddDays(-2), expired ? now.AddDays(-1) : now.AddDays(2), RandomNumberGenerator.GetBytes(16));
            using var keyedLeaf = publicLeaf.CopyWithPrivateKey(leafKey);
            // Windows SChannel cannot use an ephemeral CNG signing key. A disposable PKCS#12
            // import supplies its normal temporary key container; no machine trust store is changed.
            var pfx = keyedLeaf.Export(X509ContentType.Pkcs12);
            try { return X509CertificateLoader.LoadPkcs12(pfx, null); }
            finally { CryptographicOperations.ZeroMemory(pfx); }
        }
        public void Dispose() { Certificate.Dispose(); key.Dispose(); File.Delete(Path); }
    }

    private sealed class Server(WebApplication app, Uri origin) : IAsyncDisposable
    {
        public Uri Origin { get; } = origin;
        public async ValueTask DisposeAsync() { await app.StopAsync(); await app.DisposeAsync(); }
    }
    private static async Task<Server> Start(X509Certificate2 leaf)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(leaf)));
        var app = builder.Build();
        app.MapGet("/ok", () => "ok");
        app.MapGet("/prices/pri_" + Suffix, (HttpContext context) =>
        {
            Assert.Equal("Bearer " + Credential, context.Request.Headers.Authorization.ToString());
            Assert.Equal("1", context.Request.Headers["Paddle-Version"].ToString());
            Assert.Equal("?include=product", context.Request.QueryString.Value);
            return Results.Text(PriceJson, "application/json");
        });
        app.MapGet("/redirect", (HttpContext context) => { context.Response.StatusCode = 302; context.Response.Headers.Location = "/ok"; });
        app.MapGet("/cookies", (HttpContext context) => { context.Response.Headers.SetCookie = "test=value"; return context.Request.Headers.Cookie.ToString(); });
        app.MapGet("/wait", async (HttpContext context) => { await Task.Delay(TimeSpan.FromMinutes(1), context.RequestAborted); });
        await app.StartAsync();
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        return new Server(app, new UriBuilder(address) { Host = "localhost" }.Uri);
    }

    [Fact]
    public void ActualHostCompositionRegistersOnlyTheLazyFrameworkTransportPort()
    {
        var builder = WebApplication.CreateSlimBuilder();
        var module = new CommerceTransportModule(_ => null);
        module.Register(builder);
        using var provider = builder.Services.BuildServiceProvider();
        var factory = provider.GetRequiredKeyedService<Func<HttpMessageHandler>>(CommerceHttpTransport.ServiceKey);
        Assert.Throws<InvalidOperationException>(() => factory());
        Assert.Empty(((IHostModule)module).RpcPolicies);
        Assert.Empty(((IHostModule)module).PlainPaths);
        Assert.Throws<InvalidOperationException>(() => new CommerceTransportModule(_ => "wrong").Register(WebApplication.CreateSlimBuilder()));
        var modules = HostModules.All(BuildIdentity.FromAssembly(typeof(HelloEndpoint).Assembly));
        Assert.Single(modules.OfType<CommerceTransportModule>());
    }

    [Fact]
    public async Task ActualProviderAndKeyedHostFactoryComposeThroughARealVerifiedTlsConnection()
    {
        using var authority = new Authority();
        using var leaf = authority.Leaf("api.paddle.com");
        await using var server = await Start(leaf);
        var builder = WebApplication.CreateSlimBuilder();
        new CommerceTransportModule(_ => "enabled", () => CommerceHttpTransport.CreateFromAuthority(authority.Path)).Register(builder);
        using var services = builder.Services.BuildServiceProvider();
        var handler = services.GetRequiredKeyedService<Func<HttpMessageHandler>>(CommerceHttpTransport.ServiceKey)();
        var sockets = Assert.IsType<SocketsHttpHandler>(Assert.IsAssignableFrom<DelegatingHandler>(handler).InnerHandler);
        Assert.Null(sockets.SslOptions.RemoteCertificateValidationCallback);
        Assert.Equal(X509ChainTrustMode.CustomRootTrust, sockets.SslOptions.CertificateChainPolicy?.TrustMode);
        // Replace only the unavailable provider network address. Hostname, CA, HTTP, authentication,
        // actual COM01 normalization and handler lifecycle remain production implementations.
        sockets.ConnectCallback = async (context, token) =>
        {
            Assert.Equal("api.paddle.com", context.DnsEndPoint.Host);
            Assert.Equal(443, context.DnsEndPoint.Port);
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            try { await socket.ConnectAsync(IPAddress.Loopback, server.Origin.Port, token); }
            catch { socket.Dispose(); throw; }
            return new NetworkStream(socket, ownsSocket: true);
        };
        var settings = new ProviderAdapterSettings(BillingEnvironment.Production, Credential,
            [new ProviderNotificationKey("component-key-v1", "component-notification-secret-only")], "component-source",
            new Uri("https://arcforges.com/billing/checkout"), new(true, true, true, true, true, false, false, []));
        using var adapter = BillingProviderFactory.Create(settings, handler);
        var price = await adapter.GetPriceAsync(new ProviderReference("pri_" + Suffix), CancellationToken.None);
        Assert.True(price.Active);
        Assert.Equal(new ProviderMoney("1000", "USD"), price.Money);
        Assert.Equal(new ProviderBillingCycle("month", 1), price.Terms.BillingCycle);
        Assert.Null(price.Terms.Trial);
    }

    [Fact]
    public async Task ActualTlsTrustsOnlyTheInjectedAuthorityAndRetainsHostnameValidation()
    {
        using var authority = new Authority();
        using var leaf = authority.Leaf();
        await using var server = await Start(leaf);
        using var client = new HttpClient(CommerceHttpTransport.CreateFromAuthority(authority.Path));
        Assert.Equal("ok", await client.GetStringAsync(new Uri(server.Origin, "ok"), TestContext.Current.CancellationToken));
        var wrongName = new UriBuilder(server.Origin) { Host = "127.0.0.1", Path = "ok" }.Uri;
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetStringAsync(wrongName, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task WrongAuthorityAndExpiredLeafFailTheRealHandshake()
    {
        using var authority = new Authority();
        using var unrelated = new Authority();
        using var valid = authority.Leaf();
        await using (var server = await Start(valid))
        using (var client = new HttpClient(CommerceHttpTransport.CreateFromAuthority(unrelated.Path)))
            await Assert.ThrowsAsync<HttpRequestException>(() => client.GetStringAsync(new Uri(server.Origin, "ok"), TestContext.Current.CancellationToken));
        using var expired = authority.Leaf(expired: true);
        await using var expiredServer = await Start(expired);
        using var trusted = new HttpClient(CommerceHttpTransport.CreateFromAuthority(authority.Path));
        await Assert.ThrowsAsync<HttpRequestException>(() => trusted.GetStringAsync(new Uri(expiredServer.Origin, "ok"), TestContext.Current.CancellationToken));
    }

    [Fact]
    public void ConfigurationAndAuthorityErrorsFailClosedWithoutSensitiveDiagnostics()
    {
        Assert.Throws<InvalidOperationException>(() => CommerceHttpTransport.Create(null));
        Assert.Throws<InvalidOperationException>(() => CommerceHttpTransport.Create("disabled"));
        using var notAuthority = new Authority(isAuthority: false);
        using var expired = new Authority(expired: true);
        foreach (var path in new[] { notAuthority.Path, expired.Path, notAuthority.Path + "-absent" })
        {
            var error = Assert.Throws<InvalidOperationException>(() => CommerceHttpTransport.CreateFromAuthority(path));
            Assert.DoesNotContain(path, error.ToString(), StringComparison.Ordinal);
            Assert.Null(error.InnerException);
        }
        File.WriteAllText(notAuthority.Path, new string('x', 64 * 1024 + 1));
        Assert.Throws<InvalidOperationException>(() => CommerceHttpTransport.CreateFromAuthority(notAuthority.Path));
        File.WriteAllText(notAuthority.Path, "malformed certificate");
        Assert.Throws<InvalidOperationException>(() => CommerceHttpTransport.CreateFromAuthority(notAuthority.Path));
        using var valid = new Authority();
        File.WriteAllText(notAuthority.Path, valid.Certificate.ExportCertificatePem() + expired.Certificate.ExportCertificatePem());
        Assert.Throws<InvalidOperationException>(() => CommerceHttpTransport.CreateFromAuthority(notAuthority.Path));
        using var privateKey = valid.Certificate.GetRSAPrivateKey();
        File.WriteAllText(notAuthority.Path, valid.Certificate.ExportCertificatePem() + privateKey!.ExportPkcs8PrivateKeyPem());
        Assert.Throws<InvalidOperationException>(() => CommerceHttpTransport.CreateFromAuthority(notAuthority.Path));
    }

    [Fact]
    public async Task ActualHandlerDoesNotFollowRedirectsOrKeepCookiesAndSupportsConcurrentCalls()
    {
        using var authority = new Authority();
        using var leaf = authority.Leaf();
        await using var server = await Start(leaf);
        using var client = new HttpClient(CommerceHttpTransport.CreateFromAuthority(authority.Path));
        using var redirect = await client.GetAsync(new Uri(server.Origin, "redirect"), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, redirect.StatusCode);
        Assert.Equal("/ok", redirect.Headers.Location?.OriginalString);
        Assert.Equal("", await client.GetStringAsync(new Uri(server.Origin, "cookies"), TestContext.Current.CancellationToken));
        Assert.Equal("", await client.GetStringAsync(new Uri(server.Origin, "cookies"), TestContext.Current.CancellationToken));
        Assert.All(await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => client.GetStringAsync(new Uri(server.Origin, "ok")))), value => Assert.Equal("ok", value));
    }

    [Fact]
    public async Task ActualCallerCancellationAndIdempotentDisposalReachTheTransport()
    {
        using var authority = new Authority();
        using var leaf = authority.Leaf();
        await using var server = await Start(leaf);
        var handler = CommerceHttpTransport.CreateFromAuthority(authority.Path);
        using var client = new HttpClient(handler);
        using var cancelled = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.GetAsync(new Uri(server.Origin, "wait"), cancelled.Token));
        client.Dispose();
        handler.Dispose();
        handler.Dispose();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.GetAsync(new Uri(server.Origin, "ok"), TestContext.Current.CancellationToken));
    }
}
