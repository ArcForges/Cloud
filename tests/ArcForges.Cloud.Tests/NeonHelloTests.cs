// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Hello.V1;
using Grpc.Core;
using Npgsql;
using Xunit;

namespace ArcForges.Cloud.Tests;

public sealed class NeonHelloTests
{
    private const string Valid = "postgresql://owner:fixture%40%3A%3B%26%2B%25@ep-fixture-pooler.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require";

    [Fact]
    public void NeonIsExplicitAndMissingSecretsFailClosed()
    {
        Assert.Null(NeonHelloOptions.FromEnvironment(_ => null));
        Assert.Throws<InvalidOperationException>(() =>
            NeonHelloOptions.FromEnvironment(key => key == NeonHelloOptions.EnabledVariable ? "enabled" : null));
    }

    [Fact]
    public void DecodesCredentialsAndRequiresVerifiedTlsWithBoundedPool()
    {
        var settings = NeonHelloOptions.Parse(Valid);
        Assert.Equal("fixture@:;&+%", settings.Password);
        Assert.Equal(SslMode.VerifyFull, settings.SslMode);
        Assert.Equal(ChannelBinding.Require, settings.ChannelBinding);
        Assert.Equal(GssEncryptionMode.Disable, settings.GssEncryptionMode);
        Assert.Equal(2, settings.MaxPoolSize);
        Assert.False(settings.IncludeErrorDetail);
        Assert.False(settings.LogParameters);
    }

    [Theory]
    [InlineData("sslmode=require", "sslmode=disable")]
    [InlineData("channel_binding=require", "channel_binding=disable")]
    [InlineData("fixture%40%3A%3B%26%2B%25", "********")]
    [InlineData(".neon.tech/", ".neon.tech.attacker.invalid/")]
    [InlineData("-pooler.", ".")]
    [InlineData("/neondb?", ":80/neondb?")]
    public void RejectsUnsafeOrIncorrectEndpointsWithoutEchoingCredentials(string from, string to)
    {
        var error = Assert.Throws<InvalidOperationException>(() => NeonHelloOptions.Parse(Valid.Replace(from, to, StringComparison.Ordinal)));
        Assert.DoesNotContain("fixture", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task HelloUsesTheConfiguredSourceRatherThanALocalGreeting()
    {
        var source = new Greeting((name, _) => Task.FromResult("database:" + name));
        var reply = await new HelloEndpoint(source).SayHello(new SayHelloRequest { Name = "ArcForges" }, null!);
        Assert.Equal("database:ArcForges", reply.Message);
    }

    [Fact]
    public async Task DatabaseFailureNeverFallsBackOrDisclosesItsMessage()
    {
        var source = new Greeting((_, _) => throw new NpgsqlException("synthetic-private-password"));
        var error = await Assert.ThrowsAsync<RpcException>(() =>
            new HelloEndpoint(source).SayHello(new SayHelloRequest { Name = "ArcForges" }, null!));
        Assert.Equal(StatusCode.Unavailable, error.StatusCode);
        Assert.DoesNotContain("synthetic-private-password", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task InvalidInputNeverCallsTheDatabase()
    {
        var calls = 0;
        var source = new Greeting((_, _) => { calls++; return Task.FromResult("unexpected"); });
        await Assert.ThrowsAsync<RpcException>(() => new HelloEndpoint(source).SayHello(new SayHelloRequest(), null!));
        Assert.Equal(0, calls);
    }

    private sealed class Greeting(Func<string, CancellationToken, Task<string>> run) : IHelloGreeting
    {
        public Task<string> GetAsync(string name, CancellationToken cancellation) => run(name, cancellation);
    }
}
