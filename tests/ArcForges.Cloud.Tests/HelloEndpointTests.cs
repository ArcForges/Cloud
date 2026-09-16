// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Hello.V1;
using Grpc.Core;
using Xunit;

namespace ArcForges.Cloud.Tests;

public sealed class HelloEndpointTests
{
    [Theory]
    [InlineData("ArcForges", "Hello, ArcForges!")]
    [InlineData("世界 👋", "Hello, 世界 👋!")]
    [InlineData(" ", "Hello,  !")]
    public async Task PreservesThePublishedGreeting(string name, string expected)
    {
        var result = await new HelloEndpoint().SayHello(new SayHelloRequest { Name = name }, null!);
        Assert.Equal(expected, result.Message);
    }

    [Fact]
    public async Task EmptyNameHasThePublishedStatus()
    {
        var error = await Assert.ThrowsAsync<RpcException>(() =>
            new HelloEndpoint().SayHello(new SayHelloRequest(), null!));
        Assert.Equal(StatusCode.InvalidArgument, error.StatusCode);
    }

    [Fact]
    public async Task OversizedNameIsResourceExhausted()
    {
        var error = await Assert.ThrowsAsync<RpcException>(() =>
            new HelloEndpoint().SayHello(new SayHelloRequest { Name = new string('x', 257) }, null!));
        Assert.Equal(StatusCode.ResourceExhausted, error.StatusCode);
    }
}
