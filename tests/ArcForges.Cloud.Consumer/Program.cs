// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Hello.V1;
using Grpc.Core;
using Grpc.Net.Client;

var url = args.Length == 1 ? args[0] : "http://127.0.0.1:18081";
using var channel = GrpcChannel.ForAddress(url);
var client = new HelloService.HelloServiceClient(channel);
foreach (var name in new[] { "ArcForges", "世界 👋" })
{
    var result = await client.SayHelloAsync(new SayHelloRequest { Name = name },
        deadline: DateTime.UtcNow.AddSeconds(10));
    if (result.Message != $"Hello, {name}!")
    {
        throw new InvalidOperationException("The published native gRPC client received an unexpected greeting.");
    }
}

try
{
    await client.SayHelloAsync(new SayHelloRequest(), deadline: DateTime.UtcNow.AddSeconds(10));
    throw new InvalidOperationException("Empty name unexpectedly succeeded.");
}
catch (RpcException error) when (error.StatusCode == StatusCode.InvalidArgument)
{
    Console.WriteLine("Native HTTP/2 gRPC: success, Unicode and INVALID_ARGUMENT verified.");
}
