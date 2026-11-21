// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Cloud.Consumer;
using ArcForges.Contracts.Hello.V1;
using Grpc.Core;
using Grpc.Net.Client;

if (Environment.GetEnvironmentVariable("CI") == "true" ||
    Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true")
{
    Console.Error.WriteLine("The independent Hello consumer runs locally. CI uses the Go Center checks.");
    return 2;
}

if (args.Length > 0 && args[0] == "probe")
{
    if (args.Length != 3 || !bool.TryParse(args[2], out var worker))
    {
        Console.Error.WriteLine("usage: ArcForges.Cloud.Consumer probe <baseUrl> <true|false>");
        return 2;
    }

    try
    {
        using var source = typeof(HelloProbe).Assembly.GetManifestResourceStream("Consumer.ContractsSource")
            ?? throw new InvalidOperationException("The Hello consumer has no restored Contracts source identity.");
        using var identity = JsonDocument.Parse(source);
        var publishedClient = identity.RootElement.GetProperty("version").GetString()
            ?? throw new InvalidOperationException("The restored Contracts source identity has no version.");
        Console.WriteLine(await HelloProbe.RunAsync(args[1], worker, publishedClient, CancellationToken.None));
        return 0;
    }
    catch (Exception error)
    {
        Console.Error.WriteLine(error.Message);
        return 1;
    }
}

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

return 0;
