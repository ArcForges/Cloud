// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Hello.V1;
using Grpc.Core;
using Npgsql;

namespace ArcForges.Cloud;

public sealed class HelloEndpoint(IHelloGreeting? greeting = null) : HelloService.HelloServiceBase
{
    private readonly IHelloGreeting greeting = greeting ?? new StatelessHelloGreeting();

    public override async Task<SayHelloResponse> SayHello(SayHelloRequest request, ServerCallContext context)
    {
        if (request.Name.Length == 0)
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Name must not be empty."));
        if (request.Name.Length > 256)
            throw new RpcException(new Status(StatusCode.ResourceExhausted, "Name exceeds 256 UTF-16 code units."));

        try
        {
            return new SayHelloResponse
            {
                Message = await greeting.GetAsync(request.Name, context?.CancellationToken ?? CancellationToken.None),
            };
        }
        catch (OperationCanceledException)
        {
            throw new RpcException(new Status(
                context?.CancellationToken.IsCancellationRequested == true ? StatusCode.Cancelled : StatusCode.DeadlineExceeded,
                "Hello request cancelled or timed out."));
        }
        catch (Exception error) when (error is NpgsqlException or TimeoutException or InvalidOperationException)
        {
            // No fallback: a database failure must not masquerade as a successful connectivity check.
            // Provider exception text can contain credentials and must not reach clients or logs.
            throw new RpcException(new Status(StatusCode.Unavailable, "Hello database unavailable."));
        }
    }
}
