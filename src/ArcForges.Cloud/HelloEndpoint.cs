// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Hello.V1;
using Grpc.Core;

namespace ArcForges.Cloud;

public sealed class HelloEndpoint : HelloService.HelloServiceBase
{
    public override Task<SayHelloResponse> SayHello(SayHelloRequest request, ServerCallContext context)
    {
        if (request.Name.Length == 0)
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Name must not be empty."));
        }

        if (request.Name.Length > 256)
        {
            throw new RpcException(new Status(StatusCode.ResourceExhausted, "Name exceeds 256 UTF-16 code units."));
        }

        return Task.FromResult(new SayHelloResponse { Message = $"Hello, {request.Name}!" });
    }
}
