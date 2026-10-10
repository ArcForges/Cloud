// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using ArcForges.Contracts.Hello.V1;
using Grpc.Core;

namespace ArcForges.Cloud.Tools.Generation;

/// <summary>
/// The Hello protocol probe (CLOUD.84 S33(3)(b)). It runs the assertions of the retired TypeScript verifyProtocol through the NuGet
/// Contracts generated <c>HelloService.HelloServiceClient</c>. The only hand-written part is the HTTP/1.1 binary gRPC-Web transport
/// below (a call invoker): request and response messages are encoded and decoded by the generated marshallers. Any failed
/// assertion throws, so the probe exits non-zero.
/// </summary>
public static class HelloProbe
{
    private const string SayHelloPath = "/arcforges.hello.v1.HelloService/SayHello";
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(20);

    public static async Task<string> RunAsync(string baseUrl, bool worker, CancellationToken cancellation)
    {
        using var http = new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,
        })
        {
            Timeout = Budget,
            DefaultRequestVersion = HttpVersion.Version11,
        };

        var client = Client(http, baseUrl, null);
        foreach (var name in new[] { "ArcForges", "世界 👋" })
        {
            var reply = await client.SayHelloAsync(new SayHelloRequest { Name = name }, deadline: Deadline(20), cancellationToken: cancellation);
            Expect(reply.Message == $"Hello, {name}!", $"greeting for {name}");
        }

        await ExpectStatusAsync(() => client.SayHelloAsync(new SayHelloRequest { Name = string.Empty }, deadline: Deadline(20), cancellationToken: cancellation).ResponseAsync, StatusCode.InvalidArgument);
        await ExpectStatusAsync(() => client.SayHelloAsync(new SayHelloRequest { Name = new string('x', 257) }, deadline: Deadline(20), cancellationToken: cancellation).ResponseAsync, StatusCode.ResourceExhausted);

        if (worker)
        {
            // Real router normalization of the content type, through the same generated client.
            foreach (var contentType in new[] { "application/grpc-web", "Application/GRPC-Web+Proto; charset=utf-8" })
            {
                var normalized = Client(http, baseUrl, message => message.Content!.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType));
                var reply = await normalized.SayHelloAsync(new SayHelloRequest { Name = "Content-Type" }, deadline: Deadline(5), cancellationToken: cancellation);
                Expect(reply.Message == "Hello, Content-Type!", $"normalized content type {contentType}");
            }

            foreach (var (timeout, code) in new[] { ("0m", StatusCode.DeadlineExceeded), ("invalid", StatusCode.InvalidArgument) })
            {
                var expired = Client(http, baseUrl, message =>
                {
                    message.Headers.Remove("grpc-timeout");
                    message.Headers.TryAddWithoutValidation("grpc-timeout", timeout);
                });
                await ExpectStatusAsync(() => expired.SayHelloAsync(new SayHelloRequest { Name = "Deadline" }, deadline: Deadline(5), cancellationToken: cancellation).ResponseAsync, code);
            }

            foreach (var (endpoint, method, expected) in new (string Endpoint, HttpMethod Method, int Status)[]
            {
                ("/unknown", HttpMethod.Get, 404),
                ("/api" + SayHelloPath, HttpMethod.Post, 404),
                (SayHelloPath, HttpMethod.Get, 405),
            })
            {
                using var response = await http.SendAsync(new HttpRequestMessage(method, baseUrl + endpoint), cancellation);
                Expect((int)response.StatusCode == expected, $"{method} {endpoint} returned {(int)response.StatusCode}, expected {expected}");
                await response.Content.ReadAsByteArrayAsync(cancellation);
            }

            using (var unsupported = new HttpRequestMessage(HttpMethod.Post, baseUrl + SayHelloPath)
            {
                Content = new ByteArrayContent("{}"u8.ToArray()) { Headers = { ContentType = new MediaTypeHeaderValue("application/json") } },
            })
            {
                using var response = await http.SendAsync(unsupported, cancellation);
                Expect((int)response.StatusCode == 415, "unsupported media type is not 415");
                await response.Content.ReadAsByteArrayAsync(cancellation);
            }

            using (var oversized = new HttpRequestMessage(HttpMethod.Post, baseUrl + SayHelloPath)
            {
                Content = new ByteArrayContent(new byte[4097]) { Headers = { ContentType = new MediaTypeHeaderValue("application/grpc-web+proto") } },
            })
            {
                using var response = await http.SendAsync(oversized, cancellation);
                Expect((int)response.StatusCode == 413, "oversized body is not 413");
                await response.Content.ReadAsByteArrayAsync(cancellation);
            }
        }

        var identity = JsonDocument.Parse(ContractsIdentity.Read(typeof(ArcForges.Cloud.HelloEndpoint).Assembly));
        var publishedClient = identity.RootElement.GetProperty("version").GetString();
        return JsonSerializer.Serialize(new
        {
            transport = "binary gRPC-Web",
            publishedClient,
            greeting = true,
            unicode = true,
            invalidArgument = true,
            resourceExhausted = true,
            workerBoundary = worker,
        });
    }

    private static HelloService.HelloServiceClient Client(HttpClient http, string baseUrl, Action<HttpRequestMessage>? mutate) =>
        new(new GrpcWebCallInvoker(http, baseUrl, mutate));

    private static DateTime Deadline(int seconds) => DateTime.UtcNow.AddSeconds(seconds);

    private static void Expect(bool condition, string what)
    {
        if (!condition) throw new InvalidOperationException($"Hello protocol probe failed: {what}.");
    }

    private static async Task ExpectStatusAsync(Func<Task> call, StatusCode expected)
    {
        try
        {
            await call();
        }
        catch (RpcException error)
        {
            Expect(error.StatusCode == expected, $"expected {expected} but saw {error.StatusCode}");
            return;
        }
        throw new InvalidOperationException($"Hello protocol probe failed: expected {expected}, but the call succeeded.");
    }

    /// <summary>The bytes one generated serializer produced for a message.</summary>
    private sealed class Serialized : SerializationContext
    {
        private readonly ArrayBufferWriter<byte> _writer = new();
        private byte[]? _payload;

        public byte[] Payload => _payload ?? throw new InvalidOperationException("The generated serializer produced no payload.");

        public override void Complete(byte[] payload) => _payload = payload;

        public override void Complete() => _payload = _writer.WrittenMemory.ToArray();

        public override IBufferWriter<byte> GetBufferWriter() => _writer;
    }

    /// <summary>The bytes of one message presented to a generated deserializer.</summary>
    private sealed class Deserialized(byte[] bytes) : DeserializationContext
    {
        public override int PayloadLength => bytes.Length;

        public override byte[] PayloadAsNewBuffer() => bytes.ToArray();

        public override ReadOnlySequence<byte> PayloadAsReadOnlySequence() => new(bytes);
    }

    /// <summary>
    /// Binary gRPC-Web over HTTP/1.1: a length-prefixed data frame out, and data and trailer frames back (trailer flag 0x80).
    /// Messages are encoded and decoded by the generated method marshallers; nothing here encodes protobuf fields.
    /// </summary>
    private sealed class GrpcWebCallInvoker(HttpClient http, string baseUrl, Action<HttpRequestMessage>? mutate) : CallInvoker
    {
        public override TResponse BlockingUnaryCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options, TRequest request) =>
            AsyncUnaryCall(method, host, options, request).GetAwaiter().GetResult();

        public override AsyncUnaryCall<TResponse> AsyncUnaryCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options, TRequest request)
        {
            var response = InvokeAsync(method, options, request);
            return new AsyncUnaryCall<TResponse>(response, Task.FromResult(new Metadata()), () => new Status(StatusCode.OK, string.Empty), () => new Metadata(), () => { });
        }

        public override AsyncServerStreamingCall<TResponse> AsyncServerStreamingCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options, TRequest request) =>
            throw new NotSupportedException("The Hello probe uses unary calls only.");

        public override AsyncClientStreamingCall<TRequest, TResponse> AsyncClientStreamingCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options) =>
            throw new NotSupportedException("The Hello probe uses unary calls only.");

        public override AsyncDuplexStreamingCall<TRequest, TResponse> AsyncDuplexStreamingCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options) =>
            throw new NotSupportedException("The Hello probe uses unary calls only.");

        private async Task<TResponse> InvokeAsync<TRequest, TResponse>(Method<TRequest, TResponse> method, CallOptions options, TRequest request)
        {
            var serialized = new Serialized();
            method.RequestMarshaller.ContextualSerializer(request, serialized);
            var payload = serialized.Payload;
            var frame = new byte[5 + payload.Length];
            BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(1, 4), (uint)payload.Length);
            payload.CopyTo(frame, 5);

            using var message = new HttpRequestMessage(HttpMethod.Post, baseUrl + method.FullName)
            {
                Version = HttpVersion.Version11,
                Content = new ByteArrayContent(frame) { Headers = { ContentType = new MediaTypeHeaderValue("application/grpc-web+proto") } },
            };
            foreach (var entry in options.Headers ?? [])
                if (entry.Key is not null && entry.Value is not null)
                    message.Headers.TryAddWithoutValidation(entry.Key, entry.Value);
            if (options.Deadline is { } deadline)
                message.Headers.TryAddWithoutValidation("grpc-timeout", Math.Max(0, (long)(deadline - DateTime.UtcNow).TotalMilliseconds).ToString(CultureInfo.InvariantCulture) + "m");
            mutate?.Invoke(message);

            using var response = await http.SendAsync(message, options.CancellationToken);
            var body = await response.Content.ReadAsByteArrayAsync(options.CancellationToken);
            var status = StatusCode.Unknown;
            var detail = string.Empty;
            TResponse? reply = default;
            var offset = 0;
            while (offset + 5 <= body.Length)
            {
                var flag = body[offset];
                var length = (int)BinaryPrimitives.ReadUInt32BigEndian(body.AsSpan(offset + 1, 4));
                var content = body.AsSpan(offset + 5, length).ToArray();
                offset += 5 + length;
                if ((flag & 0x80) != 0)
                {
                    foreach (var line in Encoding.ASCII.GetString(content).Split("\r\n", StringSplitOptions.RemoveEmptyEntries))
                    {
                        var separator = line.IndexOf(':', StringComparison.Ordinal);
                        if (separator < 0) continue;
                        var key = line[..separator].Trim();
                        var value = line[(separator + 1)..].Trim();
                        if (key == "grpc-status") status = (StatusCode)int.Parse(value, CultureInfo.InvariantCulture);
                        if (key == "grpc-message") detail = Uri.UnescapeDataString(value);
                    }
                }
                else
                {
                    reply = method.ResponseMarshaller.ContextualDeserializer(new Deserialized(content));
                }
            }
            if (status == StatusCode.Unknown && response.Headers.TryGetValues("grpc-status", out var headerStatus))
                status = (StatusCode)int.Parse(headerStatus.First(), CultureInfo.InvariantCulture);
            if (status != StatusCode.OK)
                throw new RpcException(new Status(status, detail));
            return reply ?? throw new RpcException(new Status(StatusCode.Internal, "The response carried no message."));
        }
    }
}
