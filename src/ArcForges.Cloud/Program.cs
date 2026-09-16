// SPDX-License-Identifier: AGPL-3.0-only
using System.Reflection;
using System.Runtime.CompilerServices;
using ArcForges.Cloud;
using Microsoft.AspNetCore.Server.Kestrel.Core;

var builder = WebApplication.CreateSlimBuilder(args);
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxRequestBodySize = 4096;
    options.Limits.MaxConcurrentConnections = 64;
    options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
    options.ListenAnyIP(8080, listen => listen.Protocols = HttpProtocols.Http1);
    options.ListenAnyIP(8081, listen => listen.Protocols = HttpProtocols.Http2);
});
builder.Services.AddGrpc(options =>
{
    options.EnableDetailedErrors = false;
    options.MaxReceiveMessageSize = 4091;
    options.MaxSendMessageSize = 4091;
});

var app = builder.Build();
app.UseGrpcWeb();
app.MapGrpcService<HelloEndpoint>().EnableGrpcWeb();

var revision = typeof(HelloEndpoint).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
    .Single(attribute => attribute.Key == "SourceRevision").Value!;
var health = new HealthStatus("arcforges-cloud", revision, !RuntimeFeature.IsDynamicCodeSupported);
app.MapGet("/healthz", () => Results.Json(health, HealthJsonContext.Default.HealthStatus));
app.Run();
