// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.CompilerServices;
using ArcForges.Cloud;
using Microsoft.AspNetCore.Server.Kestrel.Core;

var identity = BuildIdentity.FromAssembly(typeof(HelloEndpoint).Assembly);
if (args is ["--build-info"])
{
    Console.WriteLine(identity.ToJsonString());
    return;
}
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

var build = identity["build"]!.AsObject();
var revision = build["sourceCommit"]!.GetValue<string>() + (build["dirty"]!.GetValue<bool>() ? "-dirty" : "");
var health = new HealthStatus("arcforges-cloud", revision, !RuntimeFeature.IsDynamicCodeSupported,
    identity["artifact"]!.AsObject(), build);
app.MapGet("/healthz", () => Results.Json(health, HealthJsonContext.Default.HealthStatus));
app.Run();
