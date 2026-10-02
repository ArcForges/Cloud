// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud;
using ArcForges.Cloud.Composition;
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

var modules = HostModules.All(identity);
foreach (var module in modules) module.Register(builder);

var app = builder.Build();
foreach (var module in modules) module.Map(app);
app.Run();
