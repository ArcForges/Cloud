// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json.Serialization;

namespace ArcForges.Cloud;

public sealed record HealthStatus(string Service, string Revision, bool NativeAot);

[JsonSerializable(typeof(HealthStatus))]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
internal sealed partial class HealthJsonContext : JsonSerializerContext;
