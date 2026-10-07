// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Application;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Infrastructure;

internal sealed class D1QuotaDefinitionStore(IModulePlanPort plans) : IQuotaDefinitionStore
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    public async Task<QuotaDefinitionResult> ReadAsync(Guid realmId, string version, CancellationToken cancellationToken)
    {
        var outcome = await plans.ReadAsync(new("entitlement.quota-definition-get", realmId.ToString("D"), [T(realmId.ToString("D")), T(version)]), cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (outcome.Status != ModulePlanStatus.Succeeded) return new(QuotaDefinitionOutcomes.Status(outcome.Status));
        if (outcome.Rows.Count == 0) return new(QuotaDefinitionStatus.NotFound);
        try
        {
            var row = outcome.Rows.Single();
            if (row.Count != 8 || row[0].AsText() != realmId.ToString("D") || row[1].AsText() != version) return new(QuotaDefinitionStatus.Defect);
            var bytes = Utf8.GetBytes(row[3].AsText());
            if (bytes.Length is < 2 or > QuotaDefinitionValidator.MaximumBytes || bytes.Length != row[6].AsInt64()
                || row[2].AsBytes().Length != 32 || !row[2].AsBytes().SequenceEqual(row[5].AsBytes())
                || !SHA256.HashData(bytes).AsSpan().SequenceEqual(row[2].AsBytes()) || row[7].AsInt64() <= 0) return new(QuotaDefinitionStatus.Defect);
            using var json = JsonDocument.Parse(bytes, new() { MaxDepth = 4 });
            var expected = json.RootElement.GetProperty("definitions").EnumerateArray()
                .Select(d => new QuotaResolverDefinition(d.GetProperty("key").GetString()!, Enum.Parse<QuotaDefinitionCombination>(d.GetProperty("combination").GetString()!, false))).ToArray();
            // Stored canonical rows are integrity-checked here. Admission independently checks the actual resolver source.
            var validated = new QuotaDefinitionValidator().Validate(bytes, version, expected, cancellationToken);
            if (validated.Profile is not { } profile) return new(QuotaDefinitionStatus.Defect);
            return new(QuotaDefinitionStatus.Succeeded, new(realmId, profile, row[4].AsText(), Convert.ToHexStringLower(row[5].AsBytes()), bytes.Length, row[7].AsInt64()));
        }
        catch (Exception error) when (error is FormatException or InvalidOperationException or OverflowException or JsonException or ArgumentException or KeyNotFoundException)
        { cancellationToken.ThrowIfCancellationRequested(); return new(QuotaDefinitionStatus.Defect); }
    }

    public async Task<QuotaDefinitionReceiptResult> ReceiptAsync(QuotaDefinitionPublishRequest request, CancellationToken cancellationToken)
    {
        var outcome = await plans.ReadAsync(new("entitlement.quota-definition-command", request.RealmId.ToString("D"),
            [T(request.CommandId.ToString("D")), T(request.PublisherRef), T(request.RealmId.ToString("D"))]), cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (outcome.Status != ModulePlanStatus.Succeeded) return new(QuotaDefinitionOutcomes.Status(outcome.Status));
        if (outcome.Rows.Count == 0) return new(QuotaDefinitionStatus.NotFound);
        try
        {
            var r = outcome.Rows.Single();
            if (r.Count != 6 || r[3].AsInt64() is not (2 or 3) || r[5].AsInt64() <= 0) return new(QuotaDefinitionStatus.Defect);
            return new(QuotaDefinitionStatus.Succeeded, new(r[0].AsText(), r[1].AsText(), r[2].AsText(), r[3].AsInt64(), r[4].AsOptionalText(), r[5].AsInt64()));
        }
        catch (Exception error) when (error is FormatException or InvalidOperationException or OverflowException) { return new(QuotaDefinitionStatus.Defect); }
    }

    public Task<ModulePlanOutcome> PublishAsync(QuotaDefinitionPublishRequest request, ApprovedQuotaConfiguration approved,
        QuotaSemanticProfile profile, string requestHash, long nowMicros, CancellationToken cancellationToken)
    {
        var entries = Json(w =>
        {
            w.WriteStartArray();
            foreach (var d in profile.Definitions)
            {
                w.WriteStartObject(); w.WriteString("key", d.Key); w.WriteNumber("unit", (int)d.Unit + 1);
                w.WriteNumber("mode", (int)d.Mode + 1); w.WriteNumber("combination", (int)d.Combination + 1); w.WriteEndObject();
            }
            w.WriteEndArray();
        });
        var canonical = Utf8.GetString(profile.CanonicalBytes.Span);
        var hash = Convert.FromHexString(profile.Hash);
        var artifactHash = Convert.FromHexString(approved.ArtifactHash);
        var payload = Json(w =>
        {
            w.WriteStartObject(); w.WriteString("realmId", request.RealmId.ToString("D")); w.WriteString("definitionsVersion", profile.DefinitionsVersion);
            w.WriteString("hash", profile.Hash); w.WriteEndObject();
        });
        var archive = Json(w =>
        {
            w.WriteStartObject(); w.WriteString("kind", QuotaDefinitionOutcomes.Operation); w.WriteString("realmId", request.RealmId.ToString("D"));
            w.WriteString("configurationRevisionId", request.ConfigurationRevisionId.ToString("D")); w.WriteString("documentHash", request.DocumentHash);
            w.WriteString("publisherRef", request.PublisherRef); w.WriteString("artifactId", approved.ArtifactId); w.WriteString("artifactProfile", approved.ArtifactProfile);
            w.WriteString("artifactHash", approved.ArtifactHash); w.WriteNumber("verifiedLength", approved.VerifiedLength);
            w.WriteString("definitionsVersion", profile.DefinitionsVersion); w.WriteString("profileHash", profile.Hash); w.WriteEndObject();
        });
        var created = Math.Max(1, nowMicros);
        var commit = new ModuleCommit(request.CommandId, null, request.PublisherRef, QuotaDefinitionOutcomes.Operation, requestHash, payload, null,
            created, checked(created + 604800000000), [], 1, archive);
        return plans.WriteAsync(new("entitlement.quota-definition-publish", request.RealmId.ToString("D"),
        [
            [T(request.CommandId.ToString("D")), T(request.RealmId.ToString("D")), T(profile.DefinitionsVersion), B(hash), T(canonical), T(approved.ArtifactId), B(artifactHash), I(approved.VerifiedLength), T(entries)],
            [T(request.RealmId.ToString("D")), T(profile.DefinitionsVersion), B(hash), T(canonical), T(approved.ArtifactId), B(artifactHash), I(approved.VerifiedLength), I(created)],
            [T(request.RealmId.ToString("D")), T(profile.DefinitionsVersion), T(entries)],
        ], commit), cancellationToken);
    }
    private static PlanValue T(string value) => PlanValue.FromText(value);
    private static PlanValue I(long value) => PlanValue.FromInt64(value);
    private static PlanValue B(byte[] value) => PlanValue.FromBytes(value);
    private static string Json(Action<Utf8JsonWriter> write)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream)) write(writer);
        return Utf8.GetString(stream.ToArray());
    }
}
