// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Infrastructure;

internal sealed class D1ResolverDefinitionStore(IModulePlanPort plans) : IResolverDefinitionStore
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    public async Task<ResolverDefinitionResult> ReadAsync(Guid realmId, string version, CancellationToken cancellationToken)
    {
        var outcome = await plans.ReadAsync(new("entitlement.resolver-definition-get", realmId.ToString("D"),
            [T(realmId.ToString("D")), T(version)]), cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (outcome.Status != ModulePlanStatus.Succeeded) return new(ResolverDefinitionOutcomes.Status(outcome.Status));
        if (outcome.Rows.Count == 0) return new(ResolverDefinitionStatus.NotFound);
        try
        {
            var row = outcome.Rows.Single();
            if (row.Count != 12 || row[0].AsText() != realmId.ToString("D") || row[1].AsText() != version) return new(ResolverDefinitionStatus.Defect);
            var bytes = Utf8.GetBytes(row[3].AsText());
            if (bytes.Length is < 2 or > ResolverDefinitionValidator.MaximumBytes || bytes.Length != row[6].AsInt64()
                || row[2].AsBytes().Length != 32 || !row[2].AsBytes().SequenceEqual(row[5].AsBytes())
                || !SHA256.HashData(bytes).AsSpan().SequenceEqual(row[2].AsBytes()) || row[8].AsBytes().Length != 32
                || !Guid.TryParseExact(row[7].AsText(), "D", out var originalRevision) || originalRevision == Guid.Empty
                || originalRevision.ToString("D") != row[7].AsText() || row[9].AsInt64() is not (1 or 2)
                || !CurrentResolverDefinitionSource.Identifier(row[4].AsText()) || !CurrentResolverDefinitionSource.Publisher(row[10].AsText())
                || row[11].AsInt64() <= 0) return new(ResolverDefinitionStatus.Defect);
            var validated = new ResolverDefinitionValidator().Validate(bytes, version, cancellationToken);
            if (validated.Profile is not { } profile) return new(ResolverDefinitionStatus.Defect);
            return new(ResolverDefinitionStatus.Succeeded, new(realmId, profile, row[4].AsText(), Convert.ToHexStringLower(row[5].AsBytes()), bytes.Length,
                originalRevision, Convert.ToHexStringLower(row[8].AsBytes()), row[9].AsInt64() == 1 ? "official" : "selfHosted", row[10].AsText(), row[11].AsInt64()));
        }
        catch (Exception error) when (error is FormatException or InvalidOperationException or OverflowException or ArgumentException)
        { cancellationToken.ThrowIfCancellationRequested(); return new(ResolverDefinitionStatus.Defect); }
    }

    public async Task<ResolverDefinitionReceiptResult> ReceiptAsync(ResolverDefinitionPublishRequest request, CancellationToken cancellationToken)
    {
        var outcome = await plans.ReadAsync(new("entitlement.resolver-definition-command", request.RealmId.ToString("D"),
            [T(request.CommandId.ToString("D")), T(request.PublisherRef), T(request.RealmId.ToString("D"))]), cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (outcome.Status != ModulePlanStatus.Succeeded) return new(ResolverDefinitionOutcomes.Status(outcome.Status));
        if (outcome.Rows.Count == 0) return new(ResolverDefinitionStatus.NotFound);
        try
        {
            var row = outcome.Rows.Single();
            if (row.Count != 6 || row[3].AsInt64() is not (2 or 3) || row[5].AsInt64() <= 0) return new(ResolverDefinitionStatus.Defect);
            return new(ResolverDefinitionStatus.Succeeded, new(row[0].AsText(), row[1].AsText(), row[2].AsText(), row[3].AsInt64(), row[4].AsOptionalText(), row[5].AsInt64()));
        }
        catch (Exception error) when (error is FormatException or InvalidOperationException or OverflowException)
        { cancellationToken.ThrowIfCancellationRequested(); return new(ResolverDefinitionStatus.Defect); }
    }

    public Task<ModulePlanOutcome> PublishAsync(ResolverDefinitionPublishRequest request, ApprovedResolverConfiguration approved,
        ResolverDefinitionProfile profile, string requestHash, long nowMicros, CancellationToken cancellationToken)
    {
        var canonical = Utf8.GetString(profile.CanonicalBytes.Span);
        var hash = Convert.FromHexString(profile.Hash);
        var artifactHash = Convert.FromHexString(approved.ArtifactHash);
        var realmKind = approved.RealmKind == "official" ? 1 : approved.RealmKind == "selfHosted" ? 2 : throw new InvalidOperationException("Invalid approved realm kind.");
        var payload = Json(writer =>
        {
            writer.WriteStartObject(); writer.WriteString("realmId", request.RealmId.ToString("D"));
            writer.WriteString("definitionsVersion", profile.DefinitionsVersion); writer.WriteString("hash", profile.Hash); writer.WriteEndObject();
        });
        var archive = Json(writer =>
        {
            writer.WriteStartObject(); writer.WriteString("kind", ResolverDefinitionOutcomes.Operation); writer.WriteString("realmId", request.RealmId.ToString("D"));
            writer.WriteString("configurationRevisionId", request.ConfigurationRevisionId.ToString("D")); writer.WriteString("documentHash", request.DocumentHash);
            writer.WriteString("publisherRef", request.PublisherRef); writer.WriteString("artifactId", approved.ArtifactId); writer.WriteString("artifactProfile", approved.ArtifactProfile);
            writer.WriteString("artifactHash", approved.ArtifactHash); writer.WriteNumber("verifiedLength", approved.VerifiedLength);
            writer.WriteString("definitionsVersion", profile.DefinitionsVersion); writer.WriteString("realmKind", approved.RealmKind);
            writer.WriteString("profileHash", profile.Hash); writer.WriteEndObject();
        });
        var created = Math.Max(1, nowMicros);
        var commit = new ModuleCommit(request.CommandId, null, request.PublisherRef, ResolverDefinitionOutcomes.Operation, requestHash, payload, null,
            created, checked(created + 604800000000), [], 1, archive);
        return plans.WriteAsync(new("entitlement.resolver-definition-publish", request.RealmId.ToString("D"),
        [
            [T(request.CommandId.ToString("D")), T(request.RealmId.ToString("D")), T(profile.DefinitionsVersion), B(hash), T(canonical), T(approved.ArtifactId), B(artifactHash), I(approved.VerifiedLength), I(realmKind)],
            [T(request.RealmId.ToString("D")), T(profile.DefinitionsVersion), B(hash), T(canonical), T(approved.ArtifactId), B(artifactHash), I(approved.VerifiedLength),
                T(approved.ConfigurationRevisionId.ToString("D")), B(Convert.FromHexString(approved.DocumentHash)), I(realmKind), T(request.PublisherRef), I(created)],
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
