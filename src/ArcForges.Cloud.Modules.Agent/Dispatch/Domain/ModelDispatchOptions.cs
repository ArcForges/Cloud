// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Agent.Dispatch.Domain;

/// <summary>One admitted model and the tariff snapshot it is priced under. The production catalogue is provided by POL.08 through AIR.00.</summary>
public sealed record AdmittedModel(string ModelId, string TariffSnapshotId);

/// <summary>
/// The dispatch configuration of the Agent module. Every value is a C# value checked against the Design ceiling; a value outside its range
/// is refused when the options are built, so nothing is dispatched under an unbounded setting (HAR.40 validation b and c).
/// </summary>
public sealed record ModelDispatchOptions
{
    /// <summary>The hard ceiling of any byte cap (1 MiB), the same value the Worker enforces.</summary>
    public const int HardByteCap = 1_048_576;

    /// <summary>The Design output cap (architecture 09 line 360).</summary>
    public const int MaxOutputTokens = 4096;

    /// <summary>The Design tool count cap (architecture 09 line 360).</summary>
    public const int MaxToolCount = 32;

    /// <summary>The Design loop deadline (contracts 05 line 88): no model deadline may exceed it.</summary>
    public const int MaxDeadlineSeconds = 120;

    /// <summary>The most admitted models one call may name, the same bound the Worker enforces.</summary>
    public const int MaxAdmittedModels = 16;

    private ModelDispatchOptions(Uri baseUrl, IReadOnlyList<AdmittedModel> admitted, int maxBodyBytes, int maxResponseBytes, int rateCapacity, int refillPerSecond)
    {
        BaseUrl = baseUrl;
        Admitted = admitted;
        MaxBodyBytes = maxBodyBytes;
        MaxResponseBytes = maxResponseBytes;
        RateCapacity = rateCapacity;
        RefillPerSecond = refillPerSecond;
    }

    /// <summary>The ai.internal base address. It is exactly the http scheme, the ai.internal host and the root path.</summary>
    public Uri BaseUrl { get; }

    /// <summary>The admitted models, each with the one tariff snapshot it is priced under. Nothing else is dispatched.</summary>
    public IReadOnlyList<AdmittedModel> Admitted { get; }

    /// <summary>The request body cap, C#-supplied to the Worker and checked before dispatch.</summary>
    public int MaxBodyBytes { get; }

    /// <summary>The response cap, C#-supplied to the Worker and checked after the answer.</summary>
    public int MaxResponseBytes { get; }

    /// <summary>The per-model token bucket capacity: the calls one model may make in a burst.</summary>
    public int RateCapacity { get; }

    /// <summary>The per-model token bucket refill, in whole tokens per second.</summary>
    public int RefillPerSecond { get; }

    /// <summary>Builds the options. Refuses any host other than ai.internal, a duplicate or empty admitted set, and any cap or rate out of range.</summary>
    public static ModelDispatchOptions Create(Uri baseUrl, IEnumerable<AdmittedModel> admitted, int maxBodyBytes, int maxResponseBytes, int rateCapacity, int refillPerSecond)
    {
        ArgumentNullException.ThrowIfNull(baseUrl);
        ArgumentNullException.ThrowIfNull(admitted);
        if (baseUrl.Scheme != Uri.UriSchemeHttp || baseUrl.Host != "ai.internal" || baseUrl.Port != 80 || baseUrl.AbsolutePath != "/"
            || baseUrl.UserInfo.Length != 0 || baseUrl.Query.Length != 0 || baseUrl.Fragment.Length != 0)
            throw new ArgumentException("The model dispatch base address is exactly http://ai.internal/.", nameof(baseUrl));
        var models = admitted.ToList();
        if (models.Count is < 1 or > MaxAdmittedModels) throw new ArgumentException("An admitted set has one to sixteen models.", nameof(admitted));
        if (models.Select(model => model.ModelId).Distinct(StringComparer.Ordinal).Count() != models.Count)
            throw new ArgumentException("A model is admitted once.", nameof(admitted));
        foreach (var model in models)
        {
            if (!IsToken(model.ModelId) || !IsToken(model.TariffSnapshotId))
                throw new ArgumentException("A model and its tariff snapshot are bounded tokens.", nameof(admitted));
        }

        if (maxBodyBytes is < 1 or > HardByteCap) throw new ArgumentOutOfRangeException(nameof(maxBodyBytes));
        if (maxResponseBytes is < 1 or > HardByteCap) throw new ArgumentOutOfRangeException(nameof(maxResponseBytes));
        if (rateCapacity is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(rateCapacity));
        if (refillPerSecond is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(refillPerSecond));
        return new ModelDispatchOptions(new Uri("http://ai.internal/"), models.AsReadOnly(), maxBodyBytes, maxResponseBytes, rateCapacity, refillPerSecond);
    }

    internal static bool IsToken(string value) =>
        value.Length is >= 1 and <= 128
        && value.All(character => character is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '@' or '/' or '.' or '_' or ':' or '-');
}
