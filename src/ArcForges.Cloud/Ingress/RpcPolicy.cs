// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;

namespace ArcForges.Cloud.Ingress;

internal enum RpcKind
{
    /// <summary>One request message, one response message and the status trailer.</summary>
    Unary,

    /// <summary>One request message and a stream of response frames ended by the status trailer. There is no client or bidirectional stream.</summary>
    ServerStream,
}

internal enum RpcAuthentication
{
    /// <summary>No credential is read, validated or forwarded; the caller is anonymous.</summary>
    Anonymous,

    /// <summary>A native bearer or an origin-bound browser cookie session must validate before any business code runs.</summary>
    Session,
}

internal enum RpcScope
{
    /// <summary>Account or anonymous scope: the envelope is not interpreted.</summary>
    None,

    /// <summary>The envelope must name a workspace the authenticated caller currently owns, in the caller's recovery generation.</summary>
    Workspace,
}

/// <summary>
/// The declared ingress contract of one public gRPC-Web method. A method without a policy is refused, so a registered service can
/// never become reachable by omission. <see cref="MaxRequestBytes"/> bounds the whole request body including the five-byte frame header.
/// </summary>
internal sealed partial record RpcPolicy(string FullName, RpcKind Kind, RpcAuthentication Authentication, RpcScope Scope, int MaxRequestBytes)
{
    public const int AbsoluteMaxRequestBytes = 262_144;

    /// <summary>
    /// The request message starts with a <c>RequestMeta</c> (field 1, wire registry 04) whose correlation id the pipeline reads and validates.
    /// A workspace-scoped method always does; an account-scoped method whose request carries the meta opts in. A method whose field 1 means
    /// something else (the Hello name) never does, so its body is not interpreted.
    /// </summary>
    public bool CarriesRequestMeta { get; init; }

    public bool ReadsRequestMeta => Scope == RpcScope.Workspace || CarriesRequestMeta;

    public static RpcPolicy Unary(string fullName, RpcAuthentication authentication, RpcScope scope, int maxRequestBytes = 4096, bool carriesRequestMeta = false) =>
        Create(fullName, RpcKind.Unary, authentication, scope, maxRequestBytes, carriesRequestMeta);

    public static RpcPolicy ServerStream(string fullName, RpcAuthentication authentication, RpcScope scope, int maxRequestBytes = 4096, bool carriesRequestMeta = false) =>
        Create(fullName, RpcKind.ServerStream, authentication, scope, maxRequestBytes, carriesRequestMeta);

    /// <summary><c>/package.Service/Method</c>: a lowercase dotted proto package, a service and a method in PascalCase.</summary>
    public static bool IsValidName(string path) => NamePattern().IsMatch(path);

    private static RpcPolicy Create(string fullName, RpcKind kind, RpcAuthentication authentication, RpcScope scope, int maxRequestBytes, bool carriesRequestMeta)
    {
        if (!IsValidName(fullName)) throw new ArgumentException("Invalid RPC name.", nameof(fullName));
        if (maxRequestBytes is < 1 or > AbsoluteMaxRequestBytes) throw new ArgumentOutOfRangeException(nameof(maxRequestBytes));
        if (authentication == RpcAuthentication.Anonymous && scope != RpcScope.None)
            throw new ArgumentException("An anonymous method has no owner scope.", nameof(scope));
        return new RpcPolicy(fullName, kind, authentication, scope, maxRequestBytes) { CarriesRequestMeta = carriesRequestMeta };
    }

    [GeneratedRegex(@"^/[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*\.[A-Z][A-Za-z0-9]*/[A-Z][A-Za-z0-9]*\z")]
    private static partial Regex NamePattern();
}

/// <summary>The deny-by-default method table: exact path to policy, duplicates refused at composition.</summary>
internal sealed class RpcPolicyRegistry
{
    private readonly Dictionary<string, RpcPolicy> byName;

    private RpcPolicyRegistry(Dictionary<string, RpcPolicy> byName) => this.byName = byName;

    public IReadOnlyCollection<RpcPolicy> All => byName.Values;

    public static RpcPolicyRegistry Create(IEnumerable<RpcPolicy> policies)
    {
        var table = new Dictionary<string, RpcPolicy>(StringComparer.Ordinal);
        foreach (var policy in policies)
        {
            if (!table.TryAdd(policy.FullName, policy)) throw new InvalidOperationException("Duplicate RPC policy: " + policy.FullName);
        }

        return new RpcPolicyRegistry(table);
    }

    public bool TryGet(string path, out RpcPolicy policy) => byName.TryGetValue(path, out policy!);
}

/// <summary>
/// Everything the host serves on the public listener: the RPC policy table and the few plain HTTP routes (health, the browser session
/// routes, the signed internal routes) that have their own checks. A path that is in neither is refused by the pipeline before routing,
/// so deny-by-default does not depend on how a path happens to look.
/// </summary>
internal sealed class IngressRoutes(RpcPolicyRegistry registry, IEnumerable<string> plainPaths, IEnumerable<string> plainPrefixes)
{
    private readonly HashSet<string> plain = new(plainPaths, StringComparer.Ordinal);
    private readonly string[] prefixes = [.. plainPrefixes];

    public RpcPolicyRegistry Registry { get; } = registry;

    /// <summary>An exact plain route, or a path strictly under a plain prefix (case-sensitive).</summary>
    public bool IsPlain(string path) =>
        plain.Contains(path) || prefixes.Any(prefix => path.Length > prefix.Length && path.StartsWith(prefix, StringComparison.Ordinal));
}
