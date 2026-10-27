// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using Npgsql;

namespace ArcForges.Cloud;

/// <summary>The Hello source is stateless locally, or a bounded read-only PostgreSQL query when explicitly enabled.</summary>
public interface IHelloGreeting
{
    Task<string> GetAsync(string name, CancellationToken cancellation);
}

internal sealed class StatelessHelloGreeting : IHelloGreeting
{
    public Task<string> GetAsync(string name, CancellationToken cancellation) => Task.FromResult($"Hello, {name}!");
}

internal sealed class NeonHelloGreeting : IHelloGreeting, IDisposable
{
    private readonly NpgsqlDataSource source;

    public NeonHelloGreeting(NpgsqlConnectionStringBuilder settings) =>
        source = new NpgsqlSlimDataSourceBuilder(settings.ConnectionString).Build();

    public async Task<string> GetAsync(string name, CancellationToken cancellation)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(TimeSpan.FromSeconds(15));
        await using var connection = await source.OpenConnectionAsync(deadline.Token);
        await using var transaction = await connection.BeginTransactionAsync(deadline.Token);
        await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY", connection, transaction))
            await readOnly.ExecuteNonQueryAsync(deadline.Token);
        // bytea preserves every valid protobuf string, including NUL, which PostgreSQL text cannot store.
        await using var command = new NpgsqlCommand("SELECT convert_to('Hello, ', 'UTF8') || $1::bytea || convert_to('!', 'UTF8')", connection, transaction);
        command.Parameters.Add(new NpgsqlParameter<byte[]> { TypedValue = Encoding.UTF8.GetBytes(name) });
        var greeting = await command.ExecuteScalarAsync(deadline.Token) as byte[]
            ?? throw new InvalidOperationException("The Hello query returned no greeting.");
        await transaction.RollbackAsync(deadline.Token);
        return Encoding.UTF8.GetString(greeting);
    }

    public void Dispose() => source.Dispose();
}

internal static class NeonHelloOptions
{
    internal const string EnabledVariable = "ARCFORGES_NEON_HELLO";
    internal const string UrlVariable = "NEON_DATABASE_URL";

    internal static NpgsqlConnectionStringBuilder? FromEnvironment(Func<string, string?> environment)
    {
        var enabled = environment(EnabledVariable);
        if (string.IsNullOrEmpty(enabled) || enabled == "disabled") return null;
        if (enabled != "enabled") throw InvalidConfiguration();
        try { return Parse(environment(UrlVariable)); }
        catch (Exception error) when (error is ArgumentException or FormatException)
        {
            // Never preserve URI/parser exceptions, which can contain credentials.
            throw InvalidConfiguration();
        }
    }

    internal static NpgsqlConnectionStringBuilder Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 8192 ||
            !Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("postgresql" or "postgres") || uri.Fragment.Length != 0 ||
            !uri.IdnHost.EndsWith(".neon.tech", StringComparison.OrdinalIgnoreCase) ||
            !uri.IdnHost.StartsWith("ep-", StringComparison.OrdinalIgnoreCase) ||
            !uri.IdnHost.Contains("-pooler.", StringComparison.OrdinalIgnoreCase) ||
            (uri.Port != -1 && uri.Port != 5432))
            throw InvalidConfiguration();

        var credentials = uri.UserInfo.Split(':', 2);
        if (credentials.Length != 2) throw InvalidConfiguration();
        var user = Uri.UnescapeDataString(credentials[0]);
        var password = Uri.UnescapeDataString(credentials[1]);
        var database = Uri.UnescapeDataString(uri.AbsolutePath.TrimStart('/'));
        if (user.Length == 0 || password.Length == 0 || password.Contains('*') ||
            database.Length == 0 || database.Contains('/') ||
            user.Contains('\0') || password.Contains('\0') || database.Contains('\0'))
            throw InvalidConfiguration();

        var query = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var part in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var pair = part.Split('=', 2);
            if (pair.Length != 2 || !query.TryAdd(Uri.UnescapeDataString(pair[0]), Uri.UnescapeDataString(pair[1])))
                throw InvalidConfiguration();
        }
        if (query.Keys.Any(key => key is not ("sslmode" or "channel_binding" or "connect_timeout")) ||
            !query.TryGetValue("sslmode", out var ssl) || ssl is not ("require" or "verify-full") ||
            (query.TryGetValue("channel_binding", out var binding) && binding != "require"))
            throw InvalidConfiguration();

        return new NpgsqlConnectionStringBuilder
        {
            Host = uri.IdnHost,
            Port = 5432,
            Database = database,
            Username = user,
            Password = password,
            SslMode = SslMode.VerifyFull,
            ChannelBinding = ChannelBinding.Require,
            GssEncryptionMode = GssEncryptionMode.Disable,
            MinPoolSize = 0,
            MaxPoolSize = 2,
            ConnectionIdleLifetime = 30,
            ConnectionPruningInterval = 10,
            Timeout = 10,
            CommandTimeout = 5,
            CancellationTimeout = 2000,
            IncludeErrorDetail = false,
            LogParameters = false,
            PersistSecurityInfo = false,
            ApplicationName = "arcforges-deployed-hello",
        };
    }

    private static InvalidOperationException InvalidConfiguration() =>
        new("Neon Hello requires a complete pooled NEON_DATABASE_URL with TLS and channel binding.");
}
