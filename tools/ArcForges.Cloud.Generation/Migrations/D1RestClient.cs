// SPDX-License-Identifier: AGPL-3.0-only
// The Cloudflare D1 REST transport of the migration engine (CLOUD.84 U9, S41(1)): POST /accounts/{account}/d1/database/{database}/query
// with a `batch` of statements, and the database lookup by exact name. It replaces the TypeScript RestMigrationClient one for one. The
// bearer secret is read from the environment by the caller, sent only in the authorization header, and never printed: every error
// text names the kind of failure and the database's own message, never a header or a URL with a credential.
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ArcForges.Cloud.Storage.D1.MigrationRunner;

namespace ArcForges.Cloud.Tools.Generation.Migrations;

public sealed class D1RestClient : IMigrationClient
{
    public const string DefaultBaseUrl = "https://api.cloudflare.com/client/v4";

    private readonly HttpClient http;
    private readonly string accountId;
    private readonly string databaseId;
    private readonly string apiToken;
    private readonly string baseUrl;

    public D1RestClient(string accountId, string databaseId, string apiToken, HttpMessageHandler? handler = null, string? baseUrl = null)
    {
        this.accountId = accountId;
        this.databaseId = databaseId;
        this.apiToken = apiToken;
        this.baseUrl = baseUrl ?? DefaultBaseUrl;
        http = handler is null ? new HttpClient() : new HttpClient(handler, disposeHandler: false);
        http.Timeout = TimeSpan.FromSeconds(60);
    }

    /// <summary>Posts one batch as one request. A transport failure is reported as an unknown outcome: the engine re-reads the receipt.</summary>
    public async Task<IReadOnlyList<BatchResult>> BatchAsync(IReadOnlyList<MigrationStatement> statements, CancellationToken cancellationToken)
    {
        var url = $"{baseUrl}/accounts/{Uri.EscapeDataString(accountId)}/d1/database/{Uri.EscapeDataString(databaseId)}/query";
        var batch = new JsonArray();
        foreach (var statement in statements)
        {
            var parameters = new JsonArray();
            foreach (var value in statement.Params) parameters.Add(ToJson(value));
            batch.Add((JsonNode)new JsonObject { ["sql"] = statement.Sql, ["params"] = parameters });
        }

        var body = new JsonObject { ["batch"] = batch }.ToJsonString();
        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiToken);
        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (error is HttpRequestException or TaskCanceledException or OperationCanceledException)
        {
            throw new MigrationClientException($"D1 request failed (outcome unknown): {error.GetType().Name}");
        }

        using (response)
        {
            var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            JsonDocument document;
            try
            {
                document = JsonDocument.Parse(text);
            }
            catch (JsonException)
            {
                throw new MigrationClientException($"D1 returned HTTP {(int)response.StatusCode} without a JSON body");
            }

            using (document)
            {
                var root = document.RootElement;
                var success = !(root.TryGetProperty("success", out var flag) && flag.ValueKind == JsonValueKind.False);
                if (!response.IsSuccessStatusCode || !success)
                {
                    var messages = root.TryGetProperty("errors", out var errors) && errors.ValueKind == JsonValueKind.Array
                        ? errors.EnumerateArray().Select(entry => entry.TryGetProperty("message", out var message) && message.ValueKind == JsonValueKind.String ? message.GetString() ?? "error" : "error").ToList()
                        : new List<string>();
                    throw new MigrationClientException($"D1 refused the batch (HTTP {(int)response.StatusCode}): {string.Join("; ", messages)}");
                }

                var results = root.TryGetProperty("result", out var resultArray) && resultArray.ValueKind == JsonValueKind.Array
                    ? resultArray.EnumerateArray().ToList()
                    : new List<JsonElement>();
                if (results.Count != statements.Count)
                    throw new MigrationClientException("D1 returned a different number of results than statements");
                return results.Select(Result).ToList();
            }
        }
    }

    /// <summary>The database id of an exact-name lookup. Nothing is created here.</summary>
    public async Task<(int Status, IReadOnlyList<(string Name, string? Uuid)>? Results)> LookupDatabasesAsync(string name, CancellationToken cancellationToken)
    {
        var url = $"{baseUrl}/accounts/{Uri.EscapeDataString(accountId)}/d1/database?name={Uri.EscapeDataString(name)}&per_page=100";
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiToken);
        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (error is HttpRequestException or TaskCanceledException or OperationCanceledException)
        {
            throw new InvalidOperationException("the D1 database lookup could not be completed");
        }

        using (response)
        {
            var status = (int)response.StatusCode;
            var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            JsonDocument document;
            try
            {
                document = JsonDocument.Parse(text);
            }
            catch (JsonException)
            {
                return (status, null);
            }

            using (document)
            {
                var root = document.RootElement;
                var success = !(root.TryGetProperty("success", out var failed) && failed.ValueKind == JsonValueKind.False);
                if (!response.IsSuccessStatusCode || !success || !root.TryGetProperty("result", out var result) || result.ValueKind != JsonValueKind.Array)
                    return (status, null);
                var found = result.EnumerateArray().Select(entry => (
                    Name: entry.TryGetProperty("name", out var nameValue) && nameValue.ValueKind == JsonValueKind.String ? nameValue.GetString() ?? string.Empty : string.Empty,
                    Uuid: entry.TryGetProperty("uuid", out var uuidValue) && uuidValue.ValueKind == JsonValueKind.String ? uuidValue.GetString() : null)).ToList();
                return (status, found);
            }
        }
    }

    private static JsonNode? ToJson(object? value) => value switch
    {
        null => null,
        string text => JsonValue.Create(text),
        long number => JsonValue.Create(number),
        _ => throw new InvalidOperationException("unsupported bind type"),
    };

    private static BatchResult Result(JsonElement entry)
    {
        var changes = entry.TryGetProperty("meta", out var meta) && meta.TryGetProperty("changes", out var count) && count.ValueKind == JsonValueKind.Number
            ? count.GetInt64()
            : 0;
        var rows = new List<IReadOnlyList<string?>>();
        if (entry.TryGetProperty("results", out var results) && results.ValueKind == JsonValueKind.Array)
        {
            foreach (var row in results.EnumerateArray())
            {
                rows.Add(row.EnumerateObject().Select(cell => Cell(cell.Value)).ToList());
            }
        }

        return new BatchResult(changes, rows);
    }

    /// <summary>A cell as text: a string as it is, a number as its decimal text, null as null.</summary>
    private static string? Cell(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Null => null,
        JsonValueKind.String => value.GetString(),
        JsonValueKind.Number => value.GetRawText(),
        JsonValueKind.True => "1",
        JsonValueKind.False => "0",
        _ => value.GetRawText(),
    };
}
