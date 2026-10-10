// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace ArcForges.Cloud.Tests.Reduction;

/// <summary>
/// The SQLite oracle of the storage-plan tests (CLOUD.84 U7, D8): node:sqlite, the engine the TypeScript tests used, prepares each statement
/// against a schema. It runs as a test-only child process, so no SQLite package is added to the solution. Each verdict is true when SQLite
/// accepts the statement.
/// </summary>
internal static class SqliteOracle
{
    private const string Script =
        "import { DatabaseSync } from 'node:sqlite'; let text = ''; process.stdin.setEncoding('utf8'); " +
        "for await (const chunk of process.stdin) text += chunk; const input = JSON.parse(text); " +
        "const database = new DatabaseSync(':memory:'); database.exec(input.schema); " +
        "const verdicts = input.statements.map((sql) => { try { database.prepare(sql); return true; } catch { return false; } }); " +
        "process.stdout.write(JSON.stringify(verdicts));";

    public static bool[] Accepts(string schema, IReadOnlyList<string> statements)
    {
        var info = new ProcessStartInfo("node")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardInputEncoding = new UTF8Encoding(false),
            StandardOutputEncoding = new UTF8Encoding(false),
            StandardErrorEncoding = new UTF8Encoding(false),
        };
        info.ArgumentList.Add("--input-type=module");
        info.ArgumentList.Add("-e");
        info.ArgumentList.Add(Script);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("node could not be started for the SQLite oracle.");
        var errors = process.StandardError.ReadToEndAsync();
        process.StandardInput.Write(JsonSerializer.Serialize(new { schema, statements }));
        process.StandardInput.Close();
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0) throw new InvalidOperationException($"The SQLite oracle failed: {errors.Result}");
        return JsonSerializer.Deserialize<bool[]>(output) ?? throw new InvalidOperationException("The SQLite oracle returned no verdicts.");
    }
}
