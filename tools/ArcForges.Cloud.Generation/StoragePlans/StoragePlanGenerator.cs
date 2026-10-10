// SPDX-License-Identifier: AGPL-3.0-only
// The storage-plan generator entry point (CLOUD.84 U7, D3): reads the reviewed plan files, renders the three outputs and either checks
// the committed files against them or writes them. This C# generator is the only generator of the three outputs (CLOUD.84 S40(1)): the Node
// generator eng/verification/storage-plans.ts was retired in U8 and keeps only test-support helpers. `npm run check:plans` runs this check.
using System.Text;

namespace ArcForges.Cloud.Tools.Generation.StoragePlans;

public static class StoragePlanGenerator
{
    /// <summary>Renders the outputs of the repository's plans and returns the paths whose committed content differs.</summary>
    public static IReadOnlyList<string> Sync(string root, bool write)
    {
        var manifest = StoragePlanParser.BuildManifest(root);
        var stale = new List<string>();
        foreach (var (path, text) in StoragePlanOutputs.Render(manifest))
        {
            var full = Path.Combine(root, path);
            var current = File.Exists(full) ? File.ReadAllText(full).Replace("\r\n", "\n", StringComparison.Ordinal) : string.Empty;
            if (current == text) continue;
            stale.Add(path);
            if (!write) continue;
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllText(full, text, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        }

        return stale;
    }
}
