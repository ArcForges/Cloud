// SPDX-License-Identifier: AGPL-3.0-only
// Independent PE metadata reader. It never loads or executes a candidate assembly.
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text.Json;

try
{
    if (args.Length != 2 || !Path.IsPathFullyQualified(args[0]) || !Path.IsPathFullyQualified(args[1]))
        throw new ArgumentException("Expected an absolute tool directory and expected identity file.");
    using var expectedDocument = JsonDocument.Parse(File.ReadAllBytes(args[1]));
    var expected = expectedDocument.RootElement;
    var artifact = expected.GetProperty("artifact");
    var build = expected.GetProperty("build");
    var version = artifact.GetProperty("version").GetString() ?? throw new InvalidDataException();
    var source = build.GetProperty("sourceCommit").GetString() ?? throw new InvalidDataException();
    var identity = new Dictionary<string, string>
    {
        ["ArcForges.SourceCommit"] = source,
        ["ArcForges.Dirty"] = "false",
        ["ArcForges.BuildKind"] = "ci",
        ["ArcForges.BuildId"] = build.GetProperty("buildId").GetString() ?? throw new InvalidDataException(),
        ["ArcForges.PipelineRun"] = build.GetProperty("pipelineRun").GetString() ?? throw new InvalidDataException(),
        ["ArcForges.SourceDateEpoch"] = build.GetProperty("sourceDateEpoch").GetInt64().ToString(System.Globalization.CultureInfo.InvariantCulture),
        ["RepositoryUrl"] = "https://github.com/ArcForges/Cloud",
    };
    var expectedFiles = expected.GetProperty("assemblies").EnumerateArray().Select(x => x.GetString() ?? throw new InvalidDataException()).Order(StringComparer.Ordinal).ToArray();
    var actualFiles = Directory.GetFiles(args[0], "ArcForges.Cloud*.dll", SearchOption.TopDirectoryOnly).Select(Path.GetFileName).Order(StringComparer.Ordinal).ToArray();
    if (expectedFiles.Length == 0 || !actualFiles.SequenceEqual(expectedFiles)) throw new InvalidDataException("First-party assembly set differs.");
    var results = new SortedDictionary<string, object>(StringComparer.Ordinal);
    foreach (var name in expectedFiles)
    {
        if (name != Path.GetFileName(name)) throw new InvalidDataException("Unsafe assembly name.");
        var file = Path.Combine(args[0], name);
        if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Linked assembly.");
        using var stream = File.OpenRead(file);
        using var pe = new PEReader(stream, PEStreamOptions.LeaveOpen);
        var meta = pe.GetMetadataReader();
        var attrs = new Dictionary<string, string>(StringComparer.Ordinal);
        var info = "";
        foreach (var handle in meta.GetAssemblyDefinition().GetCustomAttributes())
        {
            var attr = meta.GetCustomAttribute(handle);
            if (attr.Constructor.Kind != HandleKind.MemberReference) continue;
            var member = meta.GetMemberReference((MemberReferenceHandle)attr.Constructor);
            if (member.Parent.Kind != HandleKind.TypeReference) continue;
            var type = meta.GetTypeReference((TypeReferenceHandle)member.Parent);
            var fullName = meta.GetString(type.Namespace) + "." + meta.GetString(type.Name);
            if (fullName is not ("System.Reflection.AssemblyMetadataAttribute" or "System.Reflection.AssemblyInformationalVersionAttribute")) continue;
            var reader = meta.GetBlobReader(attr.Value);
            if (reader.ReadUInt16() != 1) throw new InvalidDataException("Invalid assembly metadata.");
            var first = reader.ReadSerializedString() ?? throw new InvalidDataException("Missing assembly metadata.");
            if (fullName == "System.Reflection.AssemblyMetadataAttribute") attrs.Add(first, reader.ReadSerializedString() ?? throw new InvalidDataException());
            else if (info.Length == 0) info = first;
            else throw new InvalidDataException("Duplicate assembly version.");
        }
        if (info != version + "+" + source || identity.Any(pair => !attrs.TryGetValue(pair.Key, out var value) || value != pair.Value))
            throw new InvalidDataException("Assembly producer/source/version differs.");
        stream.Position = 0;
        results.Add(name, new { sha256 = Convert.ToHexStringLower(SHA256.HashData(stream)), informationalVersion = info, metadata = identity });
    }
    Console.WriteLine(JsonSerializer.Serialize(results));
}
catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException or ArgumentException or InvalidOperationException or JsonException or BadImageFormatException or FormatException or OverflowException or NotSupportedException)
{
    Console.Error.WriteLine("Security bridge assembly verification failed: " + error.Message);
    return 1;
}
return 0;
