// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;
using ArcForges.Cloud.Modules.Commerce.Adapters;
using Xunit;

namespace ArcForges.Cloud.Tests.Commerce.Adapter;

public sealed partial class ProviderContainmentTests
{
    [GeneratedRegex("Paddle|(?:pri|txn|sub|ctm|adj|evt|txnitm)_[a-z0-9]{26}|\"(?:custom_data|scheduled_change|method_details|payment_method_id)\"", RegexOptions.CultureInvariant)]
    private static partial Regex SupplierShape();

    [Fact]
    public void ActualProductionProviderFormatsRemainInsideAdaptersAndNegativeFixtureIsDetected()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "Cloud.slnx"))) root = root.Parent;
        Assert.NotNull(root);
        var problems = new List<string>();
        foreach (var folder in new[] { "src", "worker" })
        {
            foreach (var file in Directory.EnumerateFiles(Path.Combine(root.FullName, folder), "*", SearchOption.AllDirectories)
                .Where(f => Path.GetExtension(f) is ".cs" or ".ts"))
            {
                var relative = Path.GetRelativePath(root.FullName, file).Replace('\\', '/');
                if (relative.Contains("/obj/", StringComparison.Ordinal) || relative.Contains("/bin/", StringComparison.Ordinal)
                    || relative.StartsWith("src/ArcForges.Cloud.Modules.Commerce/Adapters/", StringComparison.Ordinal)
                    || relative.StartsWith("worker/commerce-provider/", StringComparison.Ordinal)) continue;
                if (SupplierShape().IsMatch(File.ReadAllText(file))) problems.Add(relative);
            }
        }
        Assert.Empty(problems);
        Assert.Matches(SupplierShape(), "var id = \"pri_01grnn4zta5a1mf02jjze7y2ys\";");
        Assert.Matches(SupplierShape(), "var header = \"Paddle-Signature\";");
        Assert.Matches(SupplierShape(), "var payload = \"custom_data\";");
        Assert.DoesNotMatch(SupplierShape(), "ProviderReference reference; PurchaseMetadata metadata;");
        Assert.DoesNotContain(typeof(IBillingProvider).Assembly.GetExportedTypes(), t => t.Name.Contains("Paddle", StringComparison.Ordinal));
    }
}
