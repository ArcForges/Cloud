// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Generation;

public static class Program
{
    public static int Main(string[] args) => args.Length == 1 && args[0] is "generate" or "check" ? 0 : 2;
}
