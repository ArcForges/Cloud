// SPDX-License-Identifier: AGPL-3.0-only
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests.AiHarness;

/// <summary>The SPDX expression suite (architecture.test.ts, HAR.40 validation (d)), with SPDX operator precedence and lower-case operators.</summary>
public sealed class SpdxExpressionTests
{
    private static readonly IReadOnlySet<string> Allowed = new HashSet<string>(StringComparer.Ordinal) { "MIT", "Apache-2.0", "BSD-3-Clause" };

    [Fact]
    public void RequiresOneAlternativeOfOrAndEveryTermOfAnd()
    {
        Assert.True(SpdxExpression.Allowed("MIT OR GPL-3.0-only", Allowed));
        Assert.True(SpdxExpression.Allowed("(Apache-2.0 AND BSD-3-Clause)", Allowed));
        Assert.False(SpdxExpression.Allowed("MIT AND GPL-3.0-only", Allowed));
        Assert.False(SpdxExpression.Allowed("GPL-3.0-only", Allowed));
    }

    [Fact]
    public void RefusesEmptyMalformedAndWithExceptionExpressions()
    {
        Assert.False(SpdxExpression.Allowed(null, Allowed));
        Assert.False(SpdxExpression.Allowed(string.Empty, Allowed));
        Assert.False(SpdxExpression.Allowed("(MIT", Allowed));
        Assert.False(SpdxExpression.Allowed("MIT OR", Allowed));
        Assert.False(SpdxExpression.Allowed("MIT WITH Classpath-exception-2.0", Allowed));
    }

    [Fact]
    public void BindsAndTighterThanOrAsTheSpdxSpecificationDoes()
    {
        // (GPL AND MIT) OR Apache: allowed. If OR bound tighter, GPL AND (MIT OR Apache) would be refused.
        Assert.True(SpdxExpression.Allowed("GPL-3.0-only AND MIT OR Apache-2.0", Allowed));
        Assert.False(SpdxExpression.Allowed("GPL-3.0-only AND (MIT OR Apache-2.0)", Allowed));
    }

    [Fact]
    public void OperatorsAreUpperCaseAndUnknownCharactersAreRefused()
    {
        Assert.False(SpdxExpression.Allowed("MIT or Apache-2.0", Allowed));
        Assert.False(SpdxExpression.Allowed("MIT!", Allowed));
        Assert.False(SpdxExpression.Allowed("MIT Apache-2.0", Allowed));
    }
}
