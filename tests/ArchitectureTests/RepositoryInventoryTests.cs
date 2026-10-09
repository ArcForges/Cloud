// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Build.Policy.Architecture;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>Layering inventory, licence boundary, exception list, naming evidence and hosted gate order fixtures.</summary>
public sealed class RepositoryInventoryTests
{
    private static readonly DateOnly Today = new(2026, 10, 4);
    private static readonly string[] Files = [.. CloudRepository.Classifications.Select(project => project.Path)];

    private static string Solution(params string[] paths) =>
        "<Solution>" + string.Concat(paths.Select(path => $"<Project Path=\"{path}\" />")) + "</Solution>";

    [Fact]
    public void SolutionProjectFilesAndRolesDescribeTheSameProjects()
    {
        Assert.Empty(RepositoryInventoryPolicy.CheckProjects(Solution(Files), Files, CloudRepository.Classifications));
    }

    [Fact]
    public void ADriftedOrUnclassifiedProjectIsRejected()
    {
        Assert.NotEmpty(RepositoryInventoryPolicy.CheckProjects(Solution(Files[..^1]), Files, CloudRepository.Classifications));
        Assert.NotEmpty(RepositoryInventoryPolicy.CheckProjects(Solution([.. Files, "src/New/New.csproj"]), Files, CloudRepository.Classifications));
        Assert.NotEmpty(RepositoryInventoryPolicy.CheckProjects(Solution(Files), [.. Files, "src/New/New.csproj"], CloudRepository.Classifications));
        Assert.NotEmpty(RepositoryInventoryPolicy.CheckProjects(Solution(Files), Files, CloudRepository.Classifications.Take(Files.Length - 1)));
        Assert.NotEmpty(RepositoryInventoryPolicy.CheckProjects(Solution(Files), Files, [.. CloudRepository.Classifications, CloudRepository.Classifications[0]]));
    }

    private static string Inventory(string repository = "Cloud", string spdx = "AGPL-3.0-only", string boundary = "AGPL", params string[] projects) =>
        "{\"repository\":\"" + repository + "\",\"spdxLicense\":\"" + spdx + "\",\"licenceBoundary\":\"" + boundary + "\",\"projects\":["
        + string.Join(',', projects.Select(path => $"{{\"path\":\"{path}\",\"kind\":\"msbuild\"}}").Append("{\"path\":\"package.json\",\"kind\":\"npm\"}")) + "]}";

    private static Dictionary<string, string> Agpl(string omitted = "") => Files.Where(path => path != omitted).ToDictionary(path => path,
        _ => "<Project><PropertyGroup><LicenceBoundary>AGPL</LicenceBoundary><PackageLicenseExpression>AGPL-3.0-only</PackageLicenseExpression></PropertyGroup></Project>");

    private const string NoLicenceProps = "<Project />";

    [Fact]
    public void EveryProjectIsListedAndDeclaredAgpl()
    {
        Assert.Empty(RepositoryInventoryPolicy.CheckLicences(Inventory(projects: Files), Agpl(), NoLicenceProps));
        string inherited = "<Project><PropertyGroup><PackageLicenseExpression>AGPL-3.0-only</PackageLicenseExpression></PropertyGroup></Project>";
        var projects = Files.ToDictionary(path => path, _ => "<Project><PropertyGroup><LicenceBoundary>AGPL</LicenceBoundary></PropertyGroup></Project>");
        Assert.Empty(RepositoryInventoryPolicy.CheckLicences(Inventory(projects: Files), projects, inherited));
    }

    [Fact]
    public void AMissingRowAnApacheProjectOrAnotherRepositoryIsRejected()
    {
        Assert.NotEmpty(RepositoryInventoryPolicy.CheckLicences(Inventory(projects: Files[..3]), Agpl(), NoLicenceProps));
        Assert.NotEmpty(RepositoryInventoryPolicy.CheckLicences(Inventory(projects: Files), Agpl(CloudRepository.Host), NoLicenceProps));
        var apache = Agpl();
        apache[CloudRepository.Host] = "<Project><PropertyGroup><LicenceBoundary>Apache</LicenceBoundary><PackageLicenseExpression>Apache-2.0</PackageLicenseExpression></PropertyGroup></Project>";
        Assert.NotEmpty(RepositoryInventoryPolicy.CheckLicences(Inventory(projects: Files), apache, NoLicenceProps));
        Assert.NotEmpty(RepositoryInventoryPolicy.CheckLicences(Inventory(repository: "Web", projects: Files), Agpl(), NoLicenceProps));
        Assert.NotEmpty(RepositoryInventoryPolicy.CheckLicences(Inventory(spdx: "Apache-2.0", projects: Files), Agpl(), NoLicenceProps));
        Assert.NotEmpty(RepositoryInventoryPolicy.CheckLicences(Inventory(boundary: "Apache", projects: Files), Agpl(), NoLicenceProps));
    }

    private static PolicyException Row(string rule = "AT-06", string path = CloudRepository.ServiceTests, string owner = CloudRepository.Owner,
        string reason = "Bounded migration", DateOnly? expires = null) => new(rule, path, owner, reason, expires ?? new DateOnly(2027, 4, 4));

    [Fact]
    public void AnEmptyInventoryAndOneExactBoundedRowAreAccepted()
    {
        Assert.Empty(RepositoryInventoryPolicy.CheckExceptions([], CloudRepository.Classifications, Today));
        Assert.Empty(RepositoryInventoryPolicy.CheckExceptions([Row()], CloudRepository.Classifications, Today));
    }

    [Theory]
    [InlineData("RP-03", CloudRepository.ServiceTests)]
    [InlineData("RP-02", CloudRepository.Host)]
    [InlineData("BAN-REFLECTION", CloudRepository.Service)]
    [InlineData("BAN-CODEGEN", CloudRepository.Service)]
    [InlineData("RP-07", CloudRepository.Service)]
    [InlineData("AT-99", CloudRepository.Service)]
    [InlineData("AT-06", "src/Other/Other.csproj")]
    [InlineData("AT-06", "*")]
    public void LicenceAotUnknownAndUnboundExceptionsAreRejected(string rule, string path)
    {
        Assert.NotEmpty(RepositoryInventoryPolicy.CheckExceptions([Row(rule, path)], CloudRepository.Classifications, Today));
    }

    [Fact]
    public void UnownedUnexplainedExpiredAndLongLivedExceptionsAreRejected()
    {
        Assert.NotEmpty(RepositoryInventoryPolicy.CheckExceptions([Row(owner: "Other")], CloudRepository.Classifications, Today));
        Assert.NotEmpty(RepositoryInventoryPolicy.CheckExceptions([Row(reason: " ")], CloudRepository.Classifications, Today));
        Assert.NotEmpty(RepositoryInventoryPolicy.CheckExceptions([Row(expires: Today)], CloudRepository.Classifications, Today));
        Assert.NotEmpty(RepositoryInventoryPolicy.CheckExceptions([Row(expires: Today.AddYears(1).AddDays(1))], CloudRepository.Classifications, Today));
    }

    [Fact]
    public void TheExceptionInventoryParserRejectsIncompleteRowsAndWildcardPaths()
    {
        Assert.Empty(CloudRepository.ParseExceptions("[]"));
        var row = Assert.Single(CloudRepository.ParseExceptions("""[{"rule":"AT-06","path":"a.csproj","owner":"Cloud","reason":"x","expires":"2027-01-01"}]"""));
        Assert.Equal(new DateOnly(2027, 1, 1), row.Expires);
        Assert.Throws<InvalidOperationException>(() => CloudRepository.ParseExceptions("{}"));
        Assert.Throws<InvalidOperationException>(() => CloudRepository.ParseExceptions("""[{"rule":"AT-06"}]"""));
        Assert.Throws<FormatException>(() => CloudRepository.ParseExceptions("""[{"rule":"AT-06","path":"a","owner":"Cloud","reason":"x","expires":"soon"}]"""));
    }

    private const string Commit = "0123456789abcdef0123456789abcdef01234567";

    private static string Report(string commit = Commit, string status = "pass", int findings = 0, bool dirty = false, string evidenceClass = "source-policy-scan",
        string repository = "Cloud", string substeps = "\"WP00.00\",\"WP00.01\"", int rows = 1)
    {
        string findingText = string.Join(',', Enumerable.Repeat("{\"rule\":\"RP-01\"}", findings));
        string row = $"{{\"repository\":\"{repository}\",\"commit\":\"{commit}\",\"dirty\":{(dirty ? "true" : "false")},\"status\":\"{status}\",\"findings\":[{findingText}]}}";
        return $"{{\"evidenceClass\":\"{evidenceClass}\",\"substeps\":[{substeps}],\"repositories\":[{string.Join(',', Enumerable.Repeat(row, rows))}]}}";
    }

    [Fact]
    public void ACleanCanonicalNamingScanOfTheExactCommitIsTrustedForBothNamingRules()
    {
        foreach (string rule in new[] { "RP-01", "RP-08" })
        {
            var evidence = CloudRepository.ReadNamingEvidence(Report(), Commit, rule);
            Assert.True(evidence.Passed);
            Assert.Empty(evidence.Findings);
        }
    }

    [Theory]
    [InlineData("stale")]
    [InlineData("dirty")]
    [InlineData("findings")]
    [InlineData("fail")]
    [InlineData("class")]
    [InlineData("substeps")]
    [InlineData("other-repository")]
    [InlineData("two-rows")]
    public void StaleDirtyFailingOrForeignNamingEvidenceIsNotTrusted(string defect)
    {
        string report = defect switch
        {
            "stale" => Report(commit: new string('b', 40)),
            "dirty" => Report(dirty: true),
            "findings" => Report(findings: 1),
            "fail" => Report(status: "fail"),
            "class" => Report(evidenceClass: "other"),
            "substeps" => Report(substeps: "\"WP00.00\""),
            "other-repository" => Report(repository: "Web"),
            _ => Report(rows: 2),
        };
        var evidence = CloudRepository.ReadNamingEvidence(report, Commit, "RP-01");
        Assert.False(evidence.Passed);
        Assert.NotEmpty(evidence.Findings);
    }

    private const string PackageJson = """
        { "scripts": { "check": "npm run check:plans && npm run policy && npm run format:check", "policy": "node tooling/project.ts naming",
          "check:dotnet": "dotnet restore Cloud.slnx --locked-mode && dotnet test --solution Cloud.slnx -c Release --no-build" },
          "devDependencies": { "@arcforges/proto": "1.0.0-ci.287.1" } }
        """;

    private const string Script = "python -I check_naming.py --repository Cloud=${root} artifacts/evidence/naming.json eng/policy/naming-candidate.json NUGET_PACKAGES archiveSha512 nupkg";

    private const string Candidate = """
        { "package": "ArcForges.Contracts.Validation", "ecosystem": "nuget", "version": "1.0.0-ci.205.1",
          "sourceCommit": "696242d16034262ce8b7268e8d157cd0e5bee544", "archiveSha512": "OWvMF30zpN6ms2KlQCtax5P7TACrgK50Vb0drN5zy4iXgk2TZd+5UU+LDGaA2ioowA1EQIZx8ZUyRoayZaHadA==",
          "assets": { "tools/naming/eng/check_naming.py": "7c4cd7041b8b53e1bfb6fc0016befcd50259ffaca512d389456e00d3c26d5eaf" } }
        """;

    private const string Props = """
        <Project><ItemGroup><PackageVersion Include="ArcForges.Contracts.Validation" Version="1.0.0-ci.205.1" /></ItemGroup></Project>
        """;

    private const string ArchitectureProject = """
        <Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="ArcForges.Contracts.Validation" GeneratePathProperty="true" PrivateAssets="all" /></ItemGroup></Project>
        """;

    private const string Lock = """
        { "version": 2, "dependencies": { "net10.0": { "ArcForges.Contracts.Validation": { "type": "Direct", "requested": "[1.0.0-ci.205.1, )", "resolved": "1.0.0-ci.205.1" } } } }
        """;

    [Fact]
    public void TheNamingScanWiringIsAcceptedWhenTheGateScanAndCandidateAgree()
    {
        Assert.Empty(NamingWiring.Check(PackageJson, Script, Candidate, Lock, Props, ArchitectureProject));
    }

    [Theory]
    [InlineData("script")]
    [InlineData("gate")]
    [InlineData("tool")]
    [InlineData("report")]
    [InlineData("candidate-version")]
    [InlineData("candidate-commit")]
    [InlineData("candidate-digest")]
    [InlineData("candidate-archive")]
    [InlineData("central-version")]
    [InlineData("project-reference")]
    [InlineData("lock-entry")]
    [InlineData("lock-direct")]
    public void BrokenNamingScanWiringIsRejected(string defect)
    {
        string packageJson = defect switch
        {
            "script" => PackageJson.Replace("node tooling/project.ts naming", "echo skipped", StringComparison.Ordinal),
            "gate" => PackageJson.Replace("npm run policy && ", string.Empty, StringComparison.Ordinal),
            _ => PackageJson,
        };
        string script = defect switch
        {
            "tool" => Script.Replace("check_naming.py", "scan.py", StringComparison.Ordinal),
            "report" => Script.Replace("artifacts/evidence/naming.json", "naming.json", StringComparison.Ordinal),
            _ => Script,
        };
        string candidate = defect switch
        {
            "candidate-version" => Candidate.Replace("1.0.0-ci.205.1", "latest", StringComparison.Ordinal),
            "candidate-commit" => Candidate.Replace("696242d16034262ce8b7268e8d157cd0e5bee544", "main", StringComparison.Ordinal),
            "candidate-digest" => Candidate.Replace("7c4cd7041b8b53e1bfb6fc0016befcd50259ffaca512d389456e00d3c26d5eaf", "unknown", StringComparison.Ordinal),
            "candidate-archive" => Candidate.Replace("OWvMF30zpN6ms2KlQCtax5P7TACrgK50Vb0drN5zy4iXgk2TZd+5UU+LDGaA2ioowA1EQIZx8ZUyRoayZaHadA==", "unknown", StringComparison.Ordinal),
            _ => Candidate,
        };
        string props = defect == "central-version" ? Props.Replace("1.0.0-ci.205.1", "1.0.0-ci.204.1", StringComparison.Ordinal) : Props;
        string project = defect == "project-reference" ? ArchitectureProject.Replace("PrivateAssets=\"all\"", string.Empty, StringComparison.Ordinal) : ArchitectureProject;
        string lockfile = defect switch
        {
            "lock-entry" => Lock.Replace("\"resolved\": \"1.0.0-ci.205.1\"", "\"resolved\": \"1.0.0-ci.204.1\"", StringComparison.Ordinal),
            "lock-direct" => Lock.Replace("\"type\": \"Direct\"", "\"type\": \"Transitive\"", StringComparison.Ordinal),
            _ => Lock,
        };
        Assert.NotEmpty(NamingWiring.Check(packageJson, script, candidate, lockfile, props, project));
    }

    private const string Workflow = """
        name: CI
        jobs:
          source:
            runs-on: ubuntu-latest
            steps:
              - run: npm run check
              - run: npm run check:dotnet
          quality:
            name: Dependency audit and repository checks
            runs-on: ubuntu-latest
            timeout-minutes: 25
            steps:
              - run: npm ci --ignore-scripts
              - name: Scan Git history for secrets
                run: docker run --rm --network none -v "$PWD:/repo:ro" zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f git /repo --redact=100 --no-banner
              - uses: actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68 # v6
                with:
                  global-json-file: global.json
              - name: Build
                run: |
                  dotnet restore Cloud.slnx --locked-mode
                  dotnet build Cloud.slnx -c Release --no-restore
              - run: npm run policy
              - name: Architecture gate
                env:
                  ARCFORGES_ARCHITECTURE_GATE: hosted
                run: dotnet test --project tests/ArchitectureTests -c Release --no-build --filter-class ArcForges.Cloud.ArchitectureTests.EvaluatedRepositoryGate
          verify:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  test "$QUALITY" = success
        """;

    [Fact]
    public void TheHostedGateOrderAfterGitleaksIsAccepted()
    {
        Assert.Empty(CiWiring.Check(Workflow, PackageJson));
    }

    [Theory]
    [InlineData("missing-setup")]
    [InlineData("missing-restore")]
    [InlineData("missing-build")]
    [InlineData("missing-policy")]
    [InlineData("missing-host")]
    [InlineData("host-before-gitleaks")]
    [InlineData("build-before-restore")]
    [InlineData("continue-on-error")]
    [InlineData("always")]
    [InlineData("weakened-gitleaks")]
    [InlineData("short-timeout")]
    [InlineData("no-mode")]
    [InlineData("verify-drops-quality")]
    [InlineData("source-drops-solution-tests")]
    [InlineData("script-drops-solution-tests")]
    public void ABrokenHostedGateIsRejected(string defect)
    {
        string workflow = defect switch
        {
            "missing-setup" => Workflow.Replace("actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68", "actions/setup-dotnet@v6", StringComparison.Ordinal),
            "missing-restore" => Workflow.Replace("dotnet restore Cloud.slnx --locked-mode", "dotnet restore Cloud.slnx", StringComparison.Ordinal),
            "missing-build" => Workflow.Replace("dotnet build Cloud.slnx -c Release --no-restore", "dotnet build", StringComparison.Ordinal),
            "missing-policy" => Workflow.Replace("npm run policy", "npm run lint", StringComparison.Ordinal),
            "missing-host" => Workflow.Replace("--filter-class ArcForges.Cloud.ArchitectureTests.EvaluatedRepositoryGate", "--filter-class Other", StringComparison.Ordinal),
            "host-before-gitleaks" => Workflow.Replace("name: Scan Git history for secrets", "name: Scan Git history", StringComparison.Ordinal)
                .Replace("- name: Architecture gate", "- name: Scan Git history for secrets", StringComparison.Ordinal),
            "build-before-restore" => Workflow.Replace("dotnet restore Cloud.slnx --locked-mode", "@@restore@@", StringComparison.Ordinal)
                .Replace("dotnet build Cloud.slnx -c Release --no-restore", "dotnet restore Cloud.slnx --locked-mode", StringComparison.Ordinal)
                .Replace("@@restore@@", "dotnet build Cloud.slnx -c Release --no-restore", StringComparison.Ordinal),
            "continue-on-error" => Workflow.Replace("- run: npm run policy", "- run: npm run policy\n                continue-on-error: true", StringComparison.Ordinal),
            "always" => Workflow.Replace("- name: Architecture gate", "- name: Architecture gate\n                if: always()", StringComparison.Ordinal),
            "weakened-gitleaks" => Workflow.Replace("--redact=100 ", string.Empty, StringComparison.Ordinal),
            "short-timeout" => Workflow.Replace("timeout-minutes: 25", "timeout-minutes: 10", StringComparison.Ordinal),
            "no-mode" => Workflow.Replace("ARCFORGES_ARCHITECTURE_GATE: hosted", "OTHER: hosted", StringComparison.Ordinal),
            "verify-drops-quality" => Workflow.Replace("test \"$QUALITY\" = success", "true", StringComparison.Ordinal),
            "source-drops-solution-tests" => Workflow.Replace("- run: npm run check:dotnet", "- run: npm run lint", StringComparison.Ordinal),
            _ => Workflow,
        };
        string package = defect == "script-drops-solution-tests"
            ? PackageJson.Replace("dotnet test --solution Cloud.slnx", "dotnet test --project tests/ArcForges.Cloud.Tests", StringComparison.Ordinal)
            : PackageJson;
        Assert.NotEmpty(CiWiring.Check(workflow, package));
    }

    [Fact]
    public void PackageLicencesComeFromTheRestoredNuspecExpression()
    {
        Assert.Equal("MIT", CloudRepository.ReadNuspecLicence("<package xmlns=\"http://schemas.microsoft.com/packaging/2011/10/nuspec.xsd\"><metadata><license type=\"expression\">MIT</license></metadata></package>"));
        Assert.Null(CloudRepository.ReadNuspecLicence("<package><metadata><licenseUrl>https://example.invalid/license</licenseUrl></metadata></package>"));
        Assert.Null(CloudRepository.ReadNuspecLicence("<package><metadata><license type=\"file\">LICENSE.txt</license></metadata></package>"));
    }
}
