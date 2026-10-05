// SPDX-License-Identifier: AGPL-3.0-only
using System.Reflection;
using ArcForges.Cloud.Composition;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Xunit;

namespace ArcForges.Cloud.Tests;

/// <summary>
/// RD-01 to RD-04 inside a module project, where the layers are namespaces: Domain references neither Application, Infrastructure
/// nor generated Contracts; Application does not reference Infrastructure nor generated Contracts. The modules are empty boundaries
/// today, so the checker is proven against fixture types that break each rule and the real assemblies are held to it from the first
/// type a module task adds.
/// </summary>
public sealed class LayeringTests
{
    private const BindingFlags Declared = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    private static string? Layer(Type type) =>
        (type.Namespace ?? "").Split('.').FirstOrDefault(segment => segment is "Domain" or "Application" or "Infrastructure");

    private static IEnumerable<Type> Mentioned(Type type)
    {
        IEnumerable<Type> Flatten(Type t)
        {
            yield return t;
            if (t.HasElementType) foreach (var inner in Flatten(t.GetElementType()!)) yield return inner;
            if (t.IsGenericType) foreach (var argument in t.GetGenericArguments()) foreach (var inner in Flatten(argument)) yield return inner;
        }

        var types = new List<Type>();
        if (type.BaseType is not null) types.Add(type.BaseType);
        types.AddRange(type.GetInterfaces());
        foreach (var field in type.GetFields(Declared)) types.Add(field.FieldType);
        foreach (var property in type.GetProperties(Declared)) types.Add(property.PropertyType);
        foreach (var method in type.GetMethods(Declared).Cast<MethodBase>().Concat(type.GetConstructors(Declared)))
        {
            if (method is MethodInfo info) types.Add(info.ReturnType);
            types.AddRange(method.GetParameters().Select(parameter => parameter.ParameterType));
        }

        return types.SelectMany(Flatten);
    }

    internal static IReadOnlyList<string> Violations(Assembly assembly)
    {
        var violations = new List<string>();
        foreach (var type in assembly.GetTypes().Where(t => !Attribute.IsDefined(t, typeof(System.Runtime.CompilerServices.CompilerGeneratedAttribute))))
        {
            var layer = Layer(type);
            if (layer is null or "Infrastructure") continue;
            foreach (var other in Mentioned(type).Distinct())
            {
                var otherLayer = Layer(other);
                var contracts = other.Assembly.GetName().Name?.StartsWith("ArcForges.Contracts.", StringComparison.Ordinal) == true;
                if (layer == "Domain" && otherLayer is "Application" or "Infrastructure") violations.Add(type.FullName + " (Domain) references " + other.FullName);
                else if (layer == "Application" && otherLayer == "Infrastructure") violations.Add(type.FullName + " (Application) references " + other.FullName);
                else if (contracts) violations.Add(type.FullName + " (" + layer + ") references the generated wire type " + other.FullName);
            }
        }

        return violations;
    }

    [Fact]
    public void NoModuleAssemblyBreaksTheLayerDirection()
    {
        foreach (var boundary in ModuleBoundaries.All) Assert.Empty(Violations(boundary.GetType().Assembly));
    }

    /// <summary>
    /// The engine does not apply AT-01 to the layers inside a module project, so this check must not pass vacuously: a module assembly
    /// that holds any layered type must hold Domain and Application types (otherwise its layers are mislabeled), and the checker has
    /// to see every one of them.
    /// </summary>
    [Fact]
    public void EveryLayeredModuleAssemblyIsCheckedNonVacuously()
    {
        var layeredAssemblies = 0;
        foreach (var boundary in ModuleBoundaries.All)
        {
            var assembly = boundary.GetType().Assembly;
            var layers = assembly.GetTypes().Where(t => !Attribute.IsDefined(t, typeof(System.Runtime.CompilerServices.CompilerGeneratedAttribute)))
                .Select(Layer).Where(layer => layer is not null).ToArray();
            if (layers.Length == 0) continue;
            layeredAssemblies++;
            Assert.Contains("Domain", layers);
            Assert.Contains("Application", layers);
            Assert.Empty(Violations(assembly));
        }

        Assert.True(layeredAssemblies >= 1, "At least the Entitlement module holds layered code.");
    }

    [Fact]
    public void TheCheckerFlagsEveryKindOfViolationAndNothingElse()
    {
        Assert.DoesNotContain(Violations(typeof(LayeringFixtures.Good.Domain.Entity).Assembly), v => v.Contains("LayeringFixtures.Good", StringComparison.Ordinal));
        var found = Violations(typeof(LayeringFixtures.Bad.Domain.DomainWithInfrastructureField).Assembly).Where(v => v.Contains("LayeringFixtures.Bad", StringComparison.Ordinal)).ToArray();
        Assert.Contains(found, v => v.Contains("DomainWithInfrastructureField (Domain) references", StringComparison.Ordinal));
        Assert.Contains(found, v => v.Contains("DomainWithApplicationParameter (Domain) references", StringComparison.Ordinal));
        Assert.Contains(found, v => v.Contains("DomainWithWireType (Domain) references the generated wire type", StringComparison.Ordinal));
        Assert.Contains(found, v => v.Contains("ApplicationWithInfrastructureProperty (Application) references", StringComparison.Ordinal));
        Assert.Contains(found, v => v.Contains("ApplicationWithWireList (Application) references the generated wire type", StringComparison.Ordinal));
        Assert.Contains(found, v => v.Contains("DomainInheritingInfrastructure (Domain) references", StringComparison.Ordinal));
        Assert.Equal(6, found.Length);
    }
}
