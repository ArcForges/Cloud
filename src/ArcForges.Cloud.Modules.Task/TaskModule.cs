// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Task.Harness.Wake;
using Microsoft.AspNetCore.Routing;

namespace ArcForges.Cloud.Modules.Task;

/// <summary>
/// Boundary of the Task module, the only owner of the <c>task_*</c> tables and of the plans under
/// <c>storage/plans/task</c>. It owns tasks, automation definitions and automation occurrences. Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// The namespace <c>Task</c> shadows <see cref="System.Threading.Tasks.Task"/> inside this module: write
/// <c>global::System.Threading.Tasks.Task</c> or add a using alias.
/// </summary>
public sealed class TaskModule : IModuleBoundary
{
    public static TaskModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("Task", "task");

    /// <summary>Maps the harness wake route (HAR.40). The route exists only when the host has registered the wake port, so production maps nothing.</summary>
    public void Map(IEndpointRouteBuilder endpoints) => HarnessWakeEndpoint.Map(endpoints);
}
