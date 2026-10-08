// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;

/// <summary>The run states of the registry enum TaskState (contracts 04 section 3). The numbers are the stored numbers of task_run.state.</summary>
internal enum RunState : int
{
    Queued = 1,
    Running = 2,
    Waiting = 3,
    Paused = 4,
    Interrupted = 5,
    Succeeded = 6,
    PartiallySucceeded = 7,
    Failed = 8,
    Canceled = 9,
}

/// <summary>The stored numbers of task_attempt.state.</summary>
internal enum AttemptState : int
{
    Pending = 1,
    Running = 2,
    Succeeded = 3,
    Failed = 4,
    Canceled = 5,
}

/// <summary>The stored numbers of task_attempt.failure_class (task.failure_class).</summary>
internal enum FailureClass : int
{
    Transient = 1,
    Permanent = 2,
    Refused = 3,
    Canceled = 4,
    UnknownEffect = 5,
}

/// <summary>The stored numbers of task_attempt.effect_certainty (EffectCertainty, contracts 04 section 3).</summary>
internal enum EffectCertainty : int
{
    DidNotHappen = 1,
    Happened = 2,
    Unknown = 3,
}

/// <summary>The stored text states of task_execution_command.state.</summary>
internal static class CommandStates
{
    /// <summary>Reserved under a fence; no external call has been made.</summary>
    internal const string Reserved = "reserved";

    /// <summary>The dispatch intent is durable; the external call may have happened.</summary>
    internal const string Dispatching = "dispatching";

    /// <summary>An outcome (success, unknown or failure after dispatch) is recorded.</summary>
    internal const string Outcome = "outcome";

    /// <summary>Refused before any dispatch; a fresh attempt may follow.</summary>
    internal const string Refused = "refused";
}
