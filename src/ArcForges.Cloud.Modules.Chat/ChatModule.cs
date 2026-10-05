// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Chat;

/// <summary>
/// Boundary of the Chat module, the only owner of the <c>chat_*</c> tables and of the plans under
/// <c>storage/plans/chat</c>. It owns conversations, messages and their committed content. Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class ChatModule : IModuleBoundary
{
    public static ChatModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("Chat", "chat");
}
