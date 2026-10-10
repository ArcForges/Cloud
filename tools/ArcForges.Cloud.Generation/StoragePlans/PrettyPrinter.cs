// SPDX-License-Identifier: AGPL-3.0-only
// A small document printer that reproduces the layout Prettier gives the generated plan files (CLOUD.84 U7, D7). The generated
// TypeScript dictionary and the families expansion are formatted by Prettier in the Node generator; the C# emitter must write the
// same bytes, so it follows Prettier's group, fits and break-propagation rules for the node kinds those files contain (object and
// array literals, string, number, boolean and null literals). Parity is proven by byte comparison in the storage-plan tests.
using System.Text;

namespace ArcForges.Cloud.Tools.Generation.StoragePlans;

/// <summary>A node of the layout document.</summary>
public abstract class Doc
{
}

public sealed class TextDoc(string text) : Doc
{
    public string Text { get; } = text;
}

public sealed class ConcatDoc(IReadOnlyList<Doc> parts) : Doc
{
    public IReadOnlyList<Doc> Parts { get; } = parts;
}

public sealed class GroupDoc(Doc contents, bool shouldBreak) : Doc
{
    public Doc Contents { get; } = contents;

    /// <summary>True when the group is printed broken, either because it was declared so or because a child group breaks.</summary>
    public bool Break { get; set; } = shouldBreak;
}

public sealed class IndentDoc(Doc contents) : Doc
{
    public Doc Contents { get; } = contents;
}

public sealed class LineDoc(bool soft) : Doc
{
    /// <summary>A soft line prints nothing when flat; a plain line prints one space.</summary>
    public bool Soft { get; } = soft;
}

public sealed class IfBreakDoc(Doc breakContents, Doc flatContents) : Doc
{
    public Doc BreakContents { get; } = breakContents;

    public Doc FlatContents { get; } = flatContents;
}

public static class Layout
{
    public const int PrintWidth = 100;
    private const int IndentWidth = 2;

    public static Doc Text(string text) => new TextDoc(text);

    public static Doc Concat(params Doc[] parts) => new ConcatDoc(parts);

    public static Doc Group(Doc contents, bool shouldBreak = false) => new GroupDoc(contents, shouldBreak);

    public static Doc Indent(Doc contents) => new IndentDoc(contents);

    public static Doc Line { get; } = new LineDoc(soft: false);

    public static Doc SoftLine { get; } = new LineDoc(soft: true);

    public static Doc IfBreak(Doc breakContents, Doc flatContents) => new IfBreakDoc(breakContents, flatContents);

    /// <summary>
    /// Prints a document the way Prettier does: a group is flat when it fits the rest of the line, a broken group breaks every
    /// line directly inside it, and a group that contains a broken group is broken too.
    /// </summary>
    public static string Print(Doc document, int startColumn)
    {
        PropagateBreaks(document);
        var output = new StringBuilder();
        var position = startColumn;
        var stack = new List<(int Indent, bool Flat, Doc Doc)> { (0, false, document) };
        while (stack.Count > 0)
        {
            var (indent, flat, doc) = stack[^1];
            stack.RemoveAt(stack.Count - 1);
            switch (doc)
            {
                case TextDoc text:
                    output.Append(text.Text);
                    position += text.Text.Length;
                    break;
                case ConcatDoc concat:
                    for (var index = concat.Parts.Count - 1; index >= 0; index--)
                        stack.Add((indent, flat, concat.Parts[index]));
                    break;
                case IndentDoc nested:
                    stack.Add((indent + IndentWidth, flat, nested.Contents));
                    break;
                case GroupDoc group:
                    if (flat && !group.Break)
                    {
                        stack.Add((indent, true, group.Contents));
                        break;
                    }

                    var next = (indent, true, group.Contents);
                    if (!group.Break && Fits(next, stack, PrintWidth - position))
                        stack.Add(next);
                    else
                        stack.Add((indent, false, group.Contents));
                    break;
                case IfBreakDoc conditional:
                    stack.Add((indent, flat, flat ? conditional.FlatContents : conditional.BreakContents));
                    break;
                case LineDoc line:
                    if (flat)
                    {
                        if (!line.Soft)
                        {
                            output.Append(' ');
                            position++;
                        }
                    }
                    else
                    {
                        while (output.Length > 0 && output[^1] is ' ' or '\t')
                            output.Length--;
                        output.Append('\n').Append(' ', indent);
                        position = indent;
                    }

                    break;
                default:
                    throw new InvalidOperationException($"Unknown layout node {doc.GetType().Name}.");
            }
        }

        return output.ToString();
    }

    /// <summary>Whether the next command fits the remaining width, reading the rest of the line up to its first break.</summary>
    private static bool Fits(
        (int Indent, bool Flat, Doc Doc) next,
        IReadOnlyList<(int Indent, bool Flat, Doc Doc)> rest,
        int width)
    {
        var remaining = width;
        var pending = new List<(bool Flat, Doc Doc)> { (next.Flat, next.Doc) };
        var restIndex = rest.Count;
        while (remaining >= 0)
        {
            if (pending.Count == 0)
            {
                if (restIndex == 0) return true;
                restIndex--;
                pending.Add((rest[restIndex].Flat, rest[restIndex].Doc));
                continue;
            }

            var (flat, doc) = pending[^1];
            pending.RemoveAt(pending.Count - 1);
            switch (doc)
            {
                case TextDoc text:
                    remaining -= text.Text.Length;
                    break;
                case ConcatDoc concat:
                    for (var index = concat.Parts.Count - 1; index >= 0; index--)
                        pending.Add((flat, concat.Parts[index]));
                    break;
                case IndentDoc nested:
                    pending.Add((flat, nested.Contents));
                    break;
                case GroupDoc group:
                    pending.Add((flat && !group.Break, group.Contents));
                    break;
                case IfBreakDoc conditional:
                    pending.Add((flat, flat ? conditional.FlatContents : conditional.BreakContents));
                    break;
                case LineDoc line:
                    if (!flat) return true;
                    if (!line.Soft) remaining--;
                    break;
            }
        }

        return false;
    }

    /// <summary>Marks every group that contains a broken group as broken, so the whole chain above a broken group breaks.</summary>
    private static bool PropagateBreaks(Doc doc)
    {
        switch (doc)
        {
            case GroupDoc group:
                {
                    var childBroken = PropagateBreaks(group.Contents);
                    if (childBroken) group.Break = true;
                    return group.Break;
                }
            case ConcatDoc concat:
                {
                    var any = false;
                    foreach (var part in concat.Parts)
                        any |= PropagateBreaks(part);
                    return any;
                }
            case IndentDoc nested:
                return PropagateBreaks(nested.Contents);
            case IfBreakDoc conditional:
                {
                    var broken = PropagateBreaks(conditional.BreakContents);
                    return PropagateBreaks(conditional.FlatContents) || broken;
                }
            default:
                return false;
        }
    }
}
