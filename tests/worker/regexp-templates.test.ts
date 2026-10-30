// SPDX-License-Identifier: AGPL-3.0-only
// A pattern a Worker module builds with `new RegExp(<expression>)` states no count of its own (worker-2, worker-js-4). The
// architecture scan (WorkerLiteralScan) reads regex literals only, so a string or template literal would let an identifier's length
// or a budget be copied by hand where it must come from a generated value (`${generatedCount}`) or from a generated pattern's own
// text. This test reads the WHOLE first argument of every such call in worker/ (a concatenation, an array joined, a template whose
// substitution holds a literal too) and refuses a quantifier whose bounds are literal numbers other than 0 and 1 in any piece of it;
// an argument that holds no literal at all must come from an identifier imported from a generated module, so that a pattern held in
// a variable of the file cannot carry a hand-written count past the scan. A substitution that sits where a quantifier's bound is
// (`{0,${n - 1}}`) is a bound too: it may hold only the numbers 0 and 1 and identifiers imported from a generated module, so a
// literal number (`{${43}}`), a number held in a variable of the file (`{0,${held}}`) or one added to the argument outside any
// quotes (`"x{" + 43 + "}"`) cannot carry a count past the scan either.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const workerRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../worker");

function sources(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) return sources(file);
    return entry.name.endsWith(".ts") && !entry.name.endsWith(".generated.ts") ? [file] : [];
  });
}

const quotes = new Set(['"', "'", "`"]);

/**
 * Reads an expression from `start` to the bracket that closes it (or, for an argument, the comma at depth 0), skipping what quotes
 * hide. Every string or template piece it meets is added to `pieces` (a template's substitution is `\u0000` in its piece, and the
 * pieces inside the substitution are added as well). The result is the index of the character that ended the expression.
 */
function scan(
  source: string,
  start: number,
  stopAtComma: boolean,
  pieces: string[],
  counted: string[],
): number {
  let depth = 0;
  for (let index = start; index < source.length; index += 1) {
    const character = source[index] as string;
    if (quotes.has(character)) {
      index = quoted(source, index, pieces, counted);
    } else if (character === "(" || character === "[" || character === "{") {
      depth += 1;
    } else if (character === ")" || character === "]" || character === "}") {
      if (depth === 0) return index;
      depth -= 1;
    } else if (character === "," && depth === 0 && stopAtComma) {
      return index;
    }
  }
  throw new Error("an expression is not closed");
}

/** Reads the string or template that opens at `start`; the result is the index of its closing quote. */
function quoted(source: string, start: number, pieces: string[], counted: string[]): number {
  const quote = source[start] as string;
  let text = "";
  let index = start + 1;
  for (; index < source.length; index += 1) {
    const character = source[index] as string;
    if (character === "\\") {
      text += source.slice(index, index + 2);
      index += 1;
    } else if (character === quote) {
      break;
    } else if (quote === "`" && character === "$" && source[index + 1] === "{") {
      const from = index + 2;
      index = scan(source, from, false, pieces, counted);
      // A substitution right after `{`, `{3,` or another substitution and a comma is a quantifier's bound.
      if (/\{(?:\d+|\u0000)?,?$/u.test(text)) counted.push(source.slice(from, index));
      text += "\u0000";
    } else {
      text += character;
    }
  }
  pieces.push(text);
  return index;
}

/** What one `new RegExp(` argument holds: its text, every string or template piece, and the expressions that stand where a bound is. */
interface Argument {
  expression: string;
  pieces: string[];
  counted: string[];
}

/** The first argument of each `new RegExp(` in a source. */
function regExpArguments(source: string): Argument[] {
  const found: Argument[] = [];
  for (const call of source.matchAll(/new\s+RegExp\s*\(\s*/gu)) {
    const start = call.index + call[0].length;
    const pieces: string[] = [];
    const counted: string[] = [];
    const end = scan(source, start, true, pieces, counted);
    found.push({ expression: source.slice(start, end).trim(), pieces, counted });
  }
  return found;
}

/** The literal numbers above 1 in an expression's code (what quotes hide is a piece, read on its own). */
function literalNumbers(code: string): string[] {
  return [...code.matchAll(/(?<![\w$.])\d+(?![\w$])/gu)]
    .map((found) => found[0])
    .filter((value) => Number(value) > 1);
}

/** The text of an argument with every string and template literal cut out (a template's substitutions stay). */
function withoutQuotes(expression: string): string {
  const pieces: string[] = [];
  let code = "";
  for (let index = 0; index < expression.length; index += 1) {
    const character = expression[index] as string;
    if (quotes.has(character)) {
      index = quoted(expression, index, pieces, []);
      code += " ";
    } else code += character;
  }
  return code;
}

/** The quantifiers of a pattern's text that state a count: `{n}`, `{n,}` or `{n,m}` with a literal number other than 0 and 1. */
function literalCounts(pattern: string): string[] {
  const counts: string[] = [];
  for (const quantifier of pattern.matchAll(/\{(\d+)(?:,(\d*))?\}/gu)) {
    const numbers = [quantifier[1], quantifier[2]].filter(
      (value) => value !== undefined && value !== "",
    );
    if (numbers.some((value) => Number(value) > 1)) counts.push(quantifier[0]);
  }
  return counts;
}

/** The names a source imports from a generated module (`*.generated.ts`). */
function generatedNames(source: string): Set<string> {
  const names = new Set<string>();
  for (const statement of source.matchAll(
    /import\s+(?:type\s+)?\{([^}]*)\}\s+from\s+["'][^"']*\.generated\.ts["']/gu,
  ))
    for (const item of (statement[1] ?? "").split(",")) {
      const name = item
        .trim()
        .split(/\s+as\s+/u)
        .at(-1);
      if (name) names.add(name);
    }
  return names;
}

/** What is wrong with the `new RegExp` calls of a source (nothing, when each is built from generated values). */
function violations(source: string): string[] {
  const generated = generatedNames(source);
  const problems: string[] = [];
  for (const { expression, pieces, counted } of regExpArguments(source)) {
    for (const piece of pieces) {
      const counts = literalCounts(piece);
      if (counts.length > 0) problems.push(`${JSON.stringify(piece)} states ${counts.join(" ")}`);
    }
    for (const bound of counted) {
      const numbers = literalNumbers(withoutQuotes(bound));
      if (numbers.length > 0)
        problems.push(`the bound ${JSON.stringify(bound)} holds the literal ${numbers.join(" ")}`);
      const names = [...withoutQuotes(bound).matchAll(/(?<![\w$.])[A-Za-z_$][\w$]*/gu)].map(
        (found) => found[0],
      );
      for (const name of names)
        if (!generated.has(name))
          problems.push(`the bound ${JSON.stringify(bound)} uses ${name}, not a generated value`);
    }
    const outside = literalNumbers(withoutQuotes(expression));
    if (outside.length > 0)
      problems.push(`${JSON.stringify(expression)} adds the literal ${outside.join(" ")}`);
    if (pieces.length === 0) {
      const root = /^[A-Za-z_$][\w$]*/u.exec(expression)?.[0];
      if (root === undefined || !generated.has(root))
        problems.push(
          `${JSON.stringify(expression)} is not a literal and not from a generated module`,
        );
    }
  }
  return problems;
}

test("no RegExp a Worker module builds states a count of its own", () => {
  const files = sources(workerRoot);
  assert(files.length > 20, "the Worker's modules were found");
  let patterns = 0;
  for (const file of files) {
    const source = readFileSync(file, "utf8");
    patterns += regExpArguments(source).length;
    assert.deepEqual(
      violations(source),
      [],
      `${path.relative(workerRoot, file)} builds a RegExp that states a count; take it from a generated value`,
    );
  }
  assert(patterns >= 3, "the patterns built from a template were found");
});

test("the reader finds every piece of the argument, a substituted expression's literals too, and counts only literal numbers", () => {
  assert.deepEqual(
    regExpArguments(
      'const a = new RegExp(`^x{43}$`, "u"); const b = new RegExp("y{0,6}"); new RegExp(\'z\')',
    ).map((call) => call.pieces),
    [["^x{43}$"], ["y{0,6}"], ["z"]],
  );
  assert.deepEqual(
    regExpArguments(`new RegExp(\`^a\${f({ g: 1 })}[0-9]{0,\${n - 1}}$\`, 'u')`).map(
      (call) => call.pieces,
    ),
    [["^a\u0000[0-9]{0,\u0000}$"]],
  );
  // A concatenation, a joined array and a substitution that holds a literal of its own: every piece is read, not the first only.
  assert.deepEqual(
    regExpArguments('new RegExp("a" + "b{43}", "u")').map((call) => call.pieces),
    [["a", "b{43}"]],
  );
  assert.deepEqual(
    regExpArguments('new RegExp(["x", "y{9}"].join(""), "u")').map((call) => call.pieces),
    [["x", "y{9}", ""]],
  );
  assert.deepEqual(
    regExpArguments(`new RegExp(\`^\${escape("z{7}")}$\`)`).map((call) => call.pieces),
    [["z{7}", "^\u0000$"]],
  );
  assert.deepEqual(literalCounts("^[A-Za-z0-9_-]{43}$"), ["{43}"]);
  assert.deepEqual(literalCounts("[1-9][0-9]{0,6}"), ["{0,6}"]);
  assert.deepEqual(literalCounts("[A-Za-z0-9%._~-]{1,512}"), ["{1,512}"]);
  assert.deepEqual(literalCounts("a{2,}"), ["{2,}"]);
  assert.deepEqual(literalCounts("[0-9]{0,\u0000}x{1}y{0}z{0,1}"), []);
});

test("a hand-written count is found in a template, a string, a concatenation, a joined array, a substitution and a variable", () => {
  const generated = 'import { limit, pattern as shape } from "../tables/x.generated.ts";\n';
  assert.deepEqual(violations(`${generated}new RegExp(\`^[0-9]{0,\${limit - 1}}$\`, "u")`), []);
  assert.deepEqual(violations(`${generated}new RegExp(shape.source, "u")`), []);
  assert.deepEqual(violations(`${generated}new RegExp(\`^x{\${limit}}$\`, "u")`), []);
  assert.deepEqual(violations(`${generated}new RegExp(\`^x{1,\${limit - 1}}$\`, "u")`), []);
  assert.deepEqual(
    violations(`${generated}new RegExp(\`^\${shape.source}x{0,\${limit}}$\`, "u")`),
    [],
  );
  assert.deepEqual(violations(`${generated}new RegExp(shape, "u")`), []);
  for (const bad of [
    'new RegExp(`^x{43}$`, "u")',
    'new RegExp("^x{43}$", "u")',
    'new RegExp("^" + "x{43}", "u")',
    'new RegExp(["^", "x{43}"].join(""), "u")',
    `new RegExp(\`^\${escape("x{43}")}$\`, "u")`,
    `new RegExp(\`^\${pick(\`y{9}\`)}$\`, "u")`,
    'const held = "x{43}"; new RegExp(held, "u")',
    `const held = \`x{\${"43"}}\`; new RegExp(held, "u")`,
    'new RegExp(local.pattern, "u")',
    'new RegExp(`^x{${43}}$`, "u")',
    'new RegExp(`^x{0,${43}}$`, "u")',
    'new RegExp(`^x{${3},${43}}$`, "u")',
    'const held = 43; new RegExp(`^x{0,${held}}$`, "u")',
    'new RegExp(`^x{0,${limit - 2}}$`, "u")',
    'new RegExp(`^x{0,${hold(limit)}}$`, "u")',
    'new RegExp("^x{" + 43 + "}$", "u")',
    'new RegExp(["^x{", 43, "}$"].join(""), "u")',
  ]) {
    assert(violations(`${generated}${bad}`).length > 0, bad);
  }
  assert.throws(() => regExpArguments('new RegExp("never closed'), /not closed/u);
});
