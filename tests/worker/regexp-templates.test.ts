// SPDX-License-Identifier: AGPL-3.0-only
// A pattern a Worker module builds with `new RegExp(<template or string>)` states no count of its own (worker-2). The architecture
// scan (WorkerLiteralScan) reads regex literals only, so a template literal would let an identifier's length or a budget be copied
// by hand where it must come from a generated value (`${generatedCount}`) or from a generated pattern's own text. This test reads the
// text of every such pattern in worker/ and refuses a quantifier whose bounds are literal numbers other than 0 and 1.
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

/** The text of the first argument of each `new RegExp(` in a source, a substitution of a template as the placeholder `\u0000`. */
function regExpArguments(source: string): string[] {
  const found: string[] = [];
  for (const start of source.matchAll(/new\s+RegExp\s*\(\s*/gu)) {
    let index = start.index + start[0].length;
    const quote = source[index];
    if (quote !== "`" && quote !== '"' && quote !== "'") continue;
    let text = "";
    for (index += 1; index < source.length; index += 1) {
      const character = source[index];
      if (character === "\\") {
        text += source.slice(index, index + 2);
        index += 1;
      } else if (character === quote) {
        break;
      } else if (quote === "`" && character === "$" && source[index + 1] === "{") {
        let depth = 0;
        for (index += 1; index < source.length; index += 1) {
          if (source[index] === "{") depth += 1;
          if (source[index] === "}") depth -= 1;
          if (depth === 0) break;
        }
        text += "\u0000";
      } else {
        text += character;
      }
    }
    found.push(text);
  }
  return found;
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

test("no RegExp a Worker module builds states a count of its own", () => {
  const files = sources(workerRoot);
  assert(files.length > 20, "the Worker's modules were found");
  let patterns = 0;
  for (const file of files) {
    for (const pattern of regExpArguments(readFileSync(file, "utf8"))) {
      patterns += 1;
      assert.deepEqual(
        literalCounts(pattern),
        [],
        `${path.relative(workerRoot, file)}: ${JSON.stringify(pattern)} states a count; take it from a generated value`,
      );
    }
  }
  assert(patterns >= 3, "the patterns built from a template were found");
});

test("the reader finds the counts a template or a string states and ignores a substituted one", () => {
  assert.deepEqual(
    regExpArguments(
      'const a = new RegExp(`^x{43}$`, "u"); const b = new RegExp("y{0,6}"); new RegExp(\'z\')',
    ),
    ["^x{43}$", "y{0,6}", "z"],
  );
  assert.deepEqual(regExpArguments(`new RegExp(\`^a\${f({ g: 1 })}[0-9]{0,\${n - 1}}$\`, 'u')`), [
    "^a\u0000[0-9]{0,\u0000}$",
  ]);
  assert.deepEqual(literalCounts("^[A-Za-z0-9_-]{43}$"), ["{43}"]);
  assert.deepEqual(literalCounts("[1-9][0-9]{0,6}"), ["{0,6}"]);
  assert.deepEqual(literalCounts("[A-Za-z0-9%._~-]{1,512}"), ["{1,512}"]);
  assert.deepEqual(literalCounts("a{2,}"), ["{2,}"]);
  assert.deepEqual(literalCounts("[0-9]{0,\u0000}x{1}y{0}z{0,1}"), []);
});
