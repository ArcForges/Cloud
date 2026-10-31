// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The test-only catalogue injection (DC-12) is pinned on the code that builds the running center, not on a file that never does:
// Options.catalogue and Options.catalogueClass are unexported, so no other package can set them, and inside this package only New may
// read them while Run composes the center with an empty Options{}. The pin parses the non-test sources (go/parser), so a mutant that
// makes Run inject a catalogue, or lets a second function read the fields, is found by the same code that reads the real files.

// injectionProblems lists every way the given sources (file name to text) could hand a running center a catalogue that its plan
// configuration did not: an identifier of the injection outside the Options declaration and New, and a Run that does not call New
// exactly once with the literal Options{}.
func injectionProblems(sources map[string]string) []string {
	var problems []string
	fset := token.NewFileSet()
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	slices.Sort(names)
	runCalls := 0
	for _, name := range names {
		file, err := parser.ParseFile(fset, name, sources[name], 0)
		if err != nil {
			problems = append(problems, name+": "+err.Error())
			continue
		}
		for _, declaration := range file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			generic, isGeneric := declaration.(*ast.GenDecl)
			allowed := isFunction && function.Recv == nil && function.Name.Name == "New" || isGeneric && declaresOptions(generic)
			ast.Inspect(declaration, func(node ast.Node) bool {
				if identifier, ok := node.(*ast.Ident); ok && (identifier.Name == "catalogue" || identifier.Name == "catalogueClass") && !allowed {
					problems = append(problems, fmt.Sprintf("%s: %s names %s outside Options and New", name, fset.Position(identifier.Pos()), identifier.Name))
				}
				return true
			})
			if !isFunction || function.Recv != nil || function.Name.Name != "Run" {
				continue
			}
			ast.Inspect(function, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				if callee, isIdentifier := call.Fun.(*ast.Ident); !isIdentifier || callee.Name != "New" {
					return true
				}
				runCalls++
				var options ast.Expr
				if len(call.Args) == 3 {
					options = call.Args[2]
				}
				empty := false
				if composite, isLiteral := options.(*ast.CompositeLit); isLiteral {
					if typed, isIdentifier := composite.Type.(*ast.Ident); isIdentifier && typed.Name == "Options" && len(composite.Elts) == 0 {
						empty = true
					}
				}
				if !empty {
					problems = append(problems, fmt.Sprintf("%s: Run does not compose the center with the literal Options{}", name))
				}
				return true
			})
		}
	}
	if runCalls != 1 {
		problems = append(problems, fmt.Sprintf("Run calls New %d times, want once", runCalls))
	}
	return problems
}

// declaresOptions reports a type declaration of Options.
func declaresOptions(declaration *ast.GenDecl) bool {
	for _, spec := range declaration.Specs {
		if typed, ok := spec.(*ast.TypeSpec); ok && typed.Name.Name == "Options" {
			return true
		}
	}
	return false
}

// packageSources are the non-test sources of this package.
func packageSources(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]string{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		sources[file] = string(data)
	}
	if _, ok := sources["server.go"]; !ok {
		t.Fatal("the sources of the package were not found")
	}
	return sources
}

func TestNoCodeOfTheRunningCenterInjectsACatalogue(t *testing.T) {
	if problems := injectionProblems(packageSources(t)); len(problems) != 0 {
		t.Fatalf("the test-only catalogue injection is reachable from the running center:\n%s", strings.Join(problems, "\n"))
	}
}

// TestThePinOnTheCatalogueInjectionFindsEachWayAroundIt proves the pin: the real server.go with Run changed in each way is refused.
func TestThePinOnTheCatalogueInjectionFindsEachWayAroundIt(t *testing.T) {
	actual := packageSources(t)
	server := actual["server.go"]
	const run = "center, err := New(cfg, logger, Options{})"
	if strings.Count(server, run) != 1 {
		t.Fatal("Run composes the center in another way than this test expects")
	}
	mutate := func(file, old, new string) map[string]string {
		changed := map[string]string{}
		for name, text := range actual {
			changed[name] = text
		}
		if strings.Count(changed[file], old) != 1 {
			t.Fatalf("%s: %q found %d times", file, old, strings.Count(changed[file], old))
		}
		changed[file] = strings.Replace(changed[file], old, new, 1)
		return changed
	}
	cases := map[string]map[string]string{
		"Run injects a production catalogue":       mutate("server.go", run, "center, err := New(cfg, logger, Options{catalogue: []byte(`{}`), catalogueClass: feature.ClassProduction})"),
		"Run injects the class alone":              mutate("server.go", run, "center, err := New(cfg, logger, Options{catalogueClass: feature.ClassProduction})"),
		"Run passes another option":                mutate("server.go", run, "center, err := New(cfg, logger, Options{Clock: time.Now})"),
		"Run passes a variable":                    mutate("server.go", run, "options := Options{}\n\tcenter, err := New(cfg, logger, options)"),
		"Run does not call New":                    mutate("server.go", run, "var center *Center\n\tvar err error"),
		"Run calls New twice":                      mutate("server.go", run, "_, _ = New(cfg, logger, Options{})\n\tcenter, err := New(cfg, logger, Options{})"),
		"a second function reads the injection":    mutate("server.go", "// logPlanConfiguration says", "func injected(options Options) []byte { return options.catalogue }\n\n// logPlanConfiguration says"),
		"a method sets the injection":              mutate("server.go", "func (c *Center) logPlanConfiguration(", "func (c *Center) inject(options *Options) { options.catalogue = nil }\n\nfunc (c *Center) logPlanConfiguration("),
		"another file of the package reads it":     mutate("clientip.go", "package server", "package server\n\nvar _ = Options{}.catalogueClass"),
		"a composite literal elsewhere sets it":    mutate("clientip.go", "package server", "package server\n\nvar _ = Options{catalogue: nil}"),
		"the start of the center is a method of C": mutate("server.go", run, "center, err := (&Center{}).New(cfg, logger, Options{})"),
	}
	for name, sources := range cases {
		t.Run(name, func(t *testing.T) {
			if problems := injectionProblems(sources); len(problems) == 0 {
				t.Fatal("the pin does not see it")
			}
		})
	}
}
