// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The test-only catalogue injection (DC-12) is pinned on the code that builds the running center, not on a file that never does.
// What is pinned, by parsing the non-test sources of the whole center module (go/parser), is:
//
//   - Options.catalogue and Options.catalogueClass are unexported, so no other package can set them, and inside package server the
//     only expressions that mention them are the two values of the keys Injected and InjectedClass of the one feature.Settings
//     literal in New (so New cannot take a catalogue from anywhere else: not by an assignment to the fields, not by a second literal);
//   - the identifiers Injected and InjectedClass appear in no other non-test file of the module (outside package feature, which
//     defines them), and neither does a call of feature.Configure or feature.ParseCatalogue (so Run, or any other function, cannot
//     build a second configuration from a document);
//   - Run composes the center with the literal Options{} and calls New once.
//
// What is not pinned: the inside of package feature (a test pins its behaviour), a catalogue obtained by reflection, a call through
// an import alias of package feature (the scan looks for the name feature), and non-Go files.
// A mutant that makes Run inject a catalogue, lets New read the fields in a condition, or builds a configuration beside New is found
// by the same code that reads the real files.

const serverFile = "internal/server/server.go"

// injectionProblems lists every way the given sources (path relative to center/ to text) could hand a running center a catalogue that
// its plan configuration did not.
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
		if strings.HasPrefix(name, "internal/feature/") {
			continue
		}
		file, err := parser.ParseFile(fset, name, sources[name], 0)
		if err != nil {
			problems = append(problems, name+": "+err.Error())
			continue
		}
		inServer := strings.HasPrefix(name, "internal/server/")
		// The two places a catalogue may enter, found first: the values of Injected and InjectedClass in the Settings literal of New.
		allowed := map[token.Pos]bool{}
		settingsLiterals := 0
		for _, declaration := range file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || name != serverFile || function.Recv != nil || function.Name.Name != "New" {
				continue
			}
			ast.Inspect(function, func(node ast.Node) bool {
				literal, ok := node.(*ast.CompositeLit)
				if !ok || !isSelector(literal.Type, "feature", "Settings") {
					return true
				}
				settingsLiterals++
				for _, element := range literal.Elts {
					pair, isPair := element.(*ast.KeyValueExpr)
					if !isPair {
						continue
					}
					key, isKey := pair.Key.(*ast.Ident)
					if !isKey || (key.Name != "Injected" && key.Name != "InjectedClass") {
						continue
					}
					want := map[string]string{"Injected": "catalogue", "InjectedClass": "catalogueClass"}[key.Name]
					if value, isValue := pair.Value.(*ast.SelectorExpr); isValue && isIdent(value.X, "options") && value.Sel.Name == want {
						allowed[key.Pos()], allowed[value.Sel.Pos()] = true, true
					}
				}
				return true
			})
		}
		if name == serverFile && settingsLiterals != 1 {
			problems = append(problems, fmt.Sprintf("%s: New holds %d feature.Settings literals, want exactly one", name, settingsLiterals))
		}
		for _, declaration := range file.Decls {
			generic, isGeneric := declaration.(*ast.GenDecl)
			declaresOptionsType := isGeneric && declaresOptions(generic)
			ast.Inspect(declaration, func(node ast.Node) bool {
				switch found := node.(type) {
				case *ast.Ident:
					switch {
					case (found.Name == "Injected" || found.Name == "InjectedClass") && !allowed[found.Pos()]:
						problems = append(problems, fmt.Sprintf("%s: %s names %s outside the Settings literal of New", name, fset.Position(found.Pos()), found.Name))
					case inServer && (found.Name == "catalogue" || found.Name == "catalogueClass") && !declaresOptionsType && !allowed[found.Pos()]:
						problems = append(problems, fmt.Sprintf("%s: %s names %s outside Options and the Settings literal of New", name, fset.Position(found.Pos()), found.Name))
					}
				case *ast.CallExpr:
					if isSelector(found.Fun, "feature", "Configure") || isSelector(found.Fun, "feature", "ParseCatalogue") {
						function, _ := declaration.(*ast.FuncDecl)
						if name != serverFile || function == nil || function.Name.Name != "New" || function.Recv != nil || !isSelector(found.Fun, "feature", "Configure") {
							problems = append(problems, fmt.Sprintf("%s: %s builds a plan configuration beside New", name, fset.Position(found.Pos())))
						}
					}
				}
				return true
			})
			function, isFunction := declaration.(*ast.FuncDecl)
			if name != serverFile || !isFunction || function.Recv != nil || function.Name.Name != "Run" {
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

func isIdent(expression ast.Expr, name string) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == name
}

func isSelector(expression ast.Expr, receiver, name string) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	return ok && isIdent(selector.X, receiver) && selector.Sel.Name == name
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

// centerSources are the non-test Go sources of the center module, by path relative to center/ (the module root, two levels up).
func centerSources(t *testing.T) map[string]string {
	t.Helper()
	root := filepath.Join("..", "..")
	sources := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		sources[filepath.ToSlash(relative)] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sources[serverFile]; !ok || len(sources) < 50 {
		t.Fatalf("the sources of the center were not found (%d files)", len(sources))
	}
	return sources
}

func TestNoCodeOfTheRunningCenterInjectsACatalogue(t *testing.T) {
	if problems := injectionProblems(centerSources(t)); len(problems) != 0 {
		t.Fatalf("the test-only catalogue injection is reachable from the running center:\n%s", strings.Join(problems, "\n"))
	}
}

// TestThePinOnTheCatalogueInjectionFindsEachWayAroundIt proves the pin: the real sources changed in each way are refused.
func TestThePinOnTheCatalogueInjectionFindsEachWayAroundIt(t *testing.T) {
	actual := centerSources(t)
	const run = "center, err := New(cfg, logger, Options{})"
	const settings = "feature.Settings{Mode: cfg.Mode, Plan: cfg.Plan, Injected: options.catalogue, InjectedClass: options.catalogueClass, Disabled: disabled}"
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
	appended := func(file, text string) map[string]string {
		changed := map[string]string{}
		for name, source := range actual {
			changed[name] = source
		}
		if _, ok := changed[file]; !ok {
			t.Fatalf("no file %s", file)
		}
		changed[file] += "\n" + text + "\n"
		return changed
	}
	cases := map[string]map[string]string{
		"Run injects a production catalogue":         mutate(serverFile, run, "center, err := New(cfg, logger, Options{catalogue: []byte(`{}`), catalogueClass: feature.ClassProduction})"),
		"Run injects the class alone":                mutate(serverFile, run, "center, err := New(cfg, logger, Options{catalogueClass: feature.ClassProduction})"),
		"Run passes another option":                  mutate(serverFile, run, "center, err := New(cfg, logger, Options{Clock: time.Now})"),
		"Run passes a variable":                      mutate(serverFile, run, "options := Options{}\n\tcenter, err := New(cfg, logger, options)"),
		"Run does not call New":                      mutate(serverFile, run, "var center *Center\n\tvar err error"),
		"Run calls New twice":                        mutate(serverFile, run, "_, _ = New(cfg, logger, Options{})\n\tcenter, err := New(cfg, logger, Options{})"),
		"the start of the center is a method":        mutate(serverFile, run, "center, err := (&Center{}).New(cfg, logger, Options{})"),
		"a second function reads the injection":      mutate(serverFile, "// logPlanConfiguration says", "func injected(options Options) []byte { return options.catalogue }\n\n// logPlanConfiguration says"),
		"a method sets the injection":                mutate(serverFile, "func (c *Center) logPlanConfiguration(", "func (c *Center) inject(options *Options) { options.catalogue = nil }\n\nfunc (c *Center) logPlanConfiguration("),
		"another file of the package reads it":       appended("internal/server/clientip.go", "var _ = Options{}.catalogueClass"),
		"a composite literal elsewhere sets it":      appended("internal/server/clientip.go", "var _ = Options{catalogue: nil}"),
		"New sets the fields before it configures":   mutate(serverFile, "\tcenter.FeatureConfiguration = feature.Configure("+settings+")", "\tif cfg.Mode == config.OfficialHosted && cfg.Plan == config.PlanNone {\n\t\toptions.catalogue, options.catalogueClass = []byte(`{}`), feature.ClassProduction\n\t}\n\tcenter.FeatureConfiguration = feature.Configure("+settings+")"),
		"New takes the document from another source": mutate(serverFile, "Injected: options.catalogue,", "Injected: []byte(`{}`),"),
		"New takes the class from another source":    mutate(serverFile, "InjectedClass: options.catalogueClass,", "InjectedClass: feature.ClassProduction,"),
		"Run builds a second configuration":          mutate(serverFile, "\tcenter.logPlanConfiguration(logger)\n", "\tcenter.FeatureConfiguration = feature.Configure(feature.Settings{Injected: []byte(`{}`), InjectedClass: feature.ClassProduction})\n\tcenter.logPlanConfiguration(logger)\n"),
		"New builds a second Settings literal":       mutate(serverFile, "\tcenter.schemaVersion.Store(-1)\n", "\t_ = feature.Settings{Injected: nil}\n\tcenter.schemaVersion.Store(-1)\n"),
		"another package injects":                    appended("internal/pages/pages.go", "var _ = feature.Settings{Injected: nil}"),
		"another package configures":                 appended("internal/pages/pages.go", "var _, _ = feature.ParseCatalogue(nil, feature.ClassProduction)"),
		"another package calls Configure":            appended("internal/pages/pages.go", "var _ = feature.Configure(feature.Settings{})"),
	}
	for name, sources := range cases {
		t.Run(name, func(t *testing.T) {
			if problems := injectionProblems(sources); len(problems) == 0 {
				t.Fatal("the pin does not see it")
			}
		})
	}
}
