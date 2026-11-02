// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The source-scan pins of the mail transport, in the style of the catalogue pin of package server: they parse the non-test sources
// of the whole center module and fail on a form that would weaken the transport, and each rule has mutants (forms injected into
// copies of the sources) that the scan must report. The scan runs on both hosts; a rule that finds nothing in the real tree is still
// checked for non-vacuity where that is meaningful.

const (
	modulePrefix  = "github.com/ArcForges/Cloud/center/"
	mailtestPath  = modulePrefix + "internal/mail/mailtest"
	mailDirectory = "internal/mail/"
	mailtestDir   = "internal/mail/mailtest/"
)

// revealAllowed are the only non-test files that may call Secret.Reveal.
var revealAllowed = []string{"internal/mail/postmark.go", "internal/mail/smtp.go"}

// Rule names, so a mutant can say which rule must report it.
const (
	ruleInsecure      = "insecure-skip-verify"
	ruleTLSPlacement  = "tls-config-outside-mail"
	ruleTLSMinVersion = "tls-config-without-minversion"
	ruleHook          = "verification-hook"
	ruleOption        = "test-only-option"
	ruleHTTP          = "forbidden-http-identifier"
	ruleEnvironment   = "environment-read"
	ruleReveal        = "reveal-caller"
	ruleImporter      = "mailtest-importer"
	ruleInRepo        = "mailtest-in-repo-import"
)

// sourceSet maps a slash-separated path relative to the module root to the source of a non-test Go file.
type sourceSet map[string][]byte

// loadSources reads every non-test Go file of the center module (not the separate tools module, not testdata).
func loadSources(t testing.TB) sourceSet {
	t.Helper()
	root := filepath.Join("..", "..")
	files := sourceSet{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == "testdata" || entry.Name() == "tools") {
			return filepath.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
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
		files[filepath.ToSlash(relative)] = data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// importName is the local name of an imported path in a file, "" when it is not imported.
func importName(file *ast.File, path, fallback string) string {
	for _, spec := range file.Imports {
		if value, err := strconv.Unquote(spec.Path.Value); err == nil && value == path {
			if spec.Name != nil {
				return spec.Name.Name
			}
			return fallback
		}
	}
	return ""
}

// selects reports whether expr is the selector pkg.name.
func selects(expr ast.Expr, pkg, name string) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != name {
		return false
	}
	ident, ok := selector.X.(*ast.Ident)
	return ok && ident.Name == pkg
}

// scanSources applies every rule to the sources and returns the findings as "rule: path: detail".
func scanSources(files sourceSet) []string {
	var findings []string
	report := func(rule, path, detail string) { findings = append(findings, rule+": "+path+": "+detail) }
	for path, source := range files {
		file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.SkipObjectResolution)
		if err != nil {
			report("parse", path, err.Error())
			continue
		}
		inMail := strings.HasPrefix(path, mailDirectory)
		inMailtest := strings.HasPrefix(path, mailtestDir)
		tlsName, httpName, osName := importName(file, "crypto/tls", "tls"), importName(file, "net/http", "http"), importName(file, "os", "os")
		for _, spec := range file.Imports {
			value, _ := strconv.Unquote(spec.Path.Value)
			if value == mailtestPath {
				report(ruleImporter, path, "a non-test file imports mailtest")
			}
			if inMailtest && strings.HasPrefix(value, modulePrefix) {
				report(ruleInRepo, path, "mailtest imports "+value)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					if selector, ok := lhs.(*ast.SelectorExpr); ok {
						switch selector.Sel.Name {
						case "InsecureSkipVerify":
							report(ruleInsecure, path, "an assignment")
						case "VerifyConnection", "VerifyPeerCertificate", "DialTLS", "DialTLSContext":
							report(ruleHook, path, "an assignment of "+selector.Sel.Name)
						case "RootCAs", "Dial", "BaseURL", "Client", "Proxy":
							if !inMail || inMailtest {
								report(ruleOption, path, "an assignment of "+selector.Sel.Name)
							}
						}
					}
				}
			case *ast.KeyValueExpr:
				if key, ok := n.Key.(*ast.Ident); ok {
					switch key.Name {
					case "InsecureSkipVerify":
						report(ruleInsecure, path, "a composite literal key")
					case "VerifyConnection", "VerifyPeerCertificate", "DialTLS", "DialTLSContext":
						report(ruleHook, path, "the key "+key.Name)
					case "RootCAs", "Dial", "BaseURL", "Client", "Proxy":
						if !inMail || inMailtest {
							report(ruleOption, path, "the key "+key.Name)
						}
					}
				}
			case *ast.SelectorExpr:
				if tlsName != "" && selects(n, tlsName, "Config") && !inMail {
					report(ruleTLSPlacement, path, "tls.Config outside internal/mail")
				}
				if httpName != "" {
					for _, name := range []string{"ProxyFromEnvironment", "DefaultClient", "DefaultTransport", "Get", "Head", "Post", "PostForm"} {
						if selects(n, httpName, name) {
							report(ruleHTTP, path, "http."+name)
						}
					}
				}
				if osName != "" && inMail {
					for _, name := range []string{"Getenv", "LookupEnv", "Environ", "ExpandEnv"} {
						if selects(n, osName, name) {
							report(ruleEnvironment, path, "os."+name)
						}
					}
				}
			case *ast.CompositeLit:
				if tlsName != "" && selects(n.Type, tlsName, "Config") {
					hasMinVersion := false
					for _, element := range n.Elts {
						if pair, ok := element.(*ast.KeyValueExpr); ok {
							if key, ok := pair.Key.(*ast.Ident); ok && key.Name == "MinVersion" {
								hasMinVersion = true
							}
						}
					}
					if !hasMinVersion {
						report(ruleTLSMinVersion, path, "a tls.Config literal without MinVersion")
					}
				}
			case *ast.CallExpr:
				if selector, ok := n.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Reveal" && !slices.Contains(revealAllowed, path) {
					report(ruleReveal, path, "Reveal is called outside the two adapters")
				}
			}
			return true
		})
	}
	slices.Sort(findings)
	return slices.Compact(findings)
}

// revealCallers lists the files that call Reveal (to show the Reveal rule is not vacuous on the real tree).
func revealCallers(files sourceSet) []string {
	var callers []string
	for path, source := range files {
		file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.SkipObjectResolution)
		if err != nil {
			continue
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Reveal" {
					callers = append(callers, path)
				}
			}
			return true
		})
	}
	slices.Sort(callers)
	return slices.Compact(callers)
}

// with returns a copy of the sources with one more file.
func (s sourceSet) with(path, source string) sourceSet {
	copied := sourceSet{}
	for key, value := range s {
		copied[key] = value
	}
	copied[path] = []byte(source)
	return copied
}

// appended returns a copy of the sources with a function added to a file that exists (a mutant of a real file).
func (s sourceSet) appended(t testing.TB, path, extra string) sourceSet {
	t.Helper()
	original, ok := s[path]
	if !ok {
		t.Fatalf("%s is not in the tree", path)
	}
	return s.with(path, string(original)+"\n"+extra)
}

// TestNoCodeWeakensTheTransport is the pin on the real tree.
func TestNoCodeWeakensTheTransport(t *testing.T) {
	files := loadSources(t)
	if _, ok := files["internal/mail/smtp.go"]; !ok {
		t.Fatal("the scan did not find the SMTP adapter: the walk is vacuous")
	}
	if findings := scanSources(files); len(findings) != 0 {
		t.Fatalf("the transport is weakened:\n%s", strings.Join(findings, "\n"))
	}
	if callers := revealCallers(files); !slices.Equal(callers, revealAllowed) {
		t.Fatalf("Reveal is called in %v, want exactly %v", callers, revealAllowed)
	}
}

// TestTheScanSeesEveryForbiddenForm injects each forbidden form into a copy of the sources, in a new file or in a copy of a real
// file, and requires the matching rule to report it. Forms that must stay legal (a read of InsecureSkipVerify, as the database
// URL check does, and the adapters' own constructor defaults) must not be reported.
func TestTheScanSeesEveryForbiddenForm(t *testing.T) {
	// The mutants need the mail package and a neighbour, not the whole module: parsing everything per mutant would take seconds.
	real := sourceSet{}
	for path, source := range loadSources(t) {
		if strings.HasPrefix(path, mailDirectory) || strings.HasPrefix(path, "internal/config/") {
			real[path] = source
		}
	}
	type mutant struct {
		name  string
		files sourceSet
		rule  string
	}
	tlsFile := func(body string) string {
		return "package other\n\nimport \"crypto/tls\"\n\nvar _ = tls.VersionTLS12\n\nfunc f() {\n" + body + "\n}\n"
	}
	httpFile := func(body string) string {
		return "package other\n\nimport \"net/http\"\n\nfunc f() {\n" + body + "\n}\n"
	}
	mutants := []mutant{
		{"assignment of InsecureSkipVerify", real.with("internal/server/x.go", tlsFile("c := &tls.Config{MinVersion: tls.VersionTLS12}\nc.InsecureSkipVerify = true")), ruleInsecure},
		{"key InsecureSkipVerify in the adapter", real.appended(t, "internal/mail/postmark.go", "var _ = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}"), ruleInsecure},
		{"key InsecureSkipVerify in mailtest", real.with("internal/mail/mailtest/x.go", tlsFile("_ = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}")), ruleInsecure},
		{"VerifyConnection hook", real.appended(t, "internal/mail/postmark.go", "var _ = &tls.Config{MinVersion: tls.VersionTLS12, VerifyConnection: nil}"), ruleHook},
		{"VerifyPeerCertificate hook", real.appended(t, "internal/mail/smtp.go", "var _ = &tls.Config{MinVersion: tls.VersionTLS12, VerifyPeerCertificate: nil}"), ruleHook},
		{"DialTLSContext assigned", real.with("internal/mail/x.go", httpFile("var t http.Transport\nt.DialTLSContext = nil")), ruleHook},
		{"DialTLS key", real.appended(t, "internal/mail/postmark.go", "var _ = &http.Transport{DialTLS: nil}"), ruleHook},
		{"tls.Config outside the mail package", real.with("internal/server/x.go", tlsFile("_ = &tls.Config{MinVersion: tls.VersionTLS12}")), ruleTLSPlacement},
		{"a tls.Config variable outside the mail package", real.with("internal/server/x.go", tlsFile("var c tls.Config\n_ = c")), ruleTLSPlacement},
		{"tls.Config without MinVersion", real.appended(t, "internal/mail/smtp.go", "var _ = &tls.Config{ServerName: \"x\"}"), ruleTLSMinVersion},
		{"RootCAs key outside the mail package", real.with("internal/server/x.go", "package other\n\ntype o struct{ RootCAs int }\n\nvar _ = o{RootCAs: 1}\n"), ruleOption},
		{"Dial key outside the mail package", real.with("internal/identity/x.go", "package other\n\ntype o struct{ Dial int }\n\nvar _ = o{Dial: 1}\n"), ruleOption},
		{"BaseURL assigned outside the mail package", real.with("internal/server/x.go", "package other\n\ntype o struct{ BaseURL string }\n\nfunc f(p *o) { p.BaseURL = \"x\" }\n"), ruleOption},
		{"Client key outside the mail package", real.with("internal/server/x.go", "package other\n\ntype o struct{ Client int }\n\nvar _ = o{Client: 1}\n"), ruleOption},
		{"Proxy key in mailtest", real.with("internal/mail/mailtest/x.go", "package mailtest\n\ntype o struct{ Proxy int }\n\nvar _ = o{Proxy: 1}\n"), ruleOption},
		{"RootCAs key in mailtest", real.with("internal/mail/mailtest/x.go", "package mailtest\n\ntype o struct{ RootCAs int }\n\nvar _ = o{RootCAs: 1}\n"), ruleOption},
		{"ProxyFromEnvironment", real.appended(t, "internal/mail/postmark.go", "var _ = http.ProxyFromEnvironment"), ruleHTTP},
		{"ProxyFromEnvironment as a key", real.appended(t, "internal/mail/postmark.go", "var _ = &http.Transport{Proxy: http.ProxyFromEnvironment}"), ruleHTTP},
		{"DefaultClient", real.with("internal/server/x.go", httpFile("_ = http.DefaultClient")), ruleHTTP},
		{"DefaultTransport", real.with("internal/server/x.go", httpFile("_ = http.DefaultTransport")), ruleHTTP},
		{"http.Get", real.with("internal/server/x.go", httpFile("_, _ = http.Get(\"x\")")), ruleHTTP},
		{"http.Post", real.with("internal/server/x.go", httpFile("_, _ = http.Post(\"x\", \"\", nil)")), ruleHTTP},
		{"http.PostForm", real.with("internal/server/x.go", httpFile("_, _ = http.PostForm(\"x\", nil)")), ruleHTTP},
		{"aliased net/http", real.with("internal/server/x.go", "package other\n\nimport h \"net/http\"\n\nvar _ = h.DefaultClient\n"), ruleHTTP},
		{"os.Getenv in the package", real.with("internal/mail/y.go", "package mail\n\nimport \"os\"\n\nvar _ = os.Getenv\n"), ruleEnvironment},
		{"os.LookupEnv in the package", real.with("internal/mail/x.go", "package mail\n\nimport \"os\"\n\nvar _ = os.LookupEnv\n"), ruleEnvironment},
		{"os.Environ in mailtest", real.with("internal/mail/mailtest/x.go", "package mailtest\n\nimport \"os\"\n\nvar _ = os.Environ\n"), ruleEnvironment},
		{"Reveal in the identity package", real.with("internal/identity/deliver.go", "package identity\n\nfunc f(s interface{ Reveal() string }) { _ = s.Reveal() }\n"), ruleReveal},
		{"Reveal inside a log call", real.with("internal/server/x.go", "package other\n\nfunc f(s interface{ Reveal() string }, log func(...any)) { log(\"token\", s.Reveal()) }\n"), ruleReveal},
		{"Reveal in the mail package outside the adapters", real.appended(t, "internal/mail/guard.go", "func leak(s interface{ Reveal() string }) string { return s.Reveal() }"), ruleReveal},
		{"mailtest imported by the server", real.with("internal/server/x.go", "package other\n\nimport _ \""+mailtestPath+"\"\n"), ruleImporter},
		{"mailtest imported by the mail package", real.with("internal/mail/x.go", "package mail\n\nimport _ \""+mailtestPath+"\"\n"), ruleImporter},
		{"mailtest importing the mail package", real.with("internal/mail/mailtest/x.go", "package mailtest\n\nimport _ \""+modulePrefix+"internal/mail\"\n"), ruleInRepo},
		{"mailtest importing config", real.with("internal/mail/mailtest/x.go", "package mailtest\n\nimport _ \""+modulePrefix+"internal/config\"\n"), ruleInRepo},
	}
	for _, m := range mutants {
		found := false
		for _, finding := range scanSources(m.files) {
			if strings.HasPrefix(finding, m.rule+": ") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: rule %s did not report it", m.name, m.rule)
		}
	}
	legal := []struct{ name, path, source string }{
		{"a read of InsecureSkipVerify", "internal/config/x.go", "package config\n\ntype c struct{ InsecureSkipVerify bool }\n\nfunc f(v *c) bool { return !v.InsecureSkipVerify }\n"},
		{"Proxy nil in the adapter", "internal/mail/x.go", "package mail\n\ntype t struct{ Proxy func() }\n\nvar _ = t{Proxy: nil}\n"},
		{"a RootCAs key in the adapter", "internal/mail/x.go", "package mail\n\nimport \"crypto/tls\"\n\nvar _ = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: nil}\n"},
		{"tls.Config in mailtest with MinVersion", "internal/mail/mailtest/x.go", "package mailtest\n\nimport \"crypto/tls\"\n\nvar _ = &tls.Config{MinVersion: tls.VersionTLS12}\n"},
		{"a Reveal definition", "internal/config/x.go", "package config\n\ntype s struct{}\n\nfunc (s) Reveal() string { return \"\" }\n"},
		{"os.Getenv outside the mail package", "internal/pgtest/x.go", "package pgtest\n\nimport \"os\"\n\nvar _ = os.Getenv\n"},
		{"a mailtest import of the standard library", "internal/mail/mailtest/x.go", "package mailtest\n\nimport _ \"testing\"\n"},
	}
	for _, l := range legal {
		if findings := scanSources(real.with(l.path, l.source)); len(findings) != 0 {
			t.Errorf("%s is reported: %v", l.name, findings)
		}
	}
}

// TestRevealRuleIsNotVacuous: the two adapters do call Reveal, so an empty finding list for Reveal means the rule ran.
func TestRevealRuleIsNotVacuous(t *testing.T) {
	files := loadSources(t)
	for _, path := range revealAllowed {
		if !slices.Contains(revealCallers(files), path) {
			t.Errorf("%s no longer calls Reveal: the allowed list or the adapter changed", path)
		}
	}
}
