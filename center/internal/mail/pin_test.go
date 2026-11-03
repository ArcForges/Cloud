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
// of the whole center module and report the forms listed below, and each rule has mutants (forms injected into copies of the
// sources) that the scan must report. The scan runs on both hosts.
//
// What it scans (and nothing more is claimed): no certificate-verification bypass or hook (InsecureSkipVerify assigned, keyed or
// address-taken; VerifyConnection, VerifyPeerCertificate, DialTLS, DialTLSContext); tls.Config only inside internal/mail, only as a
// literal there, whose MinVersion is tls.VersionTLS12 or tls.VersionTLS13 and whose other keys are on an allow-list, and no later
// assignment of MinVersion, CipherSuites, Renegotiation or KeyLogWriter outside the test double; the test-only options RootCAs,
// Dial, BaseURL, Client and Proxy (and Now in package mail) set, by key or by assignment (parentheses included), only in smtp.go and
// postmark.go, the adapters' own files, and in New by no key, assignment or positional literal (TestNewSetsNoTestOnlyOption, backed
// by the behavioural checks of new_test.go); no environment proxy, default HTTP client or default transport,
// no http.Get-style helper; no environment read in internal/mail; net/smtp imported only by smtp.go; no dot import of the packages
// above; Secret.Reveal referenced (called or taken as a method value) only in the two adapters; mailtest imported by no non-test file
// and importing nothing of this repository.
//
// What it does NOT scan: reflection by string name (reflect FieldByName or MethodByName), encoding into a configuration
// (json.Unmarshal into a tls.Config), the contents of package config itself (its own field p), and the effective values of a
// transport or configuration at run time: those are the job of the behavioural tests (the TLS floor, the proxy, the certificate
// tests) and of the review.

const (
	modulePrefix  = "github.com/ArcForges/Cloud/center/"
	mailtestPath  = modulePrefix + "internal/mail/mailtest"
	mailDirectory = "internal/mail/"
	mailtestDir   = "internal/mail/mailtest/"
	smtpFile      = "internal/mail/smtp.go"
	postmarkFile  = "internal/mail/postmark.go"
)

// revealAllowed are the only non-test files that may reference Secret.Reveal.
var revealAllowed = []string{"internal/mail/postmark.go", "internal/mail/smtp.go"}

// Rule names, so a mutant can say which rule must report it.
const (
	ruleInsecure      = "insecure-skip-verify"
	ruleTLSPlacement  = "tls-config-outside-mail"
	ruleTLSLiteral    = "tls-config-not-a-literal"
	ruleTLSMinVersion = "tls-config-min-version"
	ruleTLSKey        = "tls-config-key"
	ruleTLSAssign     = "tls-config-assignment"
	ruleHook          = "verification-hook"
	ruleOption        = "test-only-option"
	ruleHTTP          = "forbidden-http-identifier"
	ruleEnvironment   = "environment-read"
	ruleReveal        = "reveal-reference"
	ruleImporter      = "mailtest-importer"
	ruleInRepo        = "mailtest-in-repo-import"
	ruleSMTP          = "second-smtp-path"
	ruleDotImport     = "dot-import"
)

// sourceSet maps a slash-separated path relative to the module root to the source of a non-test Go file.
type sourceSet map[string][]byte

// loadSources reads every non-test Go file of the center module.
func loadSources(t testing.TB) sourceSet { return loadSourcesFrom(t, filepath.Join("..", "..")) }

// loadSourcesFrom reads every non-test Go file under root. It skips a directory named testdata (the go tool ignores it) and a
// nested module (a directory with its own go.mod, such as center/tools, which the go tool does not build with this module); it does
// NOT skip a directory merely because of its name, so a package named tools below internal is scanned like any other.
func loadSourcesFrom(t testing.TB, root string) sourceSet {
	t.Helper()
	files := sourceSet{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			if path != root {
				if _, statErr := os.Stat(filepath.Join(path, "go.mod")); statErr == nil {
					return filepath.SkipDir
				}
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
		files[filepath.ToSlash(relative)] = data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// localNames returns every local name under which a file imports a path (a file may import it twice, under two names), "." for a
// dot import.
func localNames(file *ast.File, path, fallback string) []string {
	var names []string
	for _, spec := range file.Imports {
		if value, err := strconv.Unquote(spec.Path.Value); err == nil && value == path {
			if spec.Name != nil {
				names = append(names, spec.Name.Name)
			} else {
				names = append(names, fallback)
			}
		}
	}
	return names
}

// selects reports whether expr is the selector pkg.name for one of the local names of pkg.
func selects(expr ast.Expr, pkgs []string, name string) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != name {
		return false
	}
	ident, ok := selector.X.(*ast.Ident)
	return ok && slices.Contains(pkgs, ident.Name)
}

// minVersionOK reports whether expr is the selector tls.VersionTLS12 or tls.VersionTLS13.
func minVersionOK(expr ast.Expr, tlsNames []string) bool {
	return selects(expr, tlsNames, "VersionTLS12") || selects(expr, tlsNames, "VersionTLS13")
}

// tlsKeys are the keys a tls.Config literal may have: the adapters' (ServerName, MinVersion, RootCAs) and the test double's
// (Certificates, MinVersion).
var tlsKeys = []string{"ServerName", "MinVersion", "RootCAs", "Certificates"}

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
		tlsNames, httpNames := localNames(file, "crypto/tls", "tls"), localNames(file, "net/http", "http")
		osNames, syscallNames := localNames(file, "os", "os"), localNames(file, "syscall", "syscall")
		for _, spec := range file.Imports {
			value, _ := strconv.Unquote(spec.Path.Value)
			if value == mailtestPath {
				report(ruleImporter, path, "a non-test file imports mailtest")
			}
			if inMailtest && strings.HasPrefix(value, modulePrefix) {
				report(ruleInRepo, path, "mailtest imports "+value)
			}
			if value == "net/smtp" && path != smtpFile {
				report(ruleSMTP, path, "net/smtp is imported outside "+smtpFile)
			}
			if spec.Name != nil && spec.Name.Name == "." && (value == "crypto/tls" || value == "net/http" || value == "os" || value == "syscall") {
				report(ruleDotImport, path, "a dot import of "+value)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					selector, ok := unparen(lhs).(*ast.SelectorExpr)
					if !ok {
						continue
					}
					switch selector.Sel.Name {
					case "InsecureSkipVerify":
						report(ruleInsecure, path, "an assignment")
					case "VerifyConnection", "VerifyPeerCertificate", "DialTLS", "DialTLSContext":
						report(ruleHook, path, "an assignment of "+selector.Sel.Name)
					case "MinVersion", "CipherSuites", "Renegotiation", "KeyLogWriter":
						if !inMailtest {
							report(ruleTLSAssign, path, "an assignment of "+selector.Sel.Name)
						}
					case "RootCAs", "Dial", "BaseURL", "Client", "Proxy":
						if path != smtpFile && path != postmarkFile {
							report(ruleOption, path, "an assignment of "+selector.Sel.Name)
						}
					case "Now":
						if inMail && path != smtpFile && path != postmarkFile {
							report(ruleOption, path, "an assignment of Now")
						}
					}
				}
			case *ast.UnaryExpr:
				if selector, ok := n.X.(*ast.SelectorExpr); ok && n.Op == token.AND && selector.Sel.Name == "InsecureSkipVerify" {
					report(ruleInsecure, path, "its address is taken")
				}
			case *ast.KeyValueExpr:
				if key, ok := n.Key.(*ast.Ident); ok {
					switch key.Name {
					case "InsecureSkipVerify":
						report(ruleInsecure, path, "a composite literal key")
					case "VerifyConnection", "VerifyPeerCertificate", "DialTLS", "DialTLSContext":
						report(ruleHook, path, "the key "+key.Name)
					case "RootCAs", "Dial", "BaseURL", "Client", "Proxy":
						if path != smtpFile && path != postmarkFile {
							report(ruleOption, path, "the key "+key.Name)
						}
					case "Now":
						if inMail && path != smtpFile && path != postmarkFile {
							report(ruleOption, path, "the key Now")
						}
					}
				}
			case *ast.SelectorExpr:
				if selects(n, tlsNames, "Config") && !inMail {
					report(ruleTLSPlacement, path, "tls.Config outside internal/mail")
				}
				for _, name := range []string{"ProxyFromEnvironment", "DefaultClient", "DefaultTransport", "Get", "Head", "Post", "PostForm"} {
					if selects(n, httpNames, name) {
						report(ruleHTTP, path, "http."+name)
					}
				}
				if inMail {
					for _, name := range []string{"Getenv", "LookupEnv", "Environ", "ExpandEnv"} {
						if selects(n, osNames, name) {
							report(ruleEnvironment, path, "os."+name)
						}
					}
					for _, name := range []string{"Getenv", "Environ", "Setenv"} {
						if selects(n, syscallNames, name) {
							report(ruleEnvironment, path, "syscall."+name)
						}
					}
				}
				if n.Sel.Name == "Reveal" && !slices.Contains(revealAllowed, path) {
					report(ruleReveal, path, "Reveal is referenced outside the two adapters")
				}
			case *ast.CallExpr:
				// new(tls.Config) and a conversion tls.Config(x) build a configuration that no literal check sees.
				if ident, ok := n.Fun.(*ast.Ident); ok && ident.Name == "new" && len(n.Args) == 1 && selects(n.Args[0], tlsNames, "Config") ||
					selects(n.Fun, tlsNames, "Config") {
					report(ruleTLSLiteral, path, "tls.Config is built by new or a conversion, not by a composite literal")
				}
			case *ast.ValueSpec:
				if selects(n.Type, tlsNames, "Config") {
					report(ruleTLSLiteral, path, "a variable of type tls.Config is not built by a composite literal")
				}
			case *ast.CompositeLit:
				if selects(n.Type, tlsNames, "Config") {
					hasMinVersion := false
					for _, element := range n.Elts {
						pair, ok := element.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						key, ok := pair.Key.(*ast.Ident)
						if !ok {
							continue
						}
						if !slices.Contains(tlsKeys, key.Name) && key.Name != "InsecureSkipVerify" && key.Name != "VerifyConnection" && key.Name != "VerifyPeerCertificate" {
							report(ruleTLSKey, path, "tls.Config key "+key.Name+" is not on the allow-list")
						}
						if key.Name == "MinVersion" {
							hasMinVersion = true
							if !minVersionOK(pair.Value, tlsNames) {
								report(ruleTLSMinVersion, path, "MinVersion is not tls.VersionTLS12 or tls.VersionTLS13")
							}
						}
					}
					if !hasMinVersion {
						report(ruleTLSMinVersion, path, "a tls.Config literal without MinVersion")
					}
				}
			}
			return true
		})
	}
	slices.Sort(findings)
	return slices.Compact(findings)
}

// revealReferences lists the files that reference Reveal (called or not), to show the Reveal rule is not vacuous on the real tree.
func revealReferences(files sourceSet) []string {
	var callers []string
	for path, source := range files {
		file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.SkipObjectResolution)
		if err != nil {
			continue
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if selector, ok := node.(*ast.SelectorExpr); ok && selector.Sel.Name == "Reveal" {
				callers = append(callers, path)
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

// appended returns a copy of the sources with a declaration added to a file that exists (a mutant of a real file).
func (s sourceSet) appended(t testing.TB, path, extra string) sourceSet {
	t.Helper()
	original, ok := s[path]
	if !ok {
		t.Fatalf("%s is not in the tree", path)
	}
	return s.with(path, string(original)+"\n"+extra)
}

// TestTransportSourcesObeyTheScannedRules is the pin on the real tree (see the comment at the top of the file for what it covers
// and what it does not).
func TestTransportSourcesObeyTheScannedRules(t *testing.T) {
	files := loadSources(t)
	if _, ok := files[smtpFile]; !ok {
		t.Fatal("the scan did not find the SMTP adapter: the walk is vacuous")
	}
	if findings := scanSources(files); len(findings) != 0 {
		t.Fatalf("a scanned rule is broken:\n%s", strings.Join(findings, "\n"))
	}
	if callers := revealReferences(files); !slices.Equal(callers, revealAllowed) {
		t.Fatalf("Reveal is referenced in %v, want exactly %v", callers, revealAllowed)
	}
}

// TestTheWalkSkipsOnlyNestedModulesAndTestdata (LG-5): a directory named tools is scanned like any other, a directory with its own
// go.mod and a testdata directory are not.
func TestTheWalkSkipsOnlyNestedModulesAndTestdata(t *testing.T) {
	root := t.TempDir()
	write := func(path, text string) {
		t.Helper()
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example\n")
	write("main.go", "package main\n")
	write("internal/server/tools/x.go", "package tools\n")
	write("internal/server/testdata/y.go", "package y\n")
	write("internal/server/y_test.go", "package server\n")
	write("tools/go.mod", "module example/tools\n")
	write("tools/z.go", "package z\n")
	got := loadSourcesFrom(t, root)
	keys := make([]string, 0, len(got))
	for key := range got {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if want := []string{"internal/server/tools/x.go", "main.go"}; !slices.Equal(keys, want) {
		t.Fatalf("loaded %v, want %v", keys, want)
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
		{"the address of InsecureSkipVerify", real.with("internal/mail/x.go", tlsFile("var c = &tls.Config{MinVersion: tls.VersionTLS12}\np := &c.InsecureSkipVerify\n*p = true")), ruleInsecure},
		{"VerifyConnection hook", real.appended(t, "internal/mail/postmark.go", "var _ = &tls.Config{MinVersion: tls.VersionTLS12, VerifyConnection: nil}"), ruleHook},
		{"VerifyPeerCertificate hook", real.appended(t, "internal/mail/smtp.go", "var _ = &tls.Config{MinVersion: tls.VersionTLS12, VerifyPeerCertificate: nil}"), ruleHook},
		{"DialTLSContext assigned", real.with("internal/mail/x.go", httpFile("var t http.Transport\nt.DialTLSContext = nil")), ruleHook},
		{"DialTLS key", real.appended(t, "internal/mail/postmark.go", "var _ = &http.Transport{DialTLS: nil}"), ruleHook},
		{"tls.Config outside the mail package", real.with("internal/server/x.go", tlsFile("_ = &tls.Config{MinVersion: tls.VersionTLS12}")), ruleTLSPlacement},
		{"a tls.Config variable outside the mail package", real.with("internal/server/x.go", tlsFile("var c tls.Config\n_ = c")), ruleTLSPlacement},
		{"new(tls.Config) outside the mail package", real.with("internal/server/x.go", tlsFile("_ = new(tls.Config)")), ruleTLSPlacement},
		{"an aliased second import of crypto/tls", real.with("internal/server/x.go", "package other\n\nimport (\n\t\"crypto/tls\"\n\tt2 \"crypto/tls\"\n)\n\nvar _ = tls.VersionTLS12\nvar _ = t2.Config{}\n"), ruleTLSPlacement},
		{"new(tls.Config) inside the mail package", real.appended(t, "internal/mail/smtp.go", "var _ = new(tls.Config)"), ruleTLSLiteral},
		{"a tls.Config variable inside the mail package", real.appended(t, "internal/mail/smtp.go", "var weak tls.Config"), ruleTLSLiteral},
		{"tls.Config without MinVersion", real.appended(t, "internal/mail/smtp.go", "var _ = &tls.Config{ServerName: \"x\"}"), ruleTLSMinVersion},
		{"MinVersion TLS 1.0", real.appended(t, "internal/mail/smtp.go", "var _ = &tls.Config{MinVersion: tls.VersionTLS10}"), ruleTLSMinVersion},
		{"MinVersion TLS 1.1", real.appended(t, "internal/mail/postmark.go", "var _ = &tls.Config{MinVersion: tls.VersionTLS11}"), ruleTLSMinVersion},
		{"MinVersion SSL 3.0", real.appended(t, "internal/mail/postmark.go", "var _ = &tls.Config{MinVersion: tls.VersionSSL30}"), ruleTLSMinVersion},
		{"MinVersion zero", real.appended(t, "internal/mail/smtp.go", "var _ = &tls.Config{MinVersion: 0}"), ruleTLSMinVersion},
		{"MinVersion a constant", real.appended(t, "internal/mail/smtp.go", "const weakVersion = tls.VersionTLS10\n\nvar _ = &tls.Config{MinVersion: weakVersion}"), ruleTLSMinVersion},
		{"MinVersion assigned later", real.appended(t, "internal/mail/smtp.go", "func weaken(c *tls.Config) { c.MinVersion = tls.VersionTLS10 }"), ruleTLSAssign},
		{"CipherSuites assigned later", real.appended(t, "internal/mail/smtp.go", "func weaken(c *tls.Config) { c.CipherSuites = nil }"), ruleTLSAssign},
		{"a key logger in the literal", real.appended(t, "internal/mail/smtp.go", "var _ = &tls.Config{MinVersion: tls.VersionTLS12, KeyLogWriter: nil}"), ruleTLSKey},
		{"a cipher list in the literal", real.appended(t, "internal/mail/postmark.go", "var _ = &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: nil}"), ruleTLSKey},
		{"renegotiation in the literal", real.appended(t, "internal/mail/postmark.go", "var _ = &tls.Config{MinVersion: tls.VersionTLS12, Renegotiation: tls.RenegotiateFreelyAsClient}"), ruleTLSKey},
		{"RootCAs key outside the mail package", real.with("internal/server/x.go", "package other\n\ntype o struct{ RootCAs int }\n\nvar _ = o{RootCAs: 1}\n"), ruleOption},
		{"Dial key outside the mail package", real.with("internal/identity/x.go", "package other\n\ntype o struct{ Dial int }\n\nvar _ = o{Dial: 1}\n"), ruleOption},
		{"BaseURL assigned outside the mail package", real.with("internal/server/x.go", "package other\n\ntype o struct{ BaseURL string }\n\nfunc f(p *o) { p.BaseURL = \"x\" }\n"), ruleOption},
		{"Client key outside the mail package", real.with("internal/server/x.go", "package other\n\ntype o struct{ Client int }\n\nvar _ = o{Client: 1}\n"), ruleOption},
		{"RootCAs assigned in a sibling file of package mail", real.appended(t, "internal/mail/guard.go", "func relaxed(c *struct{ RootCAs int }) { c.RootCAs = 1 }"), ruleOption},
		{"RootCAs assigned in parentheses in a sibling file", real.appended(t, "internal/mail/guard.go", "func relaxed(c *struct{ RootCAs int }) { (c.RootCAs) = 1 }"), ruleOption},
		{"Dial key in a sibling file of package mail", real.appended(t, "internal/mail/guard.go", "var _ = struct{ Dial int }{Dial: 1}"), ruleOption},
		{"Now key in a sibling file of package mail", real.appended(t, "internal/mail/guard.go", "var _ = struct{ Now int }{Now: 1}"), ruleOption},
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
		{"a dot import of net/http", real.with("internal/server/x.go", "package other\n\nimport . \"net/http\"\n\nvar _ = DefaultClient\n"), ruleDotImport},
		{"a dot import of crypto/tls", real.with("internal/mail/x.go", "package mail\n\nimport . \"crypto/tls\"\n\nvar _ = &Config{}\n"), ruleDotImport},
		{"a dot import of os in the mail package", real.with("internal/mail/x.go", "package mail\n\nimport . \"os\"\n\nvar _ = Getenv\n"), ruleDotImport},
		{"os.Getenv in the package", real.with("internal/mail/y.go", "package mail\n\nimport \"os\"\n\nvar _ = os.Getenv\n"), ruleEnvironment},
		{"os.LookupEnv in the package", real.with("internal/mail/x.go", "package mail\n\nimport \"os\"\n\nvar _ = os.LookupEnv\n"), ruleEnvironment},
		{"os.Environ in mailtest", real.with("internal/mail/mailtest/x.go", "package mailtest\n\nimport \"os\"\n\nvar _ = os.Environ\n"), ruleEnvironment},
		{"syscall.Getenv in the package", real.with("internal/mail/x.go", "package mail\n\nimport \"syscall\"\n\nvar _ = syscall.Getenv\n"), ruleEnvironment},
		{"net/smtp imported by the server", real.with("internal/server/x.go", "package other\n\nimport _ \"net/smtp\"\n"), ruleSMTP},
		{"net/smtp imported by another file of the mail package", real.with("internal/mail/x.go", "package mail\n\nimport \"net/smtp\"\n\nvar _ = smtp.SendMail\n"), ruleSMTP},
		{"Reveal in the identity package", real.with("internal/identity/deliver.go", "package identity\n\nfunc f(s interface{ Reveal() string }) { _ = s.Reveal() }\n"), ruleReveal},
		{"Reveal inside a log call", real.with("internal/server/x.go", "package other\n\nfunc f(s interface{ Reveal() string }, log func(...any)) { log(\"token\", s.Reveal()) }\n"), ruleReveal},
		{"Reveal as a method value", real.with("internal/identity/deliver.go", "package identity\n\nfunc f(s interface{ Reveal() string }) string { g := s.Reveal; return g() }\n"), ruleReveal},
		{"Reveal passed as a method value", real.with("internal/server/x.go", "package other\n\nfunc f(s interface{ Reveal() string }, use func(func() string)) { use(s.Reveal) }\n"), ruleReveal},
		{"Reveal in the mail package outside the adapters", real.appended(t, "internal/mail/guard.go", "func leak(s interface{ Reveal() string }) string { return s.Reveal() }"), ruleReveal},
		{"mailtest imported by the server", real.with("internal/server/x.go", "package other\n\nimport _ \""+mailtestPath+"\"\n"), ruleImporter},
		{"mailtest imported by the mail package", real.with("internal/mail/x.go", "package mail\n\nimport _ \""+mailtestPath+"\"\n"), ruleImporter},
		{"mailtest importing the mail package", real.with("internal/mail/mailtest/x.go", "package mailtest\n\nimport _ \""+modulePrefix+"internal/mail\"\n"), ruleInRepo},
		{"mailtest importing config", real.with("internal/mail/mailtest/x.go", "package mailtest\n\nimport _ \""+modulePrefix+"internal/config\"\n"), ruleInRepo},
		{"a package named tools below internal", real.with("internal/mail/tools/x.go", tlsFile("_ = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}")), ruleInsecure},
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
		{"Proxy nil in the adapter", "internal/mail/postmark.go", "package mail\n\ntype t struct{ Proxy func() }\n\nvar _ = t{Proxy: nil}\n"},
		{"a RootCAs key in the adapter", "internal/mail/postmark.go", "package mail\n\nimport \"crypto/tls\"\n\nvar _ = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: nil}\n"},
		{"TLS 1.3 as the floor", "internal/mail/x.go", "package mail\n\nimport \"crypto/tls\"\n\nvar _ = &tls.Config{MinVersion: tls.VersionTLS13}\n"},
		{"tls.Config in mailtest with MinVersion and certificates", "internal/mail/mailtest/x.go", "package mailtest\n\nimport \"crypto/tls\"\n\nvar _ = &tls.Config{Certificates: nil, MinVersion: tls.VersionTLS12}\n"},
		{"the test double weakening its own server", "internal/mail/mailtest/x.go", "package mailtest\n\nimport \"crypto/tls\"\n\nfunc f(c *tls.Config) { c.MinVersion, c.MaxVersion = tls.VersionTLS10, tls.VersionTLS11 }\n"},
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

// TestRevealRuleIsNotVacuous: the two adapters do reference Reveal, so an empty finding list for Reveal means the rule ran.
func TestRevealRuleIsNotVacuous(t *testing.T) {
	files := loadSources(t)
	for _, path := range revealAllowed {
		if !slices.Contains(revealReferences(files), path) {
			t.Errorf("%s no longer references Reveal: the allowed list or the adapter changed", path)
		}
	}
}

// testOnlyOptions are the options of the adapters that only tests set.
var testOnlyOptions = []string{"RootCAs", "Dial", "BaseURL", "Client", "Proxy", "Now"}

// unparen removes the parentheses around an expression: (o.RootCAs) = x assigns the field like o.RootCAs = x.
func unparen(expression ast.Expr) ast.Expr {
	for {
		paren, ok := expression.(*ast.ParenExpr)
		if !ok {
			return expression
		}
		expression = paren.X
	}
}

// newSetsTestOnlyOptions lists the test-only options that the function New of internal/mail/new.go sets, as a key of a literal or by
// assignment; it fails the pin when the function does not exist (a vacuous pin).
func newSetsTestOnlyOptions(t testing.TB, files sourceSet) []string {
	t.Helper()
	source, ok := files["internal/mail/new.go"]
	if !ok {
		t.Fatal("internal/mail/new.go is not in the tree")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "new.go", source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	var seenNew bool
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "New" || function.Recv != nil {
			continue
		}
		seenNew = true
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.KeyValueExpr:
				if key, ok := n.Key.(*ast.Ident); ok && slices.Contains(testOnlyOptions, key.Name) {
					found = append(found, key.Name)
				}
			case *ast.CompositeLit:
				// A positional literal of an options type sets every field by position, the test-only ones included.
				if name, ok := n.Type.(*ast.Ident); ok && strings.HasSuffix(name.Name, "Options") {
					for _, element := range n.Elts {
						if _, keyed := element.(*ast.KeyValueExpr); !keyed {
							found = append(found, "a positional "+name.Name)
							break
						}
					}
				}
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					if selector, ok := unparen(lhs).(*ast.SelectorExpr); ok && slices.Contains(testOnlyOptions, selector.Sel.Name) {
						found = append(found, selector.Sel.Name)
					}
				}
			}
			return true
		})
	}
	if !seenNew {
		t.Fatal("new.go has no function New")
	}
	return found
}

// TestNewSetsNoTestOnlyOption is the pin of the production constructor: it builds the adapters with the system roots, a plain
// dialer, the constant endpoint and their own transport. The scan of the whole module allows these options inside package mail (the
// adapters' own defaults read them), so this check is the one that keeps the constructor itself clean.
func TestNewSetsNoTestOnlyOption(t *testing.T) {
	files := loadSources(t)
	if found := newSetsTestOnlyOptions(t, files); len(found) != 0 {
		t.Fatalf("New sets the test-only options %v", found)
	}
	original := string(files["internal/mail/new.go"])
	for name, mutated := range map[string]string{
		"a Client key":               strings.Replace(original, "Timeout: m.Timeout})), nil\n\tcase config.MailSMTP", "Timeout: m.Timeout, Client: nil})), nil\n\tcase config.MailSMTP", 1),
		"a RootCAs key":              strings.Replace(original, "FromName: m.FromName, Timeout: m.Timeout})), nil\n\t}", "FromName: m.FromName, Timeout: m.Timeout, RootCAs: nil})), nil\n\t}", 1),
		"a Now key":                  strings.Replace(original, "FromName: m.FromName, Timeout: m.Timeout})), nil\n\t}", "FromName: m.FromName, Timeout: m.Timeout, Now: nil})), nil\n\t}", 1),
		"a positional literal":       strings.Replace(original, "SMTPOptions{Host: m.SMTPHost, Port: m.SMTPPort, Mode: mode, Username: m.SMTPUsername, Password: m.SMTPPassword,\n\t\t\tFrom: m.From, FromName: m.FromName, Timeout: m.Timeout}", "SMTPOptions{m.SMTPHost, m.SMTPPort, mode, m.SMTPUsername, m.SMTPPassword, m.From, m.FromName, \"\", m.Timeout, nil, nil, nil}", 1),
		"a parenthesised assignment": strings.Replace(original, "var mode SMTPMode", "var mode SMTPMode\n\t\tvar o SMTPOptions\n\t\t(o.RootCAs) = nil", 1),
		"a Dial key":                 strings.Replace(original, "FromName: m.FromName, Timeout: m.Timeout})), nil\n\t}", "FromName: m.FromName, Timeout: m.Timeout, Dial: nil})), nil\n\t}", 1),
		"a BaseURL key":              strings.Replace(original, "Stream: m.PostmarkStream,", "Stream: m.PostmarkStream, BaseURL: \"http://127.0.0.1:1/\",", 1),
		"an assignment":              strings.Replace(original, "var mode SMTPMode", "var mode SMTPMode\n\t\tvar o SMTPOptions\n\t\to.RootCAs = nil", 1),
		"a Proxy assignment":         strings.Replace(original, "var mode SMTPMode", "var mode SMTPMode\n\t\tvar tr struct{ Proxy int }\n\t\ttr.Proxy = 1", 1),
	} {
		if mutated == original {
			t.Fatalf("%s: the mutant did not apply", name)
		}
		if found := newSetsTestOnlyOptions(t, files.with("internal/mail/new.go", mutated)); len(found) == 0 {
			t.Errorf("%s: the pin did not see it", name)
		}
	}
}
