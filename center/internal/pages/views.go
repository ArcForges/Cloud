// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"strings"
	"time"
)

// The pages' templates, script and style sheet are embedded: a self-hosted center serves them without any Web deployment, and
// nothing is loaded from anywhere else (the content security policy admits no other source).
var (
	//go:embed templates/*.gohtml
	templateFiles embed.FS
	//go:embed static/account.js static/account.css
	staticFiles embed.FS
)

// pageNames are the templates; each is a content template laid out by base.html.
var pageNames = []string{"sign-in", "bootstrap", "sign-out", "passkeys", "sessions", "devices", "register", "error"}

// views are the parsed templates and the static files.
type views struct {
	base      string
	templates map[string]*template.Template
	script    []byte
	style     []byte
}

func loadViews(basePath string) (*views, error) {
	result := &views{base: basePath, templates: map[string]*template.Template{}}
	for _, name := range pageNames {
		parsed, err := template.New("base").ParseFS(templateFiles, "templates/base.gohtml", "templates/"+name+".gohtml")
		if err != nil {
			return nil, fmt.Errorf("the %s template: %w", name, err)
		}
		result.templates[name] = parsed
	}
	var err error
	if result.script, err = staticFiles.ReadFile("static/account.js"); err != nil {
		return nil, err
	}
	if result.style, err = staticFiles.ReadFile("static/account.css"); err != nil {
		return nil, err
	}
	return result, nil
}

// errorView is the text of the error summary a page shows.
type errorView struct{ Text string }

// pageData is everything a template reads.
type pageData struct {
	Title  string
	Page   string
	Base   string
	CSRF   string
	Signed bool
	Error  *errorView

	// The error page.
	Heading  string
	Detail   string
	Back     string
	BackText string

	// The account and passkeys page.
	Profile   profileView
	Passkeys  []passkeyRow
	CanRemove bool
	AddTarget string

	// The sessions page.
	Sessions         []sessionRow
	RevokeAllTarget  string
	RevokeAllCommand string
	HasMore          bool

	// The devices page.
	Devices []deviceRow

	// The passkey creation page.
	Register registerView
}

type profileView struct {
	DisplayName string
	Locale      string
	Timezone    string
}

type passkeyRow struct {
	ID            string
	Name          string
	CreatedAt     string
	CreatedText   string
	LastUsedAt    string
	LastUsedText  string
	RenameCommand string
	RemoveCommand string
	RemoveTarget  string
}

type sessionRow struct {
	ID            string
	Where         string
	Current       bool
	IssuedAt      string
	IssuedText    string
	LastUsedAt    string
	LastUsedText  string
	ExpiresAt     string
	ExpiresText   string
	RevokeCommand string
	RevokeTarget  string
}

type deviceRow struct {
	ID            string
	Name          string
	Platform      string
	Installed     []string
	Current       bool
	RenameCommand string
	RevokeCommand string
	RevokeTarget  string
}

// registerView is the creation options of a passkey registration, carried as data attributes of the page's form (the content
// security policy admits no inline script, so the script reads them from the page).
type registerView struct {
	FlowID      string
	CommandID   string
	Challenge   string
	RPID        string
	UserHandle  string
	Excluded    string
	AccountName string
}

// render executes a page template into bytes.
func (v *views) render(name string, data pageData) ([]byte, error) {
	tmpl, ok := v.templates[name]
	if !ok {
		return nil, fmt.Errorf("no template %s", name)
	}
	data.Base = v.base
	var buffer bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buffer, "base", data); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// timeText is a time as the pages show it: UTC, to the minute.
func timeText(at time.Time) string { return at.UTC().Format("2006-01-02 15:04 UTC") }

// attribute is a time as a <time> element's datetime.
func attribute(at time.Time) string { return formatInstant(at) }

// joinCredentials is a list of credential IDs as one attribute value.
func joinCredentials(ids []string) string { return strings.Join(ids, ",") }
