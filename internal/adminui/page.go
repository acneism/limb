package adminui

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"strings"
	"time"
)

//go:embed templates/*.html.tmpl
var templateFiles embed.FS

const layoutName = "layout"

// LanguageLink is a link that switches the language of the page.
type LanguageLink struct {
	// Code is the tag of the language.
	Code string
	// Name is what the language is called in itself.
	Name string
	// Current tells that the page is in this language.
	Current bool
	// Href is the address of the switch, relative to the page.
	Href string
}

// Page is what a template of the administration is given.
type Page struct {
	// Lang is the language of the page.
	Lang string
	// Languages are the links that switch the language.
	Languages []LanguageLink
	// Title is the title of the page.
	Title string
	// Service is the name of the service.
	Service string
	// Base is the path that the administration is mounted at, without the slash at
	// the end, empty for the root.
	Base string
	// Stylesheet is the address of the stylesheet.
	Stylesheet string
	// CSRF is the token that the forms of a signed-in administrator send back.
	CSRF string
	// Login is the login of the administrator who is signed in, empty when nobody
	// is.
	Login string
	// Flash is a message to show above the content, already in the language of the
	// page, and FlashKind is "error" or "notice".
	Flash     string
	FlashKind string
	// Data is what the template of the page needs.
	Data any

	catalog *Catalog
}

// NewPage returns a page in the language, which has to be one that the catalog
// speaks.
func NewPage(c *Catalog, language string) *Page {
	if !c.Has(language) {
		language = DefaultLanguage
	}
	return &Page{Lang: language, catalog: c}
}

// T returns the text with the key in the language of the page.
func (p *Page) T(key string, args ...any) string {
	return p.catalog.Text(p.Lang, key, args...)
}

// TimeText returns a time as text, to the minute in UTC, for a sentence that
// holds it. Time is the element that carries the exact moment, for a time that
// stands on its own.
func (p *Page) TimeText(at time.Time) string {
	return p.T("time.utc", at.UTC().Format("2006-01-02 15:04"))
}

// Time returns a time as an element that carries the exact moment and shows it to
// the minute in UTC.
func (p *Page) Time(at time.Time) template.HTML {
	shown := template.HTMLEscapeString(p.TimeText(at))
	return template.HTML(fmt.Sprintf(`<time datetime="%s">%s</time>`, at.UTC().Format(time.RFC3339), shown)) //nolint:gosec
}

// AuditTable is what the table of the records of the audit log needs.
type AuditTable struct {
	// Page is the page that the table is part of, for its texts and its times.
	Page *Page
	// Caption is the key of the text that names the table, and Empty the key of
	// the text that stands for a table that has no records.
	Caption, Empty string
	// WithUser adds the column of the user that a record was done to.
	WithUser bool
	// Rows are the records.
	Rows []AuditRow
}

// AuditTable returns the table of records that the template "auditrows" draws.
func (p *Page) AuditTable(caption, empty string, withUser bool, rows []AuditRow) AuditTable {
	return AuditTable{Page: p, Caption: caption, Empty: empty, WithUser: withUser, Rows: rows}
}

// Templates are the templates of the pages, parsed.
type Templates struct {
	pages map[string]*template.Template
}

// Parse parses the templates of the pages. Every page is a file that defines the
// templates "title" and "content", which the layout puts together.
func Parse() (*Templates, error) {
	layout, err := fs.ReadFile(templateFiles, "templates/"+layoutName+".html.tmpl")
	if err != nil {
		return nil, fmt.Errorf("adminui: read the layout: %w", err)
	}
	base, err := template.New(layoutName).Parse(string(layout))
	if err != nil {
		return nil, fmt.Errorf("adminui: parse the layout: %w", err)
	}
	entries, err := fs.ReadDir(templateFiles, "templates")
	if err != nil {
		return nil, fmt.Errorf("adminui: list the templates: %w", err)
	}
	t := &Templates{pages: map[string]*template.Template{}}
	for _, entry := range entries {
		name, found := strings.CutSuffix(entry.Name(), ".html.tmpl")
		if !found || name == layoutName {
			continue
		}
		text, readErr := fs.ReadFile(templateFiles, "templates/"+entry.Name())
		if readErr != nil {
			return nil, fmt.Errorf("adminui: read %s: %w", entry.Name(), readErr)
		}
		clone, cloneErr := base.Clone()
		if cloneErr != nil {
			return nil, fmt.Errorf("adminui: clone the layout: %w", cloneErr)
		}
		if _, parseErr := clone.Parse(string(text)); parseErr != nil {
			return nil, fmt.Errorf("adminui: parse %s: %w", entry.Name(), parseErr)
		}
		t.pages[name] = clone
	}
	return t, nil
}

// Pages returns the names of the pages.
func (t *Templates) Pages() []string {
	names := make([]string, 0, len(t.pages))
	for name := range t.pages {
		names = append(names, name)
	}
	return names
}

// Render returns the page that is made of the template with the name and the
// data. Nothing is returned when the template fails, so that a page is never
// half written.
func (t *Templates) Render(name string, p *Page) ([]byte, error) {
	page, found := t.pages[name]
	if !found {
		return nil, fmt.Errorf("adminui: there is no page %q", name)
	}
	var out bytes.Buffer
	if err := page.ExecuteTemplate(&out, layoutName, p); err != nil {
		return nil, fmt.Errorf("adminui: render the page %q: %w", name, err)
	}
	return out.Bytes(), nil
}
