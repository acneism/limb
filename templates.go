package limb

import (
	"bytes"
	"cmp"
	"embed"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"net/url"
	"strings"
	texttemplate "text/template"
	"time"
	"unicode"
)

//go:embed templates/*/*.tmpl
var builtinTemplates embed.FS

const (
	emailChannel   = "email"
	sampleCode     = "123456"
	sampleLinkBase = "https://app.example.com/page#token="
)

var (
	errUnsafeLink = errors.New("limb: the link of a message must be an absolute https address")
	errBadText    = errors.New("limb: a template gave a text that is not allowed")
)

type templateOverride struct {
	kind     MessageKind
	language string
	template MessageTemplate
}

type templateKey struct {
	kind     MessageKind
	language string
}

type templateSet struct {
	subject *texttemplate.Template
	text    *texttemplate.Template
	short   *texttemplate.Template
	html    *htmltemplate.Template
}

type renderedMessage struct {
	subject string
	text    string
	html    string
}

type renderer struct {
	sets        map[templateKey]templateSet
	serviceName string
	development bool
}

func newRenderer(overrides []templateOverride, serviceName string, development bool) (*renderer, error) {
	sources := make(map[templateKey]MessageTemplate, len(messageKinds)*len(supportedLanguages))
	for _, kind := range messageKinds {
		for _, language := range supportedLanguages {
			built, err := builtinSource(kind, language)
			if err != nil {
				return nil, err
			}
			sources[templateKey{kind, language}] = built
		}
	}
	seen := make(map[templateKey]bool, len(overrides))
	for _, o := range overrides {
		key := templateKey{o.kind, o.language}
		if seen[key] {
			return nil, fmt.Errorf("limb: the template of the %s message in %s is given twice", o.kind, o.language)
		}
		seen[key] = true
		source := sources[key]
		source.Subject = cmp.Or(o.template.Subject, source.Subject)
		source.Text = cmp.Or(o.template.Text, source.Text)
		source.HTML = cmp.Or(o.template.HTML, source.HTML)
		source.Short = cmp.Or(o.template.Short, source.Short)
		sources[key] = source
	}
	r := &renderer{sets: make(map[templateKey]templateSet, len(sources)), serviceName: serviceName, development: development}
	for _, kind := range messageKinds {
		for _, language := range supportedLanguages {
			key := templateKey{kind, language}
			set, err := parseSet(key, sources[key])
			if err != nil {
				return nil, err
			}
			if err = r.check(key, set); err != nil {
				return nil, err
			}
			r.sets[key] = set
		}
	}
	return r, nil
}

func builtinSource(kind MessageKind, language string) (MessageTemplate, error) {
	read := func(part string) (string, error) {
		raw, err := builtinTemplates.ReadFile(fmt.Sprintf("templates/%s/%s.%s.tmpl", language, kind, part))
		if err != nil {
			return "", fmt.Errorf("limb: read the built-in %s template of the %s message in %s: %w", part, kind, language, err)
		}
		return string(raw), nil
	}
	var source MessageTemplate
	parts := []struct {
		name string
		into *string
	}{{"subject", &source.Subject}, {"text", &source.Text}, {"html", &source.HTML}, {"short", &source.Short}}
	for _, part := range parts {
		text, err := read(part.name)
		if err != nil {
			return MessageTemplate{}, err
		}
		*part.into = text
	}
	return source, nil
}

func parseSet(key templateKey, source MessageTemplate) (templateSet, error) {
	fail := func(part string, err error) (templateSet, error) {
		return templateSet{}, fmt.Errorf("limb: the %s template of the %s message in %s is not valid: %w", part, key.kind, key.language, err)
	}
	var set templateSet
	var err error
	if set.subject, err = texttemplate.New("subject").Parse(source.Subject); err != nil {
		return fail("subject", err)
	}
	if set.text, err = texttemplate.New("text").Parse(source.Text); err != nil {
		return fail("text", err)
	}
	if set.short, err = texttemplate.New("short").Parse(source.Short); err != nil {
		return fail("short", err)
	}
	if set.html, err = htmltemplate.New("html").Parse(source.HTML); err != nil {
		return fail("HTML", err)
	}
	return set, nil
}

func (r *renderer) check(key templateKey, set templateSet) error {
	link := sampleLinkBase + strings.Repeat("A", 43)
	samples := []MessageData{{}}
	if key.kind == MessageVerification || key.kind == MessagePasswordReset {
		samples = []MessageData{{Link: link, Code: sampleCode}, {Code: sampleCode}}
	}
	for _, data := range samples {
		data.LinkExpiresIn, data.CodeExpiresIn = describeDuration(key.language, 30*time.Minute), describeDuration(key.language, 10*time.Minute)
		data.Language = key.language
		data.ServiceName = r.name(key.language)
		if _, err := runEmail(set, data); err != nil {
			return fmt.Errorf("limb: the e-mail templates of the %s message in %s: %w", key.kind, key.language, err)
		}
		if _, err := runShort(set, data); err != nil {
			return fmt.Errorf("limb: the short template of the %s message in %s: %w", key.kind, key.language, err)
		}
	}
	return nil
}

func (r *renderer) name(language string) string {
	if r.serviceName != "" {
		return r.serviceName
	}
	if language == "ru" {
		return "сервис"
	}
	return "the service"
}

func (r *renderer) render(kind MessageKind, language, channel string, data MessageData) (renderedMessage, error) {
	language = normalizeLanguage(language)
	set, found := r.sets[templateKey{kind, language}]
	if !found {
		return renderedMessage{}, fmt.Errorf("limb: there is no template for the %q message", kind)
	}
	if err := r.checkLink(data.Link); err != nil {
		return renderedMessage{}, err
	}
	data.Language = language
	data.ServiceName = r.name(language)
	if channel == emailChannel {
		return runEmail(set, data)
	}
	return runShort(set, data)
}

func (r *renderer) checkLink(link string) error {
	if link == "" {
		return nil
	}
	u, err := url.Parse(link)
	switch {
	case err != nil, u.Host == "", hasControl(link), strings.ContainsAny(link, " \t\r\n"):
		return errUnsafeLink
	case u.Scheme == "https", u.Scheme == "http" && r.development:
		return nil
	}
	return errUnsafeLink
}

func runEmail(set templateSet, data MessageData) (renderedMessage, error) {
	subject, err := execute(set.subject, data)
	if err != nil {
		return renderedMessage{}, err
	}
	text, err := execute(set.text, data)
	if err != nil {
		return renderedMessage{}, err
	}
	var page bytes.Buffer
	if err = set.html.Execute(&page, data); err != nil {
		return renderedMessage{}, fmt.Errorf("limb: execute the HTML template: %w", err)
	}
	out := renderedMessage{subject: subject, text: text, html: strings.TrimSpace(page.String())}
	switch {
	case out.subject == "", out.text == "":
		return renderedMessage{}, fmt.Errorf("%w: the subject and the text must not be empty", errBadText)
	case hasControl(out.subject):
		return renderedMessage{}, fmt.Errorf("%w: the subject must be one line without control characters", errBadText)
	}
	return out, nil
}

func runShort(set templateSet, data MessageData) (renderedMessage, error) {
	short, err := execute(set.short, data)
	if err != nil {
		return renderedMessage{}, err
	}
	switch {
	case short == "":
		return renderedMessage{}, fmt.Errorf("%w: the short text must not be empty", errBadText)
	case hasControl(short):
		return renderedMessage{}, fmt.Errorf("%w: the short text must be one line without control characters", errBadText)
	}
	return renderedMessage{text: short}, nil
}

func execute(t *texttemplate.Template, data MessageData) (string, error) {
	var out bytes.Buffer
	if err := t.Execute(&out, data); err != nil {
		return "", fmt.Errorf("limb: execute the %s template: %w", t.Name(), err)
	}
	return strings.TrimSpace(out.String()), nil
}

func hasControl(text string) bool {
	return strings.ContainsFunc(text, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r)
	})
}

func describeDuration(language string, d time.Duration) string {
	switch {
	case d > 48*time.Hour && d%(24*time.Hour) == 0:
		return counted(language, int(d/(24*time.Hour)), "day")
	case d >= time.Hour && d%time.Hour == 0:
		return counted(language, int(d/time.Hour), "hour")
	}
	return counted(language, max(1, int((d+time.Minute-1)/time.Minute)), "minute")
}

var unitForms = map[string]map[string][3]string{
	"en": {
		"minute": {"minute", "minutes", "minutes"},
		"hour":   {"hour", "hours", "hours"},
		"day":    {"day", "days", "days"},
	},
	"ru": {
		"minute": {"минута", "минуты", "минут"},
		"hour":   {"час", "часа", "часов"},
		"day":    {"день", "дня", "дней"},
	},
}

func counted(language string, n int, unit string) string {
	forms, found := unitForms[language]
	if !found {
		forms = unitForms[defaultLanguage]
	}
	return fmt.Sprintf("%d %s", n, forms[unit][pluralForm(language, n)])
}

func pluralForm(language string, n int) int {
	if language == "ru" {
		switch {
		case n%10 == 1 && n%100 != 11:
			return 0
		case n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14):
			return 1
		}
		return 2
	}
	if n == 1 {
		return 0
	}
	return 1
}
