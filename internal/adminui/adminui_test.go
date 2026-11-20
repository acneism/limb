package adminui

import (
	"bytes"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/acneism/limb/internal/totp"
)

func sampleURI(t *testing.T) (uri, key string) {
	t.Helper()
	seed, err := totp.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	return totp.URI("Acme", "root", seed), totp.EncodeSecret(seed)
}

func samplePage(t *testing.T, c *Catalog, language string) map[string]*Page {
	t.Helper()
	uri, key := sampleURI(t)
	qr, err := QR(uri, "key")
	if err != nil {
		t.Fatal(err)
	}
	signedAt := time.Date(2026, 11, 18, 3, 4, 5, 0, time.UTC)
	data := map[string]any{
		"login":    LoginData{Login: "ro<ot"},
		"code":     CodeData{Login: "root"},
		"enroll":   EnrollData{Login: "root", QR: qr, Secret: key, URI: template.URL(uri)}, //nolint:gosec
		"recovery": RecoveryData{Codes: []string{"ABCDE-FGHJK-MNPQR-STVWX", "23456-789AB-CDEFG-HJKMN"}},
		"home":     HomeData{Login: "root", SignedAt: signedAt, RecoveryCodes: 2},
		"account": AccountData{Login: "root", CreatedAt: signedAt, SecondFactor: true, RecoveryCodes: 7, HasOthers: true, Sessions: []SessionRow{
			{ID: "first-session", SignedAt: signedAt, LastSeenAt: signedAt, IP: "203.0.113.7", UserAgent: `Mozilla/5.0 "<script>alert(1)</script>"`, Current: true},
			{ID: "second-session", SignedAt: signedAt, LastSeenAt: signedAt, IP: "2001:db8::7"},
		}},
		"users": UsersData{
			Form: UsersForm{
				Search: `al"<b>`, Statuses: []Choice{{Name: "status", Value: "active", Label: "Active", Checked: true}, {Name: "status", Value: "blocked", Label: "Blocked"}},
				Confirmed: []Option{{Value: "", Label: "Any", Selected: true}, {Value: "yes", Label: "Yes"}},
				Via:       []Option{{Value: "", Label: "Any", Selected: true}}, Order: []Option{{Value: "created", Label: "Created", Selected: true}},
				Direction: []Option{{Value: "desc", Label: "Descending", Selected: true}}, Limit: []Option{{Value: "50", Label: "50", Selected: true}},
				CreatedFrom: "2026-01-02", Never: true,
			},
			Rows: []UserRow{
				{
					Href: "/admin/users/one", Title: "alice@example.com", Status: "active", StatusLabel: "Active", CreatedAt: signedAt, LastLoginAt: signedAt, Via: "By an invitation",
					Identifiers: []IdentifierView{{Type: "email", Value: "alice@example.com", Verified: true}, {Type: "username", Value: "<alice>"}},
				},
				{Href: "/admin/users/two", Title: "two", Status: "blocked", StatusLabel: "Blocked", BlockedUntil: signedAt, CreatedAt: signedAt, MustChangePassword: true},
			},
			ByCreated: SortLink{Href: "/admin/users?order=created&dir=asc", State: "descending"}, ByLastLogin: SortLink{Href: "/admin/users?order=last_login", State: "none"},
			ByStatus: SortLink{Href: "/admin/users?order=status", State: "none"}, Next: "/admin/users?cursor=x", First: "/admin/users", Filtered: true,
		},
		"user": UserData{
			ID: "0198f2a4-7c11-7d44-9b0e-3c6c2f1d9a55", Title: "alice@example.com", Status: "blocked", StatusLabel: "Blocked", BlockedReason: `spam "<b>"`,
			BlockedUntil: signedAt, DeletedAt: signedAt, PurgeAfter: signedAt, CreatedAt: signedAt, LastLoginAt: signedAt, Via: "Invitation", MustChangePassword: true,
			HasPassword: true, CanSend: true, Invited: true, CanInvite: true, ReasonLimit: 512, BlockReason: `<reason>`, BlockUntil: "2030-01-01",
			MessageLanguages: []Option{{Value: "en", Label: "English", Selected: true}, {Value: "ru", Label: "Русский"}},
			Identifiers: []IdentifierRow{
				{Type: "email", Value: "Alice@Example.com", Verified: true, VerifiedAt: signedAt, Editable: true},
				{Type: "username", Value: "<alice>", Editable: true, CanRemove: true},
				{Type: "phone", Value: "+1 202 555 0100", Editable: true, CanConfirm: true, CanRemove: true},
			},
			MissingTypes: []Option{{Value: "nick", Label: "nick"}},
			Sessions:     []UserSessionRow{{ID: "s1", Kind: "cookie", IP: "203.0.113.7", UserAgent: "<agent>", CreatedAt: signedAt, LastSeenAt: signedAt, ExpiresAt: signedAt}},
			SignIns:      []AuditRow{{At: signedAt, Actor: "the user", Action: "auth.login", Label: "Signed in", IP: "203.0.113.7", Details: []DetailPair{{Key: "kind", Value: "cookie"}}}},
			Journal: []AuditRow{
				{At: signedAt, Actor: "root", Action: "user.blocked", Label: "User blocked", UserID: "one", UserHref: "/admin/users/one", IP: "203.0.113.8", Details: []DetailPair{{Key: "reason", Value: "<spam>"}}},
			},
		},
		"newuser": NewUserData{
			Fields: []NewUserField{
				{Type: "email", Value: `a"<b>@example.com`, Required: true, Delivery: true, Verified: true}, {Type: "username", Value: "<alice>"},
			},
			Mode: "invite", Keep: true, CanInvite: true, Languages: []Option{{Value: "en", Label: "English", Selected: true}, {Value: "ru", Label: "Русский"}},
		},
		"audit": AuditData{
			Form: AuditForm{
				User: `u"<b>`, Admins: []Option{{Value: "", Label: "Any", Selected: true}, {Value: "a1", Label: "root"}},
				Actions: []Option{{Value: "", Label: "Any", Selected: true}, {Value: "user.blocked", Label: "User blocked"}},
				Limit:   []Option{{Value: "50", Label: "50", Selected: true}}, From: "2026-01-02", To: "2026-02-03",
			},
			Rows: []AuditRow{
				{At: signedAt, Actor: "root", Action: "user.blocked", Label: "User blocked", UserID: "one", UserHref: "/admin/users/one", IP: "203.0.113.8", Details: []DetailPair{{Key: "reason", Value: "<spam>"}}},
				{At: signedAt, Actor: "command line", Action: "admin.created", Label: "Administrator created"},
			},
			Next: "/admin/audit?cursor=x", First: "/admin/audit", Filtered: true,
		},
		"temporary": TemporaryData{UserHref: "/admin/users/one", Title: "<alice>", Password: "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY"},
		"rebind":    RebindData{Login: "root", QR: qr, Secret: key, URI: template.URL(uri), Token: "token-of-the-binding"}, //nolint:gosec
		"error":     ErrorData{Title: "Page not found", Text: "There is nothing at this address."},
	}
	pages := map[string]*Page{}
	for name, d := range data {
		p := NewPage(c, language)
		p.Service, p.Base, p.Stylesheet, p.Data = "Acme", "/admin", "/admin/assets/"+StylesheetName(), d
		p.Title = name
		for _, code := range c.Languages() {
			p.Languages = append(p.Languages, LanguageLink{Code: code, Name: LanguageName(code), Current: code == language, Href: "?lang=" + code})
		}
		if name != "login" && name != "code" && name != "enroll" && name != "error" {
			p.Login, p.CSRF = "root", "token-of-the-session"
		}
		pages[name] = p
	}
	return pages
}

func TestEveryPageIsRenderedInEveryLanguageAsWellFormedHTMLThatHasNoScriptAndNoStyle(t *testing.T) {
	c, err := NewCatalog(map[string]map[string]string{"de": {"login.title": "Anmelden"}})
	if err != nil {
		t.Fatal(err)
	}
	templates, err := Parse()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(templates.Pages()); got != 13 {
		t.Fatalf("there are %d pages: %v", got, templates.Pages())
	}
	key := regexp.MustCompile(`\b(?:[a-z]+\.){1,3}[a-z]+\b`)
	for _, language := range c.Languages() {
		for name, page := range samplePage(t, c, language) {
			out, renderErr := templates.Render(name, page)
			if renderErr != nil {
				t.Fatalf("%s in %s: %v", name, language, renderErr)
			}
			checkDocument(t, name+" in "+language, out)
			text := string(out)
			for _, k := range Keys() {
				if strings.Contains(textOnly(out), k) && key.MatchString(k) {
					t.Errorf("%s in %s: the key %q is shown as it is", name, language, k)
				}
			}
			if !strings.Contains(text, `<html lang="`+language+`">`) || !strings.Contains(text, `href="/admin/assets/`+StylesheetName()+`"`) {
				t.Errorf("%s in %s: the page does not tell its language and its stylesheet", name, language)
			}
			if strings.Contains(text, "ro<ot") {
				t.Errorf("%s in %s: a login with a bracket is not escaped", name, language)
			}
			if strings.Contains(text, "&lt;time") {
				t.Errorf("%s in %s: the element of a time is shown as words", name, language)
			}
		}
	}
}

func textOnly(page []byte) string {
	z := html.NewTokenizer(bytes.NewReader(page))
	var text strings.Builder
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return text.String()
		}
		if tt == html.TextToken {
			text.Write(z.Text())
			text.WriteByte(' ')
		}
	}
}

func checkDocument(t *testing.T, label string, page []byte) {
	t.Helper()
	z := html.NewTokenizer(bytes.NewReader(page))
	labels, ids, controls := map[string]bool{}, map[string]bool{}, map[string]bool{}
	depth := map[string]int{}
	readOnlyForm := false
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if !errors.Is(z.Err(), io.EOF) {
				t.Errorf("%s: the HTML is broken: %v", label, z.Err())
			}
			break
		}
		switch tt { //nolint:exhaustive
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			tag := string(name)
			if tt == html.StartTagToken && !isVoid(tag) {
				depth[tag]++
			}
			attrs := map[string]string{}
			for hasAttr {
				var k, v []byte
				k, v, hasAttr = z.TagAttr()
				attrs[string(k)] = string(v)
			}
			if tag == "script" || tag == "style" || tag == "iframe" || tag == "object" || tag == "embed" || tag == "img" || tag == "link" && attrs["rel"] != "stylesheet" {
				t.Errorf("%s: the page has a <%s>", label, tag)
			}
			for k, v := range attrs {
				if k == "style" || strings.HasPrefix(k, "on") {
					t.Errorf("%s: the page has %s=%q on <%s>", label, k, v, tag)
				}
				if (k == "href" || k == "src" || k == "action") && (strings.HasPrefix(v, "http:") || strings.HasPrefix(v, "https:") || strings.HasPrefix(v, "//")) {
					t.Errorf("%s: the page refers to another site: %s=%q", label, k, v)
				}
				if k == "id" {
					if ids[v] {
						t.Errorf("%s: the id %q is used twice", label, v)
					}
					ids[v] = true
				}
			}
			if tag == "label" {
				labels[attrs["for"]] = true
			}
			inLabel := depth["label"] > 0 && tag != "label"
			field := tag == "input" && attrs["type"] != "hidden" && attrs["type"] != "submit" || tag == "select" || tag == "textarea"
			if field && !inLabel {
				controls[attrs["id"]] = true
				if attrs["id"] == "" {
					t.Errorf("%s: a field has no id to be labelled by", label)
				}
			}
			if tag == "input" && attrs["type"] == "password" && readOnlyForm {
				t.Errorf("%s: a password is sent by a form that is sent with GET", label)
			}
			if tag == "form" {
				readOnlyForm = attrs["method"] == "get"
				if attrs["method"] != "post" && !readOnlyForm {
					t.Errorf("%s: a form that is sent with neither POST nor GET", label)
				}
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			if string(name) == "form" {
				readOnlyForm = false
			}
			depth[string(name)]--
			if depth[string(name)] < 0 {
				t.Errorf("%s: </%s> closes nothing", label, name)
			}
		}
	}
	for tag, n := range depth {
		if n != 0 {
			t.Errorf("%s: <%s> is not closed (%d)", label, tag, n)
		}
	}
	for id := range controls {
		if !labels[id] {
			t.Errorf("%s: the input %q has no label", label, id)
		}
	}
}

func isVoid(tag string) bool {
	switch tag {
	case "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr":
		return true
	}
	return false
}

func TestTheCatalogHasTheSameKeysInEnglishAndRussianAndFallsBackToEnglish(t *testing.T) {
	for key := range english {
		if _, found := russian[key]; !found {
			t.Errorf("the key %q has no Russian text", key)
		}
	}
	for key := range russian {
		if _, found := english[key]; !found {
			t.Errorf("the key %q has no English text", key)
		}
	}
	for key, text := range english {
		if strings.Count(text, "%")+strings.Count(russian[key], "%") > 0 && strings.Count(text, "%") != strings.Count(russian[key], "%") {
			t.Errorf("the key %q has a different number of arguments in the two languages", key)
		}
	}
	c, err := NewCatalog(map[string]map[string]string{"de": {"login.title": "Anmelden"}, "ru": {"login.title": "Войти"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Text("de", "login.title"); got != "Anmelden" {
		t.Errorf("the German title is %q", got)
	}
	if got := c.Text("de", "login.password"); got != english["login.password"] {
		t.Errorf("a German text that is missing is %q, want the English one", got)
	}
	if got := c.Text("ru", "login.title"); got != "Войти" || c.Text("ru", "login.login") != russian["login.login"] {
		t.Errorf("the Russian title is %q: it is replaced and the rest stay", got)
	}
	if got := c.Text("fr", "login.title"); got != english["login.title"] {
		t.Errorf("an unknown language shows %q, want English", got)
	}
	if got := c.Text("en", "no.such.key"); got != "no.such.key" {
		t.Errorf("an unknown key shows %q", got)
	}
	if got := c.Text("en", "home.welcome", "root"); got != "Welcome, root." {
		t.Errorf("a text with an argument is %q", got)
	}
	if languages := c.Languages(); len(languages) != 3 || languages[0] != "de" || languages[1] != "en" || languages[2] != "ru" || !c.Has("de") || c.Has("fr") {
		t.Errorf("the languages are %v", languages)
	}
	if LanguageName("ru") != "Русский" || LanguageName("de") != "de" {
		t.Error("the names of the languages are wrong")
	}
}

func TestTheCatalogRefusesWhatCannotBeAText(t *testing.T) {
	for name, overrides := range map[string]map[string]map[string]string{
		"a language with capitals":   {"EN": {"login.title": "x"}},
		"a language tag with a part": {"en-GB": {"login.title": "x"}},
		"a language that is empty":   {"": {"login.title": "x"}},
		"a language that is long":    {"engl": {"login.title": "x"}},
		"a key that no text has":     {"en": {"login.titel": "x"}},
		"an empty text":              {"en": {"login.title": ""}},
	} {
		if _, err := NewCatalog(overrides); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if len(Keys()) < 50 {
		t.Errorf("there are only %d keys", len(Keys()))
	}
}

func TestTheCatalogRefusesATextThatDoesNotUseItsArgumentsAsTheOriginalDoes(t *testing.T) {
	refused := map[string]map[string]map[string]string{
		"an argument that is dropped":                  {"en": {"home.welcome": "Welcome"}},
		"an argument of the wrong kind":                {"en": {"error.seconds": "%s s"}},
		"one argument too many":                        {"en": {"home.welcome": "Welcome, %s and %s."}},
		"a percent sign that is no verb":               {"en": {"home.welcome": "100% welcome, %s."}},
		"an argument in a text that takes none":        {"en": {"login.title": "Sign in, %s"}},
		"a percent sign in a text that takes none":     {"en": {"login.title": "100 %"}},
		"an escaped percent in a text that takes none": {"de": {"login.title": "100%%"}},
	}
	for name, overrides := range refused {
		if _, err := NewCatalog(overrides); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	accepted := map[string]map[string]map[string]string{
		"an escaped percent sign":       {"en": {"home.welcome": "50%% welcome, %s."}},
		"arguments that are moved":      {"ru": {"home.signed.in": "Вход выполнен: %[1]s"}},
		"a text of a new language":      {"de": {"home.welcome": "Willkommen, %s.", "error.minutes": "%d Min."}},
		"a text that takes none, plain": {"en": {"login.title": "Come in"}},
	}
	for name, overrides := range accepted {
		if _, err := NewCatalog(overrides); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
	for key, text := range russian {
		if err := checkArguments(key, text); err != nil {
			t.Errorf("the Russian text of %q does not use the arguments of the English one: %v", key, err)
		}
	}
	for key, text := range english {
		for i := 0; i+1 < len(text); i++ {
			if text[i] == '%' && !strings.ContainsRune("sd%", rune(text[i+1])) {
				t.Errorf("the text %q has the verb %%%c, which the catalog does not know how to check", key, text[i+1])
			}
		}
	}
}

func TestAPageThatDoesNotExistIsAnError(t *testing.T) {
	templates, err := Parse()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = templates.Render("nowhere", &Page{}); err == nil {
		t.Fatal("a page that does not exist was rendered")
	}
}

func TestTheStylesheetIsNamedByItsHashAndHoldsNoReferences(t *testing.T) {
	name := StylesheetName()
	if !regexp.MustCompile(`^admin\.[0-9a-f]{16}\.css$`).MatchString(name) {
		t.Fatalf("the name is %q", name)
	}
	css := string(Stylesheet())
	if len(css) < 1000 || !strings.HasPrefix(css, "/*! tailwindcss v") {
		t.Fatalf("the stylesheet is %d bytes: %.60q", len(css), css)
	}
	for _, banned := range []string{"url(", "@import", "expression(", "javascript:"} {
		if strings.Contains(css, banned) {
			t.Errorf("the stylesheet has %q in it: a page that asks nothing of another site cannot have it", banned)
		}
	}
}

func TestTheStylesheetHasEveryClassThatATemplateUses(t *testing.T) {
	css := string(Stylesheet())
	entries, err := fs.ReadDir(templateFiles, "templates")
	if err != nil {
		t.Fatal(err)
	}
	attribute := regexp.MustCompile(`class="([^"]*)"`)
	used := map[string]string{}
	for _, entry := range entries {
		text, readErr := fs.ReadFile(templateFiles, "templates/"+entry.Name())
		if readErr != nil {
			t.Fatal(readErr)
		}
		for _, match := range attribute.FindAllStringSubmatch(string(text), -1) {
			values := []string{match[1]}
			for placeholder, expansions := range map[string][]string{"{{.FlashKind}}": {"error", "notice"}, "{{.Status}}": {"active", "blocked", "deleted"}, "{{.Data.Status}}": {"active", "blocked", "deleted"}} {
				var expanded []string
				for _, value := range values {
					if !strings.Contains(value, placeholder) {
						expanded = append(expanded, value)
						continue
					}
					for _, expansion := range expansions {
						expanded = append(expanded, strings.ReplaceAll(value, placeholder, expansion))
					}
				}
				values = expanded
			}
			for _, value := range values {
				if strings.Contains(value, "{{") {
					t.Errorf("%s has the class %q that is made by a template action, which this test does not know how to expand", entry.Name(), value)
					continue
				}
				for _, class := range strings.Fields(value) {
					used[class] = entry.Name()
				}
			}
		}
	}
	if len(used) < 20 {
		t.Fatalf("the templates use only %d classes: %v", len(used), used)
	}
	for class, name := range used {
		if !regexp.MustCompile(`\.` + regexp.QuoteMeta(class) + `[^a-zA-Z0-9_-]`).MatchString(css) {
			t.Errorf("%s uses the class %q, which the stylesheet does not have: build it again with make css", name, class)
		}
	}
}

func TestATimeIsShownInUTCWithItsExactMoment(t *testing.T) {
	c, _ := NewCatalog(nil)
	p := NewPage(c, "en")
	got := p.Time(time.Date(2026, 11, 18, 5, 4, 3, 0, time.FixedZone("x", 3*3600)))
	if string(got) != `<time datetime="2026-11-18T02:04:03Z">2026-11-18 02:04 UTC</time>` {
		t.Fatalf("the time is %s", got)
	}
	at := time.Date(2026, 11, 18, 5, 4, 3, 0, time.FixedZone("x", 3*3600))
	if text := p.TimeText(at); text != "2026-11-18 02:04 UTC" {
		t.Fatalf("the text of the time is %q", text)
	}
	if text := NewPage(c, "ru").TimeText(at); text != "2026-11-18 02:04 UTC" {
		t.Fatalf("the text of the time in Russian is %q", text)
	}
	if NewPage(c, "zz").Lang != DefaultLanguage {
		t.Fatal("a page in a language that is not spoken is not in English")
	}
}
