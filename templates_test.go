package limb

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	texttemplate "text/template"
	"time"
	"unicode/utf8"
)

var sampleLink = "https://app.example.com/reset#token=" + strings.Repeat("A", 43)

func newTestRenderer(t *testing.T) *renderer {
	t.Helper()
	r, err := newRenderer(nil, "", false)
	if err != nil {
		t.Fatalf("newRenderer failed: %v", err)
	}
	return r
}

func dataFor(language string, link, code bool) MessageData {
	data := MessageData{Language: language}
	if link {
		data.Link, data.LinkExpiresIn = sampleLink, describeDuration(language, 24*time.Hour)
	}
	if code {
		data.Code, data.CodeExpiresIn = "123456", describeDuration(language, 10*time.Minute)
	}
	return data
}

func TestEveryBuiltInTemplateRunsForEveryKindLanguageAndData(t *testing.T) {
	r := newTestRenderer(t)
	for _, kind := range messageKinds {
		for _, language := range supportedLanguages {
			for _, withLink := range []bool{true, false} {
				for _, withCode := range []bool{true, false} {
					name := fmt.Sprintf("%s/%s/link=%v/code=%v", kind, language, withLink, withCode)
					data := dataFor(language, withLink, withCode)
					email, err := r.render(kind, language, "email", data)
					if err != nil {
						t.Errorf("%s: render for e-mail failed: %v", name, err)
						continue
					}
					short, err := r.render(kind, language, "phone", data)
					if err != nil {
						t.Errorf("%s: render for a phone failed: %v", name, err)
						continue
					}
					checkRendered(t, name, email, short, data)
				}
			}
		}
	}
}

func checkRendered(t *testing.T, name string, email, short renderedMessage, data MessageData) {
	t.Helper()
	if email.subject == "" || email.text == "" || !strings.HasPrefix(email.html, "<!doctype html>") {
		t.Errorf("%s: an e-mail needs a subject, a text and an HTML part: %+v", name, email)
	}
	if short.text == "" || short.subject != "" || short.html != "" {
		t.Errorf("%s: a short message is only a text: %+v", name, short)
	}
	for _, text := range []string{email.subject, email.text, email.html, short.text} {
		if strings.Contains(text, "<no value>") || strings.Contains(text, "{{") || strings.Contains(text, "}}") {
			t.Errorf("%s: a template left a mark in %q", name, text)
		}
	}
	for _, text := range []string{email.subject, short.text} {
		if hasControl(text) || text != strings.TrimSpace(text) {
			t.Errorf("%s: %q is not one line without control characters", name, text)
		}
	}
	if !strings.Contains(email.subject, "the service") && !strings.Contains(email.subject, "сервис") {
		t.Errorf("%s: the subject %q does not name the service", name, email.subject)
	}
	for _, text := range []string{email.text, email.html} {
		if strings.Contains(text, "ServiceName") {
			t.Errorf("%s: a template shows a field name: %q", name, text)
		}
		if data.Link != "" && !strings.Contains(text, data.Link) && strings.Contains(text, "https://") {
			t.Errorf("%s: the message shows another link than the one it was given: %q", name, text)
		}
	}
}

func TestBuiltInMessagesCarryTheLinkAndTheCode(t *testing.T) {
	r := newTestRenderer(t)
	for _, kind := range []MessageKind{MessageVerification, MessagePasswordReset} {
		for _, language := range supportedLanguages {
			both, err := r.render(kind, language, "email", dataFor(language, true, true))
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{both.text, both.html} {
				if !strings.Contains(text, sampleLink) || !strings.Contains(text, "123456") {
					t.Errorf("%s/%s: the message lacks the link or the code: %q", kind, language, text)
				}
			}
			codeOnly, err := r.render(kind, language, "email", dataFor(language, false, true))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(codeOnly.text, "https://") || !strings.Contains(codeOnly.text, "123456") {
				t.Errorf("%s/%s: a message with only a code must not mention a link: %q", kind, language, codeOnly.text)
			}
			phone, err := r.render(kind, language, "phone", dataFor(language, true, true))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(phone.text, "123456") || strings.Contains(phone.text, "https://") {
				t.Errorf("%s/%s: a short message carries the code and no link: %q", kind, language, phone.text)
			}
		}
	}
	for _, kind := range []MessageKind{MessagePasswordChanged, MessageSignupAttempt} {
		for _, language := range supportedLanguages {
			out, err := r.render(kind, language, "email", dataFor(language, false, false))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.text, "123456") || strings.Contains(out.text, "https://") {
				t.Errorf("%s/%s: a notice carries no secret: %q", kind, language, out.text)
			}
		}
	}
}

func TestBuiltInTextsRead(t *testing.T) {
	r := newTestRenderer(t)
	cases := []struct {
		kind     MessageKind
		language string
		channel  string
		data     MessageData
		subject  string
		text     string
	}{
		{
			MessageVerification, "en", "email", dataFor("en", true, true), "Confirm your address on the service",
			"the service\n\nSomeone gave this address and asked to confirm it.\n\n" +
				"To confirm it, open this link. It works for 24 hours:\n\n" + sampleLink + "\n\n" +
				"Or enter this code. It works for 10 minutes:\n\n123456\n\n" +
				"If this was not you, ignore this message. Nothing will change.",
		},
		{
			MessagePasswordReset, "en", "email", dataFor("en", false, true), "Reset your password on the service",
			"the service\n\nSomeone asked to reset the password of the account that uses this address.\n\n" +
				"To choose a new password, enter this code. It works for 10 minutes:\n\n123456\n\n" +
				"If this was not you, ignore this message. Your password will not change.",
		},
		{
			MessageVerification, "ru", "email", dataFor("ru", true, true), "Подтверждение адреса: сервис",
			"сервис\n\nКто-то указал этот адрес и просит подтвердить его.\n\n" +
				"Чтобы подтвердить адрес, откройте ссылку. Она действует 24 часа:\n\n" + sampleLink + "\n\n" +
				"Или введите код. Он действует 10 минут:\n\n123456\n\n" +
				"Если это были не вы, проигнорируйте письмо: ничего не изменится.",
		},
		{
			MessagePasswordChanged, "ru", "email", dataFor("ru", false, false), "Пароль изменён: сервис",
			"сервис\n\nПароль учётной записи с этим адресом был изменён.\n\n" +
				"Если это были вы, больше ничего делать не нужно. " +
				"Если нет, сразу сбросьте пароль и смените его на других сайтах, где вы им пользуетесь.",
		},
		{
			MessageSignupAttempt, "en", "email", dataFor("en", false, false), "Someone tried to sign up on the service with your address",
			"the service\n\nSomeone tried to sign up with this address, but an account that uses it exists already.\n\n" +
				"If it was you, sign in or reset your password. If it was not, you do not need to do anything.",
		},
		{
			MessagePasswordReset, "ru", "phone", dataFor("ru", true, true), "",
			"сервис: код для сброса пароля 123456. Действует 10 минут. Если это были не вы, проигнорируйте сообщение.",
		},
		{
			MessageVerification, "en", "phone", dataFor("en", true, true), "",
			"the service: your confirmation code is 123456. It works for 10 minutes.",
		},
	}
	for _, c := range cases {
		got, err := r.render(c.kind, c.language, c.channel, c.data)
		if err != nil {
			t.Errorf("%s/%s/%s: %v", c.kind, c.language, c.channel, err)
			continue
		}
		if got.subject != c.subject || got.text != c.text {
			t.Errorf("%s/%s/%s:\n got subject %q and text %q\nwant subject %q and text %q", c.kind, c.language, c.channel, got.subject, got.text, c.subject, c.text)
		}
	}
}

func TestTheServiceNameComesFromTheOptionOrTheLanguage(t *testing.T) {
	named, err := newRenderer(nil, "Acme", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, language := range supportedLanguages {
		out, renderErr := named.render(MessagePasswordChanged, language, "email", dataFor(language, false, false))
		if renderErr != nil || !strings.Contains(out.subject, "Acme") || !strings.HasPrefix(out.text, "Acme\n") {
			t.Errorf("%s: the name of the service is missing: %+v, %v", language, out, renderErr)
		}
	}
	plain := newTestRenderer(t)
	if out, _ := plain.render(MessagePasswordChanged, "en", "email", MessageData{}); !strings.HasPrefix(out.text, "the service\n") {
		t.Errorf("the English name of the service by default = %q", out.text)
	}
	if out, _ := plain.render(MessagePasswordChanged, "ru", "email", MessageData{}); !strings.HasPrefix(out.text, "сервис\n") {
		t.Errorf("the Russian name of the service by default = %q", out.text)
	}
}

func TestHTMLEscapesWhatItInsertsAndTextDoesNot(t *testing.T) {
	r, err := newRenderer(nil, `<b onload="x">&Co`, false)
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.render(MessagePasswordChanged, "en", "email", MessageData{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.html, "<b onload") || !strings.Contains(out.html, "&lt;b onload=&#34;x&#34;&gt;&amp;Co") {
		t.Errorf("the HTML did not escape the name of the service: %q", out.html)
	}
	if !strings.Contains(out.text, `<b onload="x">&Co`) || !strings.Contains(out.subject, `<b onload="x">&Co`) {
		t.Errorf("the plain texts must keep the name as it is: %q %q", out.subject, out.text)
	}
}

func TestLanguageFallsBackToEnglish(t *testing.T) {
	r := newTestRenderer(t)
	for _, language := range []string{"", "de", "fr-CA", "xx", "русский", "ruu", "r"} {
		out, err := r.render(MessagePasswordChanged, language, "email", MessageData{})
		if err != nil || !strings.Contains(out.subject, "was changed") {
			t.Errorf("the language %q gave %+v, %v; want English", language, out, err)
		}
	}
	for _, language := range []string{"ru", "RU", "ru-RU", "ru_RU", " ru "} {
		out, err := r.render(MessagePasswordChanged, language, "email", MessageData{})
		if err != nil || !strings.Contains(out.subject, "Пароль изменён") {
			t.Errorf("the language %q gave %+v, %v; want Russian", language, out, err)
		}
	}
}

func TestNormalizeLanguage(t *testing.T) {
	cases := []struct{ tag, want string }{
		{"", "en"}, {"en", "en"}, {"EN", "en"}, {"en-US", "en"}, {"en_GB", "en"},
		{"ru", "ru"}, {"ru-RU", "ru"}, {"ru_RU", "ru"}, {"RU-ru", "ru"}, {" ru ", "ru"},
		{"de", "en"}, {"fr-CA", "en"}, {"русский", "en"}, {"ruu", "en"}, {"r", "en"}, {"-ru", "en"}, {"x-ru", "en"},
	}
	for _, c := range cases {
		if got := normalizeLanguage(c.tag); got != c.want {
			t.Errorf("normalizeLanguage(%q) = %q, want %q", c.tag, got, c.want)
		}
	}
}

func TestAnOverrideReplacesOnlyItsOwnFields(t *testing.T) {
	override := templateOverride{
		kind:     MessagePasswordReset,
		language: "en",
		template: MessageTemplate{Subject: "Password for {{.ServiceName}}", Short: "{{.Code}} is your code"},
	}
	r, err := newRenderer([]templateOverride{override}, "Acme", false)
	if err != nil {
		t.Fatal(err)
	}
	custom, err := r.render(MessagePasswordReset, "en", "email", dataFor("en", false, true))
	if err != nil {
		t.Fatal(err)
	}
	builtIn := newTestRenderer(t)
	original, err := builtIn.render(MessagePasswordReset, "en", "email", dataFor("en", false, true))
	if err != nil {
		t.Fatal(err)
	}
	if custom.subject != "Password for Acme" {
		t.Errorf("the subject = %q, want the override", custom.subject)
	}
	if strings.ReplaceAll(custom.text, "Acme", "the service") != original.text {
		t.Errorf("the text must be the built-in one: %q", custom.text)
	}
	if short, _ := r.render(MessagePasswordReset, "en", "phone", dataFor("en", false, true)); short.text != "123456 is your code" {
		t.Errorf("the short text = %q, want the override", short.text)
	}
	if russian, _ := r.render(MessagePasswordReset, "ru", "email", dataFor("ru", false, true)); !strings.HasPrefix(russian.subject, "Сброс пароля") {
		t.Errorf("the Russian message must keep its own text: %q", russian.subject)
	}
	if other, _ := r.render(MessageVerification, "en", "email", dataFor("en", false, true)); !strings.HasPrefix(other.subject, "Confirm") {
		t.Errorf("another kind must keep its own text: %q", other.subject)
	}
}

func TestAnHTMLTemplateThatGivesNothingLeavesTheHTMLPartOut(t *testing.T) {
	override := templateOverride{kind: MessageVerification, language: "en", template: MessageTemplate{HTML: " "}}
	r, err := newRenderer([]templateOverride{override}, "", false)
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.render(MessageVerification, "en", "email", dataFor("en", true, true))
	if err != nil || out.html != "" || out.text == "" {
		t.Fatalf("render = %+v, %v; want a message without an HTML part", out, err)
	}
}

func TestBadOverridesAreRefused(t *testing.T) {
	cases := map[string]MessageTemplate{
		"a subject that does not parse":     {Subject: "{{.ServiceName"},
		"a text that does not parse":        {Text: "{{if}}"},
		"an HTML that does not parse":       {HTML: "<p>{{if .Link}}</p>"},
		"a short text that does not parse":  {Short: "{{end}}"},
		"a field that does not exist":       {Text: "{{.Password}}"},
		"a function that does not exist":    {Text: "{{ shell .Code }}"},
		"a call that fails":                 {Subject: "{{index .Code 99}}"},
		"a subject with a line feed":        {Subject: "Hello\nBcc: someone@example.com"},
		"a subject with a carriage return":  {Subject: "Hello\rBcc: someone@example.com"},
		"a subject with a tab":              {Subject: "Hello\tthere"},
		"a subject with a NUL":              {Subject: "Hello\x00"},
		"a subject with a line separator":   {Subject: "Hello" + string(rune(0x2028)) + "there"},
		"a subject with a paragraph break":  {Subject: "Hello" + string(rune(0x2029)) + "there"},
		"a subject with a next line":        {Subject: "Hello" + string(rune(0x85)) + "there"},
		"a short text with a line feed":     {Short: "Code\n{{.Code}}"},
		"a short text with a carriage":      {Short: "Code\r{{.Code}}"},
		"a break only when there is a code": {Subject: "Hello{{if .Code}}\nthere{{end}}"},
		"a break only when there is a link": {Short: "Hello{{if .Link}}\r\nthere{{end}}"},
		"a subject that gives nothing":      {Subject: "{{/* nothing */}}"},
		"a text that gives nothing":         {Text: "  "},
		"a short text that gives nothing":   {Short: "{{\"\"}}"},
	}
	for name, template := range cases {
		for _, language := range supportedLanguages {
			_, err := newRenderer([]templateOverride{{kind: MessageVerification, language: language, template: template}}, "", false)
			if err == nil {
				t.Errorf("%s in %s: the template was accepted", name, language)
				continue
			}
			if !strings.Contains(err.Error(), "limb:") || !strings.Contains(err.Error(), string(MessageVerification)) || !strings.Contains(err.Error(), language) {
				t.Errorf("%s in %s: the error does not say which template it is: %v", name, language, err)
			}
		}
	}
}

func TestTheSameTemplateGivenTwiceIsRefused(t *testing.T) {
	override := templateOverride{kind: MessageVerification, language: "en", template: MessageTemplate{Subject: "x"}}
	if _, err := newRenderer([]templateOverride{override, override}, "", false); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("newRenderer = %v, want an error about a template given twice", err)
	}
	other := override
	other.language = "ru"
	if _, err := newRenderer([]templateOverride{override, other}, "", false); err != nil {
		t.Fatalf("a template for another language is not a duplicate: %v", err)
	}
}

func TestAMessageWhoseTextBreaksTheRulesIsRefusedWhenItIsSent(t *testing.T) {
	r := newTestRenderer(t)
	key := templateKey{MessageVerification, "en"}
	bad := r.sets[key]
	subject, short := parseOrFail(t, "Hello{{if .Link}}\nthere{{end}}"), parseOrFail(t, "Code{{if .Link}}\rthere{{end}}")
	bad.subject, bad.short = subject, short
	r.sets[key] = bad
	for _, channel := range []string{"email", "phone"} {
		if _, err := r.render(MessageVerification, "en", channel, dataFor("en", true, true)); !errors.Is(err, errBadText) {
			t.Errorf("render for %s = %v, want errBadText", channel, err)
		}
		if _, err := r.render(MessageVerification, "en", channel, dataFor("en", false, true)); err != nil {
			t.Errorf("render for %s of data that does not trigger the break failed: %v", channel, err)
		}
	}
}

func TestOnlyAnAbsoluteHTTPSLinkGoesIntoAMessage(t *testing.T) {
	r := newTestRenderer(t)
	development, err := newRenderer(nil, "", true)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		link        string
		production  bool
		development bool
	}{
		{"https://app.example.com/reset#token=abc", true, true},
		{"HTTPS://app.example.com/reset", true, true},
		{"http://localhost:8080/reset#token=abc", false, true},
		{"javascript:alert(1)", false, false},
		{"data:text/html,x", false, false},
		{"//app.example.com/reset", false, false},
		{"/reset#token=abc", false, false},
		{"reset", false, false},
		{"https://", false, false},
		{"https:///reset", false, false},
		{"ftp://app.example.com/reset", false, false},
		{"https://app.example.com/re set", false, false},
		{"https://app.example.com/reset\n", false, false},
		{"https://app.example.com/reset\r\nBcc: x", false, false},
		{"https://app.example.com/\x00", false, false},
		{"https://app.example.com/%zz", false, false},
		{" https://app.example.com/reset", false, false},
	}
	for _, c := range cases {
		for name, renderer := range map[string]*renderer{"production": r, "development": development} {
			want := c.production
			if name == "development" {
				want = c.development
			}
			data := dataFor("en", false, true)
			data.Link, data.LinkExpiresIn = c.link, "30 minutes"
			_, err := renderer.render(MessageVerification, "en", "email", data)
			if (err == nil) != want {
				t.Errorf("%s: the link %q gave %v, want accepted = %v", name, c.link, err, want)
			}
			if err != nil && !errors.Is(err, errUnsafeLink) {
				t.Errorf("%s: the link %q gave %v, want errUnsafeLink", name, c.link, err)
			}
		}
	}
	if _, err := r.render(MessageVerification, "en", "email", dataFor("en", false, true)); err != nil {
		t.Errorf("a message without a link must be accepted: %v", err)
	}
}

func TestUnknownKindsHaveNoTemplate(t *testing.T) {
	r := newTestRenderer(t)
	if _, err := r.render("other", "en", "email", MessageData{}); err == nil {
		t.Fatal("a message of an unknown kind was rendered")
	}
}

func TestDescribeDuration(t *testing.T) {
	cases := []struct {
		d        time.Duration
		language string
		want     string
	}{
		{0, "en", "1 minute"},
		{time.Second, "en", "1 minute"},
		{time.Minute, "en", "1 minute"},
		{61 * time.Second, "en", "2 minutes"},
		{10 * time.Minute, "en", "10 minutes"},
		{30 * time.Minute, "en", "30 minutes"},
		{90 * time.Minute, "en", "90 minutes"},
		{time.Hour, "en", "1 hour"},
		{2 * time.Hour, "en", "2 hours"},
		{24 * time.Hour, "en", "24 hours"},
		{48 * time.Hour, "en", "48 hours"},
		{72 * time.Hour, "en", "3 days"},
		{7 * 24 * time.Hour, "en", "7 days"},
		{49 * time.Hour, "en", "49 hours"},
		{0, "ru", "1 минута"},
		{2 * time.Minute, "ru", "2 минуты"},
		{4 * time.Minute, "ru", "4 минуты"},
		{5 * time.Minute, "ru", "5 минут"},
		{10 * time.Minute, "ru", "10 минут"},
		{11 * time.Minute, "ru", "11 минут"},
		{12 * time.Minute, "ru", "12 минут"},
		{14 * time.Minute, "ru", "14 минут"},
		{21 * time.Minute, "ru", "21 минута"},
		{22 * time.Minute, "ru", "22 минуты"},
		{25 * time.Minute, "ru", "25 минут"},
		{30 * time.Minute, "ru", "30 минут"},
		{111 * time.Minute, "ru", "111 минут"},
		{121 * time.Minute, "ru", "121 минута"},
		{time.Hour, "ru", "1 час"},
		{2 * time.Hour, "ru", "2 часа"},
		{5 * time.Hour, "ru", "5 часов"},
		{11 * time.Hour, "ru", "11 часов"},
		{21 * time.Hour, "ru", "21 час"},
		{24 * time.Hour, "ru", "24 часа"},
		{72 * time.Hour, "ru", "3 дня"},
		{5 * 24 * time.Hour, "ru", "5 дней"},
		{21 * 24 * time.Hour, "ru", "21 день"},
		{time.Hour, "de", "1 hour"},
	}
	for _, c := range cases {
		if got := describeDuration(c.language, c.d); got != c.want {
			t.Errorf("describeDuration(%q, %v) = %q, want %q", c.language, c.d, got, c.want)
		}
	}
}

func TestHasControl(t *testing.T) {
	for _, text := range []string{"\n", "a\rb", "\t", "\x00", "\x7f", "a" + string(rune(0x85)), string(rune(0x2028)), string(rune(0x2029)), "\x1b[31m"} {
		if !hasControl(text) {
			t.Errorf("hasControl(%q) = false", text)
		}
	}
	for _, text := range []string{"", "plain", "Пароль изменён", "emoji \U0001F600", "a b", "tab-free; punctuation!"} {
		if hasControl(text) {
			t.Errorf("hasControl(%q) = true", text)
		}
	}
}

func TestEveryBuiltInTemplateFileIsValidUTF8WithoutControlCharacters(t *testing.T) {
	for _, kind := range messageKinds {
		for _, language := range supportedLanguages {
			source, err := builtinSource(kind, language)
			if err != nil {
				t.Fatal(err)
			}
			for name, text := range map[string]string{"subject": source.Subject, "text": source.Text, "html": source.HTML, "short": source.Short} {
				if !utf8.ValidString(text) || strings.ContainsFunc(text, func(r rune) bool { return r < ' ' && r != '\n' }) {
					t.Errorf("the %s template of %s in %s has characters that are not allowed", name, kind, language)
				}
			}
		}
	}
}

func parseOrFail(t *testing.T, source string) *texttemplate.Template {
	t.Helper()
	parsed, err := texttemplate.New("x").Parse(source)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
