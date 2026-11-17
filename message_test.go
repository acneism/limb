package limb

import (
	"context"
	"strings"
	"testing"

	"github.com/acneism/limb/internal/memstore"
)

type nopSender struct{}

func (nopSender) Send(context.Context, Message) error { return nil }

func TestNewRejectsBadMessageOptions(t *testing.T) {
	cases := []struct {
		name    string
		option  Option
		mention string
	}{
		{"a nil sender", WithSender(nil), "sender"},
		{"an empty service name", WithServiceName(""), "name of the service"},
		{"a long service name", WithServiceName(strings.Repeat("a", 65)), "name of the service"},
		{"a service name with a break", WithServiceName("Acme\nBcc: x"), "name of the service"},
		{"a service name that is bytes", WithServiceName(string([]byte{0xff, 0xfe})), "name of the service"},
		{"an unknown kind", WithMessageTemplate("other", "en", MessageTemplate{Subject: "x"}), "kind of message"},
		{"an unknown language", WithMessageTemplate(MessageVerification, "de", MessageTemplate{Subject: "x"}), "language"},
		{"a language in capitals", WithMessageTemplate(MessageVerification, "EN", MessageTemplate{Subject: "x"}), "language"},
		{"a template that is broken", WithMessageTemplate(MessageVerification, "en", MessageTemplate{Text: "{{"}), "not valid"},
		{"a subject with a break", WithMessageTemplate(MessageVerification, "ru", MessageTemplate{Subject: "a\nb"}), "one line"},
		{"a template given twice", func(c *config) {
			WithMessageTemplate(MessageVerification, "en", MessageTemplate{Subject: "a"})(c)
			WithMessageTemplate(MessageVerification, "en", MessageTemplate{Subject: "b"})(c)
		}, "twice"},
	}
	for _, c := range cases {
		_, err := NewWithStore(memstore.New(), []byte(testKey), WithAutoMigrate(), c.option)
		if err == nil || !strings.Contains(err.Error(), c.mention) {
			t.Errorf("%s: New = %v, want an error that mentions %q", c.name, err, c.mention)
		}
	}
}

func TestNewAcceptsGoodMessageOptions(t *testing.T) {
	good := []Option{
		WithSender(nopSender{}),
		WithServiceName(strings.Repeat("я", 64)),
		WithServiceName("Acme & Co <1>"),
		WithMessageTemplate(MessageVerification, "ru", MessageTemplate{Subject: "Проверка {{.ServiceName}}", Short: "{{.Code}}"}),
		WithMessageTemplate(MessageVerification, "en", MessageTemplate{Subject: "Check {{.ServiceName}}"}),
		WithMessageTemplate(MessagePasswordReset, "en", MessageTemplate{HTML: "<p>{{.Code}}</p>"}),
	}
	a, err := NewWithStore(memstore.New(), []byte(testKey), append([]Option{WithAutoMigrate()}, good...)...)
	if err != nil {
		t.Fatalf("New refused good options: %v", err)
	}
	out, err := a.renderer.render(MessageVerification, "ru", "phone", MessageData{Code: "123456"})
	if err != nil || out.text != "123456" {
		t.Fatalf("the template of the option was not used: %+v, %v", out, err)
	}
}

func TestAServiceWithoutOptionsHasTheBuiltInTemplates(t *testing.T) {
	a := newTestAuth(t)
	out, err := a.renderer.render(MessagePasswordChanged, "en", "email", MessageData{})
	if err != nil || out.subject != "Your password on the service was changed" {
		t.Fatalf("render = %+v, %v", out, err)
	}
}
