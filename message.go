package limb

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Sender delivers the messages of limb to users: the links and codes of
// verification and password reset, and the notices about a changed password and
// an attempt to sign up with an address that is taken. The application
// implements it on top of its mail service or its SMS gateway.
//
// limb calls Send from a background goroutine, after the request that caused the
// message has been answered, with a context that ends when the sending timeout
// of WithSending passes. Send has to stop when its context ends: a Send that
// does not return keeps one of the workers of limb busy. limb calls Send once for
// a message and does not repeat it when it fails, because a repeat could deliver
// a code that is out of date or deliver the same message twice, so a Sender that
// needs retries makes them itself. Send may be called from several goroutines at
// once.
//
// A returned error, a panic and a timeout are logged, without the link or the
// code, and reported to OnEvent as a MessageFailed event.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// MessageKind says what a message is about.
type MessageKind string

// The kinds of messages.
const (
	// MessageVerification carries the link and the code that confirm an address
	// or a phone number.
	MessageVerification MessageKind = "verification"
	// MessagePasswordReset carries the link and the code that let the user choose
	// a new password.
	MessagePasswordReset MessageKind = "password_reset"
	// MessagePasswordChanged tells the user that the password of their account was
	// changed. It carries no secret.
	MessagePasswordChanged MessageKind = "password_changed"
	// MessageSignupAttempt tells the owner of an address that someone tried to
	// sign up with it, which an account has already. It carries no secret.
	MessageSignupAttempt MessageKind = "signup_attempt"
	// MessageInvitation tells the holder of an address or a phone number that an
	// administrator made an account for them, and carries the link that lets them
	// choose the password. It has no code.
	MessageInvitation MessageKind = "invitation"
	// MessageIdentifierChanged tells the user that an administrator changed an
	// address, a phone number or a name that they sign in with or are reached at.
	// It goes to the channels that were confirmed before the change, and it
	// carries no secret.
	MessageIdentifierChanged MessageKind = "identifier_changed"
)

var messageKinds = []MessageKind{
	MessageVerification, MessagePasswordReset, MessagePasswordChanged, MessageSignupAttempt, MessageInvitation, MessageIdentifierChanged,
}

// Message is what a Sender delivers. It comes ready to send, with the texts that
// the templates made, and it carries the raw data too, for an application whose
// provider makes the messages from templates of its own.
type Message struct {
	// Kind says what the message is about.
	Kind MessageKind

	// UserID is the user the message is for.
	UserID string

	// Channel is the name of the identifier type that the message goes to, for
	// example "email" or "phone", and To is the address in that channel in its
	// normalized form: the e-mail address with the domain in lower case, the phone
	// number in the international form.
	Channel string
	To      string

	// Language is the language of the texts: "ru" or "en".
	Language string

	// Subject is the subject line. It is set only for the channel "email", is one
	// line and has no control characters.
	Subject string

	// Text is the body in plain text. For a channel other than "email" it is the
	// short text that fits a text message, one line without control characters.
	Text string

	// HTML is the body in HTML. It is set only for the channel "email", and a
	// template can leave it out.
	HTML string

	// Link is the link that does what the message asks, with the secret in the
	// fragment of its address. It is empty when the message has no link, either
	// because it carries no secret or because the application gave no address of
	// the page to open it on.
	Link string

	// Code is the code of six digits that does the same as the link, empty when
	// the message carries no secret.
	Code string

	// LinkExpiresAt and CodeExpiresAt say when the link and the code stop working,
	// the zero time when there is none.
	LinkExpiresAt time.Time
	CodeExpiresAt time.Time
}

// MessageTemplate holds the texts of one kind of message in one language. The
// texts are written in the syntax of the packages text/template and
// html/template and are given the fields of MessageData.
//
// Subject and Short are made with text/template and have to give one line
// without control characters, which keeps a Sender that builds a message by
// hand safe from a header injection. Text is made with text/template, and HTML
// with html/template, which escapes what it inserts by the context. A field
// that is empty keeps the built-in text. To send no HTML part, give an HTML
// template that gives nothing but white space.
type MessageTemplate struct {
	// Subject is the subject line of an e-mail.
	Subject string
	// Text is the body of an e-mail in plain text.
	Text string
	// HTML is the body of an e-mail in HTML.
	HTML string
	// Short is the text of a message to a channel other than e-mail, such as a
	// phone: the only text it has.
	Short string
}

// MessageData is what the templates of messages can use. The fields that a
// message has no value for are empty: a message that has no link has an empty
// Link, so a template tests {{if .Link}} before it writes about the link.
type MessageData struct {
	// ServiceName is the name of the service, see WithServiceName.
	ServiceName string
	// Link is the link, whose address starts with https, or with http in the
	// development mode.
	Link string
	// Code is the code of six digits.
	Code string
	// LinkExpiresIn and CodeExpiresIn say how long the link and the code work, in
	// words of the language of the message, for example "30 minutes".
	LinkExpiresIn string
	CodeExpiresIn string
	// Language is the language of the message: "ru" or "en".
	Language string
}

const maxServiceNameLength = 64

var supportedLanguages = []string{defaultLanguage, "ru"}

func normalizeLanguage(tag string) string {
	primary, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(tag)), "-")
	primary, _, _ = strings.Cut(primary, "_")
	for _, language := range supportedLanguages {
		if primary == language {
			return language
		}
	}
	return defaultLanguage
}

// WithSender sets the Sender that delivers the messages of limb. Without it
// limb sends nothing, and the operations that need a message, the confirmation of
// an address and the reset of a password, are not available.
func WithSender(s Sender) Option {
	return func(c *config) {
		if s == nil {
			c.fail(errors.New("limb: the sender is nil"))
			return
		}
		c.sender = s
	}
}

// WithServiceName sets the name that the messages call the service by. It is
// 1 to 64 characters long without control characters. Without it the messages say
// "the service" and "сервис".
func WithServiceName(name string) Option {
	return func(c *config) {
		if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > maxServiceNameLength || hasControl(name) {
			c.fail(fmt.Errorf("limb: the name of the service must be 1 to %d characters without control characters", maxServiceNameLength))
			return
		}
		c.serviceName = name
	}
}

// WithMessageTemplate replaces the texts of one kind of message in one language,
// "ru" or "en". The fields of the template that are empty keep the built-in
// text. An HTML template that gives nothing but white space, for example a
// single space, leaves the HTML part out: Message.HTML is then empty and the
// message has only its plain text. The option can be given for every kind and
// language, but once for each.
// New fails for a kind or a language that does not exist, for a template that
// does not parse or cannot be run, and for a Subject or a Short text that is not
// one line without control characters.
func WithMessageTemplate(kind MessageKind, language string, t MessageTemplate) Option {
	return func(c *config) {
		switch {
		case !slices.Contains(messageKinds, kind):
			c.fail(fmt.Errorf("limb: unknown kind of message %q", kind))
		case !slices.Contains(supportedLanguages, language):
			c.fail(fmt.Errorf("limb: the language %q is not supported, use one of %s", language, strings.Join(supportedLanguages, ", ")))
		default:
			c.templates = append(c.templates, templateOverride{kind: kind, language: language, template: t})
		}
	}
}
