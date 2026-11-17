package limb

import "context"

type languageKey struct{}

// ContextWithLanguage returns a context that tells limb which language to use
// for the messages that an operation sends on its own, such as the notice that
// the password was changed, when the operation has no argument for it. The tag
// is a language tag such as "ru" or "en-GB"; a language limb has no texts for
// gives English.
func ContextWithLanguage(ctx context.Context, tag string) context.Context {
	return context.WithValue(ctx, languageKey{}, tag)
}

func (a *Auth) languageFor(ctx context.Context, explicit string) string {
	if explicit != "" {
		return normalizeLanguage(explicit)
	}
	if tag, ok := ctx.Value(languageKey{}).(string); ok {
		return normalizeLanguage(tag)
	}
	return defaultLanguage
}
