package adminui

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// DefaultLanguage is the language that is shown when the one that is asked for
// has no text.
const DefaultLanguage = "en"

var languagePattern = regexp.MustCompile(`^[a-z]{2,3}$`)

// Catalog holds the texts of the administration in the languages that it speaks.
type Catalog struct {
	texts     map[string]map[string]string
	languages []string
}

// NewCatalog returns the texts that the library has, English and Russian, with
// what the application replaced or added over them. A language that the library
// has no texts for is added with the texts that are given and shows English for the
// rest. It returns an error for a language tag that is not two or three lower
// case letters, for a key that no text of the library has, for a replacement
// that has no text at all and for one that does not use the arguments of the
// original: a text that takes none must not hold a percent sign, and one that
// takes some must use them with the same verbs, in any order.
func NewCatalog(overrides map[string]map[string]string) (*Catalog, error) {
	c := &Catalog{texts: map[string]map[string]string{
		"en": maps.Clone(english),
		"ru": maps.Clone(russian),
	}}
	for _, language := range slices.Sorted(maps.Keys(overrides)) {
		if !languagePattern.MatchString(language) {
			return nil, fmt.Errorf("%q is not a language: it is two or three lower case letters", language)
		}
		if c.texts[language] == nil {
			c.texts[language] = map[string]string{}
		}
		for _, key := range slices.Sorted(maps.Keys(overrides[language])) {
			if _, known := english[key]; !known {
				return nil, fmt.Errorf("there is no text %q to replace", key)
			}
			if overrides[language][key] == "" {
				return nil, fmt.Errorf("the text %q of the language %q is empty", key, language)
			}
			if err := checkArguments(key, overrides[language][key]); err != nil {
				return nil, fmt.Errorf("%w, language %q", err, language)
			}
			c.texts[language][key] = overrides[language][key]
		}
	}
	c.languages = slices.Sorted(maps.Keys(c.texts))
	return c, nil
}

func checkArguments(key, text string) error {
	args := argumentsOf(english[key])
	if len(args) == 0 {
		if strings.Contains(text, "%") {
			return fmt.Errorf("the text %q takes no argument, so it must not hold a percent sign", key)
		}
		return nil
	}
	if strings.Contains(fmt.Sprintf(text, args...), "%!") {
		return fmt.Errorf("the text %q must use its arguments as the original %q does", key, english[key])
	}
	return nil
}

func argumentsOf(original string) []any {
	var args []any
	for i := 0; i+1 < len(original); i++ {
		if original[i] != '%' {
			continue
		}
		i++
		switch original[i] {
		case 's':
			args = append(args, "text")
		case 'd':
			args = append(args, 1)
		}
	}
	return args
}

// Languages returns the tags of the languages, in alphabetical order.
func (c *Catalog) Languages() []string {
	return slices.Clone(c.languages)
}

// Has tells whether the administration speaks the language.
func (c *Catalog) Has(language string) bool {
	_, found := c.texts[language]
	return found
}

// Text returns the text of the key in the language, formatted with the
// arguments if there are any. A language that lacks the key shows the English
// text, and a key that no language has shows itself, so that a mistake of a
// template is seen on the page and never breaks it.
func (c *Catalog) Text(language, key string, args ...any) string {
	text, found := c.texts[language][key]
	if !found {
		text, found = c.texts[DefaultLanguage][key]
	}
	if !found {
		return key
	}
	if len(args) == 0 {
		return text
	}
	return fmt.Sprintf(text, args...)
}

// Keys returns the keys of all texts, in alphabetical order.
func Keys() []string {
	return slices.Sorted(maps.Keys(english))
}

// LanguageName returns how a language is called in itself, for the switch of the
// language, and its tag when it has no name.
func LanguageName(language string) string {
	if name, found := names[language]; found {
		return name
	}
	return language
}

var names = map[string]string{
	"en": "English",
	"ru": "Русский",
}
