package password

import (
	_ "embed"
	"slices"
	"strings"
	"sync"
)

//go:embed data/common-passwords.txt
var commonList string

var commonEntries = sync.OnceValue(func() []string {
	return strings.Split(strings.TrimSuffix(commonList, "\n"), "\n")
})

func IsCommon(password string) bool {
	_, found := slices.BinarySearch(commonEntries(), strings.ToLower(Normalize(password)))
	return found
}
