package password

import (
	_ "embed"
	"strings"
	"sync"
)

//go:embed data/10k-most-common.txt
var commonList string

var commonSet = sync.OnceValue(func() map[string]struct{} {
	lines := strings.Split(commonList, "\n")
	set := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		line = strings.ToLower(strings.TrimSpace(line))
		if line != "" {
			set[line] = struct{}{}
		}
	}
	return set
})

func IsCommon(password string) bool {
	_, found := commonSet()[strings.ToLower(password)]
	return found
}
