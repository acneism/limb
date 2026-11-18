package adminui

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
)

//go:embed static/admin.css
var staticFiles embed.FS

var stylesheet = readStylesheet()

func readStylesheet() []byte {
	data, err := staticFiles.ReadFile("static/admin.css")
	if err != nil {
		panic("adminui: the stylesheet is not embedded: " + err.Error())
	}
	return data
}

// StylesheetName is the name under which the stylesheet is served: it carries the
// first 16 hexadecimal digits of the SHA-256 of the file, so that a browser may
// keep it for good and fetches the new one whenever the file changes.
func StylesheetName() string {
	sum := sha256.Sum256(stylesheet)
	return "admin." + hex.EncodeToString(sum[:8]) + ".css"
}

// Stylesheet returns the stylesheet of the administration.
func Stylesheet() []byte {
	return stylesheet
}
