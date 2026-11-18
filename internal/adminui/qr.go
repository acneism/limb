package adminui

import (
	"fmt"
	"html/template"
	"strings"

	"rsc.io/qr"
)

const quietZone = 4

// QR returns the QR code of the text as an SVG image that is meant to be put into
// a page as it is. It is one path of rectangles on a white background with the
// quiet zone that scanners need, so it has no style, no script and no reference to
// anything, and a policy that allows no inline style and no images of other
// origins does not stand in its way. label is what a screen reader says for it.
func QR(text, label string) (template.HTML, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", fmt.Errorf("adminui: encode the QR code: %w", err)
	}
	size := code.Size + 2*quietZone
	var path strings.Builder
	for y := range code.Size {
		for x := 0; x < code.Size; {
			if !code.Black(x, y) {
				x++
				continue
			}
			start := x
			for x < code.Size && code.Black(x, y) {
				x++
			}
			fmt.Fprintf(&path, "M%d %dh%dv1h-%dz", start+quietZone, y+quietZone, x-start, x-start)
		}
	}
	return template.HTML(fmt.Sprintf( //nolint:gosec
		`<svg xmlns="http://www.w3.org/2000/svg" class="qr" viewBox="0 0 %[1]d %[1]d" role="img" aria-label="%[2]s" shape-rendering="crispEdges">`+
			`<rect width="%[1]d" height="%[1]d" fill="#fff"/><path d="%[3]s" fill="#000"/></svg>`,
		size, template.HTMLEscapeString(label), path.String())), nil
}
