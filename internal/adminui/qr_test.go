package adminui

import (
	"encoding/xml"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"rsc.io/qr"
)

func TestAQRCodeIsOneSVGWithoutStyleScriptOrReferences(t *testing.T) {
	uri, _ := sampleURI(t)
	svg, err := QR(uri, `A "QR" code <of> the key`)
	if err != nil {
		t.Fatal(err)
	}
	text := string(svg)
	for _, banned := range []string{"style=", "<style", "<script", "href", "xlink", "url(", "onload", "<image", "<use", "data:"} {
		if strings.Contains(text, banned) {
			t.Errorf("the image has %q in it: %s", banned, text[:min(len(text), 300)])
		}
	}
	var parsed struct {
		XMLName xml.Name
		Label   string `xml:"aria-label,attr"`
		Role    string `xml:"role,attr"`
		Box     string `xml:"viewBox,attr"`
		Paths   []struct {
			D    string `xml:"d,attr"`
			Fill string `xml:"fill,attr"`
		} `xml:"path"`
	}
	if err = xml.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("the image is not XML: %v", err)
	}
	if parsed.XMLName.Local != "svg" || parsed.Role != "img" || parsed.Label != `A "QR" code <of> the key` || len(parsed.Paths) != 1 || parsed.Paths[0].Fill != "#000" {
		t.Fatalf("the image is %+v", parsed)
	}
	if strings.Count(text, "<svg") != 1 || !strings.Contains(text, `<rect width="`) || !strings.Contains(text, `fill="#fff"`) {
		t.Fatal("the image has no white background")
	}
}

func TestTheModulesOfAQRCodeAreTheOnesThatTheEncoderMade(t *testing.T) {
	text, _ := sampleURI(t)
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		t.Fatal(err)
	}
	svg, err := QR(text, "code")
	if err != nil {
		t.Fatal(err)
	}
	size := code.Size + 2*quietZone
	if !strings.Contains(string(svg), `viewBox="0 0 `+strconv.Itoa(size)+" "+strconv.Itoa(size)+`"`) {
		t.Fatalf("the size of the image is not %d modules with the quiet zone of %d", size, quietZone)
	}
	paint := make([][]bool, size)
	for i := range paint {
		paint[i] = make([]bool, size)
	}
	d := regexp.MustCompile(` d="([^"]*)"`).FindStringSubmatch(string(svg))[1]
	for _, m := range regexp.MustCompile(`M(\d+) (\d+)h(\d+)v1h-(\d+)z`).FindAllStringSubmatch(d, -1) {
		x, _ := strconv.Atoi(m[1])
		y, _ := strconv.Atoi(m[2])
		w, _ := strconv.Atoi(m[3])
		if m[3] != m[4] || w < 1 {
			t.Fatalf("a rectangle is %v", m)
		}
		for i := range w {
			if paint[y][x+i] {
				t.Fatalf("the module %d,%d is painted twice", x+i, y)
			}
			paint[y][x+i] = true
		}
	}
	for y := range size {
		for x := range size {
			want := x >= quietZone && y >= quietZone && x < size-quietZone && y < size-quietZone && code.Black(x-quietZone, y-quietZone)
			if paint[y][x] != want {
				t.Fatalf("the module %d,%d is %v, want %v", x, y, paint[y][x], want)
			}
		}
	}
}

func TestATextThatDoesNotFitAQRCodeIsAnError(t *testing.T) {
	if _, err := QR(strings.Repeat("x", 5000), "code"); err == nil {
		t.Fatal("a text of 5000 characters was encoded")
	}
}
