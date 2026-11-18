package adminui

import (
	"os"
	"strings"
	"testing"
)

const textsDocument = "../../docs/admin-texts.md"

func textsTable() string {
	var out strings.Builder
	out.WriteString("# Texts of the administration\n\n")
	out.WriteString("`limb.WithAdminTexts` replaces these texts and gives the administration languages of its own. ")
	out.WriteString("A text that has `%s` or `%d` in it takes an argument, which the page fills in, and a replacement must use the same arguments, in any order, with `%[1]s` for the first one and so on. ")
	out.WriteString("A text that takes none must not have a percent sign in it. A language that lacks a text shows the English one.\n\n")
	out.WriteString("This file is made from the texts of the library by a test. After a text changes, make it again with `LIMB_UPDATE_DOCS=1 go test ./internal/adminui -run TestTheTableOfTheTextsIsUpToDate`.\n\n")
	out.WriteString("| Key | English | Русский |\n| --- | --- | --- |\n")
	cell := strings.NewReplacer("|", `\|`, "\n", " ")
	for _, key := range Keys() {
		out.WriteString("| `" + key + "` | " + cell.Replace(english[key]) + " | " + cell.Replace(russian[key]) + " |\n")
	}
	return out.String()
}

func TestTheTableOfTheTextsIsUpToDate(t *testing.T) {
	want := textsTable()
	if os.Getenv("LIMB_UPDATE_DOCS") == "1" {
		if err := os.WriteFile(textsDocument, []byte(want), 0o644); err != nil { //nolint:gosec
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(textsDocument)
	if err != nil {
		t.Fatalf("the table of the texts cannot be read: %v; make it with LIMB_UPDATE_DOCS=1 go test ./internal/adminui -run TestTheTableOfTheTextsIsUpToDate", err)
	}
	if string(got) != want {
		t.Fatal("docs/admin-texts.md is not the table of the texts of the library; make it again with LIMB_UPDATE_DOCS=1 go test ./internal/adminui -run TestTheTableOfTheTextsIsUpToDate")
	}
}
