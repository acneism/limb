package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	exitClean      = 0
	exitViolations = 1
	exitFailure    = 2
	defaultRoot    = "."
	examplePrefix  = "Example"
	nolintPrefix   = "//nolint"
	usage          = "usage: commentcheck [dir ...]"
)

var (
	nolintDirective = regexp.MustCompile(`^//nolint:[A-Za-z0-9_-]+(,[A-Za-z0-9_-]+)*$`)
	outputMarker    = regexp.MustCompile(`(?i)^(unordered )?output:`)
)

type violation struct {
	path string
	line int
	col  int
}

func (v violation) String() string {
	return fmt.Sprintf("%s:%d:%d: comment not allowed", v.path, v.line, v.col)
}

func compareViolations(a, b violation) int {
	if c := strings.Compare(a.path, b.path); c != 0 {
		return c
	}
	if a.line != b.line {
		return a.line - b.line
	}
	return a.col - b.col
}

type groupSet map[*ast.CommentGroup]bool

func (s groupSet) add(group *ast.CommentGroup) {
	if group != nil {
		s[group] = true
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	roots := args
	if len(roots) == 0 {
		roots = []string{defaultRoot}
	}
	cwd, err := os.Getwd()
	if err != nil {
		printLine(stderr, err.Error())
		return exitFailure
	}
	files, err := collectGoFiles(roots)
	if err != nil {
		printLine(stderr, err.Error())
		return exitFailure
	}
	violations, failed := checkFiles(cwd, files, stderr)
	if failed {
		return exitFailure
	}
	slices.SortFunc(violations, compareViolations)
	for _, v := range violations {
		printLine(stdout, v.String())
	}
	if len(violations) > 0 {
		return exitViolations
	}
	return exitClean
}

func printLine(w io.Writer, line string) {
	_, _ = fmt.Fprintln(w, line)
}

func checkFiles(cwd string, files []string, stderr io.Writer) ([]violation, bool) {
	var all []violation
	failed := false
	for _, file := range files {
		found, err := checkFile(cwd, file)
		if err != nil {
			printLine(stderr, err.Error())
			failed = true
			continue
		}
		all = append(all, found...)
	}
	return all, failed
}

func checkFile(cwd, file string) ([]violation, error) {
	src, err := os.ReadFile(file) //nolint:gosec
	if err != nil {
		return nil, err
	}
	return checkSource(displayPath(cwd, file), src)
}

func displayPath(cwd, file string) string {
	rel, err := filepath.Rel(cwd, file)
	if err != nil {
		return file
	}
	return rel
}

func collectGoFiles(roots []string) ([]string, error) {
	seen := make(map[string]bool)
	var files []string
	for _, root := range roots {
		found, err := walkRoot(root)
		if err != nil {
			return nil, err
		}
		for _, file := range found {
			if !seen[file] {
				seen[file] = true
				files = append(files, file)
			}
		}
	}
	return files, nil
}

func walkRoot(root string) ([]string, error) {
	if strings.HasPrefix(root, "-") {
		return nil, fmt.Errorf("%s: unknown flag %q", usage, root)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs) //nolint:gosec
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s: not a directory", root)
	}
	var files []string
	err = filepath.WalkDir(abs, func(path string, entry fs.DirEntry, walkErr error) error { //nolint:gosec
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != abs && isSkippedDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type().IsRegular() && strings.HasSuffix(path, ".go") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func isSkippedDir(name string) bool {
	return name == "testdata" || name == "vendor" ||
		strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
}

func checkSource(path string, src []byte) ([]violation, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	if ast.IsGenerated(file) {
		return nil, nil
	}
	allowed := allowedGroups(file, strings.HasSuffix(path, "_test.go"))
	var found []violation
	for _, group := range file.Comments {
		for _, comment := range group.List {
			if commentAllowed(comment, allowed[group]) {
				continue
			}
			pos := fset.Position(comment.Slash)
			found = append(found, violation{path: path, line: pos.Line, col: pos.Column})
		}
	}
	slices.SortFunc(found, compareViolations)
	return found, nil
}

func commentAllowed(comment *ast.Comment, inAllowedGroup bool) bool {
	if strings.HasPrefix(comment.Text, "/*") {
		return false
	}
	if strings.HasPrefix(comment.Text, nolintPrefix) {
		return nolintDirective.MatchString(comment.Text)
	}
	return inAllowedGroup || isDirective(comment.Text)
}

func isDirective(text string) bool {
	return strings.HasPrefix(text, "//go:") || nolintDirective.MatchString(text)
}

func allowedGroups(file *ast.File, isTestFile bool) groupSet {
	allowed := groupSet{}
	allowed.add(file.Doc)
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if isExportedFunc(d) {
				allowed.add(d.Doc)
			}
			if isTestFile && isExampleFunc(d) {
				allowed.addOutputGroups(file, d)
			}
		case *ast.GenDecl:
			allowed.addGenDecl(d)
		}
	}
	return allowed
}

func (s groupSet) addOutputGroups(file *ast.File, fn *ast.FuncDecl) {
	if fn.Body == nil {
		return
	}
	for _, group := range file.Comments {
		inBody := group.Pos() > fn.Body.Lbrace && group.End() < fn.Body.Rbrace
		if inBody && isOutputGroup(group) {
			s.add(group)
		}
	}
}

func isOutputGroup(group *ast.CommentGroup) bool {
	first := group.List[0].Text
	if !strings.HasPrefix(first, "//") {
		return false
	}
	return outputMarker.MatchString(strings.TrimSpace(strings.TrimPrefix(first, "//")))
}

func isExampleFunc(fn *ast.FuncDecl) bool {
	if fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, examplePrefix) {
		return false
	}
	rest := strings.TrimPrefix(fn.Name.Name, examplePrefix)
	if rest == "" {
		return true
	}
	first, _ := utf8.DecodeRuneInString(rest)
	return !unicode.IsLower(first)
}

func isExportedFunc(fn *ast.FuncDecl) bool {
	if !fn.Name.IsExported() {
		return false
	}
	if fn.Recv == nil {
		return true
	}
	return len(fn.Recv.List) > 0 && ast.IsExported(baseTypeName(fn.Recv.List[0].Type))
}

func baseTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return baseTypeName(e.X)
	case *ast.ParenExpr:
		return baseTypeName(e.X)
	case *ast.IndexExpr:
		return baseTypeName(e.X)
	case *ast.IndexListExpr:
		return baseTypeName(e.X)
	case *ast.SelectorExpr:
		return e.Sel.Name
	default:
		return ""
	}
}

func (s groupSet) addGenDecl(decl *ast.GenDecl) {
	declaresExported := false
	for _, spec := range decl.Specs {
		if s.addSpec(spec) {
			declaresExported = true
		}
	}
	if declaresExported {
		s.add(decl.Doc)
	}
}

func (s groupSet) addSpec(spec ast.Spec) bool {
	switch sp := spec.(type) {
	case *ast.ValueSpec:
		if !anyExported(sp.Names) {
			return false
		}
		s.add(sp.Doc)
		return true
	case *ast.TypeSpec:
		if !sp.Name.IsExported() {
			return false
		}
		s.add(sp.Doc)
		s.addTypeMembers(sp.Type)
		return true
	default:
		return false
	}
}

func (s groupSet) addTypeMembers(expr ast.Expr) {
	switch t := expr.(type) {
	case *ast.StructType:
		for _, field := range t.Fields.List {
			if isExportedField(field) {
				s.add(field.Doc)
			}
		}
	case *ast.InterfaceType:
		for _, method := range t.Methods.List {
			if anyExported(method.Names) {
				s.add(method.Doc)
			}
		}
	}
}

func isExportedField(field *ast.Field) bool {
	if len(field.Names) == 0 {
		return ast.IsExported(baseTypeName(field.Type))
	}
	return anyExported(field.Names)
}

func anyExported(names []*ast.Ident) bool {
	return slices.ContainsFunc(names, (*ast.Ident).IsExported)
}
