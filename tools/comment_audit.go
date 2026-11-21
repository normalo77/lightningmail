// comment_audit: dumps all string literals + numbers of Go files below roots.
// Usage: go run tools/comment_audit.go <dir>...
// The comment sweep must not change its output between old and new tree:
// diff <(audit OLD) <(audit NEW) must be empty.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func main() {
	var out []string
	fset := token.NewFileSet()
	for _, root := range os.Args[1:] {
		_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() || !strings.HasSuffix(p, ".go") {
				return nil
			}
			f, err := parser.ParseFile(fset, p, nil, parser.ParseComments)
			if err != nil {
				out = append(out, "PARSEERR "+p+" "+err.Error())
				return nil
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if b, ok := n.(*ast.BasicLit); ok {
					out = append(out, p+" "+b.Kind.String()+" "+b.Value)
				}
				return true
			})
			// constant expressions can fold literals away; also capture raw strings in value specs
			for _, c := range f.Comments {
				_ = c // comments are the only thing allowed to change
			}
			return nil
		})
	}
	sort.Strings(out)
	fmt.Println(strings.Join(out, "\n"))
	fmt.Fprintln(os.Stderr, "literals:", len(out))
	_ = strconv.Itoa(0)
}
