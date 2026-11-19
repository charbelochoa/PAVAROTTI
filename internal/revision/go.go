package revision

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
)

const MaxSource = 1 << 20

type Report struct {
	Package string    `json:"package"`
	Imports []string  `json:"imports"`
	Signals []Finding `json:"signals"`
}

type Finding struct {
	Line   int    `json:"line"`
	Column int    `json:"column"`
	Rule   string `json:"rule"`
	Review string `json:"review"`
}

func ReviewGo(source []byte) (Report, error) {
	if len(source) > MaxSource {
		return Report{}, fmt.Errorf("la revisión de código admite archivos Go de hasta 1 MiB")
	}
	files := token.NewFileSet()
	file, err := parser.ParseFile(files, "fuente.go", source, parser.SkipObjectResolution)
	if err != nil {
		return Report{}, fmt.Errorf("fuente Go inválida: %w", err)
	}
	report := Report{Package: file.Name.Name, Imports: []string{}, Signals: []Finding{}}
	aliases := make(map[string]string)
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		report.Imports = append(report.Imports, path)
		name := ""
		switch path {
		case "crypto/tls":
			name = "tls"
		case "net/http":
			name = "http"
		case "os/exec":
			name = "exec"
		}
		if name == "" {
			continue
		}
		if spec.Name != nil {
			name = spec.Name.Name
		}
		aliases[name] = path
	}
	add := func(node ast.Node, rule, message string) {
		if len(report.Signals) >= 250 {
			return
		}
		pos := files.Position(node.Pos())
		report.Signals = append(report.Signals, Finding{Line: pos.Line, Column: pos.Column, Rule: rule, Review: message})
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch entry := node.(type) {
		case *ast.CallExpr:
			pkg, name := selector(entry.Fun, aliases)
			switch {
			case pkg == "net/http" && (name == "Get" || name == "Post" || name == "ListenAndServe"):
				add(entry, "http-limites", "Revisa los límites de tiempo del cliente o servidor HTTP.")
			case pkg == "os/exec" && (name == "Command" || name == "CommandContext"):
				add(entry, "proceso-externo", "Verifica el origen del comando y de sus argumentos.")
			}
		case *ast.CompositeLit:
			pkg, name := selector(entry.Type, aliases)
			if pkg == "crypto/tls" && name == "Config" {
				for _, element := range entry.Elts {
					pair, ok := element.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, keyOK := pair.Key.(*ast.Ident)
					value, valueOK := pair.Value.(*ast.Ident)
					if keyOK && valueOK && key.Name == "InsecureSkipVerify" && value.Name == "true" {
						add(pair, "tls-verificacion", "La configuración deshabilita la verificación TLS. Revisa su uso.")
					}
				}
			}
		}
		return true
	})
	return report, nil
}

func selector(expression ast.Expr, aliases map[string]string) (string, string) {
	selected, ok := expression.(*ast.SelectorExpr)
	if !ok {
		return "", ""
	}
	identifier, ok := selected.X.(*ast.Ident)
	if !ok {
		return "", ""
	}
	return aliases[identifier.Name], selected.Sel.Name
}
