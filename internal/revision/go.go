package revision

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"strconv"

	"pavarotti/internal/caso"
)

const (
	MaxSource   = 1 << 20
	MaxFindings = 250
)

type Report = caso.CodeReview

func ReviewGo(source []byte) (Report, error) {
	if len(source) > MaxSource {
		return Report{}, fmt.Errorf("la revisión de código admite archivos Go de hasta 1 MiB")
	}
	files := token.NewFileSet()
	file, err := parser.ParseFile(files, "fuente.go", source, 0)
	if err != nil {
		return Report{}, fmt.Errorf("fuente Go inválida: %w", err)
	}
	report := Report{Package: file.Name.Name, Imports: []string{}, Signals: []caso.Finding{}, Engine: "go-ast-2"}
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
		case "crypto/hmac":
			name = "hmac"
		case "crypto/md5":
			name = "md5"
		case "crypto/sha1":
			name = "sha1"
		}
		if name == "" {
			continue
		}
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name != "_" && name != "." {
			aliases[name] = path
		}
	}
	add := func(node ast.Node, rule, message string) {
		report.Total++
		if len(report.Signals) >= MaxFindings {
			return
		}
		pos := files.PositionFor(node.Pos(), false)
		report.Signals = append(report.Signals, caso.Finding{Line: pos.Line, Column: pos.Column, Rule: rule, Review: message})
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch entry := node.(type) {
		case *ast.CallExpr:
			pkg, name := selector(entry.Fun, aliases)
			switch {
			case pkg == "net/http" && defaultHTTP(name):
				add(entry, "http-limites", "Revisa los límites de tiempo del cliente o servidor HTTP.")
			case pkg == "os/exec" && (name == "Command" || name == "CommandContext"):
				add(entry, "proceso-externo", "Verifica el origen del comando y de sus argumentos.")
			case pkg == "crypto/hmac" && name == "New" && len(entry.Args) > 0:
				hash, fn := selector(entry.Args[0], aliases)
				if fn == "New" && (hash == "crypto/md5" || hash == "crypto/sha1") {
					add(entry.Args[0], "hmac-hash-heredado", "El HMAC usa una función heredada. Revisa si el protocolo permite migrar a SHA-256.")
				}
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
					if !keyOK {
						continue
					}
					value, valueOK := ast.Unparen(pair.Value).(*ast.Ident)
					if key.Name == "InsecureSkipVerify" && valueOK && value.Obj == nil && value.Name == "true" {
						add(pair, "tls-verificacion", "La configuración deshabilita la verificación TLS. Revisa su uso.")
					}
					if key.Name == "MinVersion" {
						versionPackage, versionName := selector(pair.Value, aliases)
						if versionPackage == "crypto/tls" && (versionName == "VersionTLS10" || versionName == "VersionTLS11") {
							add(pair, "tls-version-heredada", "TLS 1.0 y 1.1 están obsoletos. Revisa la versión mínima del servicio.")
						}
					}
				}
			}
			if pkg == "net/http" && name == "Client" && !hasTimeout(entry, "Timeout", "") {
				add(entry, "http-cliente-timeout", "Revisa si el cliente HTTP tiene un plazo para completar las solicitudes.")
			}
			if pkg == "net/http" && name == "Server" && !hasTimeout(entry, "ReadHeaderTimeout", "ReadTimeout") {
				add(entry, "http-servidor-cabeceras", "Revisa el tiempo límite para leer cabeceras HTTP.")
			}
		}
		return true
	})
	return report, nil
}

func selector(expression ast.Expr, aliases map[string]string) (string, string) {
	selected, ok := ast.Unparen(expression).(*ast.SelectorExpr)
	if !ok {
		return "", ""
	}
	identifier, ok := selected.X.(*ast.Ident)
	if !ok || identifier.Obj != nil {
		return "", ""
	}
	return aliases[identifier.Name], selected.Sel.Name
}

func defaultHTTP(name string) bool {
	switch name {
	case "Get", "Head", "Post", "PostForm", "ListenAndServe", "ListenAndServeTLS":
		return true
	}
	return false
}

func hasTimeout(literal *ast.CompositeLit, primary, fallback string) bool {
	configured := false
	for _, field := range literal.Elts {
		pair, keyed := field.(*ast.KeyValueExpr)
		if !keyed {
			return true
		}
		name, named := pair.Key.(*ast.Ident)
		if !named || name.Name != primary && name.Name != fallback {
			continue
		}
		sign, known := durationSign(pair.Value)
		if known && sign < 0 && name.Name == primary {
			return false
		}
		configured = configured || !known || sign > 0
	}
	return configured
}

func durationSign(expression ast.Expr) (int, bool) {
	expression = ast.Unparen(expression)
	multiplier := 1
	if unary, ok := expression.(*ast.UnaryExpr); ok && (unary.Op == token.ADD || unary.Op == token.SUB) {
		if unary.Op == token.SUB {
			multiplier = -1
		}
		expression = ast.Unparen(unary.X)
	}
	literal, ok := expression.(*ast.BasicLit)
	if !ok || (literal.Kind != token.INT && literal.Kind != token.FLOAT) {
		return 0, false
	}
	value := constant.MakeFromLiteral(literal.Value, literal.Kind, 0)
	if value.Kind() == constant.Unknown {
		return 0, false
	}
	return multiplier * constant.Sign(value), true
}
