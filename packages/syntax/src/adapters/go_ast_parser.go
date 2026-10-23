package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"strings"
	"unicode"
)

type SourceSpan struct {
	FilePath        string  `json:"file_path"`
	StartLine       int     `json:"start_line"`
	StartCol        int     `json:"start_col"`
	EndLine         int     `json:"end_line"`
	EndCol          int     `json:"end_col"`
	ByteOffsetStart int     `json:"byte_offset_start"`
	ByteOffsetEnd   int     `json:"byte_offset_end"`
	TextSlice       *string `json:"text_slice,omitempty"`
}

type SymbolParameter struct {
	Name         string  `json:"name"`
	Type         *string `json:"type,omitempty"`
	DefaultValue *string `json:"default_value,omitempty"`
	IsRest       bool    `json:"is_rest"`
}

type SymbolFact struct {
	Name         string            `json:"name"`
	Kind         string            `json:"kind"`
	Visibility   string            `json:"visibility"`
	Span         SourceSpan        `json:"span"`
	Docstring    *string           `json:"docstring,omitempty"`
	Parameters   []SymbolParameter `json:"parameters"`
	ReturnType   *string           `json:"return_type,omitempty"`
	ParentSymbol *string           `json:"parent_symbol,omitempty"`
	Modifiers    []string          `json:"modifiers"`
	Decorators   []string          `json:"decorators"`
}

type ImportedSymbol struct {
	Name        string  `json:"name"`
	Alias       *string `json:"alias,omitempty"`
	IsTypeOnly  bool    `json:"is_type_only"`
	IsDefault   bool    `json:"is_default"`
	IsNamespace bool    `json:"is_namespace"`
}

type ImportFact struct {
	ModuleSpecifier string           `json:"module_specifier"`
	ImportKind      string           `json:"import_kind"`
	ImportedSymbols []ImportedSymbol `json:"imported_symbols"`
	RawStatement    *string          `json:"raw_statement,omitempty"`
	Span            SourceSpan       `json:"span"`
}

type ExportFact struct {
	ExportedSymbol string     `json:"exported_symbol"`
	Alias          *string    `json:"alias,omitempty"`
	IsDefault      bool       `json:"is_default"`
	IsReexport     bool       `json:"is_reexport"`
	SourceModule   *string    `json:"source_module,omitempty"`
	RawStatement   *string    `json:"raw_statement,omitempty"`
	Span           SourceSpan `json:"span"`
}

type CallSiteFact struct {
	CalleeName       string     `json:"callee_name"`
	Receiver         *string    `json:"receiver,omitempty"`
	ArgumentCount    int        `json:"argument_count"`
	ArgumentsSummary []string   `json:"arguments_summary"`
	IsAwait          bool       `json:"is_await"`
	Span             SourceSpan `json:"span"`
}

type AstNodeSummary struct {
	Kind string     `json:"kind"`
	Span SourceSpan `json:"span"`
}

type GoParseOutput struct {
	Symbols        []SymbolFact     `json:"symbols"`
	Imports        []ImportFact     `json:"imports"`
	Exports        []ExportFact     `json:"exports"`
	CallSites      []CallSiteFact   `json:"call_sites"`
	AstNodes       []AstNodeSummary `json:"ast_nodes"`
	HasParseError  bool             `json:"has_parse_error"`
	ErrorMessage   *string          `json:"error_message,omitempty"`
	ErrorLocation  *struct {
		Line   int `json:"line"`
		Col    int `json:"col"`
		Offset int `json:"offset"`
	} `json:"error_location,omitempty"`
}

func makeSpan(fset *token.FileSet, filePath string, start, end token.Pos, lines []string) SourceSpan {
	pStart := fset.Position(start)
	pEnd := fset.Position(end)

	var textSlice *string
	if pStart.Line >= 1 && pStart.Line <= len(lines) {
		line := lines[pStart.Line-1]
		if pStart.Line == pEnd.Line {
			if pEnd.Column > pStart.Column && pEnd.Column-1 <= len(line) {
				s := line[pStart.Column-1 : pEnd.Column-1]
				textSlice = &s
			}
		} else {
			s := line[pStart.Column-1:]
			textSlice = &s
		}
	}

	return SourceSpan{
		FilePath:        filePath,
		StartLine:       pStart.Line,
		StartCol:        pStart.Column,
		EndLine:         pEnd.Line,
		EndCol:          pEnd.Column,
		ByteOffsetStart: pStart.Offset,
		ByteOffsetEnd:   pEnd.Offset,
		TextSlice:       textSlice,
	}
}

func exprToString(expr ast.Expr) string {
	if expr == nil {
		return ""
	}
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + exprToString(t.X)
	case *ast.SelectorExpr:
		return exprToString(t.X) + "." + t.Sel.Name
	case *ast.ArrayType:
		return "[]" + exprToString(t.Elt)
	case *ast.MapType:
		return fmt.Sprintf("map[%s]%s", exprToString(t.Key), exprToString(t.Value))
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.Ellipsis:
		return "..." + exprToString(t.Elt)
	case *ast.FuncType:
		return "func(...)"
	case *ast.BasicLit:
		return t.Value
	case *ast.CallExpr:
		return exprToString(t.Fun) + "(...)"
	case *ast.IndexExpr:
		return fmt.Sprintf("%s[%s]", exprToString(t.X), exprToString(t.Index))
	case *ast.IndexListExpr:
		return fmt.Sprintf("%s[...]", exprToString(t.X))
	case *ast.UnaryExpr:
		return t.Op.String() + exprToString(t.X)
	default:
		return "any"
	}
}

func isPublic(name string) bool {
	if len(name) == 0 {
		return false
	}
	return unicode.IsUpper(rune(name[0]))
}

func main() {
	filePath := "source.go"
	if len(os.Args) > 1 {
		filePath = os.Args[1]
	}

	sourceBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
		os.Exit(1)
	}
	sourceText := string(sourceBytes)
	lines := strings.Split(sourceText, "\n")

	fset := token.NewFileSet()
	fileNode, parseErr := parser.ParseFile(fset, filePath, sourceBytes, parser.ParseComments)

	out := GoParseOutput{
		Symbols:   make([]SymbolFact, 0),
		Imports:   make([]ImportFact, 0),
		Exports:   make([]ExportFact, 0),
		CallSites: make([]CallSiteFact, 0),
		AstNodes:  make([]AstNodeSummary, 0),
	}

	if parseErr != nil {
		msg := parseErr.Error()
		out.HasParseError = true
		out.ErrorMessage = &msg
		// Try to continue if fileNode is partially parsed, otherwise serialize error
		if fileNode == nil {
			json.NewEncoder(os.Stdout).Encode(out)
			return
		}
	}

	// 1. Package statement
	if fileNode.Name != nil {
		pkgSpan := makeSpan(fset, filePath, fileNode.Package, fileNode.Name.End(), lines)
		pkgName := fileNode.Name.Name
		out.Symbols = append(out.Symbols, SymbolFact{
			Name:       pkgName,
			Kind:       "MODULE",
			Visibility: "PUBLIC",
			Span:       pkgSpan,
			Modifiers:  []string{"package"},
			Decorators: make([]string, 0),
			Parameters: make([]SymbolParameter, 0),
		})
	}

	// 2. Imports
	for _, imp := range fileNode.Imports {
		span := makeSpan(fset, filePath, imp.Pos(), imp.End(), lines)
		pathVal := strings.Trim(imp.Path.Value, "\"")
		var alias *string
		if imp.Name != nil {
			alias = &imp.Name.Name
		}
		raw := imp.Path.Value
		if alias != nil {
			raw = *alias + " " + raw
		}
		nameForSym := pathVal
		if alias != nil {
			nameForSym = *alias
		}

		out.Imports = append(out.Imports, ImportFact{
			ModuleSpecifier: pathVal,
			ImportKind:      "STATIC",
			ImportedSymbols: []ImportedSymbol{
				{
					Name:        nameForSym,
					Alias:       alias,
					IsTypeOnly:  false,
					IsDefault:   false,
					IsNamespace: alias != nil && *alias == ".",
				},
			},
			RawStatement: &raw,
			Span:         span,
		})
	}

	// 3. Declarations (Types, Structs, Interfaces, Functions, Methods)
	for _, decl := range fileNode.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			var doc string
			if d.Doc != nil {
				doc = strings.TrimSpace(d.Doc.Text())
			}
			var docPtr *string
			if doc != "" {
				docPtr = &doc
			}

			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					span := makeSpan(fset, filePath, s.Pos(), s.End(), lines)
					typeName := s.Name.Name
					vis := "PACKAGE"
					if isPublic(typeName) {
						vis = "PUBLIC"
					}

					kind := "TYPE_ALIAS"
					modifiers := make([]string, 0)
					if s.TypeParams != nil {
						for _, field := range s.TypeParams.List {
							typeStr := exprToString(field.Type)
							for _, name := range field.Names {
								modifiers = append(modifiers, fmt.Sprintf("generic:%s %s", name.Name, typeStr))
							}
						}
					}
					switch s.Type.(type) {
					case *ast.StructType:
						kind = "STRUCT"
					case *ast.InterfaceType:
						kind = "INTERFACE"
					}

					out.Symbols = append(out.Symbols, SymbolFact{
						Name:       typeName,
						Kind:       kind,
						Visibility: vis,
						Span:       span,
						Docstring:  docPtr,
						Modifiers:  modifiers,
						Decorators: make([]string, 0),
						Parameters: make([]SymbolParameter, 0),
					})

					if vis == "PUBLIC" {
						out.Exports = append(out.Exports, ExportFact{
							ExportedSymbol: typeName,
							Span:           span,
						})
					}
				}
			}

		case *ast.FuncDecl:
			span := makeSpan(fset, filePath, d.Pos(), d.End(), lines)
			fnName := d.Name.Name
			var doc string
			if d.Doc != nil {
				doc = strings.TrimSpace(d.Doc.Text())
			}
			var docPtr *string
			if doc != "" {
				docPtr = &doc
			}

			vis := "PACKAGE"
			if isPublic(fnName) {
				vis = "PUBLIC"
			}

			kind := "FUNCTION"
			var parentSym *string

			// Check if Method
			if d.Recv != nil && len(d.Recv.List) > 0 {
				kind = "METHOD"
				recvType := exprToString(d.Recv.List[0].Type)
				cleanRecv := strings.TrimPrefix(recvType, "*")
				parentSym = &cleanRecv
			}

			// Parameters
			params := make([]SymbolParameter, 0)
			if d.Type.Params != nil {
				for _, p := range d.Type.Params.List {
					typeStr := exprToString(p.Type)
					isRest := strings.HasPrefix(typeStr, "...")
					if len(p.Names) == 0 {
						params = append(params, SymbolParameter{
							Name:   "",
							Type:   &typeStr,
							IsRest: isRest,
						})
					} else {
						for _, pName := range p.Names {
							params = append(params, SymbolParameter{
								Name:   pName.Name,
								Type:   &typeStr,
								IsRest: isRest,
							})
						}
					}
				}
			}

			// Return types
			var returnType *string
			if d.Type.Results != nil {
				resTypes := make([]string, 0)
				for _, r := range d.Type.Results.List {
					resTypes = append(resTypes, exprToString(r.Type))
				}
				retStr := strings.Join(resTypes, ", ")
				if len(resTypes) > 1 {
					retStr = "(" + retStr + ")"
				}
				returnType = &retStr
			}

			fnModifiers := make([]string, 0)
			if d.Type.TypeParams != nil {
				for _, field := range d.Type.TypeParams.List {
					typeStr := exprToString(field.Type)
					for _, name := range field.Names {
						fnModifiers = append(fnModifiers, fmt.Sprintf("generic:%s %s", name.Name, typeStr))
					}
				}
			}

			out.Symbols = append(out.Symbols, SymbolFact{
				Name:         fnName,
				Kind:         kind,
				Visibility:   vis,
				Span:         span,
				Docstring:    docPtr,
				Parameters:   params,
				ReturnType:   returnType,
				ParentSymbol: parentSym,
				Modifiers:    fnModifiers,
				Decorators:   make([]string, 0),
			})

			if vis == "PUBLIC" && kind == "FUNCTION" {
				out.Exports = append(out.Exports, ExportFact{
					ExportedSymbol: fnName,
					Span:           span,
				})
			}
		}
	}

	// 4. Call Sites & AST Control Flow Nodes via ast.Inspect
	ast.Inspect(fileNode, func(n ast.Node) bool {
		if n == nil {
			return true
		}

		switch node := n.(type) {
		case *ast.CallExpr:
			span := makeSpan(fset, filePath, node.Pos(), node.End(), lines)
			calleeName := ""
			var receiver *string

			switch fn := node.Fun.(type) {
			case *ast.Ident:
				calleeName = fn.Name
			case *ast.SelectorExpr:
				calleeName = fn.Sel.Name
				recvStr := exprToString(fn.X)
				receiver = &recvStr
			default:
				calleeName = exprToString(node.Fun)
			}

			argsSummary := make([]string, 0)
			for i, arg := range node.Args {
				if i >= 5 {
					break
				}
				argsSummary = append(argsSummary, exprToString(arg))
			}

			out.CallSites = append(out.CallSites, CallSiteFact{
				CalleeName:       calleeName,
				Receiver:         receiver,
				ArgumentCount:    len(node.Args),
				ArgumentsSummary: argsSummary,
				IsAwait:          false,
				Span:             span,
			})

		case *ast.IfStmt:
			span := makeSpan(fset, filePath, node.Pos(), node.End(), lines)
			out.AstNodes = append(out.AstNodes, AstNodeSummary{Kind: "IfStmt", Span: span})

		case *ast.ForStmt:
			span := makeSpan(fset, filePath, node.Pos(), node.End(), lines)
			out.AstNodes = append(out.AstNodes, AstNodeSummary{Kind: "ForStmt", Span: span})

		case *ast.RangeStmt:
			span := makeSpan(fset, filePath, node.Pos(), node.End(), lines)
			out.AstNodes = append(out.AstNodes, AstNodeSummary{Kind: "RangeStmt", Span: span})

		case *ast.SwitchStmt:
			span := makeSpan(fset, filePath, node.Pos(), node.End(), lines)
			out.AstNodes = append(out.AstNodes, AstNodeSummary{Kind: "SwitchStmt", Span: span})

		case *ast.SelectStmt:
			span := makeSpan(fset, filePath, node.Pos(), node.End(), lines)
			out.AstNodes = append(out.AstNodes, AstNodeSummary{Kind: "SelectStmt", Span: span})

		case *ast.ReturnStmt:
			span := makeSpan(fset, filePath, node.Pos(), node.End(), lines)
			out.AstNodes = append(out.AstNodes, AstNodeSummary{Kind: "ReturnStmt", Span: span})
		}

		return true
	})

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(out)
	os.Stdout.Write(buf.Bytes())
}
