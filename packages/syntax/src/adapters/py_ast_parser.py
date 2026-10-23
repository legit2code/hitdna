#!/usr/bin/env python3
"""
Authoritative Python AST Parser using Python's native `ast` module.
Extracts symbols, imports, exports, call sites, and AST facts.
"""
import sys
import ast
import json

def get_node_span(node, file_path, source_lines):
    start_line = getattr(node, 'lineno', 1)
    start_col = getattr(node, 'col_offset', 0) + 1
    end_line = getattr(node, 'end_lineno', start_line)
    end_col = getattr(node, 'end_col_offset', start_col) + 1

    # Extract text slice if available
    text_slice = None
    if 1 <= start_line <= len(source_lines):
        if start_line == end_line:
            line = source_lines[start_line - 1]
            text_slice = line[start_col - 1:end_col - 1] if end_col > start_col else line[start_col - 1:]
        else:
            first_line = source_lines[start_line - 1][start_col - 1:]
            last_line = source_lines[end_line - 1][:end_col - 1] if end_line <= len(source_lines) else ''
            text_slice = first_line + '\n...\n' + last_line

    return {
        "file_path": file_path,
        "start_line": start_line,
        "start_col": start_col,
        "end_line": end_line,
        "end_col": end_col,
        "byte_offset_start": 0,
        "byte_offset_end": 0,
        "text_slice": text_slice[:200] if text_slice else None
    }

def format_arg(arg, default_val=None):
    arg_name = arg.arg
    type_ann = None
    if arg.annotation:
        try:
            type_ann = ast.unparse(arg.annotation)
        except Exception:
            type_ann = None
    return {
        "name": arg_name,
        "type": type_ann,
        "default_value": default_val,
        "is_rest": False
    }

def extract_decorators(decorator_list):
    decs = []
    for d in decorator_list:
        try:
            # ast.unparse handles complex decorators like @tool(name="calc") or @decor.sub
            decs.append(ast.unparse(d))
        except Exception:
            if isinstance(d, ast.Name):
                decs.append(d.id)
            elif isinstance(d, ast.Attribute):
                decs.append(f"{ast.unparse(d.value)}.{d.attr}")
            elif isinstance(d, ast.Call):
                decs.append(ast.unparse(d.func))
    return decs

def parse_python_ast(source_text, file_path):
    source_lines = source_text.splitlines()
    symbols = []
    imports = []
    exports = []
    call_sites = []
    ast_nodes_summary = []

    try:
        tree = ast.parse(source_text, filename=file_path)
    except IndentationError:
        import textwrap
        try:
            tree = ast.parse(textwrap.dedent(source_text), filename=file_path)
        except SyntaxError as e:
            return {
                "symbols": [],
                "imports": [],
                "exports": [],
                "call_sites": [],
                "ast_nodes": [],
                "has_parse_error": True,
                "error_message": f"SyntaxError: {e.msg} at line {e.lineno}, col {e.offset}",
                "error_location": {
                    "line": e.lineno or 1,
                    "col": e.offset or 1,
                    "offset": 0
                }
            }
    except SyntaxError as e:
        return {
            "symbols": [],
            "imports": [],
            "exports": [],
            "call_sites": [],
            "ast_nodes": [],
            "has_parse_error": True,
            "error_message": f"SyntaxError: {e.msg} at line {e.lineno}, col {e.offset}",
            "error_location": {
                "line": e.lineno or 1,
                "col": e.offset or 1,
                "offset": 0
            }
        }
    except Exception as e:
        return {
            "symbols": [],
            "imports": [],
            "exports": [],
            "call_sites": [],
            "ast_nodes": [],
            "has_parse_error": True,
            "error_message": str(e)
        }

    # Extract __all__ if defined
    all_exports = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == '__all__':
                    if isinstance(node.value, (ast.List, ast.Tuple)):
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                all_exports.add(elt.value)

    # Traverse AST
    for node in ast.walk(tree):
        # 1. Imports
        if isinstance(node, ast.Import):
            span = get_node_span(node, file_path, source_lines)
            for alias in node.names:
                imported_syms = [{
                    "name": alias.name,
                    "alias": alias.asname,
                    "is_default": False,
                    "is_type_only": False,
                    "is_namespace": False
                }]
                import_obj = {
                    "module_specifier": alias.name,
                    "import_kind": "STATIC",
                    "imported_symbols": imported_syms,
                    "raw_statement": f"import {alias.name}" + (f" as {alias.asname}" if alias.asname else ""),
                    "span": span
                }
                imports.append(import_obj)
        elif isinstance(node, ast.ImportFrom):
            span = get_node_span(node, file_path, source_lines)
            mod = node.module or ('.' * node.level)
            imported_syms = []
            for alias in node.names:
                imported_syms.append({
                    "name": alias.name,
                    "alias": alias.asname,
                    "is_default": False,
                    "is_type_only": False,
                    "is_namespace": alias.name == '*'
                })
            imports.append({
                "module_specifier": mod,
                "import_kind": "STATIC",
                "imported_symbols": imported_syms,
                "raw_statement": f"from {mod} import " + ", ".join(s["name"] for s in imported_syms),
                "span": span
            })

        # 2. Call Sites
        elif isinstance(node, ast.Call):
            span = get_node_span(node, file_path, source_lines)
            callee_name = ""
            receiver = None

            if isinstance(node.func, ast.Name):
                callee_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                callee_name = node.func.attr
                try:
                    receiver = ast.unparse(node.func.value)
                except Exception:
                    receiver = getattr(node.func.value, 'id', None)
            else:
                try:
                    callee_name = ast.unparse(node.func)
                except Exception:
                    callee_name = "<dynamic_call>"

            args_summary = []
            for a in node.args:
                try:
                    args_summary.append(ast.unparse(a)[:40])
                except Exception:
                    args_summary.append("...")

            call_sites.append({
                "callee_name": callee_name,
                "receiver": receiver,
                "argument_count": len(node.args) + len(node.keywords),
                "arguments_summary": args_summary[:5],
                "is_await": False, # Will check parent context if needed
                "span": span
            })

        # 3. Control Flow Summary Nodes
        elif isinstance(node, (ast.If, ast.For, ast.While, ast.Try, ast.With, ast.Return, ast.Raise)):
            span = get_node_span(node, file_path, source_lines)
            kind_name = type(node).__name__
            ast_nodes_summary.append({
                "kind": kind_name,
                "span": span
            })

    # Traverse top-level and class-level for definitions (preserving hierarchy)
    def process_body_nodes(body_nodes, parent_class=None):
        for node in body_nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                span = get_node_span(node, file_path, source_lines)
                is_async = isinstance(node, ast.AsyncFunctionDef)
                docstring = ast.get_docstring(node)
                decorators = extract_decorators(node.decorator_list)

                # Return type
                return_type = None
                if node.returns:
                    try:
                        return_type = ast.unparse(node.returns)
                    except Exception:
                        return_type = None

                # Parameters
                params = []
                all_args = node.args.posonlyargs + node.args.args
                # Defaults are aligned from right
                defaults = [None] * (len(all_args) - len(node.args.defaults))
                for d in node.args.defaults:
                    try:
                        defaults.append(ast.unparse(d))
                    except Exception:
                        defaults.append("...")

                for i, arg in enumerate(all_args):
                    default_v = defaults[i] if i < len(defaults) else None
                    params.append(format_arg(arg, default_v))

                if node.args.vararg:
                    params.append({
                        "name": f"*{node.args.vararg.arg}",
                        "is_rest": True
                    })
                for i, kwarg in enumerate(node.args.kwonlyargs):
                    kw_default = None
                    if i < len(node.args.kw_defaults) and node.args.kw_defaults[i] is not None:
                        try:
                            kw_default = ast.unparse(node.args.kw_defaults[i])
                        except Exception:
                            kw_default = "..."
                    params.append(format_arg(kwarg, kw_default))
                if node.args.kwarg:
                    params.append({
                        "name": f"**{node.args.kwarg.arg}",
                        "is_rest": True
                    })

                kind = "METHOD" if parent_class else ("ASYNC_FUNCTION" if is_async else "FUNCTION")
                if parent_class and node.name == '__init__':
                    kind = "CONSTRUCTOR"

                modifiers = (["async"] if is_async else []) + (["classmethod"] if any("classmethod" in d for d in decorators) else [])
                if hasattr(node, 'type_params') and node.type_params:
                    for tp in node.type_params:
                        try:
                            modifiers.append(f"generic:{ast.unparse(tp)}")
                        except Exception:
                            pass

                is_private = node.name.startswith('_') and not node.name.startswith('__')
                sym = {
                    "name": node.name,
                    "kind": kind,
                    "visibility": "PRIVATE" if is_private else "PUBLIC",
                    "span": span,
                    "docstring": docstring,
                    "parameters": params,
                    "return_type": return_type,
                    "parent_symbol": parent_class,
                    "modifiers": modifiers,
                    "decorators": decorators
                }
                symbols.append(sym)

                if not parent_class and (node.name in all_exports or not node.name.startswith('_')):
                    exports.append({
                        "exported_symbol": node.name,
                        "is_default": False,
                        "is_reexport": False,
                        "span": span
                    })

            elif isinstance(node, ast.ClassDef):
                span = get_node_span(node, file_path, source_lines)
                docstring = ast.get_docstring(node)
                decorators = extract_decorators(node.decorator_list)
                bases = []
                for b in node.bases:
                    try:
                        bases.append(ast.unparse(b))
                    except Exception:
                        if isinstance(b, ast.Name):
                            bases.append(b.id)

                class_modifiers = [f"extends:{b}" for b in bases]
                if hasattr(node, 'type_params') and node.type_params:
                    for tp in node.type_params:
                        try:
                            class_modifiers.append(f"generic:{ast.unparse(tp)}")
                        except Exception:
                            pass

                is_private = node.name.startswith('_')
                sym = {
                    "name": node.name,
                    "kind": "CLASS",
                    "visibility": "PRIVATE" if is_private else "PUBLIC",
                    "span": span,
                    "docstring": docstring,
                    "parameters": [],
                    "modifiers": class_modifiers,
                    "decorators": decorators
                }
                symbols.append(sym)

                if node.name in all_exports or not node.name.startswith('_'):
                    exports.append({
                        "exported_symbol": node.name,
                        "is_default": False,
                        "is_reexport": False,
                        "span": span
                    })

                # Recursively process methods inside class
                process_body_nodes(node.body, parent_class=node.name)

    process_body_nodes(tree.body)

    return {
        "symbols": symbols,
        "imports": imports,
        "exports": exports,
        "call_sites": call_sites,
        "ast_nodes": ast_nodes_summary,
        "has_parse_error": False
    }

if __name__ == '__main__':
    content = sys.stdin.read()
    file_name = sys.argv[1] if len(sys.argv) > 1 else 'script.py'
    result = parse_python_ast(content, file_name)
    print(json.dumps(result))
