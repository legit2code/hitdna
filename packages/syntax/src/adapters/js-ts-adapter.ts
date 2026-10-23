/**
 * Authoritative JavaScript & TypeScript AST Adapter
 * Uses the TypeScript Compiler API (not regex) for 100% sound AST extraction.
 */

import ts from 'typescript';
import { 
  SymbolFact, 
  ImportFact, 
  ExportFact, 
  CallSiteFact, 
  SourceSpan,
  SymbolKind,
  SymbolVisibility,
  ImportedSymbol
} from '../types.ts';
import { SourceSpanUtil } from '../source-span-util.ts';

export interface JsTsParseOutput {
  symbols: SymbolFact[];
  imports: ImportFact[];
  exports: ExportFact[];
  call_sites: CallSiteFact[];
  ast_nodes?: Array<{ kind: string; span: SourceSpan; label?: string }>;
  has_parse_error: boolean;
  error_message?: string;
  error_location?: { line: number; col: number; offset: number };
  sourceFile?: ts.SourceFile;
}

export class JsTsAdapter {
  public static readonly ID = 'syntax-adapter:js-ts';
  public static readonly VERSION = '2.0.0-ast-authoritative';

  /**
   * Authoritative parser for JavaScript and TypeScript source text using the TypeScript Compiler API.
   * Produces a real AST rather than flat regular expression approximations.
   */
  public static parse(filePath: string, sourceText: string): JsTsParseOutput {
    const lineStarts = SourceSpanUtil.createLineIndex(sourceText);
    const symbols: SymbolFact[] = [];
    const imports: ImportFact[] = [];
    const exports: ExportFact[] = [];
    const call_sites: CallSiteFact[] = [];
    const astNodes: Array<{ kind: string; span: SourceSpan; label?: string }> = [];

    let scriptKind = ts.ScriptKind.TS;
    if (filePath.endsWith('.tsx')) {
      scriptKind = ts.ScriptKind.TSX;
    } else if (filePath.endsWith('.jsx')) {
      scriptKind = ts.ScriptKind.JSX;
    } else if (filePath.endsWith('.js') || filePath.endsWith('.mjs') || filePath.endsWith('.cjs')) {
      scriptKind = ts.ScriptKind.JS;
    }

    let sourceFile: ts.SourceFile;
    try {
      sourceFile = ts.createSourceFile(
        filePath,
        sourceText,
        ts.ScriptTarget.Latest,
        true, // setParentNodes
        scriptKind
      );
    } catch (err: any) {
      return {
        symbols,
        imports,
        exports,
        call_sites,
        has_parse_error: true,
        error_message: err?.message || 'TypeScript Compiler API failed to tokenize source',
      };
    }

    // Check parse diagnostics for syntactic failures
    const parseDiagnostics = (sourceFile as any).parseDiagnostics;
    let hasParseError = false;
    let errorMessage: string | undefined;
    let errorLocation: { line: number; col: number; offset: number } | undefined;

    if (Array.isArray(parseDiagnostics) && parseDiagnostics.length > 0) {
      const firstDiag = parseDiagnostics[0];
      if (firstDiag.category === ts.DiagnosticCategory.Error) {
        hasParseError = true;
        errorMessage = typeof firstDiag.messageText === 'string' 
          ? firstDiag.messageText 
          : firstDiag.messageText?.messageText;
        if (firstDiag.start !== undefined) {
          const { line, character } = sourceFile.getLineAndCharacterOfPosition(firstDiag.start);
          errorLocation = {
            line: line + 1,
            col: character + 1,
            offset: firstDiag.start,
          };
        }
      }
    }

    const spanOf = (node: ts.Node, symbolHint?: string): SourceSpan => {
      const start = node.getStart(sourceFile);
      const end = node.getEnd();
      return SourceSpanUtil.offsetToSpan(filePath, sourceText, start, end, lineStarts, symbolHint);
    };

    const getDocstring = (node: ts.Node): string | undefined => {
      const fullText = sourceText;
      const leadingComments = ts.getLeadingCommentRanges(fullText, node.getFullStart());
      if (leadingComments && leadingComments.length > 0) {
        const lastComment = leadingComments[leadingComments.length - 1];
        const commentText = fullText.substring(lastComment.pos, lastComment.end);
        if (commentText.startsWith('/**')) {
          return commentText.replace(/^\/\*\*|\*\/$/g, '').replace(/^\s*\* ?/gm, '').trim();
        }
      }
      return undefined;
    };

    const extractDecorators = (node: ts.Node): string[] => {
      const decorators: string[] = [];
      const decList = ts.canHaveDecorators(node) ? ts.getDecorators(node) : undefined;
      if (decList && decList.length > 0) {
        for (const d of decList) {
          const raw = d.expression.getText(sourceFile);
          decorators.push(raw.startsWith('@') ? raw.slice(1) : raw);
        }
      } else if ((node as any).modifiers) {
        // Fallback for older decorator syntax
        for (const mod of (node as any).modifiers) {
          if (ts.isDecorator(mod)) {
            const raw = mod.expression.getText(sourceFile);
            decorators.push(raw.startsWith('@') ? raw.slice(1) : raw);
          }
        }
      }
      return decorators;
    };

    const extractModifiers = (node: ts.Node): string[] => {
      const mods: string[] = [];
      const modifiers = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
      if (modifiers) {
        for (const m of modifiers) {
          if (m.kind === ts.SyntaxKind.ExportKeyword) mods.push('export');
          else if (m.kind === ts.SyntaxKind.DefaultKeyword) mods.push('default');
          else if (m.kind === ts.SyntaxKind.AsyncKeyword) mods.push('async');
          else if (m.kind === ts.SyntaxKind.StaticKeyword) mods.push('static');
          else if (m.kind === ts.SyntaxKind.AbstractKeyword) mods.push('abstract');
          else if (m.kind === ts.SyntaxKind.PublicKeyword) mods.push('public');
          else if (m.kind === ts.SyntaxKind.PrivateKeyword) mods.push('private');
          else if (m.kind === ts.SyntaxKind.ProtectedKeyword) mods.push('protected');
          else if (m.kind === ts.SyntaxKind.ReadonlyKeyword) mods.push('readonly');
        }
      }
      return mods;
    };

    const extractParameters = (params: ts.NodeArray<ts.ParameterDeclaration>) => {
      return params.map(param => {
        let name = param.name.getText(sourceFile);
        const type = param.type ? param.type.getText(sourceFile) : undefined;
        const default_value = param.initializer ? param.initializer.getText(sourceFile) : undefined;
        const is_rest = Boolean(param.dotDotDotToken);
        return {
          name,
          type,
          default_value,
          is_rest,
        };
      });
    };

    // Recursive helper to flatten destructured binding elements
    const extractBindings = (pattern: ts.BindingPattern | ts.Identifier): Array<{ name: string; propertyName?: string; isRest: boolean; node: ts.Node }> => {
      const results: Array<{ name: string; propertyName?: string; isRest: boolean; node: ts.Node }> = [];
      if (ts.isIdentifier(pattern)) {
        results.push({ name: pattern.text, isRest: false, node: pattern });
        return results;
      }
      for (const element of pattern.elements) {
        if (ts.isOmittedExpression(element)) continue;
        const isRest = Boolean(element.dotDotDotToken);
        if (ts.isIdentifier(element.name)) {
          const propName = element.propertyName && ts.isIdentifier(element.propertyName)
            ? element.propertyName.text
            : undefined;
          results.push({
            name: element.name.text,
            propertyName: propName,
            isRest,
            node: element.name,
          });
        } else if (ts.isObjectBindingPattern(element.name) || ts.isArrayBindingPattern(element.name)) {
          results.push(...extractBindings(element.name));
        }
      }
      return results;
    };

    // AST Visitor
    const visit = (node: ts.Node, parentClass?: string) => {
      // 1. Imports
      if (ts.isImportDeclaration(node)) {
        const moduleSpecifier = ts.isStringLiteral(node.moduleSpecifier) 
          ? node.moduleSpecifier.text 
          : node.moduleSpecifier.getText(sourceFile).replace(/['"]/g, '');
        const span = spanOf(node, moduleSpecifier);
        const importedSymbols: ImportedSymbol[] = [];
        const isTypeOnly = Boolean(node.importClause?.isTypeOnly);

        if (node.importClause) {
          // Default import: import foo from 'bar'
          if (node.importClause.name) {
            importedSymbols.push({
              name: node.importClause.name.text,
              is_default: true,
              is_type_only: isTypeOnly,
              is_namespace: false,
            });
          }

          // Named or Namespace imports
          if (node.importClause.namedBindings) {
            if (ts.isNamespaceImport(node.importClause.namedBindings)) {
              importedSymbols.push({
                name: node.importClause.namedBindings.name.text,
                is_namespace: true,
                is_default: false,
                is_type_only: isTypeOnly,
              });
            } else if (ts.isNamedImports(node.importClause.namedBindings)) {
              for (const elem of node.importClause.namedBindings.elements) {
                const orig = elem.propertyName ? elem.propertyName.text : elem.name.text;
                const alias = elem.propertyName ? elem.name.text : undefined;
                importedSymbols.push({
                  name: orig,
                  alias,
                  is_type_only: isTypeOnly || Boolean(elem.isTypeOnly),
                  is_default: false,
                  is_namespace: false,
                });
              }
            }
          }
        }

        imports.push({
          module_specifier: moduleSpecifier,
          import_kind: 'STATIC',
          imported_symbols: importedSymbols,
          raw_statement: node.getText(sourceFile),
          span,
        });
      }

      // 2. Dynamic Import: import(...)
      if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        const arg = node.arguments[0];
        const specifier = arg ? (ts.isStringLiteral(arg) ? arg.text : arg.getText(sourceFile).replace(/['"`]/g, '')) : '<dynamic>';
        imports.push({
          module_specifier: specifier,
          import_kind: 'DYNAMIC',
          imported_symbols: [],
          raw_statement: node.getText(sourceFile),
          span: spanOf(node, specifier),
        });
      }

      // 3. CommonJS require: require('mod')
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'require') {
        const arg = node.arguments[0];
        const specifier = arg ? (ts.isStringLiteral(arg) ? arg.text : arg.getText(sourceFile).replace(/['"`]/g, '')) : '<dynamic>';
        
        // Check if assigned in a variable statement (e.g. const { a, b: { c } } = require('mod'))
        const importedSymbols: ImportedSymbol[] = [];
        let parentDecl = node.parent;
        if (ts.isVariableDeclaration(parentDecl)) {
          if (ts.isIdentifier(parentDecl.name)) {
            importedSymbols.push({
              name: parentDecl.name.text,
              is_default: true,
              is_type_only: false,
              is_namespace: false,
            });
          } else if (ts.isObjectBindingPattern(parentDecl.name) || ts.isArrayBindingPattern(parentDecl.name)) {
            const bindings = extractBindings(parentDecl.name);
            for (const b of bindings) {
              importedSymbols.push({
                name: b.propertyName || b.name,
                alias: b.propertyName ? b.name : undefined,
                is_default: false,
                is_type_only: false,
                is_namespace: false,
              });
            }
          }
        }

        imports.push({
          module_specifier: specifier,
          import_kind: 'REQUIRE',
          imported_symbols: importedSymbols,
          raw_statement: node.getText(sourceFile),
          span: spanOf(node, specifier),
        });
      }

      // 4. Exports
      if (ts.isExportDeclaration(node)) {
        const sourceMod = node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier) 
          ? node.moduleSpecifier.text 
          : undefined;
        const span = spanOf(node);

        if (node.exportClause && ts.isNamedExports(node.exportClause)) {
          for (const elem of node.exportClause.elements) {
            const orig = elem.propertyName ? elem.propertyName.text : elem.name.text;
            const alias = elem.propertyName ? elem.name.text : undefined;
            exports.push({
              exported_symbol: orig,
              alias,
              is_default: alias === 'default',
              is_reexport: Boolean(sourceMod),
              source_module: sourceMod,
              raw_statement: node.getText(sourceFile),
              span,
            });
          }
        }
      } else if (ts.isExportAssignment(node)) {
        const name = node.expression ? node.expression.getText(sourceFile) : 'default';
        exports.push({
          exported_symbol: name,
          is_default: true,
          is_reexport: false,
          raw_statement: node.getText(sourceFile),
          span: spanOf(node, name),
        });
      }

      // 5. Functions (Declarations, Expressions, Arrow Functions)
      if (ts.isFunctionDeclaration(node)) {
        const name = node.name ? node.name.text : 'default';
        const isAsync = Boolean(node.modifiers?.some(m => m.kind === ts.SyntaxKind.AsyncKeyword));
        const isGenerator = Boolean(node.asteriskToken);
        const isExport = Boolean(node.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword));
        const docstring = getDocstring(node);
        const decorators = extractDecorators(node);
        const modifiers = extractModifiers(node);
        if (isGenerator) modifiers.push('generator');
        if (node.typeParameters && node.typeParameters.length > 0) {
          for (const tp of node.typeParameters) {
            modifiers.push(`generic:${tp.getText(sourceFile)}`);
          }
        }

        const kind: SymbolKind = isGenerator ? 'GENERATOR_FUNCTION' : (isAsync ? 'ASYNC_FUNCTION' : 'FUNCTION');
        const span = spanOf(node, name);

        symbols.push({
          name,
          kind,
          visibility: 'PUBLIC',
          span,
          docstring,
          parameters: extractParameters(node.parameters),
          return_type: node.type ? node.type.getText(sourceFile) : undefined,
          modifiers,
          decorators,
        });

        if (isExport) {
          exports.push({
            exported_symbol: name,
            is_default: Boolean(node.modifiers?.some(m => m.kind === ts.SyntaxKind.DefaultKeyword)),
            is_reexport: false,
            raw_statement: node.getText(sourceFile).slice(0, 100),
            span,
          });
        }
      }

      // 6. Classes
      if (ts.isClassDeclaration(node)) {
        const className = node.name ? node.name.text : '<anonymous_class>';
        const isExport = Boolean(node.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword));
        const isAbstract = Boolean(node.modifiers?.some(m => m.kind === ts.SyntaxKind.AbstractKeyword));
        const docstring = getDocstring(node);
        const decorators = extractDecorators(node);
        const modifiers = extractModifiers(node);
        if (node.typeParameters && node.typeParameters.length > 0) {
          for (const tp of node.typeParameters) {
            modifiers.push(`generic:${tp.getText(sourceFile)}`);
          }
        }

        if (node.heritageClauses) {
          for (const h of node.heritageClauses) {
            for (const t of h.types) {
              const clauseType = h.token === ts.SyntaxKind.ExtendsKeyword ? 'extends' : 'implements';
              modifiers.push(`${clauseType}:${t.expression.getText(sourceFile)}`);
            }
          }
        }

        const span = spanOf(node, className);

        symbols.push({
          name: className,
          kind: 'CLASS',
          visibility: 'PUBLIC',
          span,
          docstring,
          modifiers,
          decorators,
          parameters: [],
        });

        if (isExport) {
          exports.push({
            exported_symbol: className,
            is_default: Boolean(node.modifiers?.some(m => m.kind === ts.SyntaxKind.DefaultKeyword)),
            is_reexport: false,
            raw_statement: node.getText(sourceFile).slice(0, 100),
            span,
          });
        }

        // Process class members
        for (const member of node.members) {
          if (ts.isMethodDeclaration(member) || ts.isConstructorDeclaration(member) || ts.isGetAccessorDeclaration(member) || ts.isSetAccessorDeclaration(member)) {
            let methodName = '';
            let kind: SymbolKind = 'METHOD';
            if (ts.isConstructorDeclaration(member)) {
              methodName = 'constructor';
              kind = 'CONSTRUCTOR';
            } else if (member.name) {
              methodName = member.name.getText(sourceFile);
            }

            const methodDoc = getDocstring(member);
            const methodDecs = extractDecorators(member);
            const methodMods = extractModifiers(member);
            const isAsync = Boolean(member.modifiers?.some(m => m.kind === ts.SyntaxKind.AsyncKeyword));
            if (isAsync) methodMods.push('async');

            let visibility: SymbolVisibility = 'PUBLIC';
            if (member.modifiers?.some(m => m.kind === ts.SyntaxKind.PrivateKeyword) || methodName.startsWith('#')) {
              visibility = 'PRIVATE';
            } else if (member.modifiers?.some(m => m.kind === ts.SyntaxKind.ProtectedKeyword)) {
              visibility = 'PROTECTED';
            }

            symbols.push({
              name: methodName,
              kind,
              visibility,
              parent_symbol: className,
              span: spanOf(member, `${className}.${methodName}`),
              docstring: methodDoc,
              parameters: extractParameters(member.parameters),
              return_type: (member as any).type ? (member as any).type.getText(sourceFile) : undefined,
              modifiers: methodMods,
              decorators: methodDecs,
            });
          }
        }
      }

      // 7. Interfaces
      if (ts.isInterfaceDeclaration(node)) {
        const name = node.name.text;
        const isExport = Boolean(node.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword));
        const docstring = getDocstring(node);
        const modifiers = extractModifiers(node);
        if (node.typeParameters && node.typeParameters.length > 0) {
          for (const tp of node.typeParameters) {
            modifiers.push(`generic:${tp.getText(sourceFile)}`);
          }
        }

        if (node.heritageClauses) {
          for (const h of node.heritageClauses) {
            for (const t of h.types) {
              modifiers.push(`extends:${t.expression.getText(sourceFile)}`);
            }
          }
        }

        const span = spanOf(node, name);
        symbols.push({
          name,
          kind: 'INTERFACE',
          visibility: 'PUBLIC',
          span,
          docstring,
          modifiers,
          decorators: [],
          parameters: [],
        });

        if (isExport) {
          exports.push({
            exported_symbol: name,
            is_default: false,
            is_reexport: false,
            span,
          });
        }
      }

      // 8. Type Aliases
      if (ts.isTypeAliasDeclaration(node)) {
        const name = node.name.text;
        const isExport = Boolean(node.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword));
        const docstring = getDocstring(node);
        const modifiers = extractModifiers(node);
        if (node.typeParameters && node.typeParameters.length > 0) {
          for (const tp of node.typeParameters) {
            modifiers.push(`generic:${tp.getText(sourceFile)}`);
          }
        }
        const span = spanOf(node, name);

        symbols.push({
          name,
          kind: 'TYPE_ALIAS',
          visibility: 'PUBLIC',
          span,
          docstring,
          modifiers,
          decorators: [],
          parameters: [],
        });

        if (isExport) {
          exports.push({
            exported_symbol: name,
            is_default: false,
            is_reexport: false,
            span,
          });
        }
      }

      // 9. Enums
      if (ts.isEnumDeclaration(node)) {
        const name = node.name.text;
        const isExport = Boolean(node.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword));
        const docstring = getDocstring(node);
        const modifiers = extractModifiers(node);
        const span = spanOf(node, name);

        symbols.push({
          name,
          kind: 'ENUM',
          visibility: 'PUBLIC',
          span,
          docstring,
          modifiers,
          decorators: [],
          parameters: [],
        });

        if (isExport) {
          exports.push({
            exported_symbol: name,
            is_default: false,
            is_reexport: false,
            span,
          });
        }
      }

      // 10. Variable Statements (Constants, Variables, Arrow Functions, Nested Destructuring)
      if (ts.isVariableStatement(node)) {
        const isExport = Boolean(node.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword));
        const isConst = Boolean(node.declarationList.flags & ts.NodeFlags.Const);
        const modifiers = extractModifiers(node);

        for (const decl of node.declarationList.declarations) {
          // Check if initializer is an arrow function or function expression
          if (decl.initializer && (ts.isArrowFunction(decl.initializer) || ts.isFunctionExpression(decl.initializer))) {
            const fnName = decl.name.getText(sourceFile);
            const isAsync = Boolean(decl.initializer.modifiers?.some(m => m.kind === ts.SyntaxKind.AsyncKeyword));
            const span = spanOf(decl, fnName);

            symbols.push({
              name: fnName,
              kind: isAsync ? 'ASYNC_FUNCTION' : 'FUNCTION',
              visibility: 'PUBLIC',
              span,
              parameters: extractParameters(decl.initializer.parameters),
              return_type: decl.type ? decl.type.getText(sourceFile) : undefined,
              modifiers,
              decorators: [],
            });

            if (isExport) {
              exports.push({
                exported_symbol: fnName,
                is_default: false,
                is_reexport: false,
                span,
              });
            }
          } else {
            // Nested destructuring pattern or standard identifier
            const bindings = extractBindings(decl.name);
            for (const b of bindings) {
              const span = spanOf(b.node, b.name);
              symbols.push({
                name: b.name,
                kind: isConst ? 'CONSTANT' : 'VARIABLE',
                visibility: 'PUBLIC',
                span,
                return_type: decl.type ? decl.type.getText(sourceFile) : undefined,
                modifiers,
                decorators: [],
                parameters: [],
              });

              if (isExport) {
                exports.push({
                  exported_symbol: b.name,
                  alias: b.propertyName,
                  is_default: false,
                  is_reexport: false,
                  span,
                });
              }
            }
          }
        }
      }

      // 11. Call Sites & New Expressions (Multiline expressions, template literals, dynamic dispatch)
      if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
        // Skip import(...) and require(...) calls handled above
        const isImportCall = node.expression.kind === ts.SyntaxKind.ImportKeyword;
        const isRequireCall = ts.isIdentifier(node.expression) && node.expression.text === 'require';

        if (!isImportCall && !isRequireCall) {
          let calleeName = '';
          let receiver: string | undefined;

          if (ts.isPropertyAccessExpression(node.expression)) {
            calleeName = node.expression.name.text;
            receiver = node.expression.expression.getText(sourceFile);
          } else if (ts.isElementAccessExpression(node.expression)) {
            calleeName = node.expression.argumentExpression ? node.expression.argumentExpression.getText(sourceFile) : '<element>';
            receiver = node.expression.expression.getText(sourceFile);
          } else if (ts.isIdentifier(node.expression)) {
            calleeName = node.expression.text;
          } else {
            calleeName = node.expression.getText(sourceFile);
          }

          // Check if parent is await
          let isAwait = false;
          let p: ts.Node | undefined = node.parent;
          while (p && !ts.isStatement(p)) {
            if (ts.isAwaitExpression(p)) {
              isAwait = true;
              break;
            }
            p = p.parent;
          }

          const args = node.arguments ? Array.from(node.arguments) : [];
          const argsSummary = args.slice(0, 5).map(a => a.getText(sourceFile).slice(0, 80));

          call_sites.push({
            callee_name: calleeName,
            receiver,
            argument_count: args.length,
            arguments_summary: argsSummary,
            is_await: isAwait,
            span: spanOf(node, calleeName),
          });
        }
      }

      // 12. AST Control Flow and Block Structure Tracking
      if (ts.isIfStatement(node)) {
        astNodes.push({ kind: 'IfStatement', span: spanOf(node), label: node.expression.getText(sourceFile).slice(0, 50) });
      } else if (ts.isForStatement(node) || ts.isForOfStatement(node) || ts.isForInStatement(node) || ts.isWhileStatement(node) || ts.isDoStatement(node)) {
        astNodes.push({ kind: 'LoopStatement', span: spanOf(node) });
      } else if (ts.isSwitchStatement(node)) {
        astNodes.push({ kind: 'SwitchStatement', span: spanOf(node) });
      } else if (ts.isTryStatement(node)) {
        astNodes.push({ kind: 'TryStatement', span: spanOf(node) });
      } else if (ts.isReturnStatement(node)) {
        astNodes.push({ kind: 'ReturnStatement', span: spanOf(node) });
      } else if (ts.isThrowStatement(node)) {
        astNodes.push({ kind: 'ThrowStatement', span: spanOf(node) });
      }

      ts.forEachChild(node, child => visit(child, parentClass));
    };

    visit(sourceFile);

    return {
      symbols,
      imports,
      exports,
      call_sites,
      ast_nodes: astNodes,
      has_parse_error: hasParseError,
      error_message: errorMessage,
      error_location: errorLocation,
      sourceFile,
    };
  }
}
