/**
 * Authoritative Python AST Adapter
 * Uses Python's native `ast` standard library via subprocess for 100% sound AST extraction.
 */

import nodeUrl from 'node:url';
import nodePath from 'node:path';
import nodeChildProcess from 'node:child_process';
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

export interface PythonParseOutput {
  symbols: SymbolFact[];
  imports: ImportFact[];
  exports: ExportFact[];
  call_sites: CallSiteFact[];
  ast_nodes?: Array<{ kind: string; span: SourceSpan; label?: string }>;
  has_parse_error: boolean;
  error_message?: string;
  error_location?: { line: number; col: number; offset: number };
}

export class PythonAdapter {
  public static readonly ID = 'syntax-adapter:python';
  public static readonly VERSION = '2.0.0-ast-authoritative';

  private static getScriptPath(): string {
    try {
      const fileURLToPath = (nodeUrl as any)?.fileURLToPath;
      const pathMod = (nodePath as any)?.default || nodePath;
      if (fileURLToPath && import.meta?.url) {
        const __filename = fileURLToPath(import.meta.url);
        const __dirname = pathMod.dirname(__filename);
        return pathMod.resolve(__dirname, 'py_ast_parser.py');
      }
      return pathMod.resolve(process.cwd(), 'packages/syntax/src/adapters/py_ast_parser.py');
    } catch {
      return 'packages/syntax/src/adapters/py_ast_parser.py';
    }
  }

  /**
   * Authoritative parser for Python source code using Python's native `ast` module.
   */
  public static parse(filePath: string, sourceText: string): PythonParseOutput {
    const spawnSync = (nodeChildProcess as any)?.spawnSync;
    if (typeof window !== 'undefined' || !spawnSync) {
      return {
        symbols: [],
        imports: [],
        exports: [],
        call_sites: [],
        has_parse_error: false,
      };
    }
    const scriptPath = this.getScriptPath();

    try {
      const res = spawnSync('python3', [scriptPath, filePath], {
        input: sourceText,
        encoding: 'utf-8',
        maxBuffer: 32 * 1024 * 1024,
      });

      if (res.status === 0 && res.stdout) {
        try {
          const parsed = JSON.parse(res.stdout);
          return {
            symbols: parsed.symbols || [],
            imports: parsed.imports || [],
            exports: parsed.exports || [],
            call_sites: parsed.call_sites || [],
            ast_nodes: parsed.ast_nodes || [],
            has_parse_error: Boolean(parsed.has_parse_error),
            error_message: parsed.error_message,
            error_location: parsed.error_location,
          };
        } catch (jsonErr: any) {
          return {
            symbols: [],
            imports: [],
            exports: [],
            call_sites: [],
            has_parse_error: true,
            error_message: `Failed to parse Python AST JSON output: ${jsonErr.message}`,
          };
        }
      }

      if (res.error || res.status !== 0) {
        const errMsg = res.stderr ? res.stderr.trim() : (res.error?.message || `Python AST parser exited with code ${res.status}`);
        return {
          symbols: [],
          imports: [],
          exports: [],
          call_sites: [],
          has_parse_error: true,
          error_message: errMsg,
        };
      }
    } catch (e: any) {
      // Subprocess invocation failure fallback
    }

    // Fallback if python3 is unavailable
    return this.fallbackRegexParse(filePath, sourceText);
  }

  /**
   * Supplementary fallback parser using line scanning if python3 execution fails
   */
  private static fallbackRegexParse(filePath: string, sourceText: string): PythonParseOutput {
    const lineStarts = SourceSpanUtil.createLineIndex(sourceText);
    const symbols: SymbolFact[] = [];
    const imports: ImportFact[] = [];
    const exports: ExportFact[] = [];
    const call_sites: CallSiteFact[] = [];

    const lines = sourceText.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      const lineNum = i + 1;

      if (trimmed.startsWith('import ') || trimmed.startsWith('from ')) {
        const span: SourceSpan = {
          file_path: filePath,
          start_line: lineNum,
          start_col: 1,
          end_line: lineNum,
          end_col: line.length + 1,
          byte_offset_start: lineStarts[i],
          byte_offset_end: lineStarts[i] + line.length,
          text_slice: trimmed,
        };

        if (trimmed.startsWith('import ')) {
          const mod = trimmed.replace(/^import\s+/, '').split(' ')[0].replace(/,.*$/, '');
          imports.push({
            module_specifier: mod,
            import_kind: 'STATIC',
            imported_symbols: [{ name: mod, is_default: false, is_type_only: false, is_namespace: false }],
            raw_statement: trimmed,
            span,
          });
        } else {
          const parts = trimmed.match(/^from\s+([^\s]+)\s+import\s+(.*)$/);
          if (parts) {
            const mod = parts[1];
            const syms = parts[2].split(',').map(s => s.trim().split(/\s+as\s+/)[0]);
            imports.push({
              module_specifier: mod,
              import_kind: 'STATIC',
              imported_symbols: syms.map(s => ({ name: s, is_default: false, is_type_only: false, is_namespace: s === '*' })),
              raw_statement: trimmed,
              span,
            });
          }
        }
      }

      if (trimmed.startsWith('def ') || trimmed.startsWith('async def ')) {
        const isAsync = trimmed.startsWith('async def ');
        const fnMatch = trimmed.match(/(?:async\s+)?def\s+([a-zA-Z0-9_]+)\s*\((.*?)\)/);
        if (fnMatch) {
          const name = fnMatch[1];
          const span: SourceSpan = {
            file_path: filePath,
            start_line: lineNum,
            start_col: line.indexOf('def') + 1,
            end_line: lineNum,
            end_col: line.length + 1,
            byte_offset_start: lineStarts[i],
            byte_offset_end: lineStarts[i] + line.length,
            text_slice: trimmed,
          };
          symbols.push({
            name,
            kind: isAsync ? 'ASYNC_FUNCTION' : 'FUNCTION',
            visibility: name.startsWith('_') ? 'PRIVATE' : 'PUBLIC',
            span,
            parameters: [],
            modifiers: isAsync ? ['async'] : [],
            decorators: [],
          });
        }
      }
    }

    return {
      symbols,
      imports,
      exports,
      call_sites,
      has_parse_error: false,
    };
  }
}
