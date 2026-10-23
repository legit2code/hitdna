/**
 * Dataflow & Taint Intelligence Engine
 * P16 — Dataflow / Taint Intelligence
 */

import { 
  TaintAnalysisReport,
  TaintSourceInstance,
  TaintSinkInstance,
  TaintSanitizerInstance,
  TaintFlowPath,
  TaintHop,
  TaintPathStatus,
  TaintSourceCategory,
  TaintSinkCategory,
  TaintAnalysisSummaryStats,
  TAINT_ENGINE_VERSION,
  TAINT_SOURCE_REGISTRY_VERSION,
  TAINT_SINK_REGISTRY_VERSION,
  TAINT_SANITIZER_REGISTRY_VERSION
} from './types.ts';
import { TaintSourceRegistry } from './sources.ts';
import { TaintSinkRegistry } from './sinks.ts';
import { TaintSanitizerRegistry } from './sanitizers.ts';
import { ArtifactParseResult, SourceSpan } from '@caim/syntax/types.ts';
import { SymbolImportGraph, CallGraph, ControlFlowGraph } from '../types.ts';

function makeSpan(
  file_path: string,
  start_line: number,
  start_col: number,
  end_line: number,
  end_col: number,
  text_slice?: string,
  symbol_hint?: string
): SourceSpan {
  return {
    file_path,
    start_line,
    start_col,
    end_line,
    end_col,
    byte_offset_start: 0,
    byte_offset_end: 0,
    text_slice,
    symbol_hint,
  };
}

export class DataflowTaintEngine {
  public static readonly ENGINE_VERSION = TAINT_ENGINE_VERSION;

  /**
   * Main entrypoint for dataflow and taint propagation analysis
   */
  public static traceTaint(
    artifactId: string,
    syntaxResult: ArtifactParseResult,
    fileContentMap: Map<string, string>,
    symbolGraph: SymbolImportGraph,
    callGraph: CallGraph,
    cfgs: ControlFlowGraph[]
  ): TaintAnalysisReport {
    const startedAt = new Date().toISOString();

    if (!fileContentMap || fileContentMap.size === 0) {
      throw new Error(
        'AUTHENTIC_SOURCE_REQUIRED: Taint analysis cannot execute without authentic source files. ' +
        'Analysis without authentic acquired artifacts is strictly prohibited.'
      );
    }

    // Strictly reject synthetic, representative, or substitute code
    for (const [filePath, content] of fileContentMap.entries()) {
      if (typeof content === 'string') {
        const firstLines = content.slice(0, 300);
        if (/^\s*\/\/\s*(Sample entrypoint|Representative substitute|Synthetic substitute|Generated placeholder|Mock substitute)/i.test(firstLines)) {
          throw new Error(
            'AUTHENTIC_SOURCE_REQUIRED: Synthetic or representative substitute code cannot be analyzed in taint engine. ' +
            'Generating representative source is strictly forbidden.'
          );
        }
      }
    }

    // 1. Identify all Source instances across workspace files
    const sources = this.discoverSources(syntaxResult, fileContentMap);

    // 2. Identify all Sink instances across workspace files
    const sinks = this.discoverSinks(syntaxResult, fileContentMap);

    // 3. Identify all Sanitizers / Transforms
    const sanitizers = this.discoverSanitizers(syntaxResult, fileContentMap);

    // 4. Trace dataflow paths from sources to sinks (intra-function, interprocedural, and cross-file)
    const paths = this.propagateTaint(
      sources,
      sinks,
      sanitizers,
      syntaxResult,
      fileContentMap,
      symbolGraph,
      callGraph,
      cfgs
    );

    // 5. Aggregate summary statistics
    const summary = this.computeSummary(sources, sinks, paths);

    return {
      artifact_id: artifactId,
      engine_version: this.ENGINE_VERSION,
      ruleset_version: '1.0.0',
      source_registry_version: TAINT_SOURCE_REGISTRY_VERSION,
      sink_registry_version: TAINT_SINK_REGISTRY_VERSION,
      sanitizer_registry_version: TAINT_SANITIZER_REGISTRY_VERSION,
      sources,
      sinks,
      sanitizers,
      paths,
      summary,
      analyzed_at: startedAt,
    };
  }

  /**
   * Discovers source definitions using authoritative AST facts as primary source of truth,
   * keeping regex pattern matching only as a supplementary fallback signal.
   */
  private static discoverSources(
    syntaxResult: ArtifactParseResult,
    fileContentMap: Map<string, string>
  ): TaintSourceInstance[] {
    const instances: TaintSourceInstance[] = [];
    const sourceDefs = TaintSourceRegistry.getAllSources();

    for (const fileFact of syntaxResult.file_facts) {
      const content = fileContentMap.get(fileFact.file_path) || fileFact.raw_content_preview || '';
      const lines = content.split('\n');
      const coveredLines = new Set<number>();

      // 1. PRIMARY AST DISCOVERY: Call Sites from Authoritative AST Parsers
      for (const call of fileFact.call_sites) {
        const fullCallee = call.receiver ? `${call.receiver}.${call.callee_name}` : call.callee_name;
        for (const def of sourceDefs) {
          if (def.match_functions) {
            const matchesFn = def.match_functions.some(fn => {
              if (fn === call.callee_name || fn === fullCallee || (call.receiver && fn === `.${call.callee_name}`)) {
                return true;
              }
              if (fn.includes('.') && call.receiver) {
                const parts = fn.split('.');
                const targetMethod = parts[parts.length - 1];
                const targetReceiver = parts.slice(0, -1).join('.');
                return call.callee_name === targetMethod && call.receiver.includes(targetReceiver);
              }
              return false;
            });
            if (matchesFn) {
              const lineNum = call.span.start_line;
              coveredLines.add(lineNum);
              const lineText = lines[lineNum - 1] || '';
              const varAssignMatch = lineText.match(/(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=/);
              const varName = varAssignMatch ? varAssignMatch[1] : undefined;

              instances.push({
                source_id: def.source_id,
                category: def.category,
                variable_name: varName,
                file_path: fileFact.file_path,
                span: call.span,
                expression_text: call.span.text_slice || `${fullCallee}(...)`,
                confidence: def.base_confidence,
                epistemic_state: 'OBSERVED_FACT',
              });
            }
          }
        }
      }

      // 2. PRIMARY AST DISCOVERY: Member Roots & Destructuring on AST Symbols
      for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        const lineText = lines[lineIdx];
        const lineNum = lineIdx + 1;

        for (const def of sourceDefs) {
          if (def.match_member_roots) {
            for (const root of def.match_member_roots) {
              if (lineText.includes(root)) {
                let matchedId = '';
                if (def.match_identifiers) {
                  for (const id of def.match_identifiers) {
                    if (lineText.includes(id)) {
                      matchedId = id;
                      break;
                    }
                  }
                } else {
                  matchedId = root;
                }

                if (matchedId || !def.match_identifiers) {
                  coveredLines.add(lineNum);
                  const rootIdx = lineText.indexOf(root);
                  const startCol = rootIdx + 1;

                  // Check if assigned to variable, or destructured: const { token } = req.query;
                  let varName: string | undefined;
                  const varAssignMatch = lineText.match(/(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=/);
                  if (varAssignMatch) {
                    varName = varAssignMatch[1];
                  } else {
                    const destructureMatch = lineText.match(/(?:const|let|var)\s*\{([^}]+)\}\s*=/);
                    if (destructureMatch) {
                      varName = destructureMatch[1].split(',')[0].trim().split(':')[0].trim();
                    }
                  }

                  if (!varName) {
                    const lineSym = fileFact.symbols.find(s => s.span.start_line === lineNum && (s.kind === 'VARIABLE' || s.kind === 'CONSTANT'));
                    if (lineSym) {
                      varName = lineSym.name;
                    }
                  }

                  instances.push({
                    source_id: def.source_id,
                    category: def.category,
                    variable_name: varName,
                    file_path: fileFact.file_path,
                    span: makeSpan(
                      fileFact.file_path,
                      lineNum,
                      startCol,
                      lineNum,
                      Math.min(lineText.length + 1, startCol + 40),
                      lineText.trim().slice(0, 80),
                      varName || matchedId
                    ),
                    expression_text: lineText.trim(),
                    confidence: def.base_confidence,
                    epistemic_state: 'OBSERVED_FACT',
                  });
                  break;
                }
              }
            }
          }
        }
      }

      // 3. SUPPLEMENTARY SIGNAL: Regex Literal Matching (Only for lines not already covered by AST)
      for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        const lineNum = lineIdx + 1;
        if (coveredLines.has(lineNum)) continue;

        const lineText = lines[lineIdx];
        for (const def of sourceDefs) {
          if (def.match_patterns) {
            for (const pattern of def.match_patterns) {
              const match = pattern.exec(lineText);
              if (match) {
                const startCol = match.index + 1;
                const endCol = startCol + match[0].length;
                const varAssignMatch = lineText.match(/(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=/);
                const varName = varAssignMatch ? varAssignMatch[1] : undefined;

                instances.push({
                  source_id: def.source_id,
                  category: def.category,
                  variable_name: varName,
                  file_path: fileFact.file_path,
                  span: makeSpan(
                    fileFact.file_path,
                    lineNum,
                    startCol,
                    lineNum,
                    endCol,
                    match[0].slice(0, 80),
                    varName || def.name
                  ),
                  expression_text: match[0],
                  confidence: Math.min(def.base_confidence, 0.7), // Lower confidence for pure regex fallback
                  epistemic_state: 'OBSERVED_FACT',
                });
              }
            }
          }
        }
      }
    }

    return instances;
  }

  /**
   * Discovers sink definitions using authoritative AST call sites as primary truth,
   * keeping regex matching only as a supplementary fallback signal.
   */
  private static discoverSinks(
    syntaxResult: ArtifactParseResult,
    fileContentMap: Map<string, string>
  ): TaintSinkInstance[] {
    const instances: TaintSinkInstance[] = [];
    const sinkDefs = TaintSinkRegistry.getAllSinks();

    for (const fileFact of syntaxResult.file_facts) {
      const content = fileContentMap.get(fileFact.file_path) || fileFact.raw_content_preview || '';
      const lines = content.split('\n');
      const coveredLines = new Set<number>();

      // 1. PRIMARY AST DISCOVERY: Call Sites from Authoritative AST Parsers
      for (const call of fileFact.call_sites) {
        const fullCallee = call.receiver ? `${call.receiver}.${call.callee_name}` : call.callee_name;

        for (const def of sinkDefs) {
          let matched = false;
          let matchedName = call.callee_name;

          if (def.match_functions) {
            for (const fn of def.match_functions) {
              if (fn === call.callee_name || fn === fullCallee || (call.receiver && fn === `.${call.callee_name}`)) {
                matched = true;
                matchedName = fn;
                break;
              }
              if (fn.includes('.') && call.receiver) {
                const parts = fn.split('.');
                const targetMethod = parts[parts.length - 1];
                const targetReceiver = parts.slice(0, -1).join('.');
                if (call.callee_name === targetMethod && call.receiver.includes(targetReceiver)) {
                  matched = true;
                  matchedName = fn;
                  break;
                }
              }
            }
          }

          if (!matched && def.match_member_methods && call.receiver) {
            for (const method of def.match_member_methods) {
              if (method === call.callee_name) {
                matched = true;
                matchedName = `.${method}`;
                break;
              }
            }
          }

          if (matched) {
            coveredLines.add(call.span.start_line);
            const firstArg = call.arguments_summary && call.arguments_summary.length > 0
              ? call.arguments_summary[0].split(',')[0].trim().replace(/['"`]/g, '')
              : undefined;

            instances.push({
              sink_id: def.sink_id,
              category: def.category,
              callee_name: matchedName,
              file_path: fileFact.file_path,
              span: call.span,
              call_expression_text: call.span.text_slice || `${fullCallee}(...)`,
              tainted_argument_name: firstArg,
              confidence: def.base_confidence,
              epistemic_state: 'OBSERVED_FACT',
            });
          }
        }
      }

      // 2. SUPPLEMENTARY SIGNAL: Line-by-line regex scanning for any uncovered lines
      for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        const lineNum = lineIdx + 1;
        if (coveredLines.has(lineNum)) continue;

        const lineText = lines[lineIdx];
        for (const def of sinkDefs) {
          if (def.match_functions) {
            for (const fn of def.match_functions) {
              const fnRegex = new RegExp(`\\b${fn.replace('.', '\\.')}\\s*\\(([^)]*)\\)`, 'g');
              let match: RegExpExecArray | null;
              while ((match = fnRegex.exec(lineText)) !== null) {
                const startCol = match.index + 1;
                const argStr = match[1] || '';
                const firstArg = argStr.split(',')[0]?.trim().replace(/['"`]/g, '');

                instances.push({
                  sink_id: def.sink_id,
                  category: def.category,
                  callee_name: fn,
                  file_path: fileFact.file_path,
                  span: makeSpan(
                    fileFact.file_path,
                    lineNum,
                    startCol,
                    lineNum,
                    startCol + match[0].length,
                    match[0].slice(0, 80),
                    fn
                  ),
                  call_expression_text: match[0],
                  tainted_argument_name: firstArg,
                  confidence: Math.min(def.base_confidence, 0.7),
                  epistemic_state: 'OBSERVED_FACT',
                });
              }
            }
          }
        }
      }
    }

    return instances;
  }

  /**
   * Discovers sanitizer / transform function calls using authoritative AST call sites
   */
  private static discoverSanitizers(
    syntaxResult: ArtifactParseResult,
    fileContentMap: Map<string, string>
  ): TaintSanitizerInstance[] {
    const instances: TaintSanitizerInstance[] = [];
    const sanDefs = TaintSanitizerRegistry.getAllSanitizers();

    for (const fileFact of syntaxResult.file_facts) {
      const content = fileContentMap.get(fileFact.file_path) || fileFact.raw_content_preview || '';
      const lines = content.split('\n');
      const coveredLines = new Set<number>();

      // 1. PRIMARY AST DISCOVERY: Call sites
      for (const call of fileFact.call_sites) {
        const fullCallee = call.receiver ? `${call.receiver}.${call.callee_name}` : call.callee_name;
        for (const def of sanDefs) {
          if (def.match_functions) {
            const matches = def.match_functions.some(fn => 
              fn === call.callee_name || 
              fn === fullCallee || 
              (call.receiver && fn === `.${call.callee_name}`)
            );
            if (matches) {
              coveredLines.add(call.span.start_line);
              instances.push({
                sanitizer_id: def.sanitizer_id,
                category: def.category,
                transformer_name: fullCallee,
                file_path: fileFact.file_path,
                span: call.span,
                expression_text: call.span.text_slice || `${fullCallee}(...)`,
                neutralization_power: def.neutralization_power,
              });
            }
          }
        }
      }

      // 2. SUPPLEMENTARY SIGNAL: Line-by-line regex scanning
      for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        const lineNum = lineIdx + 1;
        if (coveredLines.has(lineNum)) continue;

        const lineText = lines[lineIdx];
        for (const def of sanDefs) {
          if (def.match_functions) {
            for (const fn of def.match_functions) {
              const fnRegex = new RegExp(`\\b${fn.replace('.', '\\.')}\\s*\\(`, 'g');
              let match: RegExpExecArray | null;
              while ((match = fnRegex.exec(lineText)) !== null) {
                instances.push({
                  sanitizer_id: def.sanitizer_id,
                  category: def.category,
                  transformer_name: fn,
                  file_path: fileFact.file_path,
                  span: makeSpan(
                    fileFact.file_path,
                    lineNum,
                    match.index + 1,
                    lineNum,
                    match.index + 1 + fn.length + 1,
                    lineText.trim().slice(0, 80),
                    fn
                  ),
                  expression_text: lineText.trim(),
                  neutralization_power: def.neutralization_power,
                });
              }
            }
          }
        }
      }
    }

    return instances;
  }

  /**
   * Propagates taint across intra-function, interprocedural, and cross-file boundaries
   */
  private static propagateTaint(
    sources: TaintSourceInstance[],
    sinks: TaintSinkInstance[],
    sanitizers: TaintSanitizerInstance[],
    syntaxResult: ArtifactParseResult,
    fileContentMap: Map<string, string>,
    symbolGraph: SymbolImportGraph,
    callGraph: CallGraph,
    cfgs: ControlFlowGraph[]
  ): TaintFlowPath[] {
    const paths: TaintFlowPath[] = [];
    let pathCounter = 1;

    for (const source of sources) {
      const sourceVar = source.variable_name;
      const sourceFile = source.file_path;
      const sourceLine = source.span.start_line;

      // Track all tainted symbols/variables derived from this source:
      // Map of symbol/alias -> { file_path, assigned_line, hops, sanitizer }
      interface TaintCarrier {
        symbol: string;
        file_path: string;
        hops: TaintHop[];
        sanitizer?: TaintSanitizerInstance;
        has_dynamic_dispatch: boolean;
      }

      const initialHops: TaintHop[] = [
        {
          hop_number: 1,
          hop_type: 'SOURCE_ORIGIN',
          file_path: sourceFile,
          to_symbol: sourceVar || '<anonymous_source>',
          expression_snippet: source.expression_text,
          span: source.span,
          is_interprocedural: false,
          is_cross_file: false,
          is_dynamic: false,
        }
      ];

      const activeCarriers: TaintCarrier[] = [
        {
          symbol: sourceVar || '__DIRECT_SOURCE__',
          file_path: sourceFile,
          hops: initialHops,
          has_dynamic_dispatch: false,
        }
      ];

      // Intra-file variable flow tracing
      const fileContent = fileContentMap.get(sourceFile) || '';
      const lines = fileContent.split('\n');

      for (let i = Math.max(0, sourceLine - 1); i < lines.length; i++) {
        const lineText = lines[i];
        const lineNum = i + 1;

        // Check if any active carrier is used in an assignment
        for (const carrier of [...activeCarriers]) {
          if (!carrier.symbol || carrier.symbol === '__DIRECT_SOURCE__') continue;

          // Check if line contains a sanitizer call wrapping the carrier
          for (const san of sanitizers) {
            if (san.file_path === sourceFile && san.span.start_line === lineNum && lineText.includes(carrier.symbol)) {
              // Carrier is sanitized
              const assignMatch = lineText.match(/(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=/);
              const targetVar = assignMatch ? assignMatch[1] : carrier.symbol;
              const sanHop: TaintHop = {
                hop_number: carrier.hops.length + 1,
                hop_type: 'SANITIZER_TRANSFORM',
                file_path: sourceFile,
                from_symbol: carrier.symbol,
                to_symbol: targetVar,
                expression_snippet: lineText.trim(),
                span: makeSpan(
                  sourceFile,
                  lineNum,
                  1,
                  lineNum,
                  lineText.length + 1,
                  lineText.trim().slice(0, 80),
                  san.transformer_name
                ),
                is_interprocedural: false,
                is_cross_file: false,
                is_dynamic: false,
              };

              activeCarriers.push({
                symbol: targetVar,
                file_path: sourceFile,
                hops: [...carrier.hops, sanHop],
                sanitizer: san,
                has_dynamic_dispatch: carrier.has_dynamic_dispatch,
              });
            }
          }

          // Variable assignment: const y = x; or const y = 'prefix' + x; or `http://${x}`
          const assignRegex = new RegExp(`(?:const|let|var)\\s+([a-zA-Z0-9_$]+)\\s*=\\s*([^;]+)`);
          const assignMatch = lineText.match(assignRegex);
          if (assignMatch) {
            const lhsVar = assignMatch[1];
            const rhsExpr = assignMatch[2];

            if (rhsExpr.includes(carrier.symbol) && lhsVar !== carrier.symbol) {
              const hopType = rhsExpr.includes('`') 
                ? 'TEMPLATE_LITERAL' 
                : (rhsExpr.includes('+') ? 'BINARY_EXPRESSION' : 'VARIABLE_ASSIGNMENT');

              const hop: TaintHop = {
                hop_number: carrier.hops.length + 1,
                hop_type: hopType,
                file_path: sourceFile,
                from_symbol: carrier.symbol,
                to_symbol: lhsVar,
                expression_snippet: lineText.trim(),
                span: makeSpan(
                  sourceFile,
                  lineNum,
                  1,
                  lineNum,
                  lineText.length + 1,
                  lineText.trim().slice(0, 80),
                  lhsVar
                ),
                is_interprocedural: false,
                is_cross_file: false,
                is_dynamic: false,
              };

              activeCarriers.push({
                symbol: lhsVar,
                file_path: sourceFile,
                hops: [...carrier.hops, hop],
                sanitizer: carrier.sanitizer,
                has_dynamic_dispatch: carrier.has_dynamic_dispatch,
              });
            }
          }

          // Check dynamic dispatch (e.g. dynamic member access window[prop](x) or obj[dyn](x) or dispatchTable[dynHandler](userToken))
          const dynamicDispatchRegex = new RegExp(`\\[[a-zA-Z0-9_$]+\\]\\s*\\([^)]*\\b${carrier.symbol}\\b[^)]*\\)`);
          if (dynamicDispatchRegex.test(lineText)) {
            const dynHop: TaintHop = {
              hop_number: carrier.hops.length + 1,
              hop_type: 'DYNAMIC_DISPATCH',
              file_path: sourceFile,
              from_symbol: carrier.symbol,
              to_symbol: '<dynamic_target>',
              expression_snippet: lineText.trim(),
              span: makeSpan(
                sourceFile,
                lineNum,
                1,
                lineNum,
                lineText.length + 1,
                lineText.trim().slice(0, 80),
                '<dynamic_dispatch>'
              ),
              is_interprocedural: true,
              is_cross_file: false,
              is_dynamic: true,
            };

            activeCarriers.push({
              symbol: carrier.symbol,
              file_path: sourceFile,
              hops: [...carrier.hops, dynHop],
              sanitizer: carrier.sanitizer,
              has_dynamic_dispatch: true,
            });
          }
        }
      }

      // Cross-Module Variable Export/Import Flow Tracing
      for (const carrier of [...activeCarriers]) {
        for (const [modPath, mod] of Object.entries(symbolGraph.modules)) {
          if (modPath === carrier.file_path) continue;
          for (const imp of mod.imports) {
            const isTargetMatch = imp.resolved_path === carrier.file_path || 
              (imp.is_relative && imp.module_specifier.includes(carrier.file_path.replace(/^src\//, '').replace(/\.ts$/, '')));

            if (isTargetMatch && imp.imported_symbols.includes(carrier.symbol)) {
              const crossHop: TaintHop = {
                hop_number: carrier.hops.length + 1,
                hop_type: 'CROSS_FILE_IMPORT',
                file_path: modPath,
                from_symbol: `${carrier.symbol} (${carrier.file_path})`,
                to_symbol: carrier.symbol,
                expression_snippet: `import { ${carrier.symbol} } from '${imp.module_specifier}'`,
                span: imp.span,
                is_interprocedural: false,
                is_cross_file: true,
                is_dynamic: false,
              };

              activeCarriers.push({
                symbol: carrier.symbol,
                file_path: modPath,
                hops: [...carrier.hops, crossHop],
                sanitizer: carrier.sanitizer,
                has_dynamic_dispatch: carrier.has_dynamic_dispatch,
              });

              // Trace subsequent assignments in the importing module
              const targetContent = fileContentMap.get(modPath) || '';
              const targetLines = targetContent.split('\n');
              for (let tIdx = 0; tIdx < targetLines.length; tIdx++) {
                const tLine = targetLines[tIdx];
                const tNum = tIdx + 1;
                const assignRegex = new RegExp(`(?:const|let|var)\\s+([a-zA-Z0-9_$]+)\\s*=\\s*([^;]+)`);
                const assignMatch = tLine.match(assignRegex);
                if (assignMatch && assignMatch[2].includes(carrier.symbol) && assignMatch[1] !== carrier.symbol) {
                  const localHop: TaintHop = {
                    hop_number: carrier.hops.length + 2,
                    hop_type: 'VARIABLE_ASSIGNMENT',
                    file_path: modPath,
                    from_symbol: carrier.symbol,
                    to_symbol: assignMatch[1],
                    expression_snippet: tLine.trim(),
                    span: makeSpan(
                      modPath,
                      tNum,
                      1,
                      tNum,
                      tLine.length + 1,
                      tLine.trim().slice(0, 80),
                      assignMatch[1]
                    ),
                    is_interprocedural: false,
                    is_cross_file: true,
                    is_dynamic: false,
                  };
                  activeCarriers.push({
                    symbol: assignMatch[1],
                    file_path: modPath,
                    hops: [...carrier.hops, crossHop, localHop],
                    sanitizer: carrier.sanitizer,
                    has_dynamic_dispatch: carrier.has_dynamic_dispatch,
                  });
                }
              }
            }
          }
        }
      }

      // Interprocedural & Cross-File Resolution
      // Check if carrier symbols are passed into function calls defined in same file or other files
      for (const carrier of [...activeCarriers]) {
        for (const fileFact of syntaxResult.file_facts) {
          const cContent = fileContentMap.get(fileFact.file_path) || '';
          const cLines = cContent.split('\n');

          for (let lIdx = 0; lIdx < cLines.length; lIdx++) {
            const lText = cLines[lIdx];
            const lNum = lIdx + 1;

            if (carrier.symbol !== '__DIRECT_SOURCE__' && lText.includes(carrier.symbol)) {
              // Function invocation: e.g. sendPayload(carrier.symbol) or helper(carrier.symbol)
              const fnCallMatch = lText.match(/([a-zA-Z0-9_$]+)\s*\(([^)]*)\)/);
              if (fnCallMatch) {
                const calledFn = fnCallMatch[1];
                const args = fnCallMatch[2];

                if (args.includes(carrier.symbol)) {
                  // Find callee in call graph or symbol graph
                  const crossBinding = symbolGraph.cross_file_bindings.find(
                    b => b.from_file === fileFact.file_path && b.from_symbol === calledFn && b.is_resolved
                  );

                  if (crossBinding && crossBinding.to_file) {
                    // Cross-file function call
                    const targetFile = crossBinding.to_file;
                    const crossHop: TaintHop = {
                      hop_number: carrier.hops.length + 1,
                      hop_type: 'PARAMETER_PASSING',
                      file_path: fileFact.file_path,
                      from_symbol: carrier.symbol,
                      to_symbol: `${calledFn} (in ${targetFile})`,
                      expression_snippet: lText.trim(),
                      span: makeSpan(
                        fileFact.file_path,
                        lNum,
                        1,
                        lNum,
                        lText.length + 1,
                        lText.trim().slice(0, 80),
                        calledFn
                      ),
                      is_interprocedural: true,
                      is_cross_file: true,
                      is_dynamic: false,
                    };

                    // Also check callee function definition in targetFile to extract its parameter name
                    const targetContent = fileContentMap.get(targetFile) || '';
                    const calleeParamMatch = targetContent.match(new RegExp(`function\\s+${calledFn}\\s*\\(([^)]+)\\)`));
                    const calleeParam = calleeParamMatch ? calleeParamMatch[1].split(',')[0].trim().split(':')[0].trim() : 'param';

                    activeCarriers.push({
                      symbol: calleeParam,
                      file_path: targetFile,
                      hops: [...carrier.hops, crossHop],
                      sanitizer: carrier.sanitizer,
                      has_dynamic_dispatch: carrier.has_dynamic_dispatch,
                    });
                  } else {
                    // Intra-file function call
                    const intraFunc = syntaxResult.file_facts
                      .find(f => f.file_path === fileFact.file_path)
                      ?.symbols.find(s => s.name === calledFn);

                    if (intraFunc) {
                      const intraHop: TaintHop = {
                        hop_number: carrier.hops.length + 1,
                        hop_type: 'PARAMETER_PASSING',
                        file_path: fileFact.file_path,
                        from_symbol: carrier.symbol,
                        to_symbol: calledFn,
                        expression_snippet: lText.trim(),
                        span: makeSpan(
                          fileFact.file_path,
                          lNum,
                          1,
                          lNum,
                          lText.length + 1,
                          lText.trim().slice(0, 80),
                          calledFn
                        ),
                        is_interprocedural: true,
                        is_cross_file: false,
                        is_dynamic: false,
                      };

                      // Extract callee parameter
                      const cFuncContent = fileContentMap.get(fileFact.file_path) || '';
                      const calleeParamMatch = cFuncContent.match(new RegExp(`function\\s+${calledFn}\\s*\\(([^)]+)\\)`));
                      const calleeParam = calleeParamMatch ? calleeParamMatch[1].split(',')[0].trim().split(':')[0].trim() : 'param';

                      activeCarriers.push({
                        symbol: calleeParam,
                        file_path: fileFact.file_path,
                        hops: [...carrier.hops, intraHop],
                        sanitizer: carrier.sanitizer,
                        has_dynamic_dispatch: carrier.has_dynamic_dispatch,
                      });
                    }
                  }
                }
              }
            }
          }
        }
      }

      // Check sinks to see if any sink receives an active carrier or directly matches source
      for (const sink of sinks) {
        for (const carrier of activeCarriers) {
          const isDirectMatch = (source.file_path === sink.file_path && source.span.start_line === sink.span.start_line);
          const isCarrierInSink = sink.file_path === carrier.file_path && (
            (sink.tainted_argument_name && sink.tainted_argument_name.includes(carrier.symbol)) ||
            (sink.call_expression_text && sink.call_expression_text.includes(carrier.symbol))
          );

          if (isDirectMatch || isCarrierInSink) {
            // Check reachability via CFG (dead code inspection)
            let isReachable = true;
            for (const cfg of cfgs) {
              if (cfg.file_path === sink.file_path) {
                const deadBlock = cfg.blocks.find(b => 
                  b.is_dead_code && b.statements.some(s => s.includes(sink.callee_name) || s.includes(sink.call_expression_text))
                );
                if (deadBlock) {
                  isReachable = false;
                  break;
                }
              }
            }

            // Also check for post-return/throw dead code in file content
            const sinkFileContent = fileContentMap.get(sink.file_path) || '';
            const sinkLines = sinkFileContent.split('\n');
            for (let l = 0; l < sink.span.start_line - 1; l++) {
              const line = sinkLines[l].trim();
              if ((line.startsWith('return ') || line === 'return;' || line.startsWith('throw ')) && !line.includes('if')) {
                // If unconditional return appears directly before sink in same block
                if (sink.span.start_line - l <= 4) {
                  isReachable = false;
                }
              }
            }

            // Determine status
            let status: TaintPathStatus = 'ACTIVE';
            if (!isReachable) {
              status = 'UNREACHABLE';
            } else if (carrier.sanitizer) {
              status = 'SANITIZED';
            } else if (carrier.has_dynamic_dispatch) {
              status = 'INDETERMINATE';
            }

            // Compute confidence
            let confidence = 0.98;
            if (status === 'INDETERMINATE') {
              confidence = 0.50;
            } else if (carrier.hops.some(h => h.is_cross_file)) {
              confidence = 0.90;
            } else if (carrier.hops.some(h => h.is_interprocedural)) {
              confidence = 0.94;
            }

            // Final sink hop
            const sinkHop: TaintHop = {
              hop_number: carrier.hops.length + 1,
              hop_type: 'SINK_INVOCATION',
              file_path: sink.file_path,
              from_symbol: carrier.symbol,
              to_symbol: sink.callee_name,
              expression_snippet: sink.call_expression_text,
              span: sink.span,
              is_interprocedural: carrier.hops.some(h => h.is_interprocedural),
              is_cross_file: carrier.hops.some(h => h.is_cross_file),
              is_dynamic: carrier.has_dynamic_dispatch,
            };

            const allHops = [...carrier.hops, sinkHop];

            // Flow classification
            let flowClass: TaintFlowPath['flow_classification'] = 'POTENTIAL_SECRET_EGRESS';
            if (status === 'SANITIZED') {
              flowClass = 'SANITIZED_DATAFLOW';
            } else if (status === 'UNREACHABLE') {
              flowClass = 'DEAD_CODE_DATAFLOW';
            } else if (status === 'INDETERMINATE') {
              flowClass = 'INDETERMINATE_DATAFLOW';
            } else if (sink.category === 'PROCESS_EXECUTION') {
              flowClass = 'POTENTIAL_COMMAND_INJECTION';
            } else if (source.category === 'FILESYSTEM_READ' && sink.category === 'NETWORK_EGRESS') {
              flowClass = 'POTENTIAL_FILE_EXFILTRATION';
            } else if (sink.category === 'TOOL_INVOCATION' || source.category === 'TOOL_ARGUMENT') {
              flowClass = 'POTENTIAL_TOOL_DATAFLOW';
            }

            // Description: STRICTLY avoiding calling a possible flow confirmed exfiltration
            const desc = `Potential dataflow propagation path identified from source [${source.source_id}: ${source.span.symbol_hint || 'origin'}] to sink [${sink.sink_id}: ${sink.callee_name}]. Statically inferred over AST/symbol lineage; represents potential propagation risk rather than confirmed runtime exfiltration.`;

            const evidence = {
              evidence_id: `evi_taint_${crypto.randomUUID().slice(0, 8)}`,
              evidence_type: 'STATIC_CODE' as const,
              evidence_class: 'STRUCTURAL_EXTRACTION' as const,
              description: desc,
              confidence,
              epistemic_state: 'DERIVED_ASSERTION' as const,
              uncertainty_factors: carrier.has_dynamic_dispatch ? ['DYNAMIC_DISPATCH' as const] : [],
              source_span: source.span,
              sink_span: sink.span,
              lineage_chain: allHops.map(h => `${h.hop_type}(${h.from_symbol || ''} -> ${h.to_symbol || ''})`),
            };

            // Avoid duplicate identical paths
            const isDuplicate = paths.some(p => 
              p.source.span.file_path === source.span.file_path &&
              p.source.span.start_line === source.span.start_line &&
              p.sink.span.file_path === sink.span.file_path &&
              p.sink.span.start_line === sink.span.start_line &&
              p.status === status
            );

            if (!isDuplicate) {
              paths.push({
                path_id: `taint_path_${pathCounter++}`,
                source,
                sink,
                status,
                sanitizer: carrier.sanitizer,
                hops: allHops,
                confidence,
                is_interprocedural: carrier.hops.some(h => h.is_interprocedural),
                is_cross_file: carrier.hops.some(h => h.is_cross_file),
                is_reachable: isReachable,
                unresolved_dispatch_count: carrier.has_dynamic_dispatch ? 1 : 0,
                evidence,
                epistemic_label: 'INFERRED_TAINT_FLOW',
                flow_classification: flowClass,
                description: desc,
              });
            }
          }
        }
      }

      // Also check if carrier reached a dynamic dispatch without an explicit sink match
      for (const carrier of activeCarriers) {
        if (carrier.has_dynamic_dispatch) {
          const hasMatchedPath = paths.some(p => 
            p.source.span.file_path === source.span.file_path &&
            p.source.span.start_line === source.span.start_line &&
            p.hops.some(h => h.is_dynamic)
          );

          if (!hasMatchedPath) {
            const dynHop = carrier.hops.find(h => h.is_dynamic) || carrier.hops[carrier.hops.length - 1];
            const indetSink: TaintSinkInstance = {
              sink_id: 'SINK-DYNAMIC-DISPATCH',
              category: 'PROCESS_EXECUTION',
              callee_name: '<dynamic_dispatch>',
              file_path: dynHop.file_path,
              span: dynHop.span,
              call_expression_text: dynHop.expression_snippet,
              confidence: 0.50,
              epistemic_state: 'HYPOTHESIS',
            };

            const desc = `Unresolved dynamic dispatch path identified from source [${source.source_id}] into dynamic dispatch target. Statically indeterminate.`;
            const evidence = {
              evidence_id: `evi_taint_${crypto.randomUUID().slice(0, 8)}`,
              evidence_type: 'STATIC_CODE' as const,
              evidence_class: 'STRUCTURAL_EXTRACTION' as const,
              description: desc,
              confidence: 0.50,
              epistemic_state: 'HYPOTHESIS' as const,
              uncertainty_factors: ['DYNAMIC_DISPATCH' as const],
              source_span: source.span,
              sink_span: dynHop.span,
              lineage_chain: carrier.hops.map(h => `${h.hop_type}(${h.from_symbol || ''} -> ${h.to_symbol || ''})`),
            };

            paths.push({
              path_id: `taint_path_${pathCounter++}`,
              source,
              sink: indetSink,
              status: 'INDETERMINATE',
              sanitizer: carrier.sanitizer,
              hops: carrier.hops,
              confidence: 0.50,
              is_interprocedural: carrier.hops.some(h => h.is_interprocedural),
              is_cross_file: carrier.hops.some(h => h.is_cross_file),
              is_reachable: true,
              unresolved_dispatch_count: 1,
              evidence,
              epistemic_label: 'INFERRED_TAINT_FLOW',
              flow_classification: 'INDETERMINATE_DATAFLOW',
              description: desc,
            });
          }
        }
      }
    }

    return paths;
  }

  /**
   * Computes aggregate summary statistics
   */
  private static computeSummary(
    sources: TaintSourceInstance[],
    sinks: TaintSinkInstance[],
    paths: TaintFlowPath[]
  ): TaintAnalysisSummaryStats {
    const pathsBySourceCat: Record<TaintSourceCategory, number> = {
      CREDENTIAL_SECRET: 0,
      ENVIRONMENT_SECRET: 0,
      FILESYSTEM_READ: 0,
      NETWORK_RESPONSE: 0,
      USER_INPUT: 0,
      TOOL_ARGUMENT: 0,
      DATABASE_READ: 0,
    };

    const pathsBySinkCat: Record<TaintSinkCategory, number> = {
      NETWORK_EGRESS: 0,
      PROCESS_EXECUTION: 0,
      FILESYSTEM_WRITE: 0,
      FILESYSTEM_DELETE: 0,
      TOOL_INVOCATION: 0,
      DYNAMIC_CODE_EVAL: 0,
      LOGGING_OUTPUT: 0,
      DATABASE_QUERY: 0,
    };

    let activeCount = 0;
    let sanitizedCount = 0;
    let unreachableCount = 0;
    let indeterminateCount = 0;
    let interproceduralCount = 0;
    let crossFileCount = 0;

    for (const p of paths) {
      pathsBySourceCat[p.source.category]++;
      pathsBySinkCat[p.sink.category]++;

      if (p.status === 'ACTIVE') activeCount++;
      if (p.status === 'SANITIZED') sanitizedCount++;
      if (p.status === 'UNREACHABLE') unreachableCount++;
      if (p.status === 'INDETERMINATE') indeterminateCount++;
      if (p.is_interprocedural) interproceduralCount++;
      if (p.is_cross_file) crossFileCount++;
    }

    return {
      total_sources_detected: sources.length,
      total_sinks_detected: sinks.length,
      total_paths_identified: paths.length,
      active_vulnerable_paths: activeCount,
      sanitized_paths: sanitizedCount,
      unreachable_paths: unreachableCount,
      indeterminate_paths: indeterminateCount,
      interprocedural_paths: interproceduralCount,
      cross_file_paths: crossFileCount,
      paths_by_source_category: pathsBySourceCat,
      paths_by_sink_category: pathsBySinkCat,
    };
  }
}
