/**
 * Static Analysis Rule Evaluator
 * P15 — Static Analysis & Control Flow
 */

import { 
  StaticFinding, 
  AnalysisStageRun, 
  SymbolImportGraph, 
  CallGraph, 
  ControlFlowGraph,
  STATIC_RULESET_VERSION 
} from '../types.ts';
import { ArtifactParseResult, SourceSpan } from '@caim/syntax/types.ts';
import { STATIC_RULES_CATALOG, StaticRuleDefinition } from './catalog.ts';
import { StaticCallGraphBuilder } from '../call-graph.ts';

export class StaticRuleEvaluator {
  private static readonly RULE_MAP = new Map<string, StaticRuleDefinition>(
    STATIC_RULES_CATALOG.map(r => [r.rule_id, r])
  );

  /**
   * Evaluates all static rules across parsed source facts, CFGs, and the Call Graph
   */
  public static evaluate(
    artifactParse: ArtifactParseResult,
    fileContents: Map<string, string>,
    symbolGraph: SymbolImportGraph,
    callGraph: CallGraph,
    cfgs: ControlFlowGraph[],
    stageRun: AnalysisStageRun
  ): StaticFinding[] {
    const findings: StaticFinding[] = [];
    const findingSet = new Set<string>();

    const addFinding = (
      ruleId: string,
      span: SourceSpan,
      overrides?: {
        title?: string;
        description?: string;
        severity?: StaticRuleDefinition['severity'];
        confidence?: number;
        interprocedural_trace?: StaticFinding['interprocedural_trace'];
        metadata?: Record<string, unknown>;
      }
    ) => {
      const def = this.RULE_MAP.get(ruleId);
      if (!def) return;

      const dedupeKey = `${ruleId}:${span.file_path}:${span.start_line}:${span.start_col}:${overrides?.description || ''}`;
      if (findingSet.has(dedupeKey)) return;
      findingSet.add(dedupeKey);

      findings.push({
        finding_id: `find_${crypto.randomUUID().slice(0, 8)}`,
        rule_id: ruleId,
        ruleset_version: STATIC_RULESET_VERSION,
        category: def.category,
        severity: overrides?.severity || def.severity,
        confidence: overrides?.confidence ?? def.default_confidence,
        title: overrides?.title || def.title,
        description: overrides?.description || def.description,
        rationale: def.rationale,
        remediation_hint: def.remediation_hint,
        canonical_concept_key: def.canonical_concept_key,
        source_span: span,
        stage_run: stageRun,
        interprocedural_trace: overrides?.interprocedural_trace,
        metadata: overrides?.metadata,
      });
    };

    // 1. Evaluate Call Sites (Network, Filesystem, Process, Tools)
    for (const fileFact of artifactParse.file_facts) {
      for (const call of fileFact.call_sites) {
        const fullCallee = call.receiver ? `${call.receiver}.${call.callee_name}` : call.callee_name;
        const calleeLower = fullCallee.toLowerCase();

        // Check enclosing function
        const enclosingFunction = this.findEnclosingFunctionName(call, fileFact.symbols);

        // Check Process Execution
        if (
          calleeLower === 'exec' || 
          calleeLower === 'execsync' || 
          calleeLower.includes('child_process.exec') || 
          calleeLower.includes('os.system') || 
          calleeLower.includes('subprocess.popen') ||
          calleeLower.includes('exec.command')
        ) {
          const trace = this.resolveTraceForCall(fileFact.file_path, enclosingFunction, callGraph);
          addFinding('SA-PROC-001', call.span, {
            description: `Shell process execution via '${fullCallee}()' detected in source.`,
            interprocedural_trace: trace,
            metadata: { callee: fullCallee, enclosing_function: enclosingFunction },
          });
        } else if (
          calleeLower === 'spawn' || 
          calleeLower === 'spawnsync' || 
          calleeLower.includes('subprocess.run') ||
          calleeLower.includes('subprocess.call')
        ) {
          const trace = this.resolveTraceForCall(fileFact.file_path, enclosingFunction, callGraph);
          addFinding('SA-PROC-002', call.span, {
            description: `Dynamic process spawn via '${fullCallee}()' detected.`,
            interprocedural_trace: trace,
          });
        }

        // Check Dynamic Eval
        if (calleeLower === 'eval' || calleeLower === 'function' || (call.callee_name === 'exec' && fileFact.file_type.language === 'Python')) {
          addFinding('SA-PROC-003', call.span, {
            description: `Dynamic code evaluation via '${fullCallee}' construct detected.`,
          });
        }

        // Check Network Client Egress
        if (
          calleeLower.includes('fetch') || 
          calleeLower.includes('axios') || 
          calleeLower.includes('urllib') || 
          calleeLower.includes('requests.get') || 
          calleeLower.includes('requests.post') || 
          calleeLower.includes('http.get') || 
          calleeLower.includes('http.post') || 
          calleeLower.includes('http.client')
        ) {
          const trace = this.resolveTraceForCall(fileFact.file_path, enclosingFunction, callGraph);
          addFinding('SA-NET-001', call.span, {
            description: `Outbound HTTP network request via '${fullCallee}()' detected.`,
            interprocedural_trace: trace,
          });
        }

        // Check WebSockets / Sockets
        if (calleeLower.includes('websocket') || calleeLower.includes('net.dial') || calleeLower.includes('socket.socket')) {
          addFinding('SA-NET-003', call.span, {
            description: `Persistent raw socket / WebSocket client initialization via '${fullCallee}'.`,
          });
        }

        // Check Filesystem Operations
        if (
          calleeLower.includes('writefile') || 
          calleeLower.includes('appendfile') || 
          calleeLower.includes('os.writefile') || 
          (calleeLower.includes('open') && call.arguments_summary.some(a => a.includes("'w'") || a.includes('"w"')))
        ) {
          const trace = this.resolveTraceForCall(fileFact.file_path, enclosingFunction, callGraph);
          addFinding('SA-FS-002', call.span, {
            description: `Filesystem write/creation operation via '${fullCallee}()'.`,
            interprocedural_trace: trace,
          });
        } else if (
          calleeLower.includes('unlink') || 
          calleeLower.includes('rmdir') || 
          calleeLower.includes('remove') || 
          calleeLower.includes('os.removeall')
        ) {
          addFinding('SA-FS-004', call.span, {
            description: `Destructive filesystem removal via '${fullCallee}()'.`,
          });
        } else if (
          calleeLower.includes('readfile') || 
          calleeLower.includes('os.readfile') || 
          (calleeLower.includes('open') && !call.arguments_summary.some(a => a.includes("'w'")))
        ) {
          addFinding('SA-FS-003', call.span, {
            description: `Filesystem read operation via '${fullCallee}()'.`,
          });
        }

        // Check Exposed Endpoints
        if (
          (calleeLower.includes('app.get') || calleeLower.includes('app.post') || calleeLower.includes('router.post') || calleeLower.includes('http.handlefunc')) &&
          call.argument_count > 0
        ) {
          addFinding('SA-TOOL-003', call.span, {
            description: `HTTP server endpoint handler registered via '${fullCallee}'.`,
          });
        }
      }

      // 2. Evaluate Literals & Code Content (Hardcoded Secrets, Sensitive Paths, Remote URLs, Tool objects)
      const content = fileContents.get(fileFact.file_path) || fileFact.raw_content_preview || '';
      if (content) {
        this.evaluateContentLiterals(fileFact.file_path, content, addFinding);
      }

      // 3. Evaluate Protocol / MCP Tools
      for (const proto of fileFact.protocols) {
        if (proto.protocol_kind === 'MCP' && proto.mcp_details) {
          for (const tool of proto.mcp_details.tools) {
            addFinding('SA-TOOL-001', tool.span || proto.span, {
              title: `MCP Tool: ${tool.name}`,
              description: `MCP Tool '${tool.name}' statically declared (${tool.description || 'no description'}).`,
              metadata: { tool_name: tool.name, schema: tool.parameters_schema },
            });
          }
        }
      }

      // 4. Evaluate Configuration Fact Tools
      if (fileFact.configuration?.tools) {
        for (const tool of fileFact.configuration.tools) {
          addFinding('SA-TOOL-001', tool.span, {
            title: `Tool Declaration: ${tool.name}`,
            description: `Tool declaration '${tool.name}' identified in source configuration.`,
            metadata: { tool_name: tool.name },
          });
        }
      }
    }

    // 5. Evaluate Control Flow Anomalies (CFGs)
    for (const cfg of cfgs) {
      if (cfg.cyclomatic_complexity > 10) {
        const topBlock = cfg.blocks[0];
        const span: SourceSpan = {
          file_path: cfg.file_path,
          start_line: topBlock.start_line,
          start_col: 1,
          end_line: topBlock.end_line,
          end_col: 50,
          byte_offset_start: 0,
          byte_offset_end: 50,
          text_slice: `function ${cfg.function_name}`,
          symbol_hint: cfg.function_name,
        };

        addFinding('SA-CFG-001', span, {
          description: `Function '${cfg.function_name}' has high cyclomatic complexity (V(G) = ${cfg.cyclomatic_complexity} > 10).`,
          metadata: { cyclomatic_complexity: cfg.cyclomatic_complexity },
        });
      }

      if (cfg.has_unreachable_blocks) {
        const deadBlock = cfg.blocks.find(b => b.is_dead_code);
        if (deadBlock) {
          const span: SourceSpan = {
            file_path: cfg.file_path,
            start_line: deadBlock.start_line,
            start_col: 1,
            end_line: deadBlock.end_line,
            end_col: 50,
            byte_offset_start: 0,
            byte_offset_end: 50,
            text_slice: deadBlock.statements.join('\n'),
            symbol_hint: cfg.function_name,
          };

          addFinding('SA-CFG-002', span, {
            description: `Unreachable dead code detected in '${cfg.function_name}' after exit statement at line ${deadBlock.start_line}.`,
          });
        }
      }
    }

    return findings;
  }

  private static findEnclosingFunctionName(
    call: any,
    symbols: Array<{ name: string; kind: string; span: { start_line: number; end_line: number } }>
  ): string | undefined {
    const callLine = call.span.start_line;
    const candidates = symbols
      .filter(s => (s.kind.includes('FUNCTION') || s.kind === 'METHOD' || s.kind === 'CLASS') && s.span.start_line <= callLine)
      .sort((a, b) => b.span.start_line - a.span.start_line);

    return candidates.length > 0 ? candidates[0].name : undefined;
  }

  private static evaluateContentLiterals(
    filePath: string,
    content: string,
    addFinding: (ruleId: string, span: SourceSpan, overrides?: any) => void
  ): void {
    const lines = content.split('\n');

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];
      const lineNum = lineIdx + 1;

      // Sensitive File Paths
      const sensitivePathMatch = line.match(/(['"`])(\/etc\/passwd|~\/\.ssh|\/root|\/etc\/shadow|C:\\\\Windows|C:\\Windows)(['"`])/i);
      if (sensitivePathMatch) {
        const startCol = (sensitivePathMatch.index || 0) + 1;
        const span: SourceSpan = {
          file_path: filePath,
          start_line: lineNum,
          start_col: startCol,
          end_line: lineNum,
          end_col: startCol + sensitivePathMatch[0].length,
          byte_offset_start: 0,
          byte_offset_end: 0,
          text_slice: line.trim(),
        };
        addFinding('SA-FS-001', span, {
          description: `Sensitive system path '${sensitivePathMatch[2]}' referenced in source text.`,
        });
      }

      // Unparameterized SQL Injection pattern
      const sqliMatch = line.match(/(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*(?:\$\{[a-zA-Z0-9_.]+\}|\+\s*[a-zA-Z0-9_]+)/i);
      if (sqliMatch) {
        const startCol = (sqliMatch.index || 0) + 1;
        const span: SourceSpan = {
          file_path: filePath,
          start_line: lineNum,
          start_col: startCol,
          end_line: lineNum,
          end_col: startCol + sqliMatch[0].length,
          byte_offset_start: 0,
          byte_offset_end: 0,
          text_slice: line.trim(),
        };
        addFinding('SA-SQLI-001', span, {
          description: `Unparameterized SQL query with dynamic variable interpolation detected.`,
        });
      }

      // Prompt injection jailbreak templates (DAN, jailbreak, ignore previous instructions)
      const promptInjMatch = line.match(/(?:ignore (?:all )?previous instructions|system prompt override|DAN mode enabled|you are now unfiltered|disregard safety guidelines)/i);
      if (promptInjMatch) {
        const startCol = (promptInjMatch.index || 0) + 1;
        const span: SourceSpan = {
          file_path: filePath,
          start_line: lineNum,
          start_col: startCol,
          end_line: lineNum,
          end_col: startCol + promptInjMatch[0].length,
          byte_offset_start: 0,
          byte_offset_end: 0,
          text_slice: line.trim(),
        };
        addFinding('SA-PROC-003', span, {
          title: 'Adversarial Prompt Injection Vector',
          description: `Prompt injection / jailbreak instruction pattern detected in prompt payload.`,
          severity: 'CRITICAL',
        });
      }

      // Obfuscated eval / String.fromCharCode
      const obfMatch = line.match(/(?:String\.fromCharCode\s*\(|unescape\s*\(|atob\s*\(|Buffer\.from\(.*['"]base64['"]\))/i);
      if (obfMatch && (line.includes('eval') || line.includes('Function') || line.includes('exec') || content.includes('eval('))) {
        const startCol = (obfMatch.index || 0) + 1;
        const span: SourceSpan = {
          file_path: filePath,
          start_line: lineNum,
          start_col: startCol,
          end_line: lineNum,
          end_col: startCol + obfMatch[0].length,
          byte_offset_start: 0,
          byte_offset_end: 0,
          text_slice: line.trim(),
        };
        addFinding('SA-PROC-003', span, {
          title: 'Obfuscated Dynamic Code Execution',
          description: `Obfuscated decode sequence feeding dynamic code evaluation construct.`,
          severity: 'CRITICAL',
        });
      }

      // Hardcoded Secret Tokens (e.g. sk-..., ghp_..., eyJ..., caim-...-secret-...)
      const secretMatch = line.match(/(['"`])(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|caim-[a-z0-9_-]+secret[a-z0-9_-]*)(['"`])/i);
      if (secretMatch) {
        const startCol = (secretMatch.index || 0) + 1;
        const span: SourceSpan = {
          file_path: filePath,
          start_line: lineNum,
          start_col: startCol,
          end_line: lineNum,
          end_col: startCol + secretMatch[0].length,
          byte_offset_start: 0,
          byte_offset_end: 0,
          text_slice: line.trim(),
        };
        addFinding('SA-CRED-001', span, {
          description: `Hardcoded credential/API key literal matched secret signature pattern.`,
        });
      }

      // Sensitive Environment Variable Ingestion
      const envMatch = line.match(/process\.env\.([A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|AUTH)[A-Z0-9_]*)|os\.environ\.get\(['"]([A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|AUTH)[A-Z0-9_]*)['"]\)/i);
      if (envMatch) {
        const envVarName = envMatch[1] || envMatch[2];
        const startCol = (envMatch.index || 0) + 1;
        const span: SourceSpan = {
          file_path: filePath,
          start_line: lineNum,
          start_col: startCol,
          end_line: lineNum,
          end_col: startCol + envMatch[0].length,
          byte_offset_start: 0,
          byte_offset_end: 0,
          text_slice: line.trim(),
        };
        addFinding('SA-CRED-002', span, {
          description: `Access to sensitive environment variable '${envVarName}' detected.`,
          metadata: { env_var: envVarName },
        });
      }

      // Hardcoded External URL
      const urlMatch = line.match(/https?:\/\/[a-zA-Z0-9.\-_]+(?:\/[a-zA-Z0-9.\-_?&=%]*)?/);
      if (urlMatch && !urlMatch[0].includes('localhost') && !urlMatch[0].includes('127.0.0.1')) {
        const startCol = (urlMatch.index || 0) + 1;
        const span: SourceSpan = {
          file_path: filePath,
          start_line: lineNum,
          start_col: startCol,
          end_line: lineNum,
          end_col: startCol + urlMatch[0].length,
          byte_offset_start: 0,
          byte_offset_end: 0,
          text_slice: line.trim(),
        };
        addFinding('SA-NET-002', span, {
          description: `Hardcoded external URL literal '${urlMatch[0]}' found in source text.`,
          metadata: { url: urlMatch[0] },
        });
      }

      // Tool Declaration in code (e.g. name: "...", description: "...", inputSchema / parameters)
      const toolDeclMatch = line.match(/(?:(?:name|tool_name)\s*:\s*['"]([^'"]+)['"]|(?:const|let|var)\s+([\w$]+Tool)\s*=)/);
      if (toolDeclMatch && (content.includes('inputSchema') || content.includes('parameters') || line.includes('Tool') || line.includes('tool'))) {
        const toolName = toolDeclMatch[1] || toolDeclMatch[2];
        const startCol = (toolDeclMatch.index || 0) + 1;
        const span: SourceSpan = {
          file_path: filePath,
          start_line: lineNum,
          start_col: startCol,
          end_line: lineNum,
          end_col: startCol + toolDeclMatch[0].length,
          byte_offset_start: 0,
          byte_offset_end: 0,
          text_slice: line.trim(),
        };
        addFinding('SA-TOOL-001', span, {
          title: `Tool Declaration: ${toolName}`,
          description: `Tool declaration '${toolName}' statically identified in source.`,
          metadata: { tool_name: toolName },
        });
      }
    }
  }

  private static resolveTraceForCall(
    filePath: string,
    enclosingFunction: string | undefined,
    callGraph: CallGraph
  ): StaticFinding['interprocedural_trace'] {
    if (!enclosingFunction || enclosingFunction === '<top-level>') {
      return undefined;
    }
    const nodeId = `${filePath}:${enclosingFunction}`;
    return StaticCallGraphBuilder.traceInterproceduralPath(nodeId, callGraph);
  }
}
