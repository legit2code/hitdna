/**
 * Static Analysis Engine Orchestrator
 * P15 — Static Analysis & Control Flow
 */

import { 
  StaticAnalysisReport, 
  StaticAnalysisJobInput, 
  AnalysisStageRun,
  CoverageReport,
  StaticAnalysisSummaryStats,
  FindingSeverity,
  StaticFindingCategory,
  STATIC_ANALYSIS_ENGINE_VERSION,
  STATIC_RULESET_VERSION
} from './types.ts';
import { StaticFileSelector } from './file-selector.ts';
import { StaticSymbolGraphBuilder } from './symbol-graph.ts';
import { StaticCallGraphBuilder } from './call-graph.ts';
import { StaticCfgBuilder } from './cfg-builder.ts';
import { StaticRuleEvaluator } from './rules/evaluator.ts';
import { DataflowTaintEngine } from './taint/engine.ts';
import { SyntaxIntelligencePipeline } from '@caim/syntax/intelligence-pipeline.ts';
import { ProvenanceRecord } from '@caim/contracts/provenance.ts';

export class StaticAnalysisEngine {
  public static readonly ENGINE_KEY = 'static-analysis-engine';
  public static readonly ENGINE_VERSION = STATIC_ANALYSIS_ENGINE_VERSION;
  public static readonly RULESET_VERSION = STATIC_RULESET_VERSION;

  /**
   * Runs the complete static analysis and control flow pipeline on input artifact files
   */
  public static analyze(input: StaticAnalysisJobInput): StaticAnalysisReport {
    const validFiles = input.files ? input.files.filter(f => f && f.content !== undefined && f.content !== null && (typeof f.content !== 'string' || f.content.trim().length > 0)) : [];
    if (!input.files || !Array.isArray(input.files) || input.files.length === 0 || validFiles.length === 0) {
      throw new Error(
        'AUTHENTIC_SOURCE_REQUIRED: Static analysis cannot execute without authentic source files. ' +
        'Analysis without authentic acquired artifacts is strictly prohibited.'
      );
    }

    // Strictly reject synthetic, representative, or substitute code
    for (const f of validFiles) {
      if ((f as any).is_representative || (f as any).is_substitute || (f as any).is_synthetic || (f as any).is_mock) {
        throw new Error(
          'AUTHENTIC_SOURCE_REQUIRED: Synthetic or representative substitute code cannot be analyzed. ' +
          'Generating representative source is strictly forbidden.'
        );
      }
      if (typeof f.content === 'string') {
        const firstLines = f.content.slice(0, 300);
        if (/^\s*\/\/\s*(Sample entrypoint|Representative substitute|Synthetic substitute|Generated placeholder|Mock substitute)/i.test(firstLines)) {
          throw new Error(
            'AUTHENTIC_SOURCE_REQUIRED: Synthetic or representative substitute code cannot be analyzed. ' +
            'Generating representative source is strictly forbidden.'
          );
        }
      }
    }

    const startedAt = new Date().toISOString();
    const stageRunId = `stage_sa_${crypto.randomUUID().slice(0, 8)}`;

    const stageRun: AnalysisStageRun = {
      stage_run_id: stageRunId,
      stage_name: 'STATIC_ANALYSIS',
      pipeline_run_id: input.pipelineRunId,
      artifact_id: input.artifactId,
      started_at: startedAt,
      completed_at: '',
      status: 'COMPLETED',
      engine_key: this.ENGINE_KEY,
      engine_version: this.ENGINE_VERSION,
      ruleset_version: this.RULESET_VERSION,
    };

    // 1. File Selection & Classification
    const fileSelection = StaticFileSelector.selectFiles(input.files, input.entrypoints);
    const sourceFiles = input.files.filter(f => 
      fileSelection.included_files.some(inc => inc.path === f.path.replace(/\\/g, '/').replace(/^\.\//, ''))
    );

    // 2. Syntax & AST Fact Extraction via Syntax Intelligence Pipeline
    const syntaxResult = SyntaxIntelligencePipeline.processArtifact(input.artifactId, sourceFiles);

    // 3. Symbol & Import Graph Construction
    const allFilePaths = fileSelection.included_files.map(f => f.path);
    const symbolGraph = StaticSymbolGraphBuilder.build(syntaxResult, allFilePaths);

    // 4. Call Graph & Interprocedural Resolution
    const callGraph = StaticCallGraphBuilder.build(syntaxResult, symbolGraph, fileSelection.entrypoint_files);

    // 5. Control Flow Graph (CFG) Generation
    const cfgs = [];
    let totalLines = 0;
    let analyzedLines = 0;
    let totalFunctions = 0;
    const fileContentMap = new Map(sourceFiles.map(f => [f.path.replace(/\\/g, '/').replace(/^\.\//, ''), f.content]));

    for (const fileFact of syntaxResult.file_facts) {
      const content = fileContentMap.get(fileFact.file_path) || fileFact.raw_content_preview || '';
      const fileLineCount = content.split('\n').length;
      totalLines += fileLineCount;
      analyzedLines += fileLineCount;

      // Build CFG for top-level module code
      const topLevelCfg = StaticCfgBuilder.buildCfg(fileFact.file_path, '<top-level>', content);
      cfgs.push(topLevelCfg);

      // Build CFG for individual functions
      for (const sym of fileFact.symbols) {
        if (sym.kind === 'FUNCTION' || sym.kind === 'ASYNC_FUNCTION' || sym.kind === 'METHOD') {
          totalFunctions++;
          const fnCfg = StaticCfgBuilder.buildCfg(fileFact.file_path, sym.name, content, sym.span);
          cfgs.push(fnCfg);
        }
      }
    }

    // 6. Static Rule Evaluation & Source-Located Finding Generation
    const findings = StaticRuleEvaluator.evaluate(
      syntaxResult,
      fileContentMap,
      symbolGraph,
      callGraph,
      cfgs,
      stageRun
    );

    // 6b. Dataflow & Taint Intelligence Analysis (P16)
    const taintReport = DataflowTaintEngine.traceTaint(
      input.artifactId,
      syntaxResult,
      fileContentMap,
      symbolGraph,
      callGraph,
      cfgs
    );

    // 7. Coverage & Unsupported Constructs Computation
    const unsupportedConstructs: CoverageReport['unsupported_constructs'] = [];

    // Check for dynamic eval constructs or unparsed modules
    for (const finding of findings) {
      if (finding.rule_id === 'SA-PROC-003') {
        unsupportedConstructs.push({
          file_path: finding.source_span.file_path,
          construct: 'dynamic_code_evaluation',
          reason: 'Dynamic eval()/Function() breaks static sound-flow bounds.',
          span: finding.source_span,
        });
      }
    }

    for (const unres of symbolGraph.unresolved_imports) {
      unsupportedConstructs.push({
        file_path: unres.from_file,
        construct: `unresolved_import: ${unres.specifier}`,
        reason: 'Relative import target could not be statically resolved in workspace files.',
        span: unres.span,
      });
    }

    const coveragePercentage = totalLines > 0 
      ? Math.round((analyzedLines / totalLines) * 100 * 10) / 10 
      : 100.0;

    const coverage: CoverageReport = {
      total_files: input.files.length,
      analyzed_files: fileSelection.included_files.length,
      total_lines: totalLines,
      analyzed_lines: analyzedLines,
      total_functions: totalFunctions,
      cfg_covered_functions: cfgs.length,
      coverage_percentage: coveragePercentage,
      unsupported_constructs: unsupportedConstructs,
    };

    // 8. Summary Statistics Aggregation
    const severityCounts: Record<FindingSeverity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };

    const categoryCounts: Record<StaticFindingCategory, number> = {
      NETWORK: 0,
      FILESYSTEM: 0,
      PROCESS_EXECUTION: 0,
      TOOL_DECLARATION: 0,
      CREDENTIAL_ACCESS: 0,
      CONTROL_FLOW_ANOMALY: 0,
      UNSUPPORTED_SYNTAX: 0,
    };

    for (const f of findings) {
      severityCounts[f.severity]++;
      categoryCounts[f.category]++;
    }

    const summaryStats: StaticAnalysisSummaryStats = {
      total_findings: findings.length,
      findings_by_severity: severityCounts,
      findings_by_category: categoryCounts,
      network_calls: categoryCounts.NETWORK,
      filesystem_calls: categoryCounts.FILESYSTEM,
      process_executions: categoryCounts.PROCESS_EXECUTION,
      tools_declared: categoryCounts.TOOL_DECLARATION,
      credentials_detected: categoryCounts.CREDENTIAL_ACCESS,
      high_complexity_functions: findings.filter(f => f.rule_id === 'SA-CFG-001').length,
    };

    stageRun.completed_at = new Date().toISOString();
    stageRun.status = unsupportedConstructs.length > 0 && coveragePercentage < 50 ? 'PARTIAL' : 'COMPLETED';

    const provenance: ProvenanceRecord = {
      provenance_id: crypto.randomUUID(),
      source_spans: findings.map(f => ({
        file_path: f.source_span.file_path,
        start_line: f.source_span.start_line,
        start_col: f.source_span.start_col,
        end_line: f.source_span.end_line,
        end_col: f.source_span.end_col,
        symbol_hint: f.source_span.symbol_hint,
      })),
      input_hashes: syntaxResult.file_facts.map(f => f.file_type.magic_signature || 'hash'),
      rule_id: 'STATIC_ANALYSIS_COMPREHENSIVE',
      ruleset_version: STATIC_RULESET_VERSION,
      transformation_type: 'DIRECT_EXTRACTION',
      confidence: 0.98,
      derived_at: new Date().toISOString(),
      engine_signature: `${this.ENGINE_KEY}@${this.ENGINE_VERSION}`,
    };

    return {
      artifact_id: input.artifactId,
      stage_run: stageRun,
      file_selection: fileSelection,
      symbol_graph: symbolGraph,
      call_graph: callGraph,
      cfgs,
      findings,
      taint_report: taintReport,
      coverage,
      summary_stats: summaryStats,
      provenance,
    };
  }
}
