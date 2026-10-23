/**
 * Static Analysis Engine Types & Interfaces
 * P15 — Static Analysis & Control Flow
 */

import { SourceSpan } from '@caim/syntax/types.ts';
import { SecurityClassification } from '@caim/contracts/enums.ts';
import { ProvenanceRecord } from '@caim/contracts/provenance.ts';
import { TaintAnalysisReport } from './taint/types.ts';

export const STATIC_ANALYSIS_ENGINE_VERSION = '1.0.0' as const;
export const STATIC_RULESET_VERSION = '1.0.0' as const;

export type StaticFindingCategory = 
  | 'NETWORK'
  | 'FILESYSTEM'
  | 'PROCESS_EXECUTION'
  | 'TOOL_DECLARATION'
  | 'CREDENTIAL_ACCESS'
  | 'CONTROL_FLOW_ANOMALY'
  | 'UNSUPPORTED_SYNTAX';

export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface AnalysisStageRun {
  stage_run_id: string;
  stage_name: 'STATIC_ANALYSIS';
  pipeline_run_id?: string;
  artifact_id: string;
  started_at: string;
  completed_at: string;
  status: 'COMPLETED' | 'FAILED' | 'PARTIAL';
  engine_key: string;
  engine_version: string;
  ruleset_version: string;
}

export interface CallGraphTraceNode {
  function_name: string;
  file_path: string;
  span?: SourceSpan;
  call_site?: string;
  step_number: number;
}

export interface StaticFinding {
  finding_id: string;
  rule_id: string;
  ruleset_version: string;
  category: StaticFindingCategory;
  severity: FindingSeverity;
  confidence: number;
  title: string;
  description: string;
  rationale: string;
  remediation_hint?: string;
  canonical_concept_key?: string;
  source_span: SourceSpan;
  stage_run: AnalysisStageRun;
  interprocedural_trace?: CallGraphTraceNode[];
  metadata?: Record<string, unknown>;
}

export interface SelectedFile {
  path: string;
  language: string;
  size_bytes: number;
  is_entrypoint: boolean;
  role: 'SOURCE' | 'CONFIG' | 'TEST' | 'RESOURCE' | 'UNKNOWN';
}

export interface ExcludedFile {
  path: string;
  reason: string;
}

export interface FileSelectionResult {
  included_files: SelectedFile[];
  excluded_files: ExcludedFile[];
  entrypoint_files: string[];
  total_files_evaluated: number;
  total_source_bytes: number;
}

export interface ModuleExport {
  name: string;
  kind: 'FUNCTION' | 'CLASS' | 'VARIABLE' | 'INTERFACE' | 'TYPE' | 'UNKNOWN';
  span?: SourceSpan;
  is_default: boolean;
}

export interface ModuleImport {
  module_specifier: string;
  resolved_path?: string;
  imported_symbols: string[];
  is_relative: boolean;
  span?: SourceSpan;
}

export interface CrossFileBinding {
  binding_id: string;
  from_file: string;
  from_symbol: string;
  to_file: string;
  to_symbol: string;
  is_resolved: boolean;
  confidence: number;
}

export interface SymbolImportGraph {
  modules: Record<string, {
    file_path: string;
    exports: ModuleExport[];
    imports: ModuleImport[];
    dependencies: string[];
  }>;
  cross_file_bindings: CrossFileBinding[];
  unresolved_imports: Array<{ from_file: string; specifier: string; span?: SourceSpan }>;
}

export interface CallGraphNode {
  node_id: string; // e.g. file_path:function_name
  file_path: string;
  function_name: string;
  is_entrypoint: boolean;
  is_exported: boolean;
  span?: SourceSpan;
  parameter_names: string[];
  call_count: number;
}

export interface CallGraphEdge {
  edge_id: string;
  caller_node_id: string;
  callee_node_id: string;
  callee_name: string;
  call_site_span?: SourceSpan;
  is_interprocedural: boolean;
  is_cross_file: boolean;
  call_type: 'DIRECT' | 'METHOD' | 'DYNAMIC' | 'CONSTRUCTOR';
}

export interface CallGraph {
  nodes: Record<string, CallGraphNode>;
  edges: CallGraphEdge[];
  entrypoints: string[];
  reachability_map: Record<string, string[]>; // node_id -> reachable node_ids
}

export type CfgBlockTerminatorKind = 
  | 'NORMAL'
  | 'BRANCH'
  | 'LOOP_HEADER'
  | 'LOOP_BACK'
  | 'RETURN'
  | 'THROW'
  | 'UNREACHABLE';

export interface CfgBasicBlock {
  block_id: string;
  label: string;
  statements: string[];
  start_line: number;
  end_line: number;
  predecessor_ids: string[];
  successor_ids: string[];
  terminator_kind: CfgBlockTerminatorKind;
  is_entry: boolean;
  is_exit: boolean;
  is_dead_code: boolean;
}

export interface ControlFlowGraph {
  cfg_id: string;
  file_path: string;
  function_name: string;
  cyclomatic_complexity: number;
  blocks: CfgBasicBlock[];
  has_unreachable_blocks: boolean;
  loop_count: number;
  exception_handlers_count: number;
  entry_block_id: string;
  exit_block_ids: string[];
}

export interface UnsupportedConstruct {
  file_path: string;
  construct: string;
  reason: string;
  span?: SourceSpan;
}

export interface CoverageReport {
  total_files: number;
  analyzed_files: number;
  total_lines: number;
  analyzed_lines: number;
  total_functions: number;
  cfg_covered_functions: number;
  coverage_percentage: number;
  unsupported_constructs: UnsupportedConstruct[];
}

export interface StaticAnalysisSummaryStats {
  total_findings: number;
  findings_by_severity: Record<FindingSeverity, number>;
  findings_by_category: Record<StaticFindingCategory, number>;
  network_calls: number;
  filesystem_calls: number;
  process_executions: number;
  tools_declared: number;
  credentials_detected: number;
  high_complexity_functions: number;
}

export interface StaticAnalysisReport {
  artifact_id: string;
  stage_run: AnalysisStageRun;
  file_selection: FileSelectionResult;
  symbol_graph: SymbolImportGraph;
  call_graph: CallGraph;
  cfgs: ControlFlowGraph[];
  findings: StaticFinding[];
  taint_report?: TaintAnalysisReport;
  coverage: CoverageReport;
  summary_stats: StaticAnalysisSummaryStats;
  provenance: ProvenanceRecord;
}

export interface StaticAnalysisJobInput {
  artifactId: string;
  files: Array<{ path: string; content: string }>;
  entrypoints?: string[];
  pipelineRunId?: string;
  customMetadata?: Record<string, unknown>;
}
