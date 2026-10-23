/**
 * Dataflow & Taint Intelligence Types & Interfaces
 * P16 — Dataflow / Taint Intelligence
 */

import { SourceSpan } from '@caim/syntax/types.ts';
import { EpistemicState, EvidenceClass, EvidenceType, UncertaintyFactor } from '@caim/contracts/enums.ts';

export const TAINT_ENGINE_VERSION = '1.0.0' as const;
export const TAINT_SOURCE_REGISTRY_VERSION = '1.0.0' as const;
export const TAINT_SINK_REGISTRY_VERSION = '1.0.0' as const;
export const TAINT_SANITIZER_REGISTRY_VERSION = '1.0.0' as const;

export type TaintSourceCategory = 
  | 'CREDENTIAL_SECRET'
  | 'ENVIRONMENT_SECRET'
  | 'FILESYSTEM_READ'
  | 'NETWORK_RESPONSE'
  | 'USER_INPUT'
  | 'TOOL_ARGUMENT'
  | 'DATABASE_READ';

export type TaintSinkCategory = 
  | 'NETWORK_EGRESS'
  | 'PROCESS_EXECUTION'
  | 'FILESYSTEM_WRITE'
  | 'FILESYSTEM_DELETE'
  | 'TOOL_INVOCATION'
  | 'DYNAMIC_CODE_EVAL'
  | 'LOGGING_OUTPUT'
  | 'DATABASE_QUERY';

export type TaintSanitizerCategory = 
  | 'CRYPTOGRAPHIC_HASH'
  | 'ENCRYPTION'
  | 'REDACTION_MASK'
  | 'URL_ENCODING'
  | 'TYPE_CAST_BOOLEAN'
  | 'VALIDATION_CHECK'
  | 'NUMERIC_PARSE';

export type TaintPathStatus = 
  | 'ACTIVE'          // Active unsanitized flow reaching reachable sink
  | 'SANITIZED'       // Taint neutralized by recognized sanitizer/transform
  | 'UNREACHABLE'     // Path or sink resides in dead code / unreachable branch
  | 'INDETERMINATE';   // Flow involves unresolved dynamic dispatch / reflection

export interface TaintSourceDefinition {
  source_id: string;
  category: TaintSourceCategory;
  name: string;
  description: string;
  pattern_type: 'IDENTIFIER' | 'MEMBER_ACCESS' | 'FUNCTION_CALL' | 'LITERAL_REGEX';
  match_identifiers?: string[];
  match_patterns?: RegExp[];
  match_member_roots?: string[];
  match_functions?: string[];
  base_confidence: number;
  sensitivity_level: 'HIGH' | 'CRITICAL' | 'MEDIUM';
}

export interface TaintSinkDefinition {
  sink_id: string;
  category: TaintSinkCategory;
  name: string;
  description: string;
  pattern_type: 'FUNCTION_CALL' | 'MEMBER_ACCESS' | 'CONSTRUCTOR';
  match_functions?: string[];
  match_member_methods?: string[];
  tainted_arg_indices?: number[]; // indices of arguments that represent vulnerable sinks (default: all)
  base_confidence: number;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  caim_capability_key?: string;
}

export interface TaintSanitizerDefinition {
  sanitizer_id: string;
  category: TaintSanitizerCategory;
  name: string;
  description: string;
  pattern_type: 'FUNCTION_CALL' | 'MEMBER_METHOD' | 'TYPE_GUARD';
  match_functions?: string[];
  match_methods?: string[];
  match_patterns?: RegExp[];
  neutralization_power: number; // 0.0 - 1.0 (1.0 = completely neutralizes sensitive payload)
}

export interface TaintSourceInstance {
  source_id: string;
  category: TaintSourceCategory;
  variable_name?: string;
  file_path: string;
  span: SourceSpan;
  expression_text: string;
  confidence: number;
  epistemic_state: EpistemicState;
}

export interface TaintSinkInstance {
  sink_id: string;
  category: TaintSinkCategory;
  callee_name: string;
  file_path: string;
  span: SourceSpan;
  call_expression_text: string;
  tainted_argument_name?: string;
  confidence: number;
  epistemic_state: EpistemicState;
}

export interface TaintSanitizerInstance {
  sanitizer_id: string;
  category: TaintSanitizerCategory;
  transformer_name: string;
  file_path: string;
  span: SourceSpan;
  expression_text: string;
  neutralization_power: number;
}

export interface TaintHop {
  hop_number: number;
  hop_type: 
    | 'SOURCE_ORIGIN'
    | 'VARIABLE_ASSIGNMENT'
    | 'BINARY_EXPRESSION'
    | 'TEMPLATE_LITERAL'
    | 'OBJECT_PROPERTY'
    | 'PARAMETER_PASSING'
    | 'FUNCTION_RETURN'
    | 'CROSS_FILE_IMPORT'
    | 'SANITIZER_TRANSFORM'
    | 'DYNAMIC_DISPATCH'
    | 'SINK_INVOCATION';
  file_path: string;
  function_name?: string;
  from_symbol?: string;
  to_symbol?: string;
  expression_snippet: string;
  span: SourceSpan;
  is_interprocedural: boolean;
  is_cross_file: boolean;
  is_dynamic: boolean;
}

export interface TaintPathEvidence {
  evidence_id: string;
  evidence_type: EvidenceType;
  evidence_class: EvidenceClass;
  description: string;
  confidence: number;
  epistemic_state: EpistemicState;
  uncertainty_factors: UncertaintyFactor[];
  source_span: SourceSpan;
  sink_span: SourceSpan;
  lineage_chain: string[];
}

export interface TaintFlowPath {
  path_id: string;
  source: TaintSourceInstance;
  sink: TaintSinkInstance;
  status: TaintPathStatus;
  sanitizer?: TaintSanitizerInstance;
  hops: TaintHop[];
  confidence: number;
  is_interprocedural: boolean;
  is_cross_file: boolean;
  is_reachable: boolean;
  unresolved_dispatch_count: number;
  evidence: TaintPathEvidence;
  epistemic_label: 'INFERRED_TAINT_FLOW';
  flow_classification: 
    | 'POTENTIAL_SECRET_EGRESS'
    | 'POTENTIAL_COMMAND_INJECTION'
    | 'POTENTIAL_FILE_EXFILTRATION'
    | 'POTENTIAL_TOOL_DATAFLOW'
    | 'SANITIZED_DATAFLOW'
    | 'DEAD_CODE_DATAFLOW'
    | 'INDETERMINATE_DATAFLOW';
  description: string; // Explicitly avoids calling it confirmed exfiltration
}

export interface TaintAnalysisSummaryStats {
  total_sources_detected: number;
  total_sinks_detected: number;
  total_paths_identified: number;
  active_vulnerable_paths: number;
  sanitized_paths: number;
  unreachable_paths: number;
  indeterminate_paths: number;
  interprocedural_paths: number;
  cross_file_paths: number;
  paths_by_source_category: Record<TaintSourceCategory, number>;
  paths_by_sink_category: Record<TaintSinkCategory, number>;
}

export interface TaintAnalysisReport {
  artifact_id: string;
  engine_version: string;
  ruleset_version: string;
  source_registry_version: string;
  sink_registry_version: string;
  sanitizer_registry_version: string;
  sources: TaintSourceInstance[];
  sinks: TaintSinkInstance[];
  sanitizers: TaintSanitizerInstance[];
  paths: TaintFlowPath[];
  summary: TaintAnalysisSummaryStats;
  analyzed_at: string;
}
