/**
 * CAIM Agent & Tooling Composer Engine Types
 * Logical Engine: E42 / Composer Capability
 * Reference: Architecture V2.0.1 Specification
 */

import { StaticAnalysisReport } from '../static-analysis/types.ts';
import { NetworkPolicy, SandboxProviderType, ExecutionMode } from '../sandbox-orchestrator/types.ts';

export type TechniqueCategory = 
  | 'DATA_EXTRACTION'
  | 'AGENT_ORCHESTRATION'
  | 'TOOL_SYNTHESIS'
  | 'API_INTEGRATION'
  | 'PROMPT_CHAINING'
  | 'SECURITY_VALIDATION'
  | 'REFACTORING';

export const ALL_TECHNIQUE_CATEGORIES: TechniqueCategory[] = [
  'DATA_EXTRACTION',
  'AGENT_ORCHESTRATION',
  'TOOL_SYNTHESIS',
  'API_INTEGRATION',
  'PROMPT_CHAINING',
  'SECURITY_VALIDATION',
  'REFACTORING',
];

export interface ComposerGenerationRequest {
  principal_id: string;
  technique_category: TechniqueCategory;
  prompt: string;
  target_name?: string;
  target_language?: 'typescript' | 'python' | 'json';
  parameters?: Record<string, any>;
  skip_static_analysis?: boolean;
}

export interface ComposerGenerationResponse {
  success: boolean;
  log_id: string;
  artifact_id?: string;
  target_name?: string;
  technique_category: TechniqueCategory;
  generated_code?: string;
  generated_files: Record<string, string>;
  source_agents_retrieved: string[];
  static_analysis?: StaticAnalysisReport | null;
  status: 'SUCCESS' | 'REFUSED' | 'FAILED';
  refusal_reason?: string;
  created_at: string;
}

export interface ComposerExecutionRequest {
  principal_id: string;
  artifact_id?: string;
  technique_category?: TechniqueCategory;
  files?: Record<string, string>;
  code?: string;
  synthetic_target_domain?: string;
  provider_type?: SandboxProviderType;
  input_payload?: Record<string, any>;
  target_port?: number;
}

export interface ComposerExecutionResponse {
  success: boolean;
  run_id: string;
  session_id: string;
  artifact_id: string;
  technique_category: TechniqueCategory;
  provider_type: SandboxProviderType | 'NONE';
  requested_provider?: SandboxProviderType;
  actual_provider?: SandboxProviderType | 'NONE';
  execution_mode?: ExecutionMode;
  fallback_reason?: string;
  synthetic_target: {
    domain: string;
    port: number;
    url: string;
    policy: NetworkPolicy;
  };
  network_policy_applied: NetworkPolicy;
  egress_evaluations: Array<{
    destination: string;
    allowed: boolean;
    reason: string;
  }>;
  runtime_events: any[];
  raw_traces: string[];
  execution_output?: any;
  status: 'COMPLETED' | 'VIOLATION_DETECTED' | 'REFUSED' | 'FAILED';
  refusal_reason?: string;
  started_at: string;
  completed_at: string;
  duration_ms: number;
}

export interface ComposerGenerationLogRecord {
  log_id: string;
  principal_id: string;
  technique_category: string;
  request_text: string;
  source_agents_retrieved: string[];
  generated_artifact_id?: string | null;
  static_analysis_result_summary?: Record<string, any> | null;
  status: 'SUCCESS' | 'REFUSED' | 'FAILED';
  refusal_reason?: string | null;
  created_at: string;
}

