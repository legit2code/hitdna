/**
 * P19 — Dynamic Sandbox, Scenarios, Telemetry & Evasion Types
 * Architecture V2.0.1 - Strict Isolation & Threat Model
 */

import { z } from 'zod';

export type SandboxProviderType = 'E2B' | 'SIMULATED' | 'DOCKER_ISOLATED';

export type SandboxSessionStatus = 
  | 'PENDING'
  | 'PROVISIONING'
  | 'RUNNING'
  | 'TERMINATING'
  | 'TERMINATED'
  | 'TIMEOUT_KILLED'
  | 'ERROR_KILLED'
  | 'FORCE_CLEANED'
  | 'TERMINATION_FAILED'
  | 'STATE_UNKNOWN';

export type NetworkPolicyType = 'DEFAULT_DENY' | 'WHITELIST_ONLY' | 'MONITORED_OPEN';

export interface ResourceQuota {
  maxDurationMs: number;
  maxMemoryMb: number;
  maxCpuPercentage: number;
  maxProcessCount: number;
  maxOutputSizeBytes: number;
}

export interface NetworkPolicy {
  type: NetworkPolicyType;
  allowedDomains: string[];
  allowedPorts: number[];
  allowDns: boolean;
  interceptEgress: boolean;
}

export interface NonfunctionalCanary {
  canary_id: string;
  name: string;
  type: 'API_KEY' | 'AWS_SECRET' | 'DB_CONNECTION' | 'JWT_TOKEN' | 'PASSWORD';
  synthetic_value: string;
  location: 'ENV_VAR' | 'FILESYSTEM' | 'MEMORY' | 'CANARY_FILE';
  target_key_name: string;
  tripped: boolean;
  tripped_at?: string;
  tripped_by_action?: string;
}

export type RuntimeEventCategory = 
  | 'PROCESS'
  | 'NETWORK'
  | 'FILESYSTEM'
  | 'TOOL'
  | 'ENVIRONMENT'
  | 'CANARY'
  | 'SECURITY';

export type RuntimeEventSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface RuntimeEvent {
  event_id: string;
  timestamp: string;
  scenario_id: string;
  scenario_version: string;
  category: RuntimeEventCategory;
  action: string;
  target: string;
  status: 'ALLOWED' | 'BLOCKED' | 'LOGGED' | 'FLAGGED';
  severity: RuntimeEventSeverity;
  metadata: Record<string, any>;
}

export interface EvasionIndicator {
  indicator_id: string;
  type: 
    | 'DELAYED_ACTIVATION'
    | 'ENVIRONMENT_FINGERPRINTING'
    | 'CODE_OBFUSCATION'
    | 'CONDITIONAL_ACTIVATION'
    | 'ANTI_ANALYSIS_TAMPERING';
  name: string;
  detected: boolean;
  confidence: number; // 0.0 - 1.0
  description: string;
  evidence: Array<{
    event_id?: string;
    timestamp: string;
    detail: string;
  }>;
}

export type ScenarioCategory = 
  | 'BENIGN'
  | 'MALFORMED_INPUT'
  | 'PROMPT_INJECTION'
  | 'PERMISSION_BOUNDARY'
  | 'CANARY_PROBE'
  | 'NETWORK_RESTRICTION'
  | 'PERSISTENCE'
  | 'SANDBOX_AWARENESS';

export interface SandboxScenario {
  id: string;
  name: string;
  version: string;
  category: ScenarioCategory;
  description: string;
  inputs: {
    prompt?: string;
    payload?: any;
    files?: Record<string, string>;
    envVars?: Record<string, string>;
  };
  networkPolicy: NetworkPolicy;
  resourceLimits: Partial<ResourceQuota>;
  canaryConfigs?: Array<{
    name: string;
    type: NonfunctionalCanary['type'];
    target_key_name: string;
    location: NonfunctionalCanary['location'];
  }>;
  expectedBehaviors: {
    shouldBlockNetwork?: boolean;
    shouldTripCanary?: boolean;
    shouldTriggerEvasion?: boolean;
    expectedEvasionTypes?: Array<EvasionIndicator['type']>;
    allowedExitCodes?: number[];
  };
}

export interface SandboxCommand {
  command: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
}

export const RESOURCE_TELEMETRY_UNAVAILABLE = 'RESOURCE_TELEMETRY_UNAVAILABLE' as const;
export type ResourceMetricValue = number | typeof RESOURCE_TELEMETRY_UNAVAILABLE;

export interface SandboxExecutionResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
  resourcePeak: {
    memoryMb: ResourceMetricValue;
    cpuPercentage: ResourceMetricValue;
    processCount: ResourceMetricValue;
  };
}

export interface TeardownSummary {
  session_id: string;
  final_status: SandboxSessionStatus;
  started_at: string;
  destroyed_at: string;
  duration_ms: number;
  resources_released: boolean;
  processes_killed: number;
  ephemeral_files_cleaned: boolean;
  guaranteed_clean: boolean;
}

export type ExecutionMode = 
  | 'REAL_EXECUTION' 
  | 'SIMULATED_EXECUTION' 
  | 'NOT_EXECUTED' 
  | 'PROVIDER_UNAVAILABLE'
  | 'LIVE' 
  | 'SIMULATED' 
  | 'FAILED';

export type DynamicSandboxStatus = 
  | 'PASSED' 
  | 'FAILED' 
  | 'VIOLATION_DETECTED' 
  | 'EVASION_FLAGGED'
  | 'PROVIDER_UNAVAILABLE'
  | 'NOT_EXECUTED';

export interface DynamicSandboxRunResult {
  run_id: string;
  artifact_id?: string;
  scenario_id: string;
  scenario_version: string;
  provider_type: SandboxProviderType;
  requested_provider: SandboxProviderType;
  actual_provider: SandboxProviderType | 'NONE';
  execution_mode: ExecutionMode;
  fallback_reason?: string;
  session_id: string;
  sandbox_id?: string;
  truth_state?: 'OBSERVED' | 'SIMULATED' | 'STATICALLY_DERIVED' | 'UNKNOWN';
  started_at: string;
  completed_at: string;
  duration_ms: number;
  status: DynamicSandboxStatus;
  
  // Policies and controls
  resource_quota: ResourceQuota;
  network_policy: NetworkPolicy;
  
  // Canaries & Sanitization
  canaries_injected: NonfunctionalCanary[];
  canaries_tripped: NonfunctionalCanary[];
  sanitization_audit: {
    forbidden_secrets_found_in_payload: number;
    sanitized: boolean;
  };

  // Telemetry & Behavior
  runtime_events: RuntimeEvent[];
  raw_traces: string[];
  behavior_sequences: Array<{
    phase: string;
    events: RuntimeEvent[];
  }>;

  // Evasion & Anti-Analysis
  evasion_indicators: EvasionIndicator[];
  evasion_risk_score: number; // 0.0 to 1.0
  anti_analysis_detected: boolean;

  // Teardown
  teardown: TeardownSummary;
}
