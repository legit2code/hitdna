import { z } from 'zod';

/**
 * Analysis Truth States & Completion Models (Architecture V2.0.1 — P08)
 * 
 * Conceptually distinguishes:
 * - STATIC_COMPLETE / STATIC_FAILED / STATIC_NOT_RUN
 * - DYNAMIC_COMPLETE / DYNAMIC_NOT_VERIFIED / DYNAMIC_FAILED
 * - PARTIAL / COMPLETE / FAILED
 * 
 * Ensures that a successful static scan never causes CAIM to represent unavailable
 * dynamic analysis as completed verification.
 */

export const StaticAnalysisStateEnum = z.enum([
  'STATIC_COMPLETE',
  'STATIC_FAILED',
  'STATIC_NOT_RUN',
]);
export type StaticAnalysisState = z.infer<typeof StaticAnalysisStateEnum>;

export const DynamicAnalysisStateEnum = z.enum([
  'DYNAMIC_COMPLETE',
  'DYNAMIC_NOT_VERIFIED',
  'DYNAMIC_FAILED',
]);
export type DynamicAnalysisState = z.infer<typeof DynamicAnalysisStateEnum>;

export const OverallAnalysisStateEnum = z.enum([
  'COMPLETE',
  'PARTIAL',
  'FAILED',
]);
export type OverallAnalysisState = z.infer<typeof OverallAnalysisStateEnum>;

export interface ExecutionSummaryRecord {
  executed: string[];
  not_verified: string[];
  why?: string;
  static_only_conclusions: string[];
  evidence_classes_available: string[];
  evidence_classes_missing: string[];
  provider_status?: string;
  actual_provider?: string;
}

export interface AnalysisTruthStateResolution {
  static_status: StaticAnalysisState;
  dynamic_status: DynamicAnalysisState;
  overall_status: OverallAnalysisState;
  analysis_run_status: 'COMPLETED' | 'PARTIAL' | 'FAILED' | 'PENDING' | 'RUNNING';
  truth_state: 'OBSERVED' | 'STATICALLY_DERIVED' | 'UNKNOWN';
  executed: string[];
  not_verified: string[];
  why?: string;
  static_only_conclusions: string[];
  evidence_classes_available: string[];
  evidence_classes_missing: string[];
  provider_status?: string;
  actual_provider?: string;
  execution_summary: ExecutionSummaryRecord;
}

export interface ResolveAnalysisTruthStateInput {
  staticReport?: {
    findings?: any[];
    errors?: any[];
    [key: string]: any;
  } | null;
  staticError?: Error | null;
  dynamicRunResult?: {
    status?: string;
    execution_mode?: string;
    actual_provider?: string;
    fallback_reason?: string;
    failure_reason?: string;
    execution_details?: {
      isReal?: boolean;
      actualProvider?: string;
      fallbackReason?: string;
      [key: string]: any;
    };
    [key: string]: any;
  } | null;
  dynamicError?: Error | null;
  isDynamicRequested?: boolean;
  dynamicProvider?: 'E2B' | 'DOCKER' | 'SIMULATED' | string;
}

/**
 * Resolves the precise, uncompromised analysis truth state.
 * Prevents static analysis success from masquerading as dynamic verification completion.
 */
export function resolveAnalysisTruthState(
  input: ResolveAnalysisTruthStateInput
): AnalysisTruthStateResolution {
  // 1. Evaluate Static Analysis State
  let static_status: StaticAnalysisState = 'STATIC_NOT_RUN';
  if (input.staticError) {
    static_status = 'STATIC_FAILED';
  } else if (input.staticReport) {
    static_status = 'STATIC_COMPLETE';
  }

  // 2. Evaluate Dynamic Analysis State
  let dynamic_status: DynamicAnalysisState = 'DYNAMIC_NOT_VERIFIED';
  let dynamicWhy: string | undefined = undefined;
  let providerStatus: string = 'NOT_REQUESTED';
  let actualProvider: string = 'NONE';

  const isE2BRequested = input.dynamicProvider === 'E2B' || !input.dynamicProvider;

  if (!input.isDynamicRequested) {
    dynamic_status = 'DYNAMIC_NOT_VERIFIED';
    dynamicWhy = 'Dynamic sandbox execution was not requested for this analysis run.';
    providerStatus = 'NOT_REQUESTED';
    actualProvider = 'NONE';
  } else if (input.dynamicError) {
    dynamic_status = 'DYNAMIC_FAILED';
    dynamicWhy = input.dynamicError.message || 'Dynamic sandbox execution encountered an unhandled error.';
    providerStatus = 'FAILED';
    actualProvider = input.dynamicRunResult?.actual_provider || 'NONE';
  } else if (input.dynamicRunResult) {
    actualProvider = input.dynamicRunResult.actual_provider ||
      input.dynamicRunResult.execution_details?.actualProvider ||
      input.dynamicRunResult.provider_type ||
      'NONE';

    // Anti-spoofing integrity gate: strictly reject any attempt to promote SIMULATED execution to OBSERVED truth state
    if (
      (actualProvider === 'SIMULATED' || input.dynamicRunResult.provider_type === 'SIMULATED' || input.dynamicRunResult.execution_mode === 'SIMULATED') &&
      (input.dynamicRunResult.truth_state === 'OBSERVED' || (input.dynamicRunResult as any).truthState === 'OBSERVED')
    ) {
      throw new Error("Invalid truth state transition: Cannot promote SIMULATED execution to OBSERVED truth state.");
    }
    const isProviderUnavailable =
      input.dynamicRunResult.status === 'PROVIDER_UNAVAILABLE' ||
      input.dynamicRunResult.execution_mode === 'PROVIDER_UNAVAILABLE' ||
      input.dynamicRunResult.execution_details?.isReal === false ||
      input.dynamicRunResult.provider_type === 'SIMULATED' ||
      actualProvider === 'NONE' ||
      actualProvider === 'SIMULATED' ||
      (isE2BRequested && actualProvider !== 'E2B');

    if (input.dynamicRunResult.status === 'FAILED') {
      dynamic_status = 'DYNAMIC_FAILED';
      dynamicWhy = input.dynamicRunResult.failure_reason || 'Dynamic sandbox execution failed.';
      providerStatus = 'FAILED';
    } else if (isProviderUnavailable) {
      dynamic_status = 'DYNAMIC_NOT_VERIFIED';
      providerStatus = 'PROVIDER_UNAVAILABLE';
      dynamicWhy =
        input.dynamicRunResult.fallback_reason ||
        input.dynamicRunResult.execution_details?.fallbackReason ||
        'E2B dynamic sandbox provider is unavailable (E2B_API_KEY is not configured or remote microVM could not be provisioned). Dynamic execution was not verified in live sandbox.';
    } else if (
      (input.dynamicRunResult.status === 'COMPLETED' || input.dynamicRunResult.status === 'SUCCESS' || !input.dynamicRunResult.status) &&
      (input.dynamicRunResult.execution_details?.isReal === true || actualProvider === 'E2B')
    ) {
      dynamic_status = 'DYNAMIC_COMPLETE';
      providerStatus = 'AVAILABLE';
      actualProvider = 'E2B';
    } else {
      dynamic_status = 'DYNAMIC_NOT_VERIFIED';
      providerStatus = 'UNVERIFIED';
      dynamicWhy = 'Dynamic execution did not complete verified live sandbox runtime.';
    }
  } else {
    // Dynamic was requested but no result or error returned (e.g. provider skipped)
    dynamic_status = 'DYNAMIC_NOT_VERIFIED';
    providerStatus = 'PROVIDER_UNAVAILABLE';
    dynamicWhy = 'Dynamic sandbox provider was unavailable to execute the requested run.';
  }

  // 3. Evaluate Overall Analysis State
  let overall_status: OverallAnalysisState = 'FAILED';
  let analysis_run_status: 'COMPLETED' | 'PARTIAL' | 'FAILED' = 'FAILED';
  let truth_state: 'OBSERVED' | 'STATICALLY_DERIVED' | 'UNKNOWN' = 'UNKNOWN';

  if (static_status === 'STATIC_COMPLETE' && dynamic_status === 'DYNAMIC_COMPLETE') {
    overall_status = 'COMPLETE';
    analysis_run_status = 'COMPLETED';
    truth_state = 'OBSERVED';
  } else if (static_status === 'STATIC_COMPLETE' && (dynamic_status === 'DYNAMIC_NOT_VERIFIED' || dynamic_status === 'DYNAMIC_FAILED')) {
    overall_status = 'PARTIAL';
    analysis_run_status = 'PARTIAL';
    truth_state = 'STATICALLY_DERIVED';
  } else if (static_status === 'STATIC_FAILED') {
    overall_status = 'FAILED';
    analysis_run_status = 'FAILED';
    truth_state = 'UNKNOWN';
  }

  // 4. Determine Executed Components
  const executed: string[] = [];
  if (static_status === 'STATIC_COMPLETE') {
    executed.push('Static AST Syntax Analysis (AST patterns & security rules)');
    executed.push('Static Taint & Source-to-Sink Dataflow Tracking');
    executed.push('Software Composition Analysis (SBOM & dependency manifest scan)');
    executed.push('Deterministic Risk & Scoring Suite (from available static evidence)');
  }
  if (dynamic_status === 'DYNAMIC_COMPLETE') {
    executed.push('E2B Isolated MicroVM Sandbox Execution');
    executed.push('Runtime Syscall, Process Lifecycle, and Filesystem Tracing');
    executed.push('Live Network Egress & Socket Connection Telemetry');
  }

  // 5. Determine Not Verified Components
  const not_verified: string[] = [];
  if (dynamic_status === 'DYNAMIC_NOT_VERIFIED' || dynamic_status === 'DYNAMIC_FAILED') {
    not_verified.push('Dynamic Sandbox Execution in Isolated MicroVM');
    not_verified.push('Live Network Egress Interception & Packet Capture');
    not_verified.push('Process Spawning, Execve Syscalls, and Filesystem Mutations');
    not_verified.push('Runtime Canary Token Probe Tripping');
    not_verified.push('Active Evasion Heuristics & Dormant Logic Verification');
  }

  // 6. Determine Static-Only Conclusions
  const static_only_conclusions: string[] = [];
  if (dynamic_status === 'DYNAMIC_NOT_VERIFIED' || dynamic_status === 'DYNAMIC_FAILED') {
    static_only_conclusions.push('Overall security score and risk band are derived solely from static AST & taint findings.');
    static_only_conclusions.push('Policy decision (ALLOW/WARN/BLOCK) was evaluated without live runtime verification.');
    static_only_conclusions.push('Absence of malicious network egress is inferred statically and was not verified via runtime telemetry.');
    static_only_conclusions.push('Vulnerability severity and exploitability have not been reproduced in an isolated sandbox.');
  }

  // 7. Evidence Classes
  const evidence_classes_available: string[] = [];
  const evidence_classes_missing: string[] = [];

  if (static_status === 'STATIC_COMPLETE') {
    evidence_classes_available.push('STATIC_CODE', 'STATIC_AST', 'STATIC_DEPENDENCY_MANIFEST', 'STATIC_CONFIG');
  }
  if (dynamic_status === 'DYNAMIC_COMPLETE') {
    evidence_classes_available.push(
      'DYNAMIC_RUNTIME',
      'DYNAMIC_EXECUTION_TRACE',
      'DYNAMIC_EGRESS_LOG',
      'RUNTIME_SYSCALL_TRACES',
      'NETWORK_EGRESS_CAPTURE'
    );
  } else {
    evidence_classes_missing.push(
      'DYNAMIC_RUNTIME',
      'DYNAMIC_EXECUTION_TRACE',
      'DYNAMIC_EGRESS_LOG',
      'RUNTIME_SYSCALL_TRACES',
      'NETWORK_EGRESS_CAPTURE'
    );
  }

  const execution_summary: ExecutionSummaryRecord = {
    executed,
    not_verified,
    why: dynamicWhy,
    static_only_conclusions,
    evidence_classes_available,
    evidence_classes_missing,
    provider_status: providerStatus,
    actual_provider: actualProvider,
  };

  return {
    static_status,
    dynamic_status,
    overall_status,
    analysis_run_status,
    truth_state,
    executed,
    not_verified,
    why: dynamicWhy,
    static_only_conclusions,
    evidence_classes_available,
    evidence_classes_missing,
    provider_status: providerStatus,
    actual_provider: actualProvider,
    execution_summary,
  };
}
