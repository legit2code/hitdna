/**
 * Sandbox Orchestration Engine (P19)
 * Coordinates sandbox provisioning, canary injection, isolated command execution,
 * telemetry ingestion, evasion analysis, and guaranteed teardown.
 */

import { 
  SandboxScenario, 
  DynamicSandboxRunResult, 
  ResourceQuota, 
  NetworkPolicy, 
  NonfunctionalCanary, 
  SandboxProviderType, 
  RuntimeEvent,
  TeardownSummary 
} from './types.ts';
import { ISandboxProvider } from './providers/sandbox-provider.interface.ts';
import { SimulatedSandboxProvider } from './providers/simulated-provider.ts';
import { E2BSandboxProvider, SandboxProviderUnavailableError } from './providers/e2b-provider.ts';
import { ScenarioRegistry } from './scenarios/registry.ts';
import { SecretSanitizer } from './security/secret-sanitizer.ts';
import { CanaryGenerator } from './security/canary-generator.ts';
import { EvasionDetector } from './evasion/detector.ts';
import { SandboxLifecycleManager } from './lifecycle/manager.ts';

export interface RunSandboxScenarioOptions {
  scenarioId?: string;
  scenario?: SandboxScenario;
  providerType?: SandboxProviderType;
  artifactId?: string;
  files?: Record<string, string>;
  envVars?: Record<string, string>;
  resourceLimits?: Partial<ResourceQuota>;
  networkPolicy?: NetworkPolicy;
  requireRealSandbox?: boolean;
}

export class SandboxOrchestrationEngine {
  public static readonly DEFAULT_RESOURCE_QUOTA: ResourceQuota = {
    maxDurationMs: 30000,
    maxMemoryMb: 512,
    maxCpuPercentage: 50,
    maxProcessCount: 10,
    maxOutputSizeBytes: 1048576, // 1MB
  };

  /**
   * Runs a complete dynamic sandbox scenario with strict isolation and guaranteed teardown.
   */
  public static async runScenario(options: RunSandboxScenarioOptions): Promise<DynamicSandboxRunResult> {
    const runId = `run-dyn-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const startedAt = new Date().toISOString();
    const startTime = Date.now();

    // 1. Resolve Scenario
    let scenario: SandboxScenario;
    if (options.scenario) {
      scenario = options.scenario;
    } else if (options.scenarioId) {
      const found = ScenarioRegistry.getScenario(options.scenarioId);
      if (!found) {
        throw new Error(`Scenario ${options.scenarioId} not found in ScenarioRegistry.`);
      }
      scenario = found;
    } else {
      scenario = ScenarioRegistry.getScenario('SCN-BENIGN-01')!;
    }

    // 2. Resolve Provider: Explicit providerType is strictly required; dynamic runs cannot default to simulation
    if (!options.providerType) {
      throw new SandboxProviderUnavailableError(
        "Explicit providerType ('E2B' or 'SIMULATED') is required. Dynamic sandbox runs cannot default to simulation."
      );
    }
    const providerType: SandboxProviderType = options.providerType;
    const provider: ISandboxProvider = providerType === 'E2B' ? new E2BSandboxProvider() : new SimulatedSandboxProvider();

    // 3. Resolve Policies and Quotas
    const resourceQuota: ResourceQuota = {
      ...this.DEFAULT_RESOURCE_QUOTA,
      ...(scenario.resourceLimits || {}),
      ...(options.resourceLimits || {}),
    };

    const networkPolicy: NetworkPolicy = options.networkPolicy || scenario.networkPolicy;

    // 4. Strict Sanitization: Scrub real platform secrets from payload
    const rawFiles = { ...(scenario.inputs.files || {}), ...(options.files || {}) };
    const rawEnv = { ...(scenario.inputs.envVars || {}), ...(options.envVars || {}) };

    const sanitizedFilesRes = SecretSanitizer.sanitizeFilePayload(rawFiles);
    const sanitizedEnvRes = SecretSanitizer.sanitizeEnvVars(rawEnv);

    const sanitizationAudit = {
      forbidden_secrets_found_in_payload: sanitizedFilesRes.report.sanitizedCount + sanitizedEnvRes.report.sanitizedCount,
      sanitized: true,
    };

    // 5. Generate and configure synthetic non-functional canaries
    const canaries: NonfunctionalCanary[] = [];
    if (scenario.canaryConfigs && scenario.canaryConfigs.length > 0) {
      for (const cfg of scenario.canaryConfigs) {
        canaries.push(CanaryGenerator.generateCanary(cfg.name, cfg.type, cfg.target_key_name, cfg.location));
      }
    } else if (scenario.category === 'CANARY_PROBE') {
      canaries.push(...CanaryGenerator.generateStandardCanarySuite());
    }

    const sessionId = `sbx-sess-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    const rawTraces: string[] = [];
    let runtimeEvents: RuntimeEvent[] = [];
    let status: DynamicSandboxRunResult['status'] = 'PASSED';
    let providerUnavailableError: Error | null = null;
    let teardownSummary: TeardownSummary | undefined;

    // 6. Provision and Execute within Guaranteed Lifecycle Block
    try {
      // Register with Lifecycle Manager for teardown protection
      SandboxLifecycleManager.registerSession(sessionId, provider, scenario.id);

      await provider.provision({
        sessionId,
        scenarioId: scenario.id,
        scenarioVersion: scenario.version,
        resourceQuota,
        networkPolicy,
        canaries,
        envVars: sanitizedEnvRes.sanitized,
        files: sanitizedFilesRes.sanitized,
        requireRealSandbox: options.requireRealSandbox,
      });

      // Execute scenario files/commands
      for (const [filePath, content] of Object.entries(sanitizedFilesRes.sanitized)) {
        rawTraces.push(`[FS_TRANSFER] Wrote ${filePath} (${content.length} bytes)`);
      }

      const filesToExecute = sanitizedFilesRes.sanitized['runner.js']
        ? ['runner.js']
        : Object.keys(sanitizedFilesRes.sanitized).filter(f => f.endsWith('.js') || f.endsWith('.ts'));

      for (const filePath of filesToExecute) {
        const content = sanitizedFilesRes.sanitized[filePath];
        const cmd = `node ${filePath}`;
        rawTraces.push(`[EXEC_COMMAND] ${cmd} :: Content: ${content}`);
        
        const execRes = await provider.executeCommand(sessionId, {
          command: 'node',
          args: [filePath],
          cwd: '/app',
          timeoutMs: resourceQuota.maxDurationMs,
        });

        rawTraces.push(`[EXEC_STDOUT] ${execRes.stdout}`);
        if (execRes.stderr) {
          rawTraces.push(`[EXEC_STDERR] ${execRes.stderr}`);
        }

        if (execRes.exitCode !== 0 && !scenario.expectedBehaviors.allowedExitCodes?.includes(execRes.exitCode)) {
          status = 'FAILED';
        }
      }

      // Collect all events generated in the sandbox
      runtimeEvents = await provider.collectRuntimeEvents(sessionId);

    } catch (err: any) {
      if (err?.name === 'SandboxProviderUnavailableError' || err?.message?.includes('PROVIDER_UNAVAILABLE')) {
        providerUnavailableError = err;
        status = 'PROVIDER_UNAVAILABLE';
        rawTraces.push(`[PROVIDER_ERROR] ${err.message}`);
      } else {
        throw err;
      }
    } finally {
      // Guaranteed teardown
      teardownSummary = await SandboxLifecycleManager.teardownSession(sessionId);
    }

    const completedAt = new Date().toISOString();
    const durationMs = Date.now() - startTime;

    // 7. Check Canaries Tripped
    const canariesTripped = canaries.filter(c => c.tripped);
    if (canariesTripped.length > 0 && scenario.category !== 'CANARY_PROBE' && status !== 'PROVIDER_UNAVAILABLE') {
      status = 'VIOLATION_DETECTED';
    }

    // 8. Evasion Detection Analysis
    const evasionAnalysis = EvasionDetector.analyze(runtimeEvents, rawTraces);
    if (evasionAnalysis.evasionRiskScore >= 0.70 && status !== 'PROVIDER_UNAVAILABLE') {
      status = 'EVASION_FLAGGED';
    }

    // 9. Formulate Behavior Sequences
    const behaviorSequences = [
      {
        phase: 'PROVISIONING',
        events: runtimeEvents.filter(e => e.action.includes('PROVISION')),
      },
      {
        phase: 'FILESYSTEM_TRANSFER',
        events: runtimeEvents.filter(e => e.category === 'FILESYSTEM'),
      },
      {
        phase: 'EXECUTION',
        events: runtimeEvents.filter(e => e.category === 'PROCESS' || e.category === 'TOOL'),
      },
      {
        phase: 'EGRESS_CANARY_MONITORING',
        events: runtimeEvents.filter(e => e.category === 'NETWORK' || e.category === 'CANARY' || e.category === 'SECURITY'),
      },
    ];

    // Extract execution details directly from provider to guarantee truthfulness
    const execDetails = typeof (provider as any).getSessionExecutionDetails === 'function'
      ? (provider as any).getSessionExecutionDetails(sessionId)
      : {
          isReal: providerType !== 'SIMULATED',
          actualProvider: providerType,
          executionMode: providerType === 'SIMULATED' ? 'SIMULATED' : 'LIVE',
        };

    const requestedProvider = providerType;
    let actualProvider: SandboxProviderType | 'NONE';
    let executionMode: DynamicSandboxRunResult['execution_mode'];
    let truthState: DynamicSandboxRunResult['truth_state'];

    if (status === 'PROVIDER_UNAVAILABLE' || execDetails.executionMode === 'PROVIDER_UNAVAILABLE') {
      actualProvider = 'NONE';
      executionMode = 'PROVIDER_UNAVAILABLE';
      truthState = 'UNKNOWN';
      status = 'PROVIDER_UNAVAILABLE';
    } else {
      actualProvider = execDetails.actualProvider || (execDetails.isReal ? 'E2B' : 'SIMULATED');
      executionMode = status === 'FAILED' && !execDetails.isReal && execDetails.executionMode === 'FAILED'
        ? 'FAILED'
        : (execDetails.executionMode || (actualProvider === 'SIMULATED' ? 'SIMULATED' : 'LIVE'));
      truthState = actualProvider === 'SIMULATED' ? 'SIMULATED' : 'OBSERVED';
    }

    const fallbackReason = providerUnavailableError?.message || execDetails.fallbackReason;

    return {
      run_id: runId,
      artifact_id: options.artifactId || 'art-default-test',
      scenario_id: scenario.id,
      scenario_version: scenario.version,
      provider_type: (actualProvider === 'NONE' ? 'E2B' : actualProvider) as SandboxProviderType,
      requested_provider: requestedProvider,
      actual_provider: actualProvider,
      execution_mode: executionMode,
      truth_state: truthState,
      sandbox_id: execDetails.sandboxId,
      ...(fallbackReason ? { fallback_reason: fallbackReason } : {}),
      session_id: sessionId,
      started_at: startedAt,
      completed_at: completedAt,
      duration_ms: durationMs,
      status,
      resource_quota: resourceQuota,
      network_policy: networkPolicy,
      canaries_injected: canaries,
      canaries_tripped: canariesTripped,
      sanitization_audit: sanitizationAudit,
      runtime_events: runtimeEvents,
      raw_traces: rawTraces,
      behavior_sequences: behaviorSequences,
      evasion_indicators: evasionAnalysis.indicators,
      evasion_risk_score: evasionAnalysis.evasionRiskScore,
      anti_analysis_detected: evasionAnalysis.antiAnalysisDetected,
      teardown: teardownSummary,
    };
  }
}
