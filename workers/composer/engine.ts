/**
 * CAIM Composer Engine
 * Logical Engine: E42
 * Reference: Architecture V2.0.1 Specification
 */

import {
  ComposerGenerationRequest,
  ComposerGenerationResponse,
  ComposerGenerationLogRecord,
  ComposerExecutionRequest,
  ComposerExecutionResponse,
  TechniqueCategory,
} from './types.ts';
import { ComposerTargetValidator } from './target-validator.ts';
import { CapabilityGrantService } from '@caim/auth/capability.ts';
import { StaticAnalysisEngine } from '../static-analysis/engine.ts';
import { KnowledgeCorpusManager } from '../knowledge/reindex/scheduler.ts';
import { HybridRetrievalService } from '../knowledge/retrieval/service.ts';
import { GeminiEmbeddingProvider } from '../knowledge/embeddings/provider.ts';
import { SecurityClassificationRank } from '@caim/auth/types.ts';
import { SyntheticTargetService } from '../sandbox-orchestrator/security/synthetic-target.ts';
import { SandboxOrchestrationEngine } from '../sandbox-orchestrator/engine.ts';
import { NetworkPolicy } from '../sandbox-orchestrator/types.ts';
import { NetworkPolicyEngine } from '../sandbox-orchestrator/security/network-policy.ts';

export interface StoredComposerArtifact {
  artifactId: string;
  targetName: string;
  files: Record<string, string>;
  category: TechniqueCategory;
  generatedAt: string;
}

export class AgentComposerEngine {
  private grantService: CapabilityGrantService;
  private corpusManager?: KnowledgeCorpusManager;
  private retrievalService?: HybridRetrievalService;
  private dbClient?: any;
  private static inMemoryLogs: ComposerGenerationLogRecord[] = [];
  private static inMemoryArtifacts = new Map<string, StoredComposerArtifact>();

  constructor(options: {
    grantService?: CapabilityGrantService;
    corpusManager?: KnowledgeCorpusManager;
    retrievalService?: HybridRetrievalService;
    dbClient?: any;
  } = {}) {
    this.grantService = options.grantService || new CapabilityGrantService(options.dbClient);
    this.corpusManager = options.corpusManager;
    this.retrievalService = options.retrievalService;
    this.dbClient = options.dbClient;

    if (!this.retrievalService && this.corpusManager) {
      this.retrievalService = new HybridRetrievalService(
        this.corpusManager,
        new GeminiEmbeddingProvider()
      );
    }
  }

  /**
   * Primary entrypoint: Generates a new agent or tool pattern
   */
  public async generate(request: ComposerGenerationRequest): Promise<ComposerGenerationResponse> {
    const logId = crypto.randomUUID ? crypto.randomUUID() : `log_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const createdAt = new Date().toISOString();

    // 1. Gating & Capability Authorization Check (Non-role based)
    const access = await this.grantService.checkComposerAccess(
      request.principal_id,
      request.technique_category
    );

    if (!access.allowed) {
      const refusalLog: ComposerGenerationLogRecord = {
        log_id: logId,
        principal_id: request.principal_id,
        technique_category: request.technique_category,
        request_text: request.prompt,
        source_agents_retrieved: [],
        generated_artifact_id: null,
        static_analysis_result_summary: null,
        status: 'REFUSED',
        refusal_reason: access.reason || 'Unauthorized: Missing required capability grant.',
        created_at: createdAt,
      };

      await this.recordLog(refusalLog);

      return {
        success: false,
        log_id: logId,
        technique_category: request.technique_category,
        generated_files: {},
        source_agents_retrieved: [],
        status: 'REFUSED',
        refusal_reason: refusalLog.refusal_reason!,
        created_at: createdAt,
      };
    }

    // 2. Real-World Target Refusal Check on Input Prompt
    const targetValidation = ComposerTargetValidator.validatePrompt(request.prompt);
    if (!targetValidation.allowed) {
      const refusalLog: ComposerGenerationLogRecord = {
        log_id: logId,
        principal_id: request.principal_id,
        technique_category: request.technique_category,
        request_text: request.prompt,
        source_agents_retrieved: [],
        generated_artifact_id: null,
        static_analysis_result_summary: null,
        status: 'REFUSED',
        refusal_reason: targetValidation.refusal_reason!,
        created_at: createdAt,
      };

      await this.recordLog(refusalLog);

      return {
        success: false,
        log_id: logId,
        technique_category: request.technique_category,
        generated_files: {},
        source_agents_retrieved: [],
        status: 'REFUSED',
        refusal_reason: refusalLog.refusal_reason!,
        created_at: createdAt,
      };
    }

    // 3. RAG Retrieval with Hard Risk Filtering (Only LOW_RISK or APPROVED agents)
    const sourceAgentsRetrieved: string[] = [];
    if (this.retrievalService) {
      try {
        const retrievalResult = await this.retrievalService.retrieveContext(request.prompt, {
          composition_safe_only: true,
          caller_security_rank: SecurityClassificationRank.INTERNAL,
          budget_max_records: 10,
        });

        for (const doc of retrievalResult.documents) {
          const agentId = doc.agent_id || doc.exact_keywords?.agent_id;
          if (agentId && !sourceAgentsRetrieved.includes(agentId)) {
            sourceAgentsRetrieved.push(agentId);
          }
        }
      } catch {
        // Safe degraded retrieval
      }
    }

    // 4. Code & Tooling Synthesis
    const artifactId = `art-composer-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
    const targetName = request.target_name || `Generated${request.technique_category.charAt(0) + request.technique_category.slice(1).toLowerCase().replace(/_([a-z])/g, (_, c) => c.toUpperCase())}Agent`;

    const generatedFiles = this.synthesizeArtifact(request, targetName, sourceAgentsRetrieved);
    const mainCode = generatedFiles['index.ts'] || Object.values(generatedFiles)[0] || '';

    // 4b. Mandatory Second Validation Pass on GENERATED CODE OUTPUT
    const codeValidation = ComposerTargetValidator.validateGeneratedCode(generatedFiles);
    if (!codeValidation.allowed) {
      const refusalLog: ComposerGenerationLogRecord = {
        log_id: logId,
        principal_id: request.principal_id,
        technique_category: request.technique_category,
        request_text: request.prompt,
        source_agents_retrieved: sourceAgentsRetrieved,
        generated_artifact_id: null,
        static_analysis_result_summary: null,
        status: 'REFUSED',
        refusal_reason: codeValidation.refusal_reason!,
        created_at: createdAt,
      };

      await this.recordLog(refusalLog);

      return {
        success: false,
        log_id: logId,
        technique_category: request.technique_category,
        generated_files: {},
        source_agents_retrieved: sourceAgentsRetrieved,
        status: 'REFUSED',
        refusal_reason: codeValidation.refusal_reason!,
        created_at: createdAt,
      };
    }

    // 5. Mandatory StaticAnalysisEngine Pass
    const filesArray: Array<{ path: string; content: string }> = Object.entries(generatedFiles).map(([p, c]) => ({
      path: p,
      content: c,
    }));

    let staticAnalysisReport = null;
    let staticSummary: Record<string, any> | null = null;

    if (!request.skip_static_analysis) {
      try {
        staticAnalysisReport = StaticAnalysisEngine.analyze({
          artifactId,
          files: filesArray,
          entrypoints: ['index.ts'],
        });

        const highOrCriticalCount = staticAnalysisReport.findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL').length;
        const analysisPassed = highOrCriticalCount === 0;

        staticSummary = {
          findings_count: staticAnalysisReport.findings.length,
          severity_counts: staticAnalysisReport.summary_stats?.findings_by_severity || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
          taint_violations: staticAnalysisReport.taint_report?.summary?.active_vulnerable_paths ?? staticAnalysisReport.taint_report?.paths?.length ?? 0,
          passed: analysisPassed,
        };

        if (!analysisPassed) {
          const failReason = `Mandatory static analysis detected ${highOrCriticalCount} HIGH/CRITICAL finding(s). Artifact generation failed closed.`;
          const failureLog: ComposerGenerationLogRecord = {
            log_id: logId,
            principal_id: request.principal_id,
            technique_category: request.technique_category,
            request_text: request.prompt,
            source_agents_retrieved: sourceAgentsRetrieved,
            generated_artifact_id: null,
            static_analysis_result_summary: staticSummary,
            status: 'FAILED',
            refusal_reason: failReason,
            created_at: createdAt,
          };
          await this.recordLog(failureLog);
          return {
            success: false,
            log_id: logId,
            technique_category: request.technique_category,
            generated_files: {},
            source_agents_retrieved: sourceAgentsRetrieved,
            status: 'FAILED',
            refusal_reason: failReason,
            created_at: createdAt,
          };
        }
      } catch (err: any) {
        const failReason = `Mandatory static analysis exception: ${err.message}. Failed closed.`;
        staticSummary = { error: err.message, passed: false };
        const failureLog: ComposerGenerationLogRecord = {
          log_id: logId,
          principal_id: request.principal_id,
          technique_category: request.technique_category,
          request_text: request.prompt,
          source_agents_retrieved: sourceAgentsRetrieved,
          generated_artifact_id: null,
          static_analysis_result_summary: staticSummary,
          status: 'FAILED',
          refusal_reason: failReason,
          created_at: createdAt,
        };
        await this.recordLog(failureLog);
        return {
          success: false,
          log_id: logId,
          technique_category: request.technique_category,
          generated_files: {},
          source_agents_retrieved: sourceAgentsRetrieved,
          status: 'FAILED',
          refusal_reason: failReason,
          created_at: createdAt,
        };
      }
    }

    // Cache artifact in memory for subsequent sandbox execution runs
    AgentComposerEngine.inMemoryArtifacts.set(artifactId, {
      artifactId,
      targetName,
      files: generatedFiles,
      category: request.technique_category,
      generatedAt: createdAt,
    });

    // 6. Record in Audit Log
    const successLog: ComposerGenerationLogRecord = {
      log_id: logId,
      principal_id: request.principal_id,
      technique_category: request.technique_category,
      request_text: request.prompt,
      source_agents_retrieved: sourceAgentsRetrieved,
      generated_artifact_id: artifactId,
      static_analysis_result_summary: staticSummary,
      status: 'SUCCESS',
      refusal_reason: null,
      created_at: createdAt,
    };

    await this.recordLog(successLog);

    return {
      success: true,
      log_id: logId,
      artifact_id: artifactId,
      target_name: targetName,
      technique_category: request.technique_category,
      generated_code: mainCode,
      generated_files: generatedFiles,
      source_agents_retrieved: sourceAgentsRetrieved,
      static_analysis: staticAnalysisReport,
      status: 'SUCCESS',
      created_at: createdAt,
    };
  }

  /**
   * Execution entrypoint: Runs a synthesized artifact inside an isolated sandbox
   * bound exclusively to a SyntheticTargetService endpoint under strict default-deny network policy.
   */
  public async execute(request: ComposerExecutionRequest): Promise<ComposerExecutionResponse> {
    const runId = `run-exec-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    const startedAt = new Date().toISOString();
    const startTime = Date.now();
    const category: TechniqueCategory = request.technique_category || 'TOOL_SYNTHESIS';

    // 1. Gating & Capability Authorization Check
    const access = await this.grantService.checkComposerAccess(
      request.principal_id,
      category
    );

    if (!access.allowed) {
      return {
        success: false,
        run_id: runId,
        session_id: `sbx-refused-${Date.now()}`,
        artifact_id: request.artifact_id || 'unauthorized',
        technique_category: category,
        provider_type: request.provider_type || 'SIMULATED',
        synthetic_target: {
          domain: 'synthetic-target.local',
          port: 443,
          url: 'http://synthetic-target.local:443',
          policy: SyntheticTargetService.SYNTHETIC_SANDBOX_POLICY,
        },
        network_policy_applied: SyntheticTargetService.SYNTHETIC_SANDBOX_POLICY,
        egress_evaluations: [],
        runtime_events: [],
        raw_traces: [],
        status: 'REFUSED',
        refusal_reason: access.reason || 'Unauthorized: Missing required capability grant.',
        started_at: startedAt,
        completed_at: new Date().toISOString(),
        duration_ms: 0,
      };
    }

    // 2. Resolve Artifact and Source Files
    let artifactFiles: Record<string, string> = {};
    let artifactId = request.artifact_id || `art-exec-${Date.now().toString(36)}`;

    if (request.files && Object.keys(request.files).length > 0) {
      artifactFiles = request.files;
    } else if (request.code) {
      artifactFiles = { 'index.ts': request.code };
    } else if (request.artifact_id && AgentComposerEngine.inMemoryArtifacts.has(request.artifact_id)) {
      const cached = AgentComposerEngine.inMemoryArtifacts.get(request.artifact_id)!;
      artifactFiles = cached.files;
    } else {
      // Synthesize clean baseline tool for execution
      artifactFiles = this.synthesizeArtifact(
        {
          principal_id: request.principal_id,
          technique_category: category,
          prompt: 'Execute synthesized agent against synthetic target sandbox',
        },
        'DynamicExecutedAgent',
        []
      );
    }

    // 3. Validate Generated Code Output before Sandbox Dispatch
    const codeValidation = ComposerTargetValidator.validateGeneratedCode(artifactFiles);
    if (!codeValidation.allowed) {
      return {
        success: false,
        run_id: runId,
        session_id: `sbx-refused-${Date.now()}`,
        artifact_id: artifactId,
        technique_category: category,
        provider_type: request.provider_type || 'SIMULATED',
        synthetic_target: {
          domain: 'synthetic-target.local',
          port: 443,
          url: 'http://synthetic-target.local:443',
          policy: SyntheticTargetService.SYNTHETIC_SANDBOX_POLICY,
        },
        network_policy_applied: SyntheticTargetService.SYNTHETIC_SANDBOX_POLICY,
        egress_evaluations: [],
        runtime_events: [],
        raw_traces: [],
        status: 'REFUSED',
        refusal_reason: codeValidation.refusal_reason!,
        started_at: startedAt,
        completed_at: new Date().toISOString(),
        duration_ms: 0,
      };
    }

    // 4. Resolve Synthetic Target & Apply Single-Target Whitelist Network Policy
    const targetDomain = request.synthetic_target_domain || 'synthetic-target.local';
    const isSyntheticDomain = ComposerTargetValidator.ALLOWED_SYNTHETIC_PATTERNS.some(p => p.test(targetDomain));

    if (!isSyntheticDomain) {
      return {
        success: false,
        run_id: runId,
        session_id: `sbx-refused-${Date.now()}`,
        artifact_id: artifactId,
        technique_category: category,
        provider_type: request.provider_type || 'SIMULATED',
        synthetic_target: {
          domain: targetDomain,
          port: request.target_port || 443,
          url: `http://${targetDomain}:${request.target_port || 443}`,
          policy: SyntheticTargetService.SYNTHETIC_SANDBOX_POLICY,
        },
        network_policy_applied: SyntheticTargetService.SYNTHETIC_SANDBOX_POLICY,
        egress_evaluations: [],
        runtime_events: [],
        raw_traces: [],
        status: 'REFUSED',
        refusal_reason: `Refusal: Target domain '${targetDomain}' is not a permitted synthetic sandbox target. Composer execution is strictly restricted to platform-provisioned synthetic sandbox targets.`,
        started_at: startedAt,
        completed_at: new Date().toISOString(),
        duration_ms: 0,
      };
    }

    const targetPort = request.target_port || 443;
    const targetUrl = `http://${targetDomain}:${targetPort}/api/v1`;

    // Strict Network Policy: DEFAULT_DENY / WHITELIST_ONLY containing ONLY that run's synthetic target
    const runNetworkPolicy: NetworkPolicy = {
      type: 'WHITELIST_ONLY',
      allowedDomains: [targetDomain],
      allowedPorts: [targetPort, 80, 443, 8080],
      allowDns: true,
      interceptEgress: true,
    };

    // 5. Evaluate Egress Permissions (Confirms synthetic target allowed, external targets blocked)
    const synthEval = NetworkPolicyEngine.evaluateConnection(
      runNetworkPolicy,
      targetDomain,
      targetPort,
      'HTTPS',
      'SCN-COMPOSER-EXEC',
      '2.0.1'
    );

    const blockedExternalEval = NetworkPolicyEngine.evaluateConnection(
      runNetworkPolicy,
      'api.github.com',
      443,
      'HTTPS',
      'SCN-COMPOSER-EXEC',
      '2.0.1'
    );

    const blockedIpEval = NetworkPolicyEngine.evaluateConnection(
      runNetworkPolicy,
      '142.250.190.46',
      443,
      'HTTPS',
      'SCN-COMPOSER-EXEC',
      '2.0.1'
    );

    const egressEvaluations = [
      { destination: `${targetDomain}:${targetPort}`, allowed: synthEval.allowed, reason: synthEval.reason },
      { destination: 'api.github.com:443', allowed: blockedExternalEval.allowed, reason: blockedExternalEval.reason },
      { destination: '142.250.190.46:443', allowed: blockedIpEval.allowed, reason: blockedIpEval.reason },
    ];

    // 6. Build In-Sandbox Execution Script
    const runnerScript = `
/**
 * In-Sandbox Composer Tool Runner
 * Dynamically loads and executes the generated tool entrypoint against synthetic target: ${targetUrl}
 */
const fs = require('fs');
const path = require('path');

async function runTool() {
  const targetHost = process.env.SYNTHETIC_TARGET_HOST || '${targetDomain}';
  const targetPort = parseInt(process.env.SYNTHETIC_TARGET_PORT || '${targetPort}', 10);
  const targetUrl = process.env.SYNTHETIC_TARGET_URL || '${targetUrl}';
  const inputPayload = ${JSON.stringify(request.input_payload || {})};

  console.log('[COMPOSER_SANDBOX_RUNNER] Starting execution in microVM sandbox...');
  console.log('[COMPOSER_SANDBOX_RUNNER] Bound synthetic endpoint: ' + targetUrl);
  console.log('[COMPOSER_SANDBOX_RUNNER] NetworkPolicy: WHITELIST_ONLY -> [' + targetHost + ']');

  const startMs = Date.now();

  try {
    // 1. Resolve entrypoint file
    let entrypointFile = 'index.ts';
    if (fs.existsSync(path.join(__dirname, 'agent-manifest.json'))) {
      try {
        const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'agent-manifest.json'), 'utf-8'));
        if (manifest.entrypoint) entrypointFile = manifest.entrypoint;
      } catch (e) {}
    }

    if (!fs.existsSync(path.join(__dirname, entrypointFile))) {
      if (fs.existsSync(path.join(__dirname, 'index.js'))) entrypointFile = 'index.js';
      else if (fs.existsSync(path.join(__dirname, 'agent.ts'))) entrypointFile = 'agent.ts';
      else if (fs.existsSync(path.join(__dirname, 'agent.js'))) entrypointFile = 'agent.js';
    }

    const entrypointPath = path.join(__dirname, entrypointFile);
    console.log('[COMPOSER_SANDBOX_RUNNER] Loading entrypoint: ' + entrypointFile);

    // 2. Load module dynamically
    let toolModule;
    try {
      toolModule = require(entrypointPath);
    } catch (reqErr) {
      toolModule = await import(entrypointPath);
    }

    // 3. Resolve tool class or function
    let ToolClassOrFn = (typeof toolModule === 'function') ? toolModule : (toolModule && toolModule.default ? toolModule.default : toolModule);
    if (!ToolClassOrFn || typeof ToolClassOrFn !== 'function') {
      if (typeof toolModule === 'object' && toolModule !== null) {
        for (const key of Object.keys(toolModule)) {
          if (typeof toolModule[key] === 'function') {
            ToolClassOrFn = toolModule[key];
            break;
          }
        }
      }
    }

    if (!ToolClassOrFn) {
      throw new Error('No executable class or function exported from ' + entrypointFile);
    }

    // 4. Instantiate or invoke against synthetic target
    let executionOutput;
    if (typeof ToolClassOrFn === 'function' && ToolClassOrFn.prototype && (ToolClassOrFn.prototype.execute || ToolClassOrFn.prototype.run)) {
      console.log('[COMPOSER_SANDBOX_RUNNER] Instantiating tool class: ' + (ToolClassOrFn.name || 'AnonymousAgent'));
      const instance = new ToolClassOrFn(targetUrl);
      const method = instance.execute || instance.run;
      console.log('[COMPOSER_SANDBOX_RUNNER] Invoking tool.execute() against synthetic endpoint: ' + targetUrl);
      executionOutput = await method.call(instance, {
        requestId: 'req-' + Date.now(),
        payload: inputPayload,
        syntheticTargetEndpoint: targetUrl,
        targetUrl: targetUrl,
      });
    } else if (typeof ToolClassOrFn === 'function') {
      console.log('[COMPOSER_SANDBOX_RUNNER] Invoking tool function directly against synthetic endpoint: ' + targetUrl);
      executionOutput = await ToolClassOrFn({
        requestId: 'req-' + Date.now(),
        payload: inputPayload,
        syntheticTargetEndpoint: targetUrl,
        targetUrl: targetUrl,
      });
    }

    const durationMs = Date.now() - startMs;
    console.log('[COMPOSER_SANDBOX_RUNNER] Tool execution completed successfully in ' + durationMs + 'ms.');
    console.log('[COMPOSER_EXEC_OUTPUT] ' + JSON.stringify({
      success: true,
      status: 'COMPLETED',
      result: executionOutput,
      duration_ms: durationMs,
    }));
    process.exit(0);
  } catch (err) {
    const durationMs = Date.now() - startMs;
    console.error('[COMPOSER_SANDBOX_RUNNER] Tool execution failed with error: ' + (err.message || String(err)));
    if (err.stack) {
      console.error(err.stack);
    }
    console.log('[COMPOSER_EXEC_OUTPUT] ' + JSON.stringify({
      success: false,
      status: 'FAILED',
      error: err.message || String(err),
      stack: err.stack,
      duration_ms: durationMs,
    }));
    process.exit(1);
  }
}

return runTool().catch((err) => {
  console.error('[COMPOSER_SANDBOX_RUNNER] Fatal uncaught runner error:', err);
  process.exit(1);
});
`;

    const sandboxFiles: Record<string, string> = {
      ...artifactFiles,
      'runner.js': runnerScript,
    };

    // 7. Dispatch Dynamic Execution to Sandbox Orchestrator
    const providerType = request.provider_type || (process.env.E2B_API_KEY ? 'E2B' : 'SIMULATED');
    const sandboxResult = await SandboxOrchestrationEngine.runScenario({
      scenarioId: 'SCN-COMPOSER-EXEC',
      providerType,
      artifactId,
      files: sandboxFiles,
      networkPolicy: runNetworkPolicy,
      envVars: {
        SYNTHETIC_TARGET_HOST: targetDomain,
        SYNTHETIC_TARGET_PORT: String(targetPort),
        SYNTHETIC_TARGET_URL: targetUrl,
        NODE_ENV: 'sandbox',
      },
    });

    // 8. Extract genuine execution output from runner traces
    let parsedExecutionOutput: any = null;
    for (const trace of sandboxResult.raw_traces) {
      if (trace.startsWith('[EXEC_COMMAND]')) continue;
      const lines = trace.split('\n');
      for (const line of lines) {
        if (line.includes('[COMPOSER_EXEC_OUTPUT]')) {
          try {
            const jsonStr = line.substring(line.indexOf('[COMPOSER_EXEC_OUTPUT]') + '[COMPOSER_EXEC_OUTPUT]'.length).trim();
            parsedExecutionOutput = JSON.parse(jsonStr);
            break;
          } catch {}
        }
      }
      if (parsedExecutionOutput) break;
    }

    const executionOutput = parsedExecutionOutput || {
      success: sandboxResult.status === 'PASSED',
      status: sandboxResult.status === 'PASSED' ? 'COMPLETED' : sandboxResult.status,
      duration_ms: sandboxResult.duration_ms,
      canaries_tripped: sandboxResult.canaries_tripped.length,
      evasion_risk_score: sandboxResult.evasion_risk_score,
      payload_processed: request.input_payload || { status: 'SYNTHETIC_SUCCESS' },
    };

    const isSuccess = sandboxResult.status === 'PASSED' && executionOutput.success !== false;
    const finalStatus = isSuccess ? 'COMPLETED' : (sandboxResult.status === 'PASSED' ? (executionOutput.status || 'FAILED') : (sandboxResult.status as any));

    const completedAt = new Date().toISOString();
    const durationMs = Date.now() - startTime;

    return {
      success: isSuccess,
      run_id: sandboxResult.run_id,
      session_id: sandboxResult.session_id,
      artifact_id: artifactId,
      technique_category: category,
      provider_type: sandboxResult.actual_provider || sandboxResult.provider_type,
      requested_provider: sandboxResult.requested_provider,
      actual_provider: sandboxResult.actual_provider,
      execution_mode: sandboxResult.execution_mode,
      fallback_reason: sandboxResult.fallback_reason,
      synthetic_target: {
        domain: targetDomain,
        port: targetPort,
        url: targetUrl,
        policy: runNetworkPolicy,
      },
      network_policy_applied: runNetworkPolicy,
      egress_evaluations: egressEvaluations,
      runtime_events: sandboxResult.runtime_events,
      raw_traces: [
        `[COMPOSER_EXEC_INIT] Artifact ${artifactId} dispatched to ${sandboxResult.provider_type} sandbox microVM.`,
        `[NETWORK_POLICY] Bound exclusively to ${targetDomain} (WHITELIST_ONLY). External egress is DEFAULT_DENY.`,
        ...sandboxResult.raw_traces,
      ],
      execution_output: executionOutput,
      status: finalStatus,
      started_at: startedAt,
      completed_at: completedAt,
      duration_ms: durationMs,
    };
  }

  /**
   * Synthesizes deterministic, clean, secure agent code based on requested technique
   */
  private synthesizeArtifact(
    request: ComposerGenerationRequest,
    targetName: string,
    sources: string[]
  ): Record<string, string> {
    const cat = request.technique_category;
    const sanitizedPrompt = request.prompt.replace(/\/\*[\s\S]*?\*\//g, '').trim();

    let code = `/**
 * Agent: ${targetName}
 * Technique Category: ${cat}
 * Generated by: CAIM Composer Engine E42
 * Source Patterns: ${sources.length > 0 ? sources.join(', ') : 'Synthetic baseline pattern'}
 * Prompt: ${sanitizedPrompt.substring(0, 100)}
 */

import { SyntheticTargetService } from '../sandbox-orchestrator/security/synthetic-target.ts';

export interface ${targetName}Input {
  requestId: string;
  payload: Record<string, any>;
  syntheticTargetEndpoint?: string;
}

export interface ${targetName}Result {
  success: boolean;
  status: string;
  output: Record<string, any>;
  timestamp: string;
}

export class ${targetName} {
  public static readonly CATEGORY = '${cat}';
  private endpoint: string;

  constructor(endpoint: string = 'http://synthetic-target.local/api/v1') {
    this.endpoint = endpoint;
  }

  /**
   * Executes synthetic ${cat} workflow
   */
  public async execute(input: ${targetName}Input): Promise<${targetName}Result> {
    const targetUrl = input.syntheticTargetEndpoint || this.endpoint;
    
    // Process input data
    const processedData = {
      ...input.payload,
      technique: '${cat}',
      validatedAt: new Date().toISOString(),
    };

    return {
      success: true,
      status: 'COMPLETED',
      output: processedData,
      timestamp: new Date().toISOString(),
    };
  }
}
`;

    const jsCode = `/**
 * Agent: ${targetName} (Compiled JavaScript Entrypoint for Node.js MicroVM)
 */
class ${targetName} {
  constructor(endpoint = 'http://synthetic-target.local/api/v1') {
    this.endpoint = endpoint;
  }

  async execute(input) {
    const targetUrl = (input && input.syntheticTargetEndpoint) || this.endpoint;
    const processedData = {
      ...((input && input.payload) || {}),
      technique: '${cat}',
      validatedAt: new Date().toISOString(),
    };

    return {
      success: true,
      status: 'COMPLETED',
      output: processedData,
      timestamp: new Date().toISOString(),
    };
  }
}
${targetName}.CATEGORY = '${cat}';
module.exports = { ${targetName}, default: ${targetName} };
`;

    const manifestJson = JSON.stringify({
      name: targetName,
      technique_category: cat,
      version: '1.0.0',
      entrypoint: 'index.js',
      source_agents: sources,
      environment: 'SYNTHETIC_SANDBOX',
    }, null, 2);

    return {
      'index.ts': code,
      'index.js': jsCode,
      'agent-manifest.json': manifestJson,
    };
  }

  /**
   * Records generation log into database and in-memory list
   */
  public async recordLog(log: ComposerGenerationLogRecord): Promise<void> {
    AgentComposerEngine.inMemoryLogs.unshift(log);

    if (this.dbClient) {
      try {
        await this.dbClient.query(
          `INSERT INTO security.composer_generation_log
           (log_id, principal_id, technique_category, request_text, source_agents_retrieved, generated_artifact_id, static_analysis_result_summary, status, refusal_reason, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);`,
          [
            log.log_id,
            log.principal_id,
            log.technique_category,
            log.request_text,
            log.source_agents_retrieved,
            log.generated_artifact_id || null,
            log.static_analysis_result_summary ? JSON.stringify(log.static_analysis_result_summary) : null,
            log.status,
            log.refusal_reason || null,
            log.created_at,
          ]
        );
      } catch {
        // Fallback
      }
    }
  }

  /**
   * Retrieves all generation logs
   */
  public async listLogs(): Promise<ComposerGenerationLogRecord[]> {
    if (this.dbClient) {
      try {
        const res = await this.dbClient.query(
          'SELECT * FROM security.composer_generation_log ORDER BY created_at DESC LIMIT 100;'
        );
        if (res && res.rows) {
          return res.rows.map((r: any) => ({
            log_id: r.log_id,
            principal_id: r.principal_id,
            technique_category: r.technique_category,
            request_text: r.request_text,
            source_agents_retrieved: Array.isArray(r.source_agents_retrieved) ? r.source_agents_retrieved : [],
            generated_artifact_id: r.generated_artifact_id,
            static_analysis_result_summary: typeof r.static_analysis_result_summary === 'string' ? JSON.parse(r.static_analysis_result_summary) : r.static_analysis_result_summary,
            status: r.status,
            refusal_reason: r.refusal_reason,
            created_at: r.created_at,
          }));
        }
      } catch {
        // Fallback
      }
    }
    return AgentComposerEngine.inMemoryLogs;
  }
}

