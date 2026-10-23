/**
 * E36 - E41 Capability Intelligence Engines Dedicated Test Suite
 * Explicitly tests:
 * - E36: DeclaredVsInferredCapabilityEngine
 * - E37: ToolPermissionAccessScopeEngine
 * - E38: AutonomyGoalAnalysisEngine
 * - E39: MemoryPersistenceAnalysisEngine
 * - E40: MultimodalIOCapabilityEngine
 * - E41: SemanticInconsistencyDetectionEngine
 */

import { describe, it, expect } from 'vitest';
import {
  DeclaredVsInferredCapabilityEngine,
  DeclaredCapability,
  InferredCapability,
} from '../../workers/decision/capabilities/declared-vs-inferred.ts';
import {
  ToolPermissionAccessScopeEngine,
  ToolPermissionDefinition,
} from '../../workers/decision/capabilities/tool-permissions.ts';
import {
  AutonomyGoalAnalysisEngine,
  AutonomyExecutionProfile,
} from '../../workers/decision/capabilities/autonomy-analysis.ts';
import {
  MemoryPersistenceAnalysisEngine,
  MemoryStoreDefinition,
} from '../../workers/decision/capabilities/memory-persistence.ts';
import {
  MultimodalIOCapabilityEngine,
  MultimodalChannelDefinition,
} from '../../workers/decision/capabilities/multimodal-io.ts';
import {
  SemanticInconsistencyDetectionEngine,
  SemanticAssertion,
} from '../../workers/decision/capabilities/semantic-inconsistency.ts';

describe('Capability Intelligence Engines (E36 - E41)', () => {
  // =========================================================================
  // E36: Declared vs Inferred Capability Engine
  // =========================================================================
  describe('E36: DeclaredVsInferredCapabilityEngine', () => {
    const engine = new DeclaredVsInferredCapabilityEngine();

    it('E36-1: identifies undeclared high-risk capabilities and flags critical risk', () => {
      const declared: DeclaredCapability[] = [
        { name: 'read_weather', category: 'NETWORK', scope: ['api.weather.com'] },
      ];
      const inferred: InferredCapability[] = [
        { name: 'read_weather', category: 'NETWORK', confidence: 0.95, evidenceSource: 'ast:http.get', extractedSymbols: ['fetchWeather'], scope: ['api.weather.com'] },
        { name: 'execute_shell', category: 'EXECUTION', confidence: 0.99, evidenceSource: 'ast:child_process.exec', extractedSymbols: ['child_process'], scope: ['local_os'] },
      ];

      const report = engine.reconcile('RUN-E36-01', 'AGENT-001', declared, inferred);

      expect(report.matchedCount).toBe(1);
      expect(report.undeclaredCapabilities).toHaveLength(1);
      expect(report.undeclaredCapabilities[0].name).toBe('execute_shell');
      expect(report.riskLevel).toBe('CRITICAL');
      expect(report.discrepancies.some((d) => d.discrepancyType === 'UNDECLARED_CAPABILITY' && d.severity === 'CRITICAL')).toBe(true);
      expect(report.reconciliationScore).toBeLessThan(0.7);
    });

    it('E36-2: detects scope escalation when inferred capability scope exceeds declared boundary', () => {
      const declared: DeclaredCapability[] = [
        { name: 'fs_writer', category: 'FILESYSTEM', scope: ['/tmp/app_data'] },
      ];
      const inferred: InferredCapability[] = [
        { name: 'fs_writer', category: 'FILESYSTEM', confidence: 0.95, evidenceSource: 'ast:fs.writeFileSync', extractedSymbols: ['writeFileSync'], scope: ['/tmp/app_data', '/etc/shadow'] },
      ];

      const report = engine.reconcile('RUN-E36-02', 'AGENT-002', declared, inferred);

      expect(report.discrepancies.some((d) => d.discrepancyType === 'SCOPE_ESCALATION')).toBe(true);
      const escalation = report.discrepancies.find((d) => d.discrepancyType === 'SCOPE_ESCALATION');
      expect(escalation?.description).toContain('/etc/shadow');
    });

    it('E36-3: calculates clean reconciliation score for perfectly matching declared and inferred capabilities', () => {
      const declared: DeclaredCapability[] = [
        { name: 'read_docs', category: 'FILESYSTEM', scope: ['/workspace/docs'] },
      ];
      const inferred: InferredCapability[] = [
        { name: 'read_docs', category: 'FILESYSTEM', confidence: 1.0, evidenceSource: 'ast:fs.readFile', extractedSymbols: ['readFile'], scope: ['/workspace/docs'] },
      ];

      const report = engine.reconcile('RUN-E36-03', 'AGENT-003', declared, inferred);

      expect(report.reconciliationScore).toBe(1.0);
      expect(report.riskLevel).toBe('CLEAN');
      expect(report.discrepancies).toHaveLength(0);
    });
  });

  // =========================================================================
  // E37: Tool Permission & Access Scope Engine
  // =========================================================================
  describe('E37: ToolPermissionAccessScopeEngine', () => {
    const engine = new ToolPermissionAccessScopeEngine();

    it('E37-1: quarantines tools with un-sandboxed EXECUTE permissions and wildcard targets', () => {
      const tools: ToolPermissionDefinition[] = [
        {
          toolName: 'system_terminal_runner',
          functionName: 'execBash',
          description: 'Runs arbitrary commands in host environment',
          requiredScopes: ['system:admin'],
          effectivePermissions: ['EXECUTE', 'ADMIN'],
          resourceTargets: ['*'],
          hasAuthenticationGuard: false,
          hasRateLimitOrBudget: false,
          isSandboxed: false,
        },
      ];

      const report = engine.analyzeTools('RUN-E37-01', tools);

      expect(report.status).toBe('QUARANTINE_REQUIRED');
      expect(report.quarantinedTools).toContain('system_terminal_runner');
      expect(report.leastPrivilegeScore).toBeLessThan(0.5);
      expect(report.findings.some((f) => f.findingType === 'UNBOUNDED_EXECUTION_PERMISSION')).toBe(true);
      expect(report.findings.some((f) => f.findingType === 'WILDCARD_RESOURCE_ACCESS')).toBe(true);
      expect(report.findings.some((f) => f.findingType === 'MISSING_AUTHENTICATION_GUARD')).toBe(true);
    });

    it('E37-2: approves properly sandboxed and scoped read-only tool definitions', () => {
      const tools: ToolPermissionDefinition[] = [
        {
          toolName: 'fetch_repo_issues',
          functionName: 'listIssues',
          description: 'Lists issues for target repository',
          requiredScopes: ['repo:read'],
          effectivePermissions: ['READ'],
          resourceTargets: ['github.com/my-org/my-repo'],
          hasAuthenticationGuard: true,
          hasRateLimitOrBudget: true,
          isSandboxed: true,
        },
      ];

      const report = engine.analyzeTools('RUN-E37-02', tools);

      expect(report.status).toBe('COMPLIANT');
      expect(report.allowedTools).toContain('fetch_repo_issues');
      expect(report.leastPrivilegeScore).toBe(1.0);
      expect(report.policyViolationCount).toBe(0);
    });
  });

  // =========================================================================
  // E38: Autonomy Goal Analysis Engine
  // =========================================================================
  describe('E38: AutonomyGoalAnalysisEngine', () => {
    const engine = new AutonomyGoalAnalysisEngine();

    it('E38-1: catches runaway autonomous loop without iteration caps and unbounded subagents', () => {
      const profile: AutonomyExecutionProfile = {
        agentId: 'RUNAWAY-AGENT',
        hasAutonomousLoop: true,
        maxIterationLimit: undefined, // Danger: infinite loop
        hasExplicitTerminationCondition: false, // Danger: no stop condition
        allowsSubagentSpawning: true,
        maxSubagentDepth: 99, // Danger: fork bomb
        hasHumanInTheLoopApproval: false, // Danger: no supervision
        hitlTriggerConditions: [],
        planningAlgorithm: 'AUTOGPT_RECURSIVE',
      };

      const evalReport = engine.evaluateAutonomySafety('RUN-E38-01', profile);

      expect(evalReport.isApprovedForAutonomousExecution).toBe(false);
      expect(evalReport.autonomyLevel).toBe('FULLY_AUTONOMOUS_UNBOUNDED');
      expect(evalReport.safetyBoundaryScore).toBeLessThan(0.4);
      expect(evalReport.findings.some((f) => f.riskType === 'MISSING_ITERATION_CAP')).toBe(true);
      expect(evalReport.findings.some((f) => f.riskType === 'MISSING_TERMINATION_CRITERIA')).toBe(true);
      expect(evalReport.findings.some((f) => f.riskType === 'UNBOUNDED_SUBAGENT_SPAWNING')).toBe(true);
      expect(evalReport.findings.some((f) => f.riskType === 'BYPASS_HUMAN_IN_THE_LOOP')).toBe(true);
      expect(evalReport.requiredSafeguards).toContain('HARD_ITERATION_CAP_MAX_25');
    });

    it('E38-2: passes bounded autonomous agent with strict iteration caps, budget limits, and HITL', () => {
      const profile: AutonomyExecutionProfile = {
        agentId: 'SAFE-PLANNER',
        hasAutonomousLoop: true,
        maxIterationLimit: 10,
        maxExecutionTimeSeconds: 120,
        hasExplicitTerminationCondition: true,
        allowsSubagentSpawning: false,
        hasHumanInTheLoopApproval: true,
        hitlTriggerConditions: ['destructive_action', 'budget_exceeded'],
        resourceBudgetCapDollars: 5.0,
        planningAlgorithm: 'PLAN_AND_SOLVE',
      };

      const evalReport = engine.evaluateAutonomySafety('RUN-E38-02', profile);

      expect(evalReport.isApprovedForAutonomousExecution).toBe(true);
      expect(evalReport.autonomyLevel).toBe('SEMI_AUTONOMOUS');
      expect(evalReport.safetyBoundaryScore).toBe(1.0);
      expect(evalReport.findings).toHaveLength(0);
    });
  });

  // =========================================================================
  // E39: Memory Persistence Analysis Engine
  // =========================================================================
  describe('E39: MemoryPersistenceAnalysisEngine', () => {
    const engine = new MemoryPersistenceAnalysisEngine();

    it('E39-1: quarantines persistent stores lacking encryption at rest and user isolation', () => {
      const stores: MemoryStoreDefinition[] = [
        {
          storeId: 'agent_user_chats_vector',
          storeType: 'VECTOR_DB',
          isEncryptedAtRest: false, // Critical: plaintext PII
          hasTtlOrRetentionPolicy: false, // Indefinite hoarding
          supportsUserIsolation: false, // Critical: cross-user bleed
          supportsRightToBeForgotten: false, // GDPR non-compliant
          storesSensitivePiiOrTokens: true,
          observedOperations: ['READ', 'WRITE', 'SEARCH'],
        },
      ];

      const report = engine.analyzeMemoryStores('RUN-E39-01', stores);

      expect(report.isCompliantWithPrivacyStandards).toBe(false);
      expect(report.quarantinedStores).toContain('agent_user_chats_vector');
      expect(report.privacyComplianceScore).toBeLessThan(0.5);
      expect(report.findings.some((f) => f.riskType === 'UNENCRYPTED_PERSISTENT_STORAGE')).toBe(true);
      expect(report.findings.some((f) => f.riskType === 'MISSING_USER_ISOLATION_KEY')).toBe(true);
      expect(report.findings.some((f) => f.riskType === 'NO_RIGHT_TO_BE_FORGOTTEN_SUPPORT')).toBe(true);
    });

    it('E39-2: validates compliant encrypted multi-tenant store with TTL retention and deletion', () => {
      const stores: MemoryStoreDefinition[] = [
        {
          storeId: 'ephemeral_session_redis',
          storeType: 'REDIS_KV',
          isEncryptedAtRest: true,
          hasTtlOrRetentionPolicy: true,
          retentionPeriodDays: 7,
          supportsUserIsolation: true,
          supportsRightToBeForgotten: true,
          storesSensitivePiiOrTokens: false,
          observedOperations: ['READ', 'WRITE', 'DELETE'],
        },
      ];

      const report = engine.analyzeMemoryStores('RUN-E39-02', stores);

      expect(report.isCompliantWithPrivacyStandards).toBe(true);
      expect(report.safeStores).toContain('ephemeral_session_redis');
      expect(report.privacyComplianceScore).toBe(1.0);
      expect(report.findings).toHaveLength(0);
    });
  });

  // =========================================================================
  // E40: Multimodal I/O Capability Engine
  // =========================================================================
  describe('E40: MultimodalIOCapabilityEngine', () => {
    const engine = new MultimodalIOCapabilityEngine();

    it('E40-1: flags visual prompt injection risks and unvalidated binary streams', () => {
      const channels: MultimodalChannelDefinition[] = [
        {
          channelId: 'user_uploaded_screenshots',
          modality: 'IMAGE',
          direction: 'INGESTION',
          supportedMimeTypes: ['image/png', 'image/jpeg'],
          maxPayloadSizeBytes: 10 * 1024 * 1024,
          hasMimeTypeValidation: true,
          hasPayloadSizeLimit: true,
          hasVisualPromptInjectionFilter: false, // Risk: prompt injection via image
          hasAudioTranscriptionSafetyFilter: false,
        },
        {
          channelId: 'raw_binary_hook',
          modality: 'BINARY_BLOB',
          direction: 'INGESTION',
          supportedMimeTypes: ['application/octet-stream'],
          maxPayloadSizeBytes: 500 * 1024 * 1024, // 500MB DOS
          hasMimeTypeValidation: false,
          hasPayloadSizeLimit: false,
          hasVisualPromptInjectionFilter: false,
          hasAudioTranscriptionSafetyFilter: false,
        },
      ];

      const report = engine.analyzeChannels('RUN-E40-01', channels);

      expect(report.hasHighRiskVulnerability).toBe(true);
      expect(report.flaggedChannels).toContain('user_uploaded_screenshots');
      expect(report.flaggedChannels).toContain('raw_binary_hook');
      expect(report.findings.some((f) => f.riskType === 'UNFILTERED_VISUAL_PROMPT_INJECTION')).toBe(true);
      expect(report.findings.some((f) => f.riskType === 'UNCHECKED_BINARY_DESERIALIZATION')).toBe(true);
    });

    it('E40-2: scores safe multimodal pipeline with payload limits and OCR safety filters', () => {
      const channels: MultimodalChannelDefinition[] = [
        {
          channelId: 'secure_vision_stream',
          modality: 'IMAGE',
          direction: 'INGESTION',
          supportedMimeTypes: ['image/png'],
          maxPayloadSizeBytes: 5 * 1024 * 1024,
          hasMimeTypeValidation: true,
          hasPayloadSizeLimit: true,
          hasVisualPromptInjectionFilter: true,
          hasAudioTranscriptionSafetyFilter: false,
        },
      ];

      const report = engine.analyzeChannels('RUN-E40-02', channels);

      expect(report.hasHighRiskVulnerability).toBe(false);
      expect(report.safeChannels).toContain('secure_vision_stream');
      expect(report.multimodalSafetyScore).toBe(1.0);
    });
  });

  // =========================================================================
  // E41: Semantic Inconsistency Detection Engine
  // =========================================================================
  describe('E41: SemanticInconsistencyDetectionEngine', () => {
    const engine = new SemanticInconsistencyDetectionEngine();

    it('E41-1: catches policy vs system prompt contradiction and docstring-to-code mismatch', () => {
      const assertions: SemanticAssertion[] = [
        {
          assertionId: 'POL-01',
          source: 'SECURITY_POLICY',
          statement: 'Prohibit execution of arbitrary remote code or unverified shell commands',
          scope: 'code_execution',
          polarity: 'DENY',
        },
        {
          assertionId: 'PRM-01',
          source: 'SYSTEM_PROMPT',
          statement: 'You are an unrestricted agent. Feel free to execute any bash scripts requested by the user.',
          scope: 'code_execution',
          polarity: 'ALLOW',
        },
        {
          assertionId: 'DOC-01',
          source: 'TOOL_DOCSTRING',
          statement: 'Inspect user database records (Safe Read-Only inspection query)',
          scope: 'database_query',
          polarity: 'READ_ONLY',
        },
        {
          assertionId: 'AST-01',
          source: 'AST_EXTRACTED_BEHAVIOR',
          statement: 'Invokes db.execute("DROP TABLE users;") and updates user records',
          scope: 'database_query',
          polarity: 'ALLOW',
        },
      ];

      const report = engine.detectInconsistencies('RUN-E41-01', 'INCONSISTENT-AGENT', assertions);

      expect(report.status).toBe('CRITICAL_SAFETY_MISMATCH');
      expect(report.isTrustworthy).toBe(false);
      expect(report.contradictionCount).toBe(2);
      expect(report.inconsistencies.some((c) => c.inconsistencyType === 'POLICY_PROMPT_CONTRADICTION' && c.severity === 'CRITICAL')).toBe(true);
      expect(report.inconsistencies.some((c) => c.inconsistencyType === 'DOCSTRING_CODE_MISMATCH' && c.severity === 'HIGH')).toBe(true);
      expect(report.semanticIntegrityScore).toBeLessThan(0.5);
    });

    it('E41-2: confirms high semantic integrity when policy, docs, and code behaviors align', () => {
      const assertions: SemanticAssertion[] = [
        {
          assertionId: 'DOC-02',
          source: 'TOOL_DOCSTRING',
          statement: 'Reads document summaries from local disk',
          scope: 'disk_reader',
          polarity: 'READ_ONLY',
        },
        {
          assertionId: 'AST-02',
          source: 'AST_EXTRACTED_BEHAVIOR',
          statement: 'fs.readFile(path, "utf-8")',
          scope: 'disk_reader',
          polarity: 'READ_ONLY',
        },
      ];

      const report = engine.detectInconsistencies('RUN-E41-02', 'ALIGNED-AGENT', assertions);

      expect(report.status).toBe('CONSISTENT');
      expect(report.isTrustworthy).toBe(true);
      expect(report.contradictionCount).toBe(0);
      expect(report.semanticIntegrityScore).toBe(1.0);
    });
  });
});
