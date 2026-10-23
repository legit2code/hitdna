import { describe, it, expect, beforeEach } from 'vitest';
import {
  LifecycleImprovementService,
  DifferentialAnalysisEngine,
  ModificationWorkspace,
  ApprovalEngine,
  ImpactAnalysisEngine,
  ReanalysisPlanner,
  ValidationEngine,
  AgentVersionSnapshot,
} from '../workers/lifecycle/index.ts';

describe('P25 — Controlled Improvement Lifecycle, Differential, Modification & Validation', () => {
  let service: LifecycleImprovementService;
  let baseVersion: AgentVersionSnapshot;

  beforeEach(() => {
    service = new LifecycleImprovementService();

    baseVersion = {
      agentVersionId: 'v-1.0.0-base',
      agentId: 'agent-sentinel-01',
      versionLabel: '1.0.0',
      status: 'ANALYZED',
      isImmutable: true,
      createdAt: '2026-08-26T10:00:00Z',
      analysisRunId: 'run-base-100',
      sourceFiles: {
        'src/index.ts': {
          path: 'src/index.ts',
          content: 'export function processUserQuery(input: string) { return eval(input); }',
          hash: 'hash-eval-bad',
          sizeBytes: 72,
        },
        'src/tools.ts': {
          path: 'src/tools.ts',
          content: 'export function searchDatabase(q: string) { return `Results for ${q}`; }',
          hash: 'hash-tools-v1',
          sizeBytes: 68,
        },
      },
      astNodes: [
        {
          id: 'ast-node-1',
          name: 'processUserQuery',
          kind: 'FUNCTION',
          filePath: 'src/index.ts',
          startLine: 1,
          endLine: 1,
          signature: '(input: string) => any',
          bodyHash: 'ast-body-eval',
        },
        {
          id: 'ast-node-2',
          name: 'searchDatabase',
          kind: 'FUNCTION',
          filePath: 'src/tools.ts',
          startLine: 1,
          endLine: 1,
          signature: '(q: string) => string',
          bodyHash: 'ast-body-search',
        },
      ],
      dependencies: {
        lodash: {
          name: 'lodash',
          version: '4.17.15',
          type: 'DIRECT',
          vulnerabilities: [
            { cveId: 'CVE-2020-8203', severity: 'HIGH', description: 'Prototype pollution' },
          ],
        },
      },
      capabilities: [
        {
          id: 'cap-db-search',
          name: 'searchDatabase',
          type: 'DECLARED',
          category: 'TOOL_USE',
          confidence: 1.0,
          associatedTools: ['searchDatabase'],
          isEssential: true,
        },
      ],
      permissions: [
        {
          scope: 'EXEC',
          resource: 'eval',
          actions: ['EXECUTE'],
          riskLevel: 'CRITICAL',
        },
      ],
      behaviors: [
        {
          scenarioId: 'scen-search-01',
          name: 'Execute Database Search',
          passed: true,
          toolCallsCount: 1,
          externalRequestsCount: 0,
          executionTimeMs: 120,
          outputs: { found: true },
        },
      ],
      riskScore: {
        overallScore: 35,
        riskIndex: 78,
        structuralRisk: 65,
        taintVulnerabilityRisk: 90,
        toolMisuseRisk: 70,
        sandboxEvasionRisk: 40,
        policyViolationsCount: 2,
        criticalFindingsCount: 1,
        highFindingsCount: 1,
      },
      analyzerConfig: {
        engineVersion: '2.0.0',
        rulesetVersion: 'sec-2026.08',
        weightMatrixVersion: 'wm-v1',
        probesCount: 42,
      },
    };

    service.registerVersion(baseVersion);
  });

  // 1. Immutable Baseline Invariant
  it('enforces immutability on original baseline version', () => {
    const ws = service.createWorkspace({
      baseVersionId: 'v-1.0.0-base',
      createdBy: 'dev-alice',
      scopeId: 'scope-prod-01',
    });

    expect(ws.verifyBaselineImmutability()).toBe(true);
    expect(Object.isFrozen(ws.baseVersion)).toBe(true);

    // Attempting to modify frozen baseVersion throws in strict mode
    expect(() => {
      (ws.baseVersion as any).versionLabel = '1.0.1';
    }).toThrow();
  });

  // 2. AI Suggestions as Proposals Only
  it('treats AI suggestions as proposals only requiring explicit acceptance', () => {
    const ws = service.createWorkspace({
      baseVersionId: 'v-1.0.0-base',
      createdBy: 'dev-alice',
      scopeId: 'scope-prod-01',
    });

    const proposal = service.stageAiProposal(ws.workspaceId, {
      proposalId: 'prop-fix-eval',
      title: 'Replace dynamic eval with safe AST expression parser',
      description: 'Eliminates Remote Code Execution via un-sanitized input',
      reasoning: 'Input should be parsed safely using JSON parser or safe AST evaluator',
      targetFile: 'src/index.ts',
      patchContent: 'export function processUserQuery(input: string) { return JSON.parse(input); }',
      confidenceScore: 0.96,
      authorType: 'AGENT',
    });

    expect(proposal.isStaged).toBe(true);
    expect(proposal.acceptedAt).toBeUndefined();

    // Working files should NOT have applied the proposal yet
    expect(ws.getChanges().length).toBe(0);
    expect(ws.getWorkingFiles()['src/index.ts'].content).toContain('eval(input)');

    // Explicit acceptance converts proposal to applied change
    const change = service.acceptProposal(ws.workspaceId, proposal.proposalId, 'dev-alice');
    expect(change.filePath).toBe('src/index.ts');
    expect(change.changeType).toBe('PATCH');
    expect(ws.getWorkingFiles()['src/index.ts'].content).toContain('JSON.parse(input)');
  });

  // 3. Human Edits & Patches
  it('supports direct human edits and patch author attribution', () => {
    const ws = service.createWorkspace({
      baseVersionId: 'v-1.0.0-base',
      createdBy: 'dev-alice',
      scopeId: 'scope-prod-01',
    });

    const edit = service.applyHumanEdit(ws.workspaceId, {
      filePath: 'src/config.ts',
      changeType: 'CREATE',
      newContent: 'export const SAFE_MODE = true;',
      actorRef: 'sec-auditor-bob',
    });

    expect(edit.authorType).toBe('HUMAN');
    expect(edit.authorRef).toBe('sec-auditor-bob');
    expect(ws.getWorkingFiles()['src/config.ts'].content).toBe('export const SAFE_MODE = true;');
  });

  // 4. Approval Flow and Audit Record Invariant
  it('enforces approval gating: unapproved workspace cannot commit when approval is required', () => {
    const ws = service.createWorkspace({
      baseVersionId: 'v-1.0.0-base',
      createdBy: 'dev-alice',
      scopeId: 'scope-prod-01',
    });

    service.applyHumanEdit(ws.workspaceId, {
      filePath: 'src/index.ts',
      newContent: 'export function processUserQuery(input: string) { return sanitize(input); }',
      actorRef: 'dev-alice',
    });

    // Attempting to commit without approval throws when requireApproval is true
    expect(() => {
      service.commitWorkspace({
        workspaceId: ws.workspaceId,
        newVersionLabel: '1.0.1-candidate',
        actorRef: 'dev-alice',
        requireApproval: true,
      });
    }).toThrow(/Unapproved modification workspace cannot commit/);

    // Record authorized approval
    const approval = service.recordApproval({
      targetEntityRefId: ws.workspaceId,
      targetType: 'MODIFICATION_WORKSPACE',
      approverId: 'auditor-carol',
      approverRole: 'security_auditor',
      decision: 'APPROVED',
      rationale: 'Verified eval removal and sanitized input parameter',
    });

    expect(approval.signature).toBeDefined();
    expect(approval.decision).toBe('APPROVED');

    // Now commit succeeds
    const newVersion = service.commitWorkspace({
      workspaceId: ws.workspaceId,
      newVersionLabel: '1.0.1-candidate',
      actorRef: 'dev-alice',
      requireApproval: true,
    });

    expect(newVersion.agentVersionId).toBeDefined();
    expect(newVersion.versionLabel).toBe('1.0.1-candidate');
    expect(newVersion.isImmutable).toBe(true);
  });

  // 5. Differential Analysis & Attribution Engine
  it('correctly attributes diffs between source changes vs analyzer upgrades', () => {
    // Case A: Source code changed, analyzer identical
    const modSource: AgentVersionSnapshot = {
      ...baseVersion,
      agentVersionId: 'v-1.0.1-codefix',
      sourceFiles: {
        ...baseVersion.sourceFiles,
        'src/index.ts': {
          path: 'src/index.ts',
          content: 'export function processUserQuery(input: string) { return sanitize(input); }',
          hash: 'hash-clean',
          sizeBytes: 80,
        },
      },
      riskScore: {
        ...baseVersion.riskScore,
        riskIndex: 20,
        criticalFindingsCount: 0,
      },
    };

    const diffSource = DifferentialAnalysisEngine.compare(baseVersion, modSource);
    expect(diffSource.attribution.overallAttribution).toBe('SOURCE_CHANGE');
    expect(diffSource.attribution.sourceCodeChanged).toBe(true);
    expect(diffSource.attribution.analyzerRulesChanged).toBe(false);
    expect(diffSource.attribution.findingsAttribution[0].attribution).toBe('REMEDIED_VULNERABILITY');

    // Case B: Source code identical, analyzer upgraded
    const modAnalyzer: AgentVersionSnapshot = {
      ...baseVersion,
      agentVersionId: 'v-1.0.0-newrules',
      analyzerConfig: {
        engineVersion: '2.1.0',
        rulesetVersion: 'sec-2026.09-expanded',
        weightMatrixVersion: 'wm-v2',
        probesCount: 65,
      },
      riskScore: {
        ...baseVersion.riskScore,
        criticalFindingsCount: 3, // Detected new issues purely from new rules
      },
    };

    const diffAnalyzer = DifferentialAnalysisEngine.compare(baseVersion, modAnalyzer);
    expect(diffAnalyzer.attribution.overallAttribution).toBe('ANALYZER_CHANGE');
    expect(diffAnalyzer.attribution.sourceCodeChanged).toBe(false);
    expect(diffAnalyzer.attribution.analyzerRulesChanged).toBe(true);
    expect(diffAnalyzer.attribution.findingsAttribution[0].attribution).toBe('NEW_DETECTION_RULE');
  });

  // 6. Impact Assessment and Reanalysis Planning
  it('assesses downstream blast radius and plans full vs incremental reanalysis', () => {
    const ws = service.createWorkspace({
      baseVersionId: 'v-1.0.0-base',
      createdBy: 'dev-alice',
      scopeId: 'scope-prod-01',
    });

    // Modifying an entry point triggers full reanalysis
    service.applyHumanEdit(ws.workspaceId, {
      filePath: 'src/index.ts',
      newContent: 'export function processUserQuery(input: string) { return sanitize(input); }',
      actorRef: 'dev-alice',
    });

    const { impact } = service.assessWorkspaceImpact(ws.workspaceId);
    expect(impact.affectsEntryPoints).toBe(true);
    expect(impact.suggestedReanalysisTrigger).toBe('FULL_REANALYSIS');

    const plan = service.planReanalysis(ws.workspaceId);
    expect(plan.trigger).toBe('FULL_REANALYSIS');
    expect(plan.stages.some((s) => s.stageId === 'stage-dynamic-sandbox')).toBe(true);
  });

  // 7. Locked Document 21B Schema & Invariant Enforcement
  it('enforces Document 21B invariants: SOURCE_MODIFICATION requires baseline != modified version', () => {
    const valResult = ValidationEngine.execute({
      validationType: 'SOURCE_MODIFICATION',
      baseline: baseVersion,
      modified: baseVersion, // Identical version ID!
      validationAnalysisRunId: 'val-run-001',
      scopeId: 'scope-prod-01',
    });

    expect(valResult.status).toBe('ERROR');
    expect(valResult.results[0].details).toContain('Invariant check violated');
  });

  // 8. Policy Gating: Risk Improvement with Unacceptable Capability Regression MUST FAIL
  it('FAILS validation if candidate version has unacceptable capability regression despite risk improvement', () => {
    const candidateWithRegression: AgentVersionSnapshot = {
      ...baseVersion,
      agentVersionId: 'v-1.0.1-broken-cap',
      analysisRunId: 'run-cand-201',
      sourceFiles: {
        'src/index.ts': {
          path: 'src/index.ts',
          content: 'export function processUserQuery() { return "fixed"; }',
          hash: 'hash-clean',
          sizeBytes: 50,
        },
      },
      capabilities: [], // Lost essential capability 'searchDatabase'!
      riskScore: {
        overallScore: 90,
        riskIndex: 10, // Major risk improvement (78 -> 10)
        structuralRisk: 10,
        taintVulnerabilityRisk: 5,
        toolMisuseRisk: 5,
        sandboxEvasionRisk: 5,
        policyViolationsCount: 0,
        criticalFindingsCount: 0,
        highFindingsCount: 0,
      },
    };

    const valResult = ValidationEngine.execute({
      validationType: 'SOURCE_MODIFICATION',
      baseline: baseVersion,
      modified: candidateWithRegression,
      validationAnalysisRunId: 'val-run-reg-001',
      scopeId: 'scope-prod-01',
    });

    // MUST FAIL validation because essential capability was lost!
    expect(valResult.status).toBe('FAILED');
    expect(valResult.validationDecision.passed).toBe(false);
    expect(valResult.validationDecision.verdict).toBe('REJECTED_REGRESSION');
    expect(valResult.validationDecision.capabilitiesPreserved).toBe(false);
    expect(valResult.validationDecision.riskReduced).toBe(true);
    expect(valResult.validationDecision.reason).toContain('unacceptable capability regression');
  });

  // 9. Clean Improvement PASSES Validation
  it('PASSES validation for clean candidate version with reduced risk and preserved capabilities', () => {
    const cleanCandidate: AgentVersionSnapshot = {
      ...baseVersion,
      agentVersionId: 'v-1.0.1-clean-fix',
      analysisRunId: 'run-cand-301',
      sourceFiles: {
        'src/index.ts': {
          path: 'src/index.ts',
          content: 'export function processUserQuery(input: string) { return sanitizeAndExecute(input); }',
          hash: 'hash-clean-safe',
          sizeBytes: 90,
        },
        'src/tools.ts': {
          path: 'src/tools.ts',
          content: 'export function searchDatabase(q: string) { return `Results for ${q}`; }',
          hash: 'hash-tools-v1',
          sizeBytes: 68,
        },
      },
      capabilities: [
        {
          id: 'cap-db-search',
          name: 'searchDatabase',
          type: 'DECLARED',
          category: 'TOOL_USE',
          confidence: 1.0,
          associatedTools: ['searchDatabase'],
          isEssential: true,
        },
      ],
      dependencies: {
        lodash: {
          name: 'lodash',
          version: '4.17.21', // Upgraded to non-vulnerable version
          type: 'DIRECT',
          vulnerabilities: [],
        },
      },
      permissions: [
        {
          scope: 'EXEC',
          resource: 'safe_parser',
          actions: ['EXECUTE'],
          riskLevel: 'LOW',
        },
      ],
      behaviors: [
        {
          scenarioId: 'scen-search-01',
          name: 'Execute Database Search',
          passed: true,
          toolCallsCount: 1,
          externalRequestsCount: 0,
          executionTimeMs: 110,
          outputs: { found: true },
        },
      ],
      riskScore: {
        overallScore: 95,
        riskIndex: 12, // Reduced from 78 -> 12
        structuralRisk: 10,
        taintVulnerabilityRisk: 10,
        toolMisuseRisk: 15,
        sandboxEvasionRisk: 10,
        policyViolationsCount: 0,
        criticalFindingsCount: 0,
        highFindingsCount: 0,
      },
    };

    const valResult = ValidationEngine.execute({
      validationType: 'SOURCE_MODIFICATION',
      baseline: baseVersion,
      modified: cleanCandidate,
      validationAnalysisRunId: 'val-run-clean-001',
      scopeId: 'scope-prod-01',
    });

    expect(valResult.status).toBe('PASSED');
    expect(valResult.validationDecision.passed).toBe(true);
    expect(valResult.validationDecision.verdict).toBe('APPROVED_FOR_RELEASE');
    expect(valResult.validationDecision.riskReduced).toBe(true);
    expect(valResult.validationDecision.capabilitiesPreserved).toBe(true);
    expect(valResult.validationDecision.hasCriticalViolations).toBe(false);
  });
});
