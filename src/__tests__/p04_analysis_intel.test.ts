import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDb } from '@caim/db/migrator.js';
import { PgMemDbRepositories } from '@caim/db/repositories.js';

describe('P04 Analysis, Evidence & Decision Repositories & Invariants', () => {
  let db: any;
  let repos: PgMemDbRepositories;

  const agentId = '11111111-1111-1111-1111-111111111111';
  const versionId = '22222222-2222-2222-2222-222222222222';
  const platformScopeId = '00000000-0000-0000-0000-000000000001';
  const agentEntityRefId = 'aaaaaaaa-1111-2222-3333-444444444444';
  const classId = '00000000-0000-0000-0000-000000000010';

  beforeEach(async () => {
    db = createTestDb({ applyMigrations: true, applySeed: true });
    repos = new PgMemDbRepositories(db);

    // Seed agent and agent_version
    await repos.createAgent({
      agent_id: agentId,
      canonical_name: 'AnalysisTargetAgent',
      status: 'ACTIVE',
      identity_confidence: 1.0,
    });

    await repos.createAgentVersion({
      agent_version_id: versionId,
      agent_id: agentId,
      version_label: '1.0.0',
      content_fingerprint: 'sha256:agentversionhash123',
    });

    // Create entity ref for the agent for assertions subject_ref
    db.public.none(`
      INSERT INTO core.entity_refs (entity_ref_id, entity_kind, native_id, agent_id, security_classification_id)
      VALUES ('${agentEntityRefId}', 'CANONICAL_AGENT', '${agentId}', '${agentId}', '${classId}');
    `);
  });

  it('enforces that two AnalysisRuns over one AgentVersion never overwrite each other (Invariant)', async () => {
    const run1Id = '33333333-3333-3333-3333-333333333331';
    const run2Id = '33333333-3333-3333-3333-333333333332';

    const run1 = await repos.createAnalysisRun({
      analysis_run_id: run1Id,
      agent_version_id: versionId,
      scope_id: platformScopeId,
      pipeline_version: '2.0.0',
      caim_version: '2.0.1',
      ontology_version: '2.0.1',
      trigger_type: 'MANUAL',
      status: 'PENDING',
    });

    const run2 = await repos.createAnalysisRun({
      analysis_run_id: run2Id,
      agent_version_id: versionId,
      scope_id: platformScopeId,
      pipeline_version: '2.0.1',
      caim_version: '2.0.1',
      ontology_version: '2.0.1',
      trigger_type: 'SCHEDULED',
      status: 'PENDING',
    });

    expect(run1.analysis_run_id).not.toBe(run2.analysis_run_id);

    // Create stage runs for each
    const stage1 = await repos.createStageRun({
      stage_run_id: '44444444-4444-4444-4444-444444444441',
      analysis_run_id: run1Id,
      engine_key: 'STATIC_AST',
      engine_version: '1.0.0',
      status: 'COMPLETED',
    });

    const stage2 = await repos.createStageRun({
      stage_run_id: '44444444-4444-4444-4444-444444444442',
      analysis_run_id: run2Id,
      engine_key: 'STATIC_AST',
      engine_version: '1.1.0',
      status: 'COMPLETED',
    });

    // Findings for run 1
    await repos.createStaticFinding({
      finding_id: '55555555-5555-5555-5555-555555555551',
      analysis_run_id: run1Id,
      stage_run_id: stage1.stage_run_id,
      rule_id: 'AST_NO_EVAL',
      finding_type: 'SECURITY_VULNERABILITY',
      severity: 'CRITICAL',
      confidence: 1.0,
      message: 'Eval detected in run 1',
      truthState: 'STATICALLY_DERIVED',
      sourceId: 'AST_NO_EVAL',
      analyzerVersion: '2.0.1',
      observedAt: new Date().toISOString(),
    });

    // Findings for run 2
    await repos.createStaticFinding({
      finding_id: '55555555-5555-5555-5555-555555555552',
      analysis_run_id: run2Id,
      stage_run_id: stage2.stage_run_id,
      rule_id: 'AST_CLEAN',
      finding_type: 'CODE_SMELL',
      severity: 'LOW',
      confidence: 0.9,
      message: 'Clean in run 2',
      truthState: 'STATICALLY_DERIVED',
      sourceId: 'AST_CLEAN',
      analyzerVersion: '2.0.1',
      observedAt: new Date().toISOString(),
    });

    const findingsRun1 = await repos.getStaticFindings(run1Id);
    const findingsRun2 = await repos.getStaticFindings(run2Id);

    expect(findingsRun1).toHaveLength(1);
    expect(findingsRun1[0].message).toBe('Eval detected in run 1');

    expect(findingsRun2).toHaveLength(1);
    expect(findingsRun2[0].message).toBe('Clean in run 2');

    const allRuns = await repos.getAnalysisRunsByAgentVersion(versionId);
    expect(allRuns).toHaveLength(2);
  });

  it('creates and queries static analysis findings, callgraph, taint flows, SBOM, and runtime events', async () => {
    const runId = 'aaaaaaaa-1111-1111-1111-111111111111';
    const stageId = 'bbbbbbbb-1111-1111-1111-111111111111';

    await repos.createAnalysisRun({
      analysis_run_id: runId,
      agent_version_id: versionId,
      scope_id: platformScopeId,
      pipeline_version: '2.0.1',
      caim_version: '2.0.1',
      ontology_version: '2.0.1',
      trigger_type: 'MANUAL',
      status: 'RUNNING',
    });

    await repos.createStageRun({
      stage_run_id: stageId,
      analysis_run_id: runId,
      engine_key: 'CONTROL_FLOW',
      engine_version: '2.0.0',
      status: 'RUNNING',
    });

    // 1. CallGraph
    const nodeA = await repos.createCallGraphNode({
      node_id: 'cccccccc-1111-1111-1111-111111111111',
      analysis_run_id: runId,
      stage_run_id: stageId,
      symbol_name: 'handleUserInput',
      node_type: 'FUNCTION',
      qualified_name: 'src/handler.ts:handleUserInput',
    });

    const nodeB = await repos.createCallGraphNode({
      node_id: 'cccccccc-2222-2222-2222-222222222222',
      analysis_run_id: runId,
      stage_run_id: stageId,
      symbol_name: 'executeCommand',
      node_type: 'FUNCTION',
      qualified_name: 'src/exec.ts:executeCommand',
    });

    await repos.createCallGraphEdge({
      edge_id: 'dddddddd-1111-1111-1111-111111111111',
      analysis_run_id: runId,
      caller_node_id: nodeA.node_id,
      callee_node_id: nodeB.node_id,
      call_type: 'DIRECT',
    });

    const graph = await repos.getCallGraph(runId);
    expect(graph.nodes).toHaveLength(2);
    expect(graph.edges).toHaveLength(1);
    expect(graph.edges[0].caller_node_id).toBe(nodeA.node_id);
    expect(graph.edges[0].callee_node_id).toBe(nodeB.node_id);

    // 2. TaintFlow
    const flow = await repos.createTaintFlow({
      taint_flow_id: 'eeeeeeee-1111-1111-1111-111111111111',
      analysis_run_id: runId,
      stage_run_id: stageId,
      source_type: 'HTTP_REQUEST_PARAM',
      sink_type: 'CHILD_PROCESS_EXEC',
      confidence: 0.95,
      path_summary: 'req.body.cmd -> sanitize() [INSUFFICIENT] -> exec()',
    });
    expect(flow.source_type).toBe('HTTP_REQUEST_PARAM');

    const taintFlows = await repos.getTaintFlows(runId);
    expect(taintFlows).toHaveLength(1);

    // 3. SBOM components and dependencies
    const comp1 = await repos.createSbomComponent({
      sbom_component_id: 'ffffffff-1111-1111-1111-111111111111',
      analysis_run_id: runId,
      stage_run_id: stageId,
      purl: 'pkg:npm/lodash@4.17.20',
      name: 'lodash',
      version: '4.17.20',
      ecosystem: 'npm',
      license_expression: 'MIT',
    });

    const comp2 = await repos.createSbomComponent({
      sbom_component_id: 'ffffffff-2222-2222-2222-222222222222',
      analysis_run_id: runId,
      stage_run_id: stageId,
      purl: 'pkg:npm/express@4.18.2',
      name: 'express',
      version: '4.18.2',
      ecosystem: 'npm',
      license_expression: 'MIT',
    });

    await repos.createSbomDependency({
      sbom_dependency_id: '12121212-1111-1111-1111-111111111111',
      analysis_run_id: runId,
      parent_component_id: comp2.sbom_component_id,
      child_component_id: comp1.sbom_component_id,
      dependency_scope: 'RUNTIME',
    });

    const sbom = await repos.getSbom(runId);
    expect(sbom.components).toHaveLength(2);
    expect(sbom.dependencies).toHaveLength(1);

    // 4. Runtime Events
    await repos.createRuntimeEvent({
      runtime_event_id: '34343434-1111-1111-1111-111111111111',
      analysis_run_id: runId,
      stage_run_id: stageId,
      event_type: 'NETWORK_OUTBOUND',
      duration_ms: 124,
      source_locator: 'https://api.unknown-endpoint.org/telemetry',
      payload: { method: 'POST', bytes_sent: 4096 },
      status: 'RECORDED',
      truthState: 'OBSERVED',
      sourceId: 'https://api.unknown-endpoint.org/telemetry',
      analyzerVersion: '2.0.1',
      observedAt: new Date().toISOString(),
      confidence: 1.0,
    });

    const events = await repos.getRuntimeEvents(runId);
    expect(events).toHaveLength(1);
    expect(events[0].event_type).toBe('NETWORK_OUTBOUND');
  });

  it('builds full Evidence -> Assertion -> Claim hierarchy with support links and contradictions', async () => {
    const runId = '10101010-1111-1111-1111-111111111111';
    const stageId = '20202020-1111-1111-1111-111111111111';

    await repos.createAnalysisRun({
      analysis_run_id: runId,
      agent_version_id: versionId,
      scope_id: platformScopeId,
      pipeline_version: '2.0.1',
      caim_version: '2.0.1',
      ontology_version: '2.0.1',
      trigger_type: 'MANUAL',
      status: 'RUNNING',
    });

    await repos.createStageRun({
      stage_run_id: stageId,
      analysis_run_id: runId,
      engine_key: 'SEMANTIC_REASONER',
      engine_version: '1.0.0',
      status: 'RUNNING',
    });

    // 1. External Intel
    const intel = await repos.createExternalIntelRef({
      intel_ref_id: '30303030-1111-1111-1111-111111111111',
      source_name: 'NVD',
      external_id: 'CVE-2021-23337',
      title: 'Command Injection in Lodash',
      severity: 'HIGH',
      cvss_score: 7.2,
      epss_score: 0.85,
    });
    expect(intel.external_id).toBe('CVE-2021-23337');

    // 2. Finding
    const finding = await repos.createStaticFinding({
      finding_id: '40404040-1111-1111-1111-111111111111',
      analysis_run_id: runId,
      stage_run_id: stageId,
      rule_id: 'SEC_UNVETTED_EXEC',
      finding_type: 'SECURITY_VULNERABILITY',
      severity: 'CRITICAL',
      confidence: 0.95,
      message: 'Unvetted command execution detected in tool dispatch',
      truthState: 'STATICALLY_DERIVED',
      sourceId: 'SEC_UNVETTED_EXEC',
      analyzerVersion: '2.0.1',
      observedAt: new Date().toISOString(),
    });

    // 3. Evidence pointing to finding and intel
    const ev1 = await repos.createEvidence({
      evidence_id: '50505050-1111-1111-1111-111111111111',
      analysis_run_id: runId,
      stage_run_id: stageId,
      evidence_type: 'STATIC_CODE',
      static_finding_id: finding.finding_id,
      description: 'Static AST finding confirms shell execution',
      confidence: 0.95,
      weight: 1.0,
      truthState: 'OBSERVED',
      sourceId: 'SEC_UNVETTED_EXEC',
      analyzerVersion: '2.0.1',
      observedAt: new Date().toISOString(),
    });
    expect((ev1 as any).scope_id).toBe(platformScopeId);

    const ev2 = await repos.createEvidence({
      evidence_id: '50505050-2222-2222-2222-222222222222',
      analysis_run_id: runId,
      stage_run_id: stageId,
      evidence_type: 'EXTERNAL_INTEL',
      external_intel_ref_id: intel.intel_ref_id,
      description: 'Known CVE vulnerability matching installed library',
      confidence: 1.0,
      weight: 0.9,
      truthState: 'EXTERNAL',
      sourceId: 'CVE-2021-23337',
      analyzerVersion: '2.0.1',
      observedAt: new Date().toISOString(),
    });
    expect((ev2 as any).scope_id).toBe(platformScopeId);

    // 4. Assertion backed by evidence
    const assertion1 = await repos.createAssertion({
      assertion_id: '60606060-1111-1111-1111-111111111111',
      analysis_run_id: runId,
      stage_run_id: stageId,
      assertion_key: 'CAN_EXECUTE_ARBITRARY_COMMANDS',
      predicate: 'CAPABLE_OF',
      subject_ref_id: agentEntityRefId,
      assertion_value: 'Arbitrary Shell Execution',
      confidence: 0.95,
      uncertainty_score: 0.05,
      calibration_version: '2.0.1',
      engine_key: 'SEMANTIC_REASONER',
    });
    expect((assertion1 as any).scope_id).toBe(platformScopeId);

    // Link assertion to evidence
    await repos.linkAssertionEvidence({
      link_id: '70707070-1111-1111-1111-111111111111',
      assertion_id: assertion1.assertion_id,
      evidence_id: ev1.evidence_id,
      relationship_type: 'SUPPORTS',
      relevance_weight: 1.0,
    });

    const assertionEv = await repos.getEvidenceForAssertion(assertion1.assertion_id);
    expect(assertionEv).toHaveLength(1);
    expect(assertionEv[0].evidence_id).toBe(ev1.evidence_id);

    // 5. Claim supported by Assertion and direct Evidence
    const claim = await repos.createClaim({
      claim_id: '80808080-1111-1111-1111-111111111111',
      analysis_run_id: runId,
      claim_type: 'CAPABILITY',
      claim_text: 'The agent possesses unconstrained shell execution privileges vulnerable to prompt injection.',
      state: 'SUPPORTED',
      confidence: 0.94,
      uncertainty_score: 0.06,
      truthState: 'INFERRED',
      sourceId: 'SEMANTIC_REASONER',
      analyzerVersion: '2.0.1',
      observedAt: new Date().toISOString(),
    });
    expect((claim as any).scope_id).toBe(platformScopeId);

    // Link claim to assertion
    await repos.linkClaimAssertion({
      link_id: '90909090-1111-1111-1111-111111111111',
      claim_id: claim.claim_id,
      assertion_id: assertion1.assertion_id,
      link_type: 'SUPPORTS',
    });

    // Link claim to direct CVE evidence
    await repos.linkClaimEvidence({
      link_id: '90909090-2222-2222-2222-222222222222',
      claim_id: claim.claim_id,
      evidence_id: ev2.evidence_id,
      support_type: 'DIRECT_SUPPORT',
      weight: 0.9,
    });

    // 6. Contradiction
    const claimCounter = await repos.createClaim({
      claim_id: '80808080-2222-2222-2222-222222222222',
      analysis_run_id: runId,
      claim_type: 'CAPABILITY',
      claim_text: 'The agent operates strictly in a read-only sandboxed sandbox without write capabilities.',
      state: 'CONTESTED',
      confidence: 0.3,
      uncertainty_score: 0.7,
      truthState: 'USER_DECLARED',
      sourceId: 'MANIFEST_SPEC',
      analyzerVersion: '2.0.1',
      observedAt: new Date().toISOString(),
    });

    const contradiction = await repos.createContradiction({
      contradiction_id: 'a1a1a1a1-1111-1111-1111-111111111111',
      analysis_run_id: runId,
      claim_a_id: claim.claim_id,
      claim_b_id: claimCounter.claim_id,
      conflict_reason: 'Shell execution capability contradicts claim of read-only sandbox restriction',
      severity: 'CRITICAL',
      resolution_status: 'UNRESOLVED',
    });
    expect(contradiction.severity).toBe('CRITICAL');

    // 7. Backward Lineage Resolution Test
    const lineageTree = await repos.resolveBackwardLineage(claim.claim_id);
    expect(lineageTree).not.toBeNull();
    expect(lineageTree?.claim.claim_id).toBe(claim.claim_id);
    expect(lineageTree?.assertions).toHaveLength(1);
    expect(lineageTree?.assertions[0].assertion.assertion_key).toBe('CAN_EXECUTE_ARBITRARY_COMMANDS');
    expect(lineageTree?.assertions[0].evidence).toHaveLength(1);
    expect(lineageTree?.assertions[0].evidence[0].finding?.rule_id).toBe('SEC_UNVETTED_EXEC');
    expect(lineageTree?.directEvidence).toHaveLength(1);
    expect(lineageTree?.directEvidence[0].evidence.evidence_id).toBe(ev2.evidence_id);
  });

  it('manages risks, multi-dimensional scoring, policy decisions with reasons, recommendations and use cases', async () => {
    const runId = 'b2b2b2b2-1111-1111-1111-111111111111';

    await repos.createAnalysisRun({
      analysis_run_id: runId,
      agent_version_id: versionId,
      scope_id: platformScopeId,
      pipeline_version: '2.0.1',
      caim_version: '2.0.1',
      ontology_version: '2.0.1',
      trigger_type: 'MANUAL',
      status: 'COMPLETED',
    });

    // 1. Risk
    const risk = await repos.createRisk({
      risk_id: 'c3c3c3c3-1111-1111-1111-111111111111',
      analysis_run_id: runId,
      risk_type: 'SECURITY',
      title: 'Remote Code Execution via Prompt Injection',
      description: 'Host commands can be influenced by untrusted input strings.',
      severity: 'CRITICAL',
      likelihood: 0.9,
      impact: 0.95,
      risk_score: 0.855,
      remediation_guidance: 'Enforce strict schema validation and remove shell access.',
    });
    expect(risk.severity).toBe('CRITICAL');

    // 2. Score Model & Dimensions
    const scoreModel = await repos.createScoreModel({
      score_model_id: 'd4d4d4d4-1111-1111-1111-111111111111',
      model_key: 'CAIM_RISK_INDEX',
      version: '2.0.0',
      formula_type: 'WEIGHTED_DIMENSIONAL',
      status: 'ACTIVE',
    });

    const dimSecurity = await repos.createScoreDimension({
      dimension_id: 'e5e5e5e5-1111-1111-1111-111111111111',
      score_model_id: scoreModel.score_model_id,
      dimension_key: 'SECURITY_POSTURE',
      display_name: 'Security Posture',
      weight: 0.6,
    });

    const dimQuality = await repos.createScoreDimension({
      dimension_id: 'e5e5e5e5-2222-2222-2222-222222222222',
      score_model_id: scoreModel.score_model_id,
      dimension_key: 'CODE_QUALITY',
      display_name: 'Code Quality',
      weight: 0.4,
    });

    const scoreResult = await repos.createScoreResult({
      score_result_id: 'f6f6f6f6-1111-1111-1111-111111111111',
      analysis_run_id: runId,
      score_model_id: scoreModel.score_model_id,
      overall_score: 42.5,
      grade: 'D',
      calibration_version: '2.0.0',
    });

    await repos.createScoreDimensionValue({
      score_dimension_value_id: 'a7a7a7a7-1111-1111-1111-111111111111',
      score_result_id: scoreResult.score_result_id,
      dimension_id: dimSecurity.dimension_id,
      raw_value: 30.0,
      weighted_value: 18.0,
    });

    await repos.createScoreDimensionValue({
      score_dimension_value_id: 'a7a7a7a7-2222-2222-2222-222222222222',
      score_result_id: scoreResult.score_result_id,
      dimension_id: dimQuality.dimension_id,
      raw_value: 61.25,
      weighted_value: 24.5,
    });

    const fetchedScore = await repos.getScoreResult(runId, scoreModel.score_model_id);
    expect(fetchedScore).not.toBeNull();
    expect(Number(fetchedScore?.overall_score)).toBe(42.5);

    // 3. Policy & Decision with Reasons
    const policy = await repos.createPolicyVersion({
      policy_version_id: 'b8b8b8b8-1111-1111-1111-111111111111',
      policy_key: 'ENTERPRISE_DEPLOYMENT_GATE',
      version: '1.0.0',
      name: 'Enterprise Deployment Gate',
      status: 'ACTIVE',
    });

    const rule = await repos.createPolicyRule({
      rule_id: 'c9c9c9c9-1111-1111-1111-111111111111',
      policy_version_id: policy.policy_version_id,
      rule_key: 'NO_CRITICAL_RISKS',
      rule_name: 'No Critical Risks Allowed',
      severity: 'CRITICAL',
      condition_expression: 'risks.filter(r => r.severity == "CRITICAL").length == 0',
    });

    const decision = await repos.createPolicyDecision({
      decision_id: 'd0d0d0d0-1111-1111-1111-111111111111',
      analysis_run_id: runId,
      policy_version_id: policy.policy_version_id,
      decision: 'FAIL',
      evaluation_summary: 'Blocked due to critical remote code execution vulnerability.',
    });

    await repos.createPolicyDecisionReason({
      reason_id: 'e1e1e1e1-1111-1111-1111-111111111111',
      decision_id: decision.decision_id,
      rule_id: rule.rule_id,
      risk_id: risk.risk_id,
      reason_text: 'Rule NO_CRITICAL_RISKS failed: 1 critical risk detected.',
      is_blocking: true,
    });

    const fetchedDecision = await repos.getPolicyDecision(runId, policy.policy_version_id);
    expect(fetchedDecision?.decision).toBe('FAIL');

    // 4. Recommendation
    await repos.createRecommendation({
      recommendation_id: 'f2f2f2f2-1111-1111-1111-111111111111',
      analysis_run_id: runId,
      risk_id: risk.risk_id,
      recommendation_type: 'REMEDIATION',
      title: 'Deprecate raw child_process invocations',
      action_steps: 'Replace child_process.exec with sandboxed runtime invocation API.',
      priority: 'P0',
      effort_estimate: 'MEDIUM',
    });

    const recs = await repos.getRecommendationsForRun(runId);
    expect(recs).toHaveLength(1);
    expect(recs[0].priority).toBe('P0');

    // 5. Use Case Evaluation
    const useCase = await repos.createUseCase({
      use_case_id: 'a3a3a3a3-1111-1111-1111-111111111111',
      use_case_key: 'CUSTOMER_FACING_CHAT',
      title: 'Customer-Facing Chatbot',
      description: 'Autonomous assistant interacting directly with external end-users.',
      category: 'ENTERPRISE_SUPPORT',
    });

    await repos.createUseCaseEvaluation({
      evaluation_id: 'b4b4b4b4-1111-1111-1111-111111111111',
      analysis_run_id: runId,
      use_case_id: useCase.use_case_id,
      suitability: 'DISAPPROVED',
      suitability_score: 0.15,
      justification: 'High risk of prompt injection and arbitrary command execution.',
    });

    const evaluations = await repos.getUseCaseEvaluationsForRun(runId);
    expect(evaluations).toHaveLength(1);
    expect(evaluations[0].suitability).toBe('DISAPPROVED');
  });
});
