import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDb } from '@caim/db/migrator.js';
import { PgMemDbRepositories } from '@caim/db/repositories.js';

describe('P05 Knowledge, Lifecycle, Operations & Audit Invariant Verification', () => {
  let db: any;
  let repo: PgMemDbRepositories;

  const tenantId = '11111111-1111-1111-1111-111111111111';
  const orgScopeId = '22222222-2222-2222-2222-222222222222';
  const platformScopeId = '33333333-3333-3333-3333-333333333333';
  const classificationId = '44444444-4444-4444-4444-444444444444';

  const agentId = '55555555-5555-5555-5555-555555555555';
  const baselineVersionId = '66666666-6666-6666-6666-666666666666';
  const modifiedVersionId = '77777777-7777-7777-7777-777777777777';

  const baselineRunId = '88888888-8888-8888-8888-888888888888';
  const modifiedRunId = '99999999-9999-9999-9999-999999999999';
  const validationAnalysisRunId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';

  beforeEach(async () => {
    // Rehearse clean rebuild from empty database
    db = createTestDb({ applyMigrations: true, applySeed: false });
    repo = new PgMemDbRepositories(db);

    // Bootstrap base security & classification context
    await repo.createTenant({
      tenant_id: tenantId,
      tenant_key: 'acme-corp',
      display_name: 'Acme Corporation',
      status: 'ACTIVE',
    });

    await repo.createAccessScope({
      scope_id: orgScopeId,
      scope_type: 'ORGANIZATION',
      tenant_id: tenantId,
    });

    await repo.createAccessScope({
      scope_id: platformScopeId,
      scope_type: 'PLATFORM',
      tenant_id: null,
    });

    db.public.none(`
      INSERT INTO security.security_classifications (security_classification_id, code, rank, description)
      VALUES ('${classificationId}', 'INTERNAL', 20, 'Internal security classification');
    `);

    // Bootstrap baseline and modified canonical agents and versions
    await repo.createAgent({
      agent_id: agentId,
      canonical_name: 'acme/financial-assistant',
      status: 'ACTIVE',
      identity_confidence: 1.0,
    });

    await repo.createAgentVersion({
      agent_version_id: baselineVersionId,
      agent_id: agentId,
      version_label: '1.0.0',
      content_fingerprint: 'sha256:baseline1111111111111111111111111111111111111111111111111111111111111111',
    });

    await repo.createAgentVersion({
      agent_version_id: modifiedVersionId,
      agent_id: agentId,
      version_label: '1.1.0',
      content_fingerprint: 'sha256:modified2222222222222222222222222222222222222222222222222222222222222222',
    });

    // Create Analysis Runs corresponding to baseline, modified, and validation
    await repo.createAnalysisRun({
      analysis_run_id: baselineRunId,
      agent_version_id: baselineVersionId,
      scope_id: orgScopeId,
      pipeline_version: '2.0.1',
      caim_version: '2.0.1',
      ontology_version: '2.0.1',
      trigger_type: 'MANUAL',
      status: 'COMPLETED',
    });

    await repo.createAnalysisRun({
      analysis_run_id: modifiedRunId,
      agent_version_id: modifiedVersionId,
      scope_id: orgScopeId,
      pipeline_version: '2.0.1',
      caim_version: '2.0.1',
      ontology_version: '2.0.1',
      trigger_type: 'MANUAL',
      status: 'COMPLETED',
    });

    await repo.createAnalysisRun({
      analysis_run_id: validationAnalysisRunId,
      agent_version_id: modifiedVersionId,
      scope_id: orgScopeId,
      pipeline_version: '2.0.1',
      caim_version: '2.0.1',
      ontology_version: '2.0.1',
      trigger_type: 'VALIDATION_REPLAY',
      status: 'COMPLETED',
    });
  });

  it('enforces ValidationRun locked V2.0.1 shape and composite FK constraints (Document 21B)', async () => {
    const validValidationRunId = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';

    // 1. Valid ValidationRun referencing exact (baseline_analysis_run_id, baseline_agent_version_id)
    const validRun = await repo.createValidationRun({
      validation_run_id: validValidationRunId,
      validation_type: 'SOURCE_MODIFICATION',
      baseline_agent_version_id: baselineVersionId,
      modified_agent_version_id: modifiedVersionId,
      baseline_analysis_run_id: baselineRunId,
      modified_analysis_run_id: modifiedRunId,
      validation_analysis_run_id: validationAnalysisRunId,
      validation_plan_version: 'v2.0.1-standard',
      scope_id: orgScopeId,
      status: 'PASSED',
    });

    expect(validRun.validation_run_id).toBe(validValidationRunId);
    expect(validRun.validation_type).toBe('SOURCE_MODIFICATION');
    expect(validRun.scope_id).toBe(orgScopeId);

    // 2. Invalid composite FK: Swapped agent versions and analysis runs must fail FK check
    const invalidValidationRunId = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
    await expect(
      repo.createValidationRun({
        validation_run_id: invalidValidationRunId,
        validation_type: 'SOURCE_MODIFICATION',
        baseline_agent_version_id: modifiedVersionId, // MISMATCH: baselineRunId belongs to baselineVersionId, not modifiedVersionId!
        modified_agent_version_id: baselineVersionId, // MISMATCH: modifiedRunId belongs to modifiedVersionId, not baselineVersionId!
        baseline_analysis_run_id: baselineRunId,
        modified_analysis_run_id: modifiedRunId,
        validation_analysis_run_id: validationAnalysisRunId,
        validation_plan_version: 'v2.0.1-standard',
        scope_id: orgScopeId,
        status: 'PENDING',
      })
    ).rejects.toThrow();

    // 3. Invalid validation_type must fail CHECK constraint
    await expect(
      repo.createValidationRun({
        validation_run_id: 'cccccccc-dddd-eeee-ffff-000000000001',
        validation_type: 'INVALID_TYPE' as any,
        baseline_agent_version_id: baselineVersionId,
        modified_agent_version_id: modifiedVersionId,
        baseline_analysis_run_id: baselineRunId,
        modified_analysis_run_id: modifiedRunId,
        validation_analysis_run_id: validationAnalysisRunId,
        validation_plan_version: 'v2.0.1-standard',
        scope_id: orgScopeId,
        status: 'PENDING',
      })
    ).rejects.toThrow();

    // 4. SOURCE_MODIFICATION with identical baseline and modified agent version must fail invariant CHECK
    await expect(
      repo.createValidationRun({
        validation_run_id: 'cccccccc-dddd-eeee-ffff-000000000002',
        validation_type: 'SOURCE_MODIFICATION',
        baseline_agent_version_id: baselineVersionId,
        modified_agent_version_id: baselineVersionId, // Same version invalid for SOURCE_MODIFICATION!
        baseline_analysis_run_id: baselineRunId,
        modified_analysis_run_id: baselineRunId,
        validation_analysis_run_id: validationAnalysisRunId,
        validation_plan_version: 'v2.0.1-standard',
        scope_id: orgScopeId,
        status: 'PENDING',
      })
    ).rejects.toThrow();

    // 5. Validation results attachment
    const valResult = await repo.createValidationResult({
      validation_result_id: 'dddddddd-dddd-dddd-dddd-dddddddddddd',
      validation_run_id: validValidationRunId,
      result_type: 'SECURITY_REGRESSION_CHECK',
      status: 'PASSED',
      before_value: { vulnerabilities: 0 },
      after_value: { vulnerabilities: 0 },
    });

    expect(valResult.status).toBe('PASSED');
  });

  it('verifies Knowledge Graph, Projections, Chunks, Embeddings, and derivative purge invariant', async () => {
    // 1. Create Core Entity Ref
    const entityRefId = 'e0000000-0000-0000-0000-000000000001';
    db.public.none(`
      INSERT INTO core.entity_refs (entity_ref_id, entity_kind, native_id, agent_id, agent_version_id, analysis_run_id, security_classification_id)
      VALUES ('${entityRefId}', 'AGENT_VERSION', '${baselineVersionId}', '${agentId}', '${baselineVersionId}', '${baselineRunId}', '${classificationId}');
    `);

    // 2. Create authoritative Evidence tied to AnalysisRun
    const evidenceId = 'e0000000-0000-0000-0000-000000000002';
    await repo.createEvidence({
      evidence_id: evidenceId,
      analysis_run_id: baselineRunId,
      entity_ref_id: entityRefId,
      evidence_type: 'AST_MATCH',
      description: 'AST match for agent capabilities',
      confidence: 1.0,
      weight: 1.0,
      truthState: 'OBSERVED',
      sourceId: 'AST_MATCHER',
      analyzerVersion: '2.0.1',
      observedAt: new Date().toISOString(),
    });

    // 3. Create derivative KnowledgeObject, Projections, Chunks, Embeddings, IndexState
    const knowledgeObjectId = 'e0000000-0000-0000-0000-000000000003';
    await repo.createKnowledgeObject({
      knowledge_object_id: knowledgeObjectId,
      entity_ref_id: entityRefId,
      object_type: 'AGENT_DOCUMENTATION',
      agent_id: agentId,
      agent_version_id: baselineVersionId,
      analysis_run_id: baselineRunId,
      security_classification_id: classificationId,
      projection_version: '1.0.0',
    });

    const projectionId = 'e0000000-0000-0000-0000-000000000004';
    await repo.createKnowledgeProjection({
      knowledge_projection_id: projectionId,
      knowledge_object_id: knowledgeObjectId,
      projection_type: 'MARKDOWN_SUMMARY',
      projection_version: '1.0.0',
      payload: { summary: 'Financial assistant agent version 1.0.0' },
      stale: false,
    });

    const chunkId = 'e0000000-0000-0000-0000-000000000005';
    await repo.createKnowledgeChunk({
      knowledge_chunk_id: chunkId,
      knowledge_projection_id: projectionId,
      sequence: 1,
      content_hash: 'sha256:chunkhash123',
      text_or_locator: 'Financial assistant handles tax and accounting requests securely.',
      token_count: 10,
      security_classification_id: classificationId,
    });

    const embeddingId = 'e0000000-0000-0000-0000-000000000006';
    await repo.createEmbedding({
      embedding_id: embeddingId,
      knowledge_chunk_id: chunkId,
      embedding_model_version: 'text-embedding-004',
      dimensions: 768,
      vector: '[0.012, -0.045, 0.891]',
    });

    await repo.createIndexState({
      index_state_id: 'e0000000-0000-0000-0000-000000000007',
      knowledge_object_id: knowledgeObjectId,
      index_type: 'HNSW_COSINE',
      index_version: 'v1',
      source_version_hash: 'sha256:chunkhash123',
      stale: false,
    });

    // 4. Create Query, Query Plan, Retrieval Run, Answer, Claims, Citations, Grounding Results
    const querySessionId = 'e0000000-0000-0000-0000-000000000008';
    await repo.createQuerySession({
      query_session_id: querySessionId,
      principal_id: 'user_123',
      access_context_hash: 'sha256:context123',
    });

    const queryId = 'e0000000-0000-0000-0000-000000000009';
    await repo.createQuery({
      query_id: queryId,
      query_session_id: querySessionId,
      principal_id: 'user_123',
      query_text_or_hash: 'What are the capabilities of Financial Assistant?',
      intent_type: 'CAPABILITY_QUERY',
      security_classification_id: classificationId,
    });

    const queryPlanId = 'e0000000-0000-0000-0000-00000000000a';
    await repo.createQueryPlan({
      query_plan_id: queryPlanId,
      query_id: queryId,
      planner_version: 'v1.0',
      plan_payload: { maxHops: 2 },
    });

    const retrievalRunId = 'e0000000-0000-0000-0000-00000000000b';
    await repo.createRetrievalRun({
      retrieval_run_id: retrievalRunId,
      query_plan_id: queryPlanId,
      retrieval_type: 'HYBRID_VECTOR_KEYWORD',
      status: 'COMPLETED',
    });

    await repo.createRetrievalResult({
      retrieval_result_id: 'e0000000-0000-0000-0000-00000000000c',
      retrieval_run_id: retrievalRunId,
      knowledge_object_id: knowledgeObjectId,
      rank: 1,
      score: 0.9421,
      retrieval_method: 'VECTOR_SIMILARITY',
      authorized: true,
    });

    const contextPkgId = 'e0000000-0000-0000-0000-00000000000d';
    await repo.createContextPackage({
      context_package_id: contextPkgId,
      query_id: queryId,
      assembler_version: 'v1.0',
      content_hash: 'sha256:ctx123',
      token_count: 50,
    });

    const answerId = 'e0000000-0000-0000-0000-00000000000e';
    await repo.createAnswer({
      answer_id: answerId,
      query_id: queryId,
      context_package_id: contextPkgId,
      model_version: 'gemini-2.5-flash',
      prompt_version: 'v1.0',
      answer_text_or_locator: 'Financial Assistant provides automated bookkeeping and tax prep.',
      status: 'COMPLETED',
    });

    const answerClaimId = 'e0000000-0000-0000-0000-00000000000f';
    await repo.createAnswerClaim({
      answer_claim_id: answerClaimId,
      answer_id: answerId,
      sequence: 1,
      claim_text: 'Financial Assistant handles tax preparation.',
      grounding_state: 'GROUNDED',
      confidence: 0.99,
      truthState: 'INFERRED',
      sourceId: answerId,
      analyzerVersion: '2.0.1',
      observedAt: new Date().toISOString(),
    });

    await repo.createCitation({
      citation_id: 'e0000000-0000-0000-0000-000000000010',
      answer_id: answerId,
      answer_claim_id: answerClaimId,
      target_entity_ref_id: entityRefId,
      citation_type: 'DIRECT_QUOTE',
      locator_payload: { chunkId },
      sequence: 1,
    });

    await repo.createGroundingResult({
      grounding_result_id: 'e0000000-0000-0000-0000-000000000011',
      answer_id: answerId,
      grounding_ruleset_version: 'v1.0',
      supported_claims: 1,
      unsupported_claims: 0,
      contradiction_count: 0,
      verdict: 'PASSED',
    });

    // 5. INVARIANT TEST: Purge derivative knowledge projections/embeddings
    const purgeResult = await repo.purgeDerivativeKnowledge(entityRefId);
    expect(purgeResult.deletedObjects).toBe(1);

    // KnowledgeObject, projections, chunks, embeddings must be gone (cascade)
    const fetchedKnowledgeObj = await repo.getKnowledgeObject(knowledgeObjectId);
    expect(fetchedKnowledgeObj).toBeNull();

    const remainingChunks = db.public.many(`SELECT * FROM knowledge.knowledge_chunks WHERE knowledge_chunk_id = '${chunkId}';`);
    expect(remainingChunks).toHaveLength(0);

    const remainingEmbeddings = db.public.many(`SELECT * FROM knowledge.embeddings WHERE embedding_id = '${embeddingId}';`);
    expect(remainingEmbeddings).toHaveLength(0);

    // BUT Authoritative Core EntityRef and Evidence MUST REMAIN UNTOUCHED!
    const remainingEvidence = await repo.getEvidenceById(evidenceId);
    expect(remainingEvidence).not.toBeNull();
    expect(remainingEvidence?.evidence_id).toBe(evidenceId);

    const remainingEntityRef = db.public.one(`SELECT * FROM core.entity_refs WHERE entity_ref_id = '${entityRefId}';`);
    expect(remainingEntityRef).not.toBeNull();
  });

  it('verifies Workflows, Queued Jobs, DLQ, Outbox, and Audit Logs', async () => {
    // 1. Workflow Definition and Workflow Run
    const wfDef = await repo.createWorkflowDefinition({
      workflow_definition_id: 'f0000000-0000-0000-0000-000000000001',
      workflow_key: 'FULL_VALIDATION_PIPELINE',
      version: '1.0.0',
      status: 'ACTIVE',
      definition_payload: { steps: ['INGEST', 'STATIC_ANALYSIS', 'VALIDATE', 'PACKAGE'] },
    });

    const wfRun = await repo.createWorkflowRun({
      workflow_run_id: 'f0000000-0000-0000-0000-000000000002',
      workflow_definition_id: wfDef.workflow_definition_id,
      agent_id: agentId,
      agent_version_id: modifiedVersionId,
      analysis_run_id: modifiedRunId,
      status: 'RUNNING',
      correlation_id: 'corr-pipeline-12345',
    });

    expect(wfRun.status).toBe('RUNNING');

    // 2. Job and Job Attempt
    const job = await repo.createJob({
      job_id: 'f0000000-0000-0000-0000-000000000003',
      workflow_run_id: wfRun.workflow_run_id,
      queue_key: 'analysis-heavy',
      idempotency_key: 'idemp-job-12345',
      priority: 20,
      status: 'RUNNING',
      payload: { step: 'STATIC_ANALYSIS' },
    });

    const attempt = await repo.createJobAttempt({
      job_attempt_id: 'f0000000-0000-0000-0000-000000000004',
      job_id: job.job_id,
      attempt_no: 1,
      worker_id: 'worker-node-1',
      failure_class: 'TRANSIENT_TIMEOUT',
      failure_code: 'ERR_TIMEOUT',
      error_message: 'Analysis stage execution timed out after 30000ms',
    });

    expect(attempt.attempt_no).toBe(1);

    // 3. Dead Letter Job recording
    const dlj = await repo.createDeadLetterJob({
      dead_letter_job_id: 'f0000000-0000-0000-0000-000000000005',
      job_id: job.job_id,
      final_failure_code: 'MAX_RETRIES_EXCEEDED',
      resolution_state: 'UNRESOLVED',
    });

    expect(dlj.resolution_state).toBe('UNRESOLVED');

    // 4. Outbox Event and Delivery
    const outboxEvt = await repo.createOutboxEvent({
      event_id: 'f0000000-0000-0000-0000-000000000006',
      event_type: 'AGENT_VERSION_VALIDATED',
      payload: { agent_version_id: modifiedVersionId, status: 'PASSED' },
      schema_version: '1.0.0',
      correlation_id: 'corr-pipeline-12345',
      status: 'PENDING',
    });

    const delivery = await repo.createOutboxDelivery({
      delivery_id: 'f0000000-0000-0000-0000-000000000007',
      event_id: outboxEvt.event_id,
      target_subscriber: 'webhook-endpoint-ci',
      status: 'DELIVERED',
      attempt_count: 1,
      delivered_at: new Date().toISOString(),
      last_error: null,
    });

    expect(delivery.status).toBe('DELIVERED');

    // 5. Immutable Audit Event
    const auditEvt = await repo.createAuditEvent({
      audit_event_id: 'f0000000-0000-0000-0000-000000000008',
      principal_or_service_id: 'service:validator-runtime',
      action: 'APPROVE_VALIDATION_RELEASE',
      outcome: 'SUCCESS',
      correlation_id: 'corr-pipeline-12345',
      metadata: { target_agent: 'acme/financial-assistant', version: '1.1.0' },
    });

    expect(auditEvt.outcome).toBe('SUCCESS');

    const auditLogs = await repo.getAuditEvents();
    expect(auditLogs.length).toBeGreaterThanOrEqual(1);
  });

  it('verifies Evaluation Runs, Golden Corpus, and Cost Usage Events', async () => {
    // 1. Evaluation Dataset & Case
    const dataset = await repo.createEvaluationDataset({
      evaluation_dataset_id: 'e1000000-0000-0000-0000-000000000001',
      name: 'Agent Security Benchmark',
      version: '2026.1',
      scope: 'SYSTEM',
      status: 'ACTIVE',
    });

    const evalCase = await repo.createEvaluationCase({
      evaluation_case_id: 'e1000000-0000-0000-0000-000000000002',
      evaluation_dataset_id: dataset.evaluation_dataset_id,
      expected_payload: { expectedFindingsCount: 0 },
      tags: ['security', 'regression', 'ast'],
    });

    // 2. Evaluation Run & Result
    const evalRun = await repo.createEvaluationRun({
      evaluation_run_id: 'e1000000-0000-0000-0000-000000000003',
      evaluation_dataset_id: dataset.evaluation_dataset_id,
      engine_key: 'CORE_ANALYZER_AST',
      engine_version: '2.0.1',
      status: 'COMPLETED',
    });

    const evalResult = await repo.createEvaluationResult({
      evaluation_result_id: 'e1000000-0000-0000-0000-000000000004',
      evaluation_run_id: evalRun.evaluation_run_id,
      evaluation_case_id: evalCase.evaluation_case_id,
      metric_key: 'PRECISION',
      metric_value: 0.985,
      pass: true,
      details: { truePositives: 49, falsePositives: 1 },
    });

    expect(evalResult.pass).toBe(true);

    // 3. Golden Corpus Item
    const goldenItem = await repo.createGoldenCorpusItem({
      golden_corpus_item_id: 'e1000000-0000-0000-0000-000000000005',
      fixture_locator: 'fixtures/agents/financial-assistant-golden.json',
      corpus_version: 'v2.0',
      truth_status: 'VERIFIED',
      tags: ['golden', 'financial', 'certified'],
    });

    expect(goldenItem.truth_status).toBe('VERIFIED');

    // 4. Cost Usage Event
    const costEvent = await repo.recordCostUsageEvent({
      cost_usage_event_id: 'e1000000-0000-0000-0000-000000000006',
      usage_type: 'LLM_INFERENCE_TOKENS',
      quantity: 1250,
      unit: 'TOKENS',
      provider: 'VERTEX_GEMINI',
      unit_cost_snapshot: 0.00002,
      agent_id: agentId,
      analysis_run_id: baselineRunId,
    });

    expect(costEvent.quantity).toBe(1250);
  });
});
