/**
 * Transactionally Consistent Analysis Persistence Engine
 * Architecture V2.0.1 - Prompt 8 Data Integrity Invariant:
 * COMPLETED ⇒ all mandatory durable records exist.
 * Required persistence failure can never result in a full completed state.
 */

import {
  AnalysisRun,
  AnalysisStageRun,
  StaticFinding,
  Evidence,
  Assertion,
  AssertionEvidenceLink,
  Claim,
  ClaimEvidenceLink,
  ClaimSupportLink,
  Contradiction,
  Risk,
  ScoreResult,
  ScoreDimensionValue,
  PolicyDecision,
  PolicyDecisionReason,
  TaintFlow,
  SbomComponent,
  SbomDependency,
  CallGraphNode,
  CallGraphEdge,
  RuntimeEvent,
  Recommendation,
  UseCase,
  UseCaseEvaluation,
  CreateStaticFindingInput,
  CreateEvidenceInput,
  CreateClaimInput,
  CreateRuntimeEventInput,
} from './types.js';

export type OutputDuality = 'REQUIRED' | 'OPTIONAL' | 'DERIVED';

/**
 * Output Inventory and Classification
 */
export const ANALYSIS_OUTPUT_CLASSIFICATION: Record<string, OutputDuality> = {
  // Required child records for COMPLETED status
  parentRun: 'REQUIRED',
  stageRuns: 'REQUIRED',
  findings: 'REQUIRED',
  evidence: 'REQUIRED',
  assertions: 'REQUIRED',
  claims: 'REQUIRED',
  assertionEvidenceLinks: 'REQUIRED',
  claimEvidenceLinks: 'REQUIRED',
  claimSupportLinks: 'REQUIRED',
  contradictions: 'REQUIRED',
  risks: 'REQUIRED',
  scoreResult: 'REQUIRED',
  scoreDimensionValues: 'REQUIRED',
  policyDecision: 'REQUIRED',
  policyDecisionReasons: 'REQUIRED',
  taintFlows: 'REQUIRED',
  sbomComponents: 'REQUIRED',
  sbomDependencies: 'REQUIRED',

  // Optional records - failure to persist must downgrade COMPLETED to PARTIAL
  recommendations: 'OPTIONAL',
  useCases: 'OPTIONAL',
  useCaseEvaluations: 'OPTIONAL',
  callGraphNodes: 'OPTIONAL',
  callGraphEdges: 'OPTIONAL',
  runtimeEvents: 'OPTIONAL',

  // Derived / Recomputable - computed on read / joins
  backwardLineage: 'DERIVED',
  findingCountMetrics: 'DERIVED',
  riskBandSummary: 'DERIVED',
};

export class AnalysisPersistenceError extends Error {
  constructor(message: string, public readonly code: string, public readonly details?: unknown) {
    super(message);
    this.name = 'AnalysisPersistenceError';
  }
}

export class RequiredChildPersistenceFailedError extends AnalysisPersistenceError {
  constructor(
    public readonly childKind: string,
    public readonly originalError: unknown,
    public readonly analysisRunId: string
  ) {
    const errorMsg = originalError instanceof Error ? originalError.message : String(originalError);
    super(
      `Required analysis child data '${childKind}' failed to persist for run ${analysisRunId}. ` +
      `Analysis CANNOT become COMPLETED when mandatory durable records fail to persist: ${errorMsg}`,
      'ERR_REQUIRED_CHILD_PERSISTENCE_FAILED',
      { childKind, originalError: errorMsg, analysisRunId }
    );
    this.name = 'RequiredChildPersistenceFailedError';
  }
}

export class IncompleteAnalysisPersistenceError extends AnalysisPersistenceError {
  constructor(
    public readonly analysisRunId: string,
    public readonly missingComponents: string[]
  ) {
    super(
      `Cannot mark analysis run ${analysisRunId} as COMPLETED. Mandatory durable records are missing: ${missingComponents.join(', ')}. ` +
      `Invariant violated: COMPLETED ⇒ all mandatory durable records exist.`,
      'ERR_INCOMPLETE_ANALYSIS_PERSISTENCE',
      { analysisRunId, missingComponents }
    );
    this.name = 'IncompleteAnalysisPersistenceError';
  }
}

export interface DatabaseClientLike {
  query: (sql: string, params?: unknown[]) => Promise<{ rows: Record<string, unknown>[]; rowCount?: number }>;
}

export interface AnalysisRunPersistenceInput {
  analysis_run_id: string;
  agent_version_id: string;
  scope_id: string;
  pipeline_version: string;
  caim_version: string;
  ontology_version: string;
  trigger_type: string;
  targetStatus?: 'COMPLETED' | 'PARTIAL';
  static_status?: string;
  dynamic_status?: string;
  overall_status?: string;
  execution_summary?: unknown;
  started_at?: string;
}

export interface PersistAnalysisBundleInput {
  run: AnalysisRunPersistenceInput;
  stageRuns?: Array<Omit<AnalysisStageRun, 'created_at' | 'started_at'>>;
  findings?: Array<CreateStaticFindingInput>;
  evidence?: Array<CreateEvidenceInput>;
  assertions?: Array<Omit<Assertion, 'created_at'>>;
  assertionEvidenceLinks?: Array<Omit<AssertionEvidenceLink, 'created_at'>>;
  claims?: Array<CreateClaimInput>;
  claimEvidenceLinks?: Array<Omit<ClaimEvidenceLink, 'created_at'>>;
  claimSupportLinks?: Array<Omit<ClaimSupportLink, 'created_at'>>;
  contradictions?: Array<Omit<Contradiction, 'created_at'>>;
  risks?: Array<Omit<Risk, 'created_at'>>;
  scoreResult?: Omit<ScoreResult, 'created_at'>;
  scoreDimensionValues?: Array<Omit<ScoreDimensionValue, 'created_at'>>;
  policyDecision?: Omit<PolicyDecision, 'created_at'>;
  policyDecisionReasons?: Array<Omit<PolicyDecisionReason, 'created_at'>>;
  taintFlows?: Array<Omit<TaintFlow, 'created_at'>>;
  sbomComponents?: Array<Omit<SbomComponent, 'created_at'>>;
  sbomDependencies?: Array<Omit<SbomDependency, 'created_at'>>;

  // Optional outputs (failure degrades status to PARTIAL instead of rolling back)
  recommendations?: Array<Omit<Recommendation, 'created_at'>>;
  useCases?: Array<Omit<UseCase, 'created_at'>>;
  useCaseEvaluations?: Array<Omit<UseCaseEvaluation, 'created_at'>>;
  callGraphNodes?: Array<Omit<CallGraphNode, 'created_at'>>;
  callGraphEdges?: Array<Omit<CallGraphEdge, 'created_at'>>;
  runtimeEvents?: Array<CreateRuntimeEventInput>;

  // Testing & Failure Injection Hooks
  failureInjection?: {
    failStage?:
      | 'BEFORE_RUN'
      | 'WRITE_STAGE_RUNS'
      | 'WRITE_FINDINGS'
      | 'WRITE_EVIDENCE'
      | 'WRITE_ASSERTIONS'
      | 'WRITE_CLAIMS'
      | 'WRITE_RISKS'
      | 'WRITE_SCORES'
      | 'WRITE_POLICY'
      | 'WRITE_FLOW_RESULTS'
      | 'WRITE_OPTIONAL_RECOMMENDATIONS'
      | 'WRITE_OPTIONAL_USE_CASES'
      | 'WRITE_OPTIONAL_CALL_GRAPH'
      | 'WRITE_OPTIONAL_RUNTIME_EVENTS'
      | 'PROMOTE_STATUS';
    errorMessage?: string;
  };
}

export interface PersistAnalysisResult {
  analysis_run_id: string;
  status: 'COMPLETED' | 'PARTIAL' | 'FAILED';
  isDegraded: boolean;
  degradedReasons: string[];
  mandatoryRecordsCount: {
    stageRuns: number;
    findings: number;
    evidence: number;
    assertions: number;
    claims: number;
    risks: number;
    scores: number;
    policyDecisions: number;
  };
  optionalRecordsCount: {
    recommendations: number;
    useCases: number;
    callGraphNodes: number;
    runtimeEvents: number;
  };
}

/**
 * Checks whether an error is strictly an exact unique constraint / idempotency violation.
 * Non-unique constraint database errors (FK violations, null constraint, check violations,
 * syntax errors, connection timeouts) MUST NOT be treated as duplicate/idempotent.
 */
export function isExactUniqueConstraintViolation(err: any, expectedConstraint?: string): boolean {
  if (!err) return false;

  const is23505 = err.code === '23505';
  const msgText = typeof err.message === 'string' ? err.message.toLowerCase() : '';
  const isDuplicateMsg = msgText.includes('duplicate key') || msgText.includes('unique constraint');

  if (!is23505 && !isDuplicateMsg) {
    return false;
  }

  // Ensure it's not a check constraint (23514), FK (23503), or not-null (23502) masquerading
  if (err.code && ['23503', '23502', '23514', '42601', '08006', '08001'].includes(err.code)) {
    return false;
  }

  if (expectedConstraint) {
    const constraintName = (err.constraint || '').toLowerCase();
    if (constraintName) {
      return constraintName === expectedConstraint.toLowerCase();
    }
    return msgText.includes(expectedConstraint.toLowerCase());
  }

  return true;
}

export class AnalysisPersistenceCoordinator {
  /**
   * Persists an entire logical analysis bundle within an atomic database transaction.
   *
   * Invariants Enforced:
   * 1. Transaction Boundary: All mandatory child outputs are written in one atomic transaction.
   * 2. Atomic Integrity: If ANY required child record fails to persist, transaction rolls back;
   *    analysis CAN NEVER be marked COMPLETED.
   * 3. Truthful Partial State: If optional outputs fail to persist, status is downgraded to PARTIAL
   *    and degraded reasons are recorded in execution_summary. Full completion is NOT claimed.
   * 4. No Broad Error Suppression: DB errors are never swallowed.
   * 5. Strict Duplicate Handling: Only exact unique constraint collisions are treated idempotently.
   */
  public static async persistAnalysisTransactionally(
    client: DatabaseClientLike,
    input: PersistAnalysisBundleInput
  ): Promise<PersistAnalysisResult> {
    const { run, failureInjection } = input;
    const runId = run.analysis_run_id;
    const requestedTargetStatus = run.targetStatus || 'COMPLETED';

    const degradedReasons: string[] = [];
    let isDegraded = false;

    // Counts for auditing and verification
    const mandatoryCount = {
      stageRuns: 0,
      findings: 0,
      evidence: 0,
      assertions: 0,
      claims: 0,
      risks: 0,
      scores: 0,
      policyDecisions: 0,
    };

    const optionalCount = {
      recommendations: 0,
      useCases: 0,
      callGraphNodes: 0,
      runtimeEvents: 0,
    };

    // 1. Begin atomic transaction
    await client.query('BEGIN;');

    try {
      if (failureInjection?.failStage === 'BEFORE_RUN') {
        throw new Error(failureInjection.errorMessage || 'Failure injected BEFORE_RUN');
      }

      // 2. Insert parent analysis.analysis_runs in RUNNING state (NEVER COMPLETED upfront)
      const executionSummary: Record<string, any> = typeof run.execution_summary === 'object' && run.execution_summary !== null
        ? { ...run.execution_summary }
        : {};

      try {
        await client.query(`
          INSERT INTO analysis.analysis_runs (
            analysis_run_id, agent_version_id, scope_id, pipeline_version,
            caim_version, ontology_version, trigger_type, status,
            static_status, dynamic_status, overall_status, execution_summary,
            started_at, created_at
          ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, 'RUNNING',
            $8, $9, $10, $11,
            COALESCE($12, now()), now()
          );
        `, [
          runId,
          run.agent_version_id,
          run.scope_id,
          run.pipeline_version,
          run.caim_version,
          run.ontology_version,
          run.trigger_type,
          run.static_status || null,
          run.dynamic_status || null,
          run.overall_status || null,
          JSON.stringify(executionSummary),
          run.started_at || null,
        ]);
      } catch (runInsertErr: any) {
        if (isExactUniqueConstraintViolation(runInsertErr, 'analysis_runs_pkey')) {
          // Idempotent retry of existing run - ensure it's reset to RUNNING during this atomic update
          await client.query(`
            UPDATE analysis.analysis_runs
            SET status = 'RUNNING', completed_at = NULL
            WHERE analysis_run_id = $1;
          `, [runId]);
        } else {
          throw new RequiredChildPersistenceFailedError('parentRun', runInsertErr, runId);
        }
      }

      // 3. Stage Runs (REQUIRED if stages were executed)
      if (failureInjection?.failStage === 'WRITE_STAGE_RUNS') {
        throw new Error(failureInjection.errorMessage || 'Failure injected WRITE_STAGE_RUNS');
      }

      if (input.stageRuns && input.stageRuns.length > 0) {
        for (const stage of input.stageRuns) {
          try {
            await client.query(`
              INSERT INTO analysis.analysis_stage_runs (
                stage_run_id, analysis_run_id, engine_key, engine_version,
                ruleset_version, model_version, input_snapshot_hash, status,
                started_at, created_at
              ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), now());
            `, [
              stage.stage_run_id,
              runId,
              stage.engine_key,
              stage.engine_version,
              stage.ruleset_version || null,
              stage.model_version || null,
              stage.input_snapshot_hash || null,
              stage.status || 'COMPLETED',
            ]);
            mandatoryCount.stageRuns++;
          } catch (stageErr: any) {
            if (isExactUniqueConstraintViolation(stageErr, 'uq_analysis_stage_runs_engine') ||
                isExactUniqueConstraintViolation(stageErr, 'analysis_stage_runs_pkey')) {
              // Idempotent re-run on identical engine
              mandatoryCount.stageRuns++;
            } else {
              throw new RequiredChildPersistenceFailedError('stageRuns', stageErr, runId);
            }
          }
        }
      }

      // 4. Static Findings (REQUIRED - if findings were generated, they MUST all persist)
      if (failureInjection?.failStage === 'WRITE_FINDINGS') {
        throw new Error(failureInjection.errorMessage || 'Failure injected WRITE_FINDINGS');
      }

      if (input.findings && input.findings.length > 0) {
        for (const finding of input.findings) {
          const truthState = (finding as any).truthState || (finding as any).truth_state || 'STATICALLY_DERIVED';
          try {
            await client.query(`
              INSERT INTO analysis.static_findings (
                finding_id, analysis_run_id, stage_run_id, entity_ref_id,
                source_span_id, rule_id, finding_type, severity,
                confidence, message, location_hint, raw_payload,
                truth_state, source_id, analyzer_version, observed_at, created_at
              ) VALUES (
                $1, $2, $3, $4,
                $5, $6, $7, $8,
                $9, $10, $11, $12,
                $13, $14, $15, now(), now()
              );
            `, [
              finding.finding_id,
              runId,
              finding.stage_run_id || null,
              finding.entity_ref_id || null,
              finding.source_span_id || null,
              finding.rule_id,
              finding.finding_type,
              finding.severity,
              finding.confidence ?? 1.0,
              finding.message,
              finding.location_hint || null,
              finding.raw_payload ? JSON.stringify(finding.raw_payload) : null,
              truthState,
              finding.source_id || 'static-ruleset',
              finding.analyzer_version || run.pipeline_version,
            ]);
            mandatoryCount.findings++;
          } catch (findingErr: any) {
            if (isExactUniqueConstraintViolation(findingErr, 'static_findings_pkey')) {
              mandatoryCount.findings++;
            } else {
              throw new RequiredChildPersistenceFailedError('findings', findingErr, runId);
            }
          }
        }
      }

      // 5. Evidence (REQUIRED - supporting evidence must durably persist)
      if (failureInjection?.failStage === 'WRITE_EVIDENCE') {
        throw new Error(failureInjection.errorMessage || 'Failure injected WRITE_EVIDENCE');
      }

      if (input.evidence && input.evidence.length > 0) {
        for (const ev of input.evidence) {
          const truthState = (ev as any).truthState || (ev as any).truth_state || 'STATICALLY_DERIVED';
          const validEvidenceType = ['STATIC_CODE', 'AST_MATCH', 'DYNAMIC_CALL', 'METADATA_MANIFEST', 'EXTERNAL_INTEL', 'HEURISTIC'].includes(ev.evidence_type)
            ? ev.evidence_type
            : 'STATIC_CODE';
          const description = ev.description || ((ev as any).raw_payload ? JSON.stringify((ev as any).raw_payload) : 'Analysis evidence');
          try {
            await client.query(`
              INSERT INTO intel.evidence (
                evidence_id, analysis_run_id, stage_run_id, entity_ref_id, evidence_type,
                source_span_id, source_observation_id, artifact_id, static_finding_id,
                runtime_event_id, external_intel_ref_id, description, confidence, weight,
                scope_id, truth_state, source_id, analyzer_version, observed_at, limitations, created_at
              ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9,
                $10, $11, $12, $13, $14,
                COALESCE($15, (SELECT scope_id FROM analysis.analysis_runs WHERE analysis_run_id = $2)),
                $16, $17, $18, COALESCE($19, now()), $20, now()
              );
            `, [
              ev.evidence_id,
              runId,
              ev.stage_run_id || null,
              (ev as any).entity_ref_id || null,
              validEvidenceType,
              (ev as any).source_span_id || null,
              (ev as any).source_observation_id || null,
              (ev as any).artifact_id || null,
              (ev as any).static_finding_id || null,
              (ev as any).runtime_event_id || null,
              (ev as any).external_intel_ref_id || null,
              description,
              (ev as any).confidence ?? 1.0,
              (ev as any).weight ?? 1.0,
              (ev as any).scope_id || null,
              truthState,
              (ev as any).source_id || 'internal-evidence',
              (ev as any).analyzer_version || run.pipeline_version,
              (ev as any).retrieved_at || (ev as any).observed_at || null,
              (ev as any).limitations || null,
            ]);
            mandatoryCount.evidence++;
          } catch (evErr: any) {
            if (isExactUniqueConstraintViolation(evErr, 'evidence_pkey')) {
              mandatoryCount.evidence++;
            } else {
              throw new RequiredChildPersistenceFailedError('evidence', evErr, runId);
            }
          }
        }
      }

      // 6. Assertions & Evidence Links (REQUIRED)
      if (failureInjection?.failStage === 'WRITE_ASSERTIONS') {
        throw new Error(failureInjection.errorMessage || 'Failure injected WRITE_ASSERTIONS');
      }

      if (input.assertions && input.assertions.length > 0) {
        for (const asrt of input.assertions) {
          const asrtAny = asrt as any;
          try {
            await client.query(`
              INSERT INTO intel.assertions (
                assertion_id, analysis_run_id, stage_run_id, entity_ref_id, assertion_key,
                concept_id, predicate, subject_ref_id, object_ref_id, assertion_value,
                confidence, uncertainty_score, uncertainty_factors, calibration_version, engine_key, rule_id, scope_id, created_at
              ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15, $16,
                COALESCE($17, (SELECT scope_id FROM analysis.analysis_runs WHERE analysis_run_id = $2)), now()
              );
            `, [
              asrt.assertion_id,
              runId,
              asrt.stage_run_id || null,
              asrt.entity_ref_id || null,
              asrt.assertion_key,
              asrt.concept_id || null,
              asrt.predicate,
              asrt.subject_ref_id,
              asrt.object_ref_id || null,
              asrt.assertion_value || null,
              asrt.confidence ?? 1.0,
              asrt.uncertainty_score ?? 0.0,
              asrt.uncertainty_factors ? JSON.stringify(asrt.uncertainty_factors) : null,
              asrt.calibration_version || null,
              asrt.engine_key,
              asrt.rule_id || null,
              asrt.scope_id || null,
            ]);
            mandatoryCount.assertions++;
          } catch (asrtErr: any) {
            if (isExactUniqueConstraintViolation(asrtErr, 'assertions_pkey')) {
              mandatoryCount.assertions++;
            } else {
              throw new RequiredChildPersistenceFailedError('assertions', asrtErr, runId);
            }
          }
        }
      }

      if (input.assertionEvidenceLinks && input.assertionEvidenceLinks.length > 0) {
        for (const link of input.assertionEvidenceLinks) {
          try {
            await client.query(`
              INSERT INTO intel.assertion_evidence_links (
                link_id, assertion_id, evidence_id, relationship_type, relevance_weight, created_at
              ) VALUES ($1, $2, $3, $4, $5, now());
            `, [
              link.link_id,
              link.assertion_id,
              link.evidence_id,
              link.relationship_type || 'SUPPORTS',
              link.relevance_weight ?? 1.0,
            ]);
          } catch (linkErr: any) {
            if (!isExactUniqueConstraintViolation(linkErr)) {
              throw new RequiredChildPersistenceFailedError('assertionEvidenceLinks', linkErr, runId);
            }
          }
        }
      }

      // 7. Claims & Evidence/Support Links (REQUIRED)
      if (failureInjection?.failStage === 'WRITE_CLAIMS') {
        throw new Error(failureInjection.errorMessage || 'Failure injected WRITE_CLAIMS');
      }

      if (input.claims && input.claims.length > 0) {
        for (const claim of input.claims) {
          const truthState = (claim as any).truthState || (claim as any).truth_state || 'STATICALLY_DERIVED';
          const claimAny = claim as any;
          try {
            await client.query(`
              INSERT INTO intel.claims (
                claim_id, analysis_run_id, entity_ref_id, claim_type, claim_text, state,
                confidence, uncertainty_score, scope_id, truth_state, source_id,
                evidence_id, analyzer_version, observed_at, limitations, created_at
              ) VALUES (
                $1, $2, $3, $4, $5, $6,
                $7, $8, COALESCE($9, (SELECT scope_id FROM analysis.analysis_runs WHERE analysis_run_id = $2)),
                $10, $11, $12, $13, $14, $15, now()
              );
            `, [
              claim.claim_id,
              runId,
              claim.entity_ref_id || null,
              claim.claim_type,
              claim.claim_text || claimAny.statement || 'Claim statement',
              claim.state || 'SUPPORTED',
              claim.confidence ?? 1.0,
              claim.uncertainty_score ?? 0.0,
              claim.scope_id || null,
              truthState,
              claimAny.source_id || 'caim-engine',
              claimAny.evidence_id || null,
              claimAny.analyzer_version || run.pipeline_version,
              claimAny.observed_at || new Date().toISOString(),
              claimAny.limitations || null,
            ]);
            mandatoryCount.claims++;
          } catch (claimErr: any) {
            if (isExactUniqueConstraintViolation(claimErr, 'claims_pkey')) {
              mandatoryCount.claims++;
            } else {
              throw new RequiredChildPersistenceFailedError('claims', claimErr, runId);
            }
          }
        }
      }

      if (input.claimEvidenceLinks && input.claimEvidenceLinks.length > 0) {
        for (const link of input.claimEvidenceLinks) {
          try {
            await client.query(`
              INSERT INTO intel.claim_evidence_links (
                link_id, claim_id, evidence_id, support_type, weight, created_at
              ) VALUES ($1, $2, $3, $4, $5, now());
            `, [
              link.link_id,
              link.claim_id,
              link.evidence_id,
              link.support_type || 'DIRECT_SUPPORT',
              link.weight ?? 1.0,
            ]);
          } catch (linkErr: any) {
            if (!isExactUniqueConstraintViolation(linkErr)) {
              throw new RequiredChildPersistenceFailedError('claimEvidenceLinks', linkErr, runId);
            }
          }
        }
      }

      if (input.claimSupportLinks && input.claimSupportLinks.length > 0) {
        for (const link of input.claimSupportLinks) {
          try {
            await client.query(`
              INSERT INTO intel.claim_support_links (
                link_id, claim_id, assertion_id, link_type, created_at
              ) VALUES ($1, $2, $3, $4, now());
            `, [
              link.link_id,
              link.claim_id,
              link.assertion_id,
              link.link_type || 'SUPPORTS',
            ]);
          } catch (linkErr: any) {
            if (!isExactUniqueConstraintViolation(linkErr)) {
              throw new RequiredChildPersistenceFailedError('claimSupportLinks', linkErr, runId);
            }
          }
        }
      }

      if (input.contradictions && input.contradictions.length > 0) {
        for (const cont of input.contradictions) {
          const contAny = cont as any;
          try {
            await client.query(`
              INSERT INTO intel.contradictions (
                contradiction_id, analysis_run_id, claim_a_id, claim_b_id,
                assertion_a_id, assertion_b_id, conflict_reason, severity, resolution_status, created_at
              ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now());
            `, [
              cont.contradiction_id,
              runId,
              cont.claim_a_id || null,
              cont.claim_b_id || null,
              cont.assertion_a_id || null,
              cont.assertion_b_id || null,
              cont.conflict_reason || contAny.description || 'Contradiction detected',
              cont.severity,
              cont.resolution_status || 'UNRESOLVED',
            ]);
          } catch (contErr: any) {
            if (!isExactUniqueConstraintViolation(contErr)) {
              throw new RequiredChildPersistenceFailedError('contradictions', contErr, runId);
            }
          }
        }
      }

      // 8. Risks (REQUIRED)
      if (failureInjection?.failStage === 'WRITE_RISKS') {
        throw new Error(failureInjection.errorMessage || 'Failure injected WRITE_RISKS');
      }

      if (input.risks && input.risks.length > 0) {
        for (const r of input.risks) {
          try {
            await client.query(`
              INSERT INTO intel.risks (
                risk_id, analysis_run_id, entity_ref_id, claim_id, risk_type,
                title, description, severity, likelihood, impact, risk_score, remediation_guidance, created_at
              ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now());
            `, [
              r.risk_id,
              runId,
              (r as any).entity_ref_id || null,
              (r as any).claim_id || null,
              r.risk_type,
              r.title,
              r.description,
              r.severity,
              (r as any).likelihood ?? 1.0,
              (r as any).impact ?? 1.0,
              (r as any).risk_score ?? 0.0,
              (r as any).remediation_guidance || null,
            ]);
            mandatoryCount.risks++;
          } catch (riskErr: any) {
            if (isExactUniqueConstraintViolation(riskErr, 'risks_pkey')) {
              mandatoryCount.risks++;
            } else {
              throw new RequiredChildPersistenceFailedError('risks', riskErr, runId);
            }
          }
        }
      }

      // 9. Flow Results & SBOM (REQUIRED if produced by stages)
      if (failureInjection?.failStage === 'WRITE_FLOW_RESULTS') {
        throw new Error(failureInjection.errorMessage || 'Failure injected WRITE_FLOW_RESULTS');
      }

      if (input.taintFlows && input.taintFlows.length > 0) {
        for (const tf of input.taintFlows) {
          try {
            await client.query(`
              INSERT INTO analysis.taint_flows (
                taint_flow_id, analysis_run_id, stage_run_id, source_span_id,
                sink_span_id, source_type, sink_type, sanitizer_type,
                confidence, path_summary, created_at
              ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now());
            `, [
              tf.taint_flow_id,
              runId,
              tf.stage_run_id || null,
              tf.source_span_id || null,
              tf.sink_span_id || null,
              tf.source_type,
              tf.sink_type,
              tf.sanitizer_type || null,
              tf.confidence ?? 1.0,
              tf.path_summary,
            ]);
          } catch (tfErr: any) {
            if (!isExactUniqueConstraintViolation(tfErr, 'taint_flows_pkey')) {
              throw new RequiredChildPersistenceFailedError('taintFlows', tfErr, runId);
            }
          }
        }
      }

      if (input.sbomComponents && input.sbomComponents.length > 0) {
        for (const comp of input.sbomComponents) {
          try {
            const compAny = comp as any;
            await client.query(`
              INSERT INTO analysis.sbom_components (
                sbom_component_id, analysis_run_id, stage_run_id, purl,
                name, version, ecosystem, license_expression, created_at
              ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now());
            `, [
              comp.sbom_component_id,
              runId,
              comp.stage_run_id || null,
              comp.purl || null,
              comp.name,
              comp.version,
              comp.ecosystem,
              comp.license_expression || compAny.license_concluded || null,
            ]);
          } catch (compErr: any) {
            if (!isExactUniqueConstraintViolation(compErr, 'sbom_components_pkey')) {
              throw new RequiredChildPersistenceFailedError('sbomComponents', compErr, runId);
            }
          }
        }
      }

      if (input.sbomDependencies && input.sbomDependencies.length > 0) {
        for (const dep of input.sbomDependencies) {
          try {
            const depId = (dep as any).sbom_dependency_id || (dep as any).dependency_id || crypto.randomUUID();
            const relType = (dep as any).dependency_scope || (dep as any).relationship_type || 'RUNTIME';
            await client.query(`
              INSERT INTO analysis.sbom_dependencies (
                sbom_dependency_id, analysis_run_id, parent_component_id,
                child_component_id, dependency_scope, created_at
              ) VALUES ($1, $2, $3, $4, $5, now());
            `, [
              depId,
              runId,
              dep.parent_component_id,
              dep.child_component_id,
              relType,
            ]);
          } catch (depErr: any) {
            if (!isExactUniqueConstraintViolation(depErr, 'sbom_dependencies_pkey')) {
              throw new RequiredChildPersistenceFailedError('sbomDependencies', depErr, runId);
            }
          }
        }
      }

      // 10. Multi-dimensional Score Results & Dimensions (REQUIRED)
      if (failureInjection?.failStage === 'WRITE_SCORES') {
        throw new Error(failureInjection.errorMessage || 'Failure injected WRITE_SCORES');
      }

      if (input.scoreResult) {
        const sr = input.scoreResult;
        const calibrationVersion = (sr as any).calibration_version || (sr as any).calibrationVersion || run.pipeline_version;
        const grade = (sr as any).grade || (sr as any).risk_band || 'LOW';
        try {
          await client.query(`
            INSERT INTO intel.score_results (
              score_result_id, analysis_run_id, score_model_id,
              overall_score, grade, calibration_version, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, now());
          `, [
            sr.score_result_id,
            runId,
            sr.score_model_id,
            sr.overall_score,
            grade,
            calibrationVersion,
          ]);
          mandatoryCount.scores++;
        } catch (scoreErr: any) {
          if (isExactUniqueConstraintViolation(scoreErr, 'score_results_pkey')) {
            mandatoryCount.scores++;
          } else {
            throw new RequiredChildPersistenceFailedError('scoreResult', scoreErr, runId);
          }
        }

        if (input.scoreDimensionValues && input.scoreDimensionValues.length > 0) {
          for (const sdv of input.scoreDimensionValues) {
            try {
              await client.query(`
                INSERT INTO intel.score_dimension_values (
                  score_dimension_value_id, score_result_id, dimension_id,
                  raw_value, weighted_value, created_at
                ) VALUES ($1, $2, $3, $4, $5, now());
              `, [
                (sdv as any).score_dimension_value_id || (sdv as any).dimension_value_id || crypto.randomUUID(),
                sr.score_result_id,
                sdv.dimension_id,
                (sdv as any).raw_value ?? (sdv as any).score_value ?? 0,
                (sdv as any).weighted_value ?? (sdv as any).score_value ?? 0,
              ]);
            } catch (dimErr: any) {
              if (!isExactUniqueConstraintViolation(dimErr, 'score_dimension_values_pkey')) {
                throw new RequiredChildPersistenceFailedError('scoreDimensionValues', dimErr, runId);
              }
            }
          }
        }
      }

      // 11. Authoritative Policy Decision & Decision Reasons (REQUIRED)
      if (failureInjection?.failStage === 'WRITE_POLICY') {
        throw new Error(failureInjection.errorMessage || 'Failure injected WRITE_POLICY');
      }

      if (input.policyDecision) {
        const pd = input.policyDecision;
        const evalSummary = typeof pd.evaluation_summary === 'string'
          ? pd.evaluation_summary
          : JSON.stringify(pd.evaluation_summary || {});
        try {
          await client.query(`
            INSERT INTO intel.policy_decisions (
              decision_id, analysis_run_id, policy_version_id,
              decision, evaluation_summary, created_at
            ) VALUES ($1, $2, $3, $4, $5, now());
          `, [
            pd.decision_id,
            runId,
            pd.policy_version_id,
            pd.decision,
            evalSummary,
          ]);
          mandatoryCount.policyDecisions++;
        } catch (pdErr: any) {
          if (isExactUniqueConstraintViolation(pdErr, 'policy_decisions_pkey')) {
            mandatoryCount.policyDecisions++;
          } else {
            throw new RequiredChildPersistenceFailedError('policyDecision', pdErr, runId);
          }
        }

        if (input.policyDecisionReasons && input.policyDecisionReasons.length > 0) {
          const isUuid = (val: string | null | undefined) =>
            val ? /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(val) : false;
          for (const reason of input.policyDecisionReasons) {
            try {
              await client.query(`
                INSERT INTO intel.policy_decision_reasons (
                  reason_id, decision_id, rule_id, risk_id,
                  reason_text, is_blocking, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, now());
              `, [
                reason.reason_id,
                pd.decision_id,
                isUuid(reason.rule_id) ? reason.rule_id : null,
                isUuid((reason as any).risk_id) ? (reason as any).risk_id : null,
                reason.reason_text,
                reason.is_blocking ?? false,
              ]);
            } catch (reasonErr: any) {
              if (!isExactUniqueConstraintViolation(reasonErr, 'policy_decision_reasons_pkey')) {
                throw new RequiredChildPersistenceFailedError('policyDecisionReasons', reasonErr, runId);
              }
            }
          }
        }
      }

      // =========================================================================
      // OPTIONAL OUTPUT PERSISTENCE (Failure must degrade COMPLETED to PARTIAL)
      // =========================================================================

      // Optional: Recommendations
      if (failureInjection?.failStage === 'WRITE_OPTIONAL_RECOMMENDATIONS') {
        isDegraded = true;
        degradedReasons.push(`Injected failure on optional recommendations persistence: ${failureInjection.errorMessage || 'Simulated failure'}`);
      } else if (input.recommendations && input.recommendations.length > 0) {
        for (const rec of input.recommendations) {
          const recAny = rec as any;
          const normalizePriority = (p: any): 'P0' | 'P1' | 'P2' | 'P3' => {
            if (p === 'P0' || p === 'CRITICAL') return 'P0';
            if (p === 'P1' || p === 'HIGH') return 'P1';
            if (p === 'P2' || p === 'MEDIUM') return 'P2';
            return 'P3';
          };
          const actionSteps = rec.action_steps || (recAny.remediation_steps ? (Array.isArray(recAny.remediation_steps) ? recAny.remediation_steps.join('\n') : String(recAny.remediation_steps)) : recAny.description || 'Follow standard security hardening guidelines');
          const recType = rec.recommendation_type || 'REMEDIATION';
          try {
            await client.query(`
              INSERT INTO intel.recommendations (
                recommendation_id, analysis_run_id, entity_ref_id, risk_id,
                recommendation_type, title, action_steps, priority, effort_estimate, created_at
              ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now());
            `, [
              rec.recommendation_id,
              runId,
              rec.entity_ref_id || null,
              rec.risk_id || null,
              recType,
              rec.title,
              actionSteps,
              normalizePriority(rec.priority),
              rec.effort_estimate || 'LOW',
            ]);
            optionalCount.recommendations++;
          } catch (recErr: any) {
            isDegraded = true;
            degradedReasons.push(`Optional recommendation '${rec.recommendation_id}' failed to persist: ${recErr.message}`);
          }
        }
      }

      // Optional: Use Cases & Evaluations
      if (failureInjection?.failStage === 'WRITE_OPTIONAL_USE_CASES') {
        isDegraded = true;
        degradedReasons.push(`Injected failure on optional use-cases persistence: ${failureInjection.errorMessage || 'Simulated failure'}`);
      } else {
        if (input.useCases && input.useCases.length > 0) {
          for (const uc of input.useCases) {
            const ucAny = uc as any;
            try {
              await client.query(`
                INSERT INTO intel.use_cases (
                  use_case_id, use_case_key, title, description, category, created_at
                ) VALUES ($1, $2, $3, $4, $5, now());
              `, [
                uc.use_case_id,
                uc.use_case_key || ucAny.name || `uc-${uc.use_case_id}`,
                uc.title || ucAny.name || 'Use Case',
                uc.description || 'Use case description',
                uc.category || 'SECURITY',
              ]);
              optionalCount.useCases++;
            } catch (ucErr: any) {
              isDegraded = true;
              degradedReasons.push(`Optional use-case '${uc.use_case_id}' failed to persist: ${ucErr.message}`);
            }
          }
        }

        if (input.useCaseEvaluations && input.useCaseEvaluations.length > 0) {
          for (const uce of input.useCaseEvaluations) {
            const uceAny = uce as any;
            const suitability = uce.suitability || (uceAny.allowed ? 'APPROVED' : 'DISAPPROVED');
            const justification = uce.justification || uceAny.rationale || 'Evaluation completed';
            try {
              await client.query(`
                INSERT INTO intel.use_case_evaluations (
                  evaluation_id, analysis_run_id, use_case_id,
                  suitability, suitability_score, justification, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, now());
              `, [
                uce.evaluation_id,
                runId,
                uce.use_case_id,
                suitability,
                uce.suitability_score ?? uceAny.confidence ?? 1.0,
                justification,
              ]);
            } catch (uceErr: any) {
              isDegraded = true;
              degradedReasons.push(`Optional use-case evaluation '${uce.evaluation_id}' failed to persist: ${uceErr.message}`);
            }
          }
        }
      }

      // Optional: CallGraph
      if (failureInjection?.failStage === 'WRITE_OPTIONAL_CALL_GRAPH') {
        isDegraded = true;
        degradedReasons.push(`Injected failure on optional call graph persistence: ${failureInjection.errorMessage || 'Simulated failure'}`);
      } else {
        if (input.callGraphNodes && input.callGraphNodes.length > 0) {
          for (const node of input.callGraphNodes) {
            try {
              await client.query(`
                INSERT INTO analysis.callgraph_nodes (
                  node_id, analysis_run_id, stage_run_id, source_span_id,
                  symbol_name, node_type, qualified_name, properties, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now());
              `, [
                node.node_id,
                runId,
                node.stage_run_id || null,
                node.source_span_id || null,
                node.symbol_name,
                node.node_type,
                node.qualified_name,
                node.properties ? JSON.stringify(node.properties) : null,
              ]);
              optionalCount.callGraphNodes++;
            } catch (nodeErr: any) {
              isDegraded = true;
              degradedReasons.push(`Optional call graph node '${node.node_id}' failed to persist: ${nodeErr.message}`);
            }
          }
        }

        if (input.callGraphEdges && input.callGraphEdges.length > 0) {
          for (const edge of input.callGraphEdges) {
            try {
              await client.query(`
                INSERT INTO analysis.callgraph_edges (
                  edge_id, analysis_run_id, caller_node_id,
                  callee_node_id, call_type, call_site_span_id, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, now());
              `, [
                edge.edge_id,
                runId,
                edge.caller_node_id,
                edge.callee_node_id,
                edge.call_type || 'DIRECT',
                edge.call_site_span_id || null,
              ]);
            } catch (edgeErr: any) {
              isDegraded = true;
              degradedReasons.push(`Optional call graph edge '${edge.edge_id}' failed to persist: ${edgeErr.message}`);
            }
          }
        }
      }

      // Optional: Runtime Events
      if (failureInjection?.failStage === 'WRITE_OPTIONAL_RUNTIME_EVENTS') {
        isDegraded = true;
        degradedReasons.push(`Injected failure on optional runtime events persistence: ${failureInjection.errorMessage || 'Simulated failure'}`);
      } else if (input.runtimeEvents && input.runtimeEvents.length > 0) {
        for (const evt of input.runtimeEvents) {
          const evtAny = evt as any;
          const truthState = evtAny.truthState || evtAny.truth_state || 'OBSERVED';
          const eventId = evt.runtime_event_id || evtAny.event_id || crypto.randomUUID();
          try {
            await client.query(`
              INSERT INTO analysis.runtime_events (
                runtime_event_id, analysis_run_id, stage_run_id, entity_ref_id, event_type,
                event_timestamp, duration_ms, source_locator, payload, status,
                truth_state, source_id, analyzer_version, observed_at, confidence, limitations, created_at
              ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, now(), $14, $15, now());
            `, [
              eventId,
              runId,
              evt.stage_run_id || null,
              evt.entity_ref_id || null,
              evt.event_type,
              evt.event_timestamp || evtAny.timestamp || new Date().toISOString(),
              evt.duration_ms || null,
              evt.source_locator || null,
              evt.payload ? JSON.stringify(evt.payload) : (evtAny.details ? JSON.stringify(evtAny.details) : null),
              evt.status || 'RECORDED',
              truthState,
              evtAny.source_id || 'runtime-sandbox',
              evtAny.analyzer_version || run.pipeline_version,
              evt.confidence ?? 1.0,
              evtAny.limitations || null,
            ]);
            optionalCount.runtimeEvents++;
          } catch (evtErr: any) {
            isDegraded = true;
            degradedReasons.push(`Optional runtime event '${eventId}' failed to persist: ${evtErr.message}`);
          }
        }
      }

      // =========================================================================
      // 12. STATUS PROMOTION & TRUTHFUL STATE RESOLUTION
      // =========================================================================
      if (failureInjection?.failStage === 'PROMOTE_STATUS') {
        throw new Error(failureInjection.errorMessage || 'Failure injected PROMOTE_STATUS');
      }

      // Invariant: If any optional output failed to persist, we CANNOT claim full COMPLETED
      let finalStatus: 'COMPLETED' | 'PARTIAL';
      if (isDegraded) {
        finalStatus = 'PARTIAL';
        executionSummary.degraded = true;
        executionSummary.degraded_reasons = degradedReasons;
        executionSummary.why = (executionSummary.why ? executionSummary.why + ' ' : '') +
          'Truthful degraded state: required analysis records persisted, but optional enrichment persistence failed.';
      } else if (requestedTargetStatus === 'PARTIAL') {
        finalStatus = 'PARTIAL';
      } else {
        finalStatus = 'COMPLETED';
      }

      // Promote status within the same transaction
      await client.query(`
        UPDATE analysis.analysis_runs
        SET status = $2,
            execution_summary = $3,
            completed_at = now()
        WHERE analysis_run_id = $1;
      `, [runId, finalStatus, JSON.stringify(executionSummary)]);

      // 13. Commit atomic transaction
      await client.query('COMMIT;');

      // Post-transaction verification of the invariant
      await this.assertMandatoryDurableRecordsExist(client, runId, {
        expectFindingsCount: (input.findings || []).length,
        expectEvidenceCount: (input.evidence || []).length,
        expectScoreResult: Boolean(input.scoreResult),
        expectPolicyDecision: Boolean(input.policyDecision),
      });

      return {
        analysis_run_id: runId,
        status: finalStatus,
        isDegraded,
        degradedReasons,
        mandatoryRecordsCount: mandatoryCount,
        optionalRecordsCount: optionalCount,
      };
    } catch (err: any) {
      // 14. Abort and Rollback transaction on ANY unhandled error or required write failure
      try {
        await client.query('ROLLBACK;');
      } catch {
        // Suppress rollback errors if client is disconnected
      }

      // Propagate the fatal integrity error so callers and orchestrators know persistence failed
      throw err;
    }
  }

  /**
   * Asserts the invariant: COMPLETED ⇒ all mandatory durable records exist.
   * If status is COMPLETED but required child rows are missing, raises an invariant violation.
   */
  public static async assertMandatoryDurableRecordsExist(
    client: DatabaseClientLike,
    analysisRunId: string,
    expectations?: {
      expectFindingsCount?: number;
      expectEvidenceCount?: number;
      expectScoreResult?: boolean;
      expectPolicyDecision?: boolean;
    }
  ): Promise<void> {
    const runRes = await client.query(`
      SELECT analysis_run_id, status FROM analysis.analysis_runs WHERE analysis_run_id = $1;
    `, [analysisRunId]);

    if (runRes.rows.length === 0) {
      throw new IncompleteAnalysisPersistenceError(analysisRunId, ['analysis_run record does not exist']);
    }

    const run = runRes.rows[0];
    if (run.status !== 'COMPLETED') {
      // If not completed (e.g. PARTIAL or FAILED), the strict COMPLETED invariant is not required
      return;
    }

    const missing: string[] = [];

    // Check findings if expected
    if (expectations?.expectFindingsCount && expectations.expectFindingsCount > 0) {
      const findingsRes = await client.query(`
        SELECT count(*)::int AS count FROM analysis.static_findings WHERE analysis_run_id = $1;
      `, [analysisRunId]);
      const actualCount = parseInt(String(findingsRes.rows[0]?.count ?? '0'), 10);
      if (actualCount < expectations.expectFindingsCount) {
        missing.push(`findings (expected ${expectations.expectFindingsCount}, found ${actualCount})`);
      }
    }

    // Check evidence if expected
    if (expectations?.expectEvidenceCount && expectations.expectEvidenceCount > 0) {
      const evidenceRes = await client.query(`
        SELECT count(*)::int AS count FROM intel.evidence WHERE analysis_run_id = $1;
      `, [analysisRunId]);
      const actualCount = parseInt(String(evidenceRes.rows[0]?.count ?? '0'), 10);
      if (actualCount < expectations.expectEvidenceCount) {
        missing.push(`evidence (expected ${expectations.expectEvidenceCount}, found ${actualCount})`);
      }
    }

    // Check score result if expected
    if (expectations?.expectScoreResult) {
      const scoreRes = await client.query(`
        SELECT score_result_id FROM intel.score_results WHERE analysis_run_id = $1;
      `, [analysisRunId]);
      if (scoreRes.rows.length === 0) {
        missing.push('score_results');
      }
    }

    // Check policy decision if expected
    if (expectations?.expectPolicyDecision) {
      const policyRes = await client.query(`
        SELECT decision_id FROM intel.policy_decisions WHERE analysis_run_id = $1;
      `, [analysisRunId]);
      if (policyRes.rows.length === 0) {
        missing.push('policy_decisions');
      }
    }

    if (missing.length > 0) {
      throw new IncompleteAnalysisPersistenceError(analysisRunId, missing);
    }
  }
}
