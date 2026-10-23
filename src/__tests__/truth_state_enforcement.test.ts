import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { createTestDb } from '@caim/db/migrator.js';
import { PgMemDbRepositories } from '@caim/db/repositories.js';
import {
  StaticFindingSchema,
  EvidenceSchema,
  ClaimSchema,
  RuntimeEventSchema,
  AnswerClaimSchema,
  TelemetryRecordSchema,
  TRUTH_STATES,
} from '@caim/db/types.js';

describe('Epistemic Metadata & truthState Database Constraint Enforcement', () => {
  let db: any;
  let client: any;
  let repos: PgMemDbRepositories;

  const agentId = '11111111-1111-1111-1111-111111111111';
  const versionId = '22222222-2222-2222-2222-222222222222';
  const platformScopeId = '00000000-0000-0000-0000-000000000001';
  const runId = '55555555-5555-5555-5555-555555555555';
  const queryId = '66666666-6666-6666-6666-666666666666';
  const answerId = '77777777-7777-7777-7777-777777777777';

  beforeAll(async () => {
    db = createTestDb({ applyMigrations: true, applySeed: true });
    repos = new PgMemDbRepositories(db);
    client = db.adapters.createPg().Client;

    // Seed agent and agent_version
    await repos.createAgent({
      agent_id: agentId,
      canonical_name: 'TruthTesterAgent',
      status: 'ACTIVE',
      identity_confidence: 1.0,
    });

    await repos.createAgentVersion({
      agent_version_id: versionId,
      agent_id: agentId,
      version_label: '1.0.0',
      content_fingerprint: 'sha256:truthtesterhash123',
    });

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

    const classId = '00000000-0000-0000-0000-000000000010';

    await repos.createQuery({
      query_id: queryId,
      principal_id: 'principal-1',
      query_text_or_hash: 'Test Query',
      intent_type: 'GENERAL',
      security_classification_id: classId,
    });

    await repos.createAnswer({
      answer_id: answerId,
      query_id: queryId,
      model_version: 'gemini-1.5-pro',
      prompt_version: 'v1',
      answer_text_or_locator: 'Test Answer',
      status: 'COMPLETED',
    });
  });

  describe('Database Schema Level Constraint: Rejection when truth_state is missing or NULL', () => {
    it('rejects attempt to insert an analysis.static_findings record without truth_state (NULL / omitted)', async () => {
      const pgClient = new client();
      await pgClient.connect();

      // Attempt raw INSERT without truth_state column or explicit NULL
      await expect(
        pgClient.query(`
          INSERT INTO analysis.static_findings (
            finding_id, analysis_run_id, rule_id, finding_type, severity, confidence, message
          ) VALUES (
            'f0000000-0000-0000-0000-000000000001', '${runId}', 'RULE-01', 'VULNERABILITY', 'HIGH', 0.9, 'Missing truthState'
          );
        `)
      ).rejects.toThrow(/chk_static_findings_truth_state|null/i);

      // Attempt explicit NULL
      await expect(
        pgClient.query(`
          INSERT INTO analysis.static_findings (
            finding_id, analysis_run_id, rule_id, finding_type, severity, confidence, message,
            truth_state, source_id, analyzer_version, observed_at
          ) VALUES (
            'f0000000-0000-0000-0000-000000000002', '${runId}', 'RULE-01', 'VULNERABILITY', 'HIGH', 0.9, 'Null truthState',
            NULL, 'src-1', '1.0.0', NOW()
          );
        `)
      ).rejects.toThrow(/chk_static_findings_truth_state|null/i);
    });

    it('rejects attempt to insert an intel.evidence record without truth_state', async () => {
      const pgClient = new client();
      await pgClient.connect();

      await expect(
        pgClient.query(`
          INSERT INTO intel.evidence (
            evidence_id, analysis_run_id, evidence_type, description, confidence, weight, scope_id
          ) VALUES (
            'e0000000-0000-0000-0000-000000000001', '${runId}', 'STATIC_CODE', 'Missing truthState', 1.0, 1.0, '${platformScopeId}'
          );
        `)
      ).rejects.toThrow(/chk_evidence_truth_state|null/i);
    });

    it('rejects attempt to insert an intel.claims record without truth_state', async () => {
      const pgClient = new client();
      await pgClient.connect();

      await expect(
        pgClient.query(`
          INSERT INTO intel.claims (
            claim_id, analysis_run_id, claim_type, claim_text, state, confidence, scope_id
          ) VALUES (
            'c0000000-0000-0000-0000-000000000001', '${runId}', 'CAPABILITY', 'Unconstrained execution', 'SUPPORTED', 0.9, '${platformScopeId}'
          );
        `)
      ).rejects.toThrow(/chk_claims_truth_state|null/i);
    });

    it('rejects attempt to insert a knowledge.answer_claims record without truth_state', async () => {
      const pgClient = new client();
      await pgClient.connect();

      await expect(
        pgClient.query(`
          INSERT INTO knowledge.answer_claims (
            answer_claim_id, answer_id, sequence, claim_text, grounding_state, confidence
          ) VALUES (
            'ac000000-0000-0000-0000-000000000001', '${answerId}', 1, 'Claim text', 'GROUNDED', 0.95
          );
        `)
      ).rejects.toThrow(/chk_answer_claims_truth_state|null/i);
    });

    it('rejects attempt to insert an analysis.runtime_events record without truth_state', async () => {
      const pgClient = new client();
      await pgClient.connect();

      await expect(
        pgClient.query(`
          INSERT INTO analysis.runtime_events (
            runtime_event_id, analysis_run_id, event_type, event_timestamp, status
          ) VALUES (
            'de000000-0000-4000-8000-000000000001', '${runId}', 'OUTBOUND_HTTP', NOW(), 'RECORDED'
          );
        `)
      ).rejects.toThrow(/chk_runtime_events_truth_state|null/i);
    });

    it('rejects attempt to insert an ops.telemetry_records record without truth_state', async () => {
      const pgClient = new client();
      await pgClient.connect();

      await expect(
        pgClient.query(`
          INSERT INTO ops.telemetry_records (
            telemetry_id, source_id, analyzer_version, observed_at, confidence
          ) VALUES (
            'be000000-0000-4000-8000-000000000001', 'agent-probe', '1.0.0', NOW(), 1.0
          );
        `)
      ).rejects.toThrow(/chk_telemetry_records_truth_state|null/i);
    });
  });

  describe('Database Schema Level Constraint: Rejection when truth_state is an invalid enum value', () => {
    it('rejects invalid truth_state value like SPECULATIVE or INVALID_STATE', async () => {
      const pgClient = new client();
      await pgClient.connect();

      await expect(
        pgClient.query(`
          INSERT INTO analysis.static_findings (
            finding_id, analysis_run_id, rule_id, finding_type, severity, confidence, message,
            truth_state, source_id, analyzer_version, observed_at
          ) VALUES (
            'f0000000-0000-0000-0000-000000000003', '${runId}', 'RULE-01', 'VULNERABILITY', 'HIGH', 0.9, 'Invalid truthState',
            'SPECULATIVE', 'src-1', '1.0.0', NOW()
          );
        `)
      ).rejects.toThrow(/invalid input value for enum truth_state|chk_static_findings_truth_state/i);
    });
  });

  describe('Database Schema: Successful insertion for all 8 defined truthState values with full epistemic metadata', () => {
    it('inserts records for all 8 truthState values with sourceId, evidenceId, analyzerVersion, observedAt, confidence, limitations', async () => {
      const pgClient = new client();
      await pgClient.connect();

      // First insert an initial authoritative evidence record to serve as an evidenceId reference
      await pgClient.query(`
        INSERT INTO intel.evidence (
          evidence_id, analysis_run_id, evidence_type, description, confidence, weight, scope_id,
          truth_state, source_id, analyzer_version, observed_at, limitations
        ) VALUES (
          'e1000000-0000-4000-8000-000000000000', '${runId}', 'STATIC_CODE', 'Root evidence', 1.0, 1.0, '${platformScopeId}',
          'OBSERVED', 'kernel-tracer', '2.0.0', NOW(), 'None'
        );
      `);

      for (let i = 0; i < TRUTH_STATES.length; i++) {
        const state = TRUTH_STATES[i];
        const findingId = `f1000000-0000-4000-8000-00000000000${i}`;
        const claimId = `c1000000-0000-4000-8000-00000000000${i}`;
        const telemetryId = `b1000000-0000-4000-8000-00000000000${i}`;

        // Static finding with epistemic metadata and evidence_id reference
        const resFinding = await pgClient.query(`
          INSERT INTO analysis.static_findings (
            finding_id, analysis_run_id, rule_id, finding_type, severity, confidence, message,
            truth_state, source_id, evidence_id, analyzer_version, observed_at, limitations
          ) VALUES (
            '${findingId}', '${runId}', 'RULE-${i}', 'VULNERABILITY', 'HIGH', 0.95, 'Finding with state ${state}',
            '${state}', 'analyzer-${i}', 'e1000000-0000-4000-8000-000000000000', '2.0.1', NOW(), 'Verified under controlled sandbox'
          ) RETURNING *;
        `);
        expect(resFinding.rows[0].truth_state).toBe(state);
        expect(resFinding.rows[0].source_id).toBe(`analyzer-${i}`);
        expect(resFinding.rows[0].evidence_id).toBe('e1000000-0000-4000-8000-000000000000');
        expect(resFinding.rows[0].analyzer_version).toBe('2.0.1');
        expect(resFinding.rows[0].limitations).toBe('Verified under controlled sandbox');

        // Claim with epistemic metadata
        const resClaim = await pgClient.query(`
          INSERT INTO intel.claims (
            claim_id, analysis_run_id, claim_type, claim_text, state, confidence, scope_id,
            truth_state, source_id, evidence_id, analyzer_version, observed_at, limitations
          ) VALUES (
            '${claimId}', '${runId}', 'CAPABILITY', 'Claim with state ${state}', 'SUPPORTED', 0.99, '${platformScopeId}',
            '${state}', 'reasoner-${i}', 'e1000000-0000-4000-8000-000000000000', '2.0.1', NOW(), 'Epistemic boundary check'
          ) RETURNING *;
        `);
        expect(resClaim.rows[0].truth_state).toBe(state);

        // Telemetry record with epistemic metadata
        const resTelemetry = await pgClient.query(`
          INSERT INTO ops.telemetry_records (
            telemetry_id, truth_state, source_id, evidence_id, analyzer_version, observed_at, confidence, limitations, metric_name, payload
          ) VALUES (
            '${telemetryId}', '${state}', 'telemetry-collector', 'e1000000-0000-4000-8000-000000000000', '2.0.1', NOW(), 1.0, 'Host probe', 'cpu_usage', '{"value": 42}'
          ) RETURNING *;
        `);
        expect(resTelemetry.rows[0].truth_state).toBe(state);
      }
    });
  });

  describe('Lint/Test Rule: Enforce explicit truthState at construction time with no defaults', () => {
    const validUuid1 = '40404040-1111-4111-8111-111111111111';
    const validUuid2 = '50505050-1111-4111-8111-111111111111';

    it('fails Zod validation when truthState is omitted or undefined on static findings', () => {
      const invalidFinding = {
        finding_id: validUuid1,
        analysis_run_id: validUuid2,
        rule_id: 'R1',
        finding_type: 'VULNERABILITY',
        severity: 'HIGH',
        confidence: 0.95,
        message: 'No truthState provided',
        sourceId: 'rule-engine',
        analyzerVersion: '1.0.0',
        observedAt: new Date().toISOString(),
        // truthState omitted
      };

      const result = StaticFindingSchema.safeParse(invalidFinding);
      expect(result.success).toBe(false);
      if (!result.success) {
        const issues = result.error.issues.map((i) => i.path.join('.'));
        expect(issues).toContain('truthState');
      }

      const validFinding = {
        ...invalidFinding,
        truthState: 'STATICALLY_DERIVED',
      };
      expect(StaticFindingSchema.safeParse(validFinding).success).toBe(true);
    });

    it('fails Zod validation when truthState is omitted or undefined on evidence', () => {
      const invalidEvidence = {
        evidence_id: validUuid1,
        analysis_run_id: validUuid2,
        evidence_type: 'STATIC_CODE',
        description: 'No truthState provided',
        confidence: 1.0,
        weight: 1.0,
        sourceId: 'evidence-engine',
        analyzerVersion: '1.0.0',
        observedAt: new Date().toISOString(),
        // truthState omitted
      };

      const result = EvidenceSchema.safeParse(invalidEvidence);
      expect(result.success).toBe(false);
      if (!result.success) {
        const issues = result.error.issues.map((i) => i.path.join('.'));
        expect(issues).toContain('truthState');
      }

      const validEvidence = {
        ...invalidEvidence,
        truthState: 'OBSERVED',
      };
      expect(EvidenceSchema.safeParse(validEvidence).success).toBe(true);
    });

    it('fails Zod validation when truthState is omitted or undefined on claims', () => {
      const invalidClaim = {
        claim_id: validUuid1,
        analysis_run_id: validUuid2,
        claim_type: 'CAPABILITY',
        claim_text: 'Claim with missing truthState',
        state: 'SUPPORTED',
        confidence: 0.9,
        uncertainty_score: 0.1,
        sourceId: 'claim-engine',
        analyzerVersion: '1.0.0',
        observedAt: new Date().toISOString(),
        // truthState omitted
      };

      const result = ClaimSchema.safeParse(invalidClaim);
      expect(result.success).toBe(false);
      if (!result.success) {
        const issues = result.error.issues.map((i) => i.path.join('.'));
        expect(issues).toContain('truthState');
      }

      const validClaim = {
        ...invalidClaim,
        truthState: 'INFERRED',
      };
      expect(ClaimSchema.safeParse(validClaim).success).toBe(true);
    });

    it('fails Zod validation when truthState is omitted or undefined on telemetry records', () => {
      const invalidTelemetry = {
        telemetry_id: validUuid1,
        sourceId: 'host-telemetry',
        analyzerVersion: '1.0.0',
        observedAt: new Date().toISOString(),
        confidence: 1.0,
        // truthState omitted
      };

      const result = TelemetryRecordSchema.safeParse(invalidTelemetry);
      expect(result.success).toBe(false);
      if (!result.success) {
        const issues = result.error.issues.map((i) => i.path.join('.'));
        expect(issues).toContain('truthState');
      }

      const validTelemetry = {
        ...invalidTelemetry,
        truthState: 'SIMULATED',
      };
      expect(TelemetryRecordSchema.safeParse(validTelemetry).success).toBe(true);
    });

    it('scans codebase to verify no call site constructs or creates records without setting truthState explicitly', () => {
      function extractFunctionCallArguments(source: string, functionName: string): string[] {
        const calls: string[] = [];
        const pattern = new RegExp(`\\b${functionName}\\s*\\(`, 'g');
        let match: RegExpExecArray | null;

        while ((match = pattern.exec(source)) !== null) {
          const startIndex = match.index + match[0].length;
          let depth = 1;
          let inString: string | null = null;
          let i = startIndex;

          while (i < source.length && depth > 0) {
            const char = source[i];
            const prevChar = i > 0 ? source[i - 1] : '';

            if (inString) {
              if (char === inString && prevChar !== '\\') {
                inString = null;
              }
            } else {
              if (char === "'" || char === '"' || char === '`') {
                inString = char;
              } else if (char === '(' || char === '{' || char === '[') {
                depth++;
              } else if (char === ')' || char === '}' || char === ']') {
                depth--;
              }
            }
            i++;
          }

          if (depth === 0) {
            calls.push(source.substring(startIndex, i - 1));
          }
        }
        return calls;
      }

      const filesToCheck = [
        join(process.cwd(), 'src/__tests__/p04_analysis_intel.test.ts'),
        join(process.cwd(), 'src/__tests__/p05_knowledge_lifecycle_ops.test.ts'),
        join(process.cwd(), 'apps/server/index.ts'),
      ];

      const monitoredFunctions = [
        'createStaticFinding',
        'createEvidence',
        'createClaim',
        'createRuntimeEvent',
        'createAnswerClaim',
      ];

      for (const filePath of filesToCheck) {
        const content = readFileSync(filePath, 'utf-8');

        for (const fn of monitoredFunctions) {
          const calls = extractFunctionCallArguments(content, fn);
          for (const callArg of calls) {
            expect(callArg).toMatch(/truthState|truth_state/);
          }
        }
      }
    });
  });
});
