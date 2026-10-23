import { describe, it, expect, beforeEach } from 'vitest';
import { newDb } from 'pg-mem';
import {
  STATE_MACHINE_VERSION,
  STATE_REGISTRY,
  getEntityCatalog,
  getStateDescriptor,
  isTerminalState,
  isReviewState,
  isFailureState,
  isCancelState,
  AnalysisRunStates,
  AnalysisStageRunStates,
  AgentVersionStates,
  ValidationRunStates,
  PackageStates,
  ShipmentStates,
  WorkflowRunStates,
  JobStates,
  LifecycleStateEngine,
  StateProjector,
  LifecycleStateMachineService,
  PolicyGateRegistry,
  InvalidStateTransitionError,
  TerminalStateError,
  PolicyGateFailedError,
  MissingTransitionReasonError,
  UnauthorizedTransitionActorError,
  StateProjectionIntegrityError,
  StateTransitionConflictError,
  StateRegistryLookupError,
} from '@caim/lifecycle';
import { runLifecycleJob } from '../../workers/lifecycle/index.ts';

describe('P08 - Authoritative Lifecycle State Engine', () => {
  let db: any;
  let client: any;

  beforeEach(async () => {
    db = newDb();
    // Setup necessary schemas and tables for persistence tests
    db.public.none(`
      CREATE SCHEMA ops;
      CREATE SCHEMA analysis;
      CREATE SCHEMA lifecycle;
      CREATE SCHEMA core;

      CREATE TABLE ops.lifecycle_state_transitions (
        state_transition_id text PRIMARY KEY,
        entity_ref_id text NOT NULL,
        from_state text,
        to_state text NOT NULL,
        transition_reason text NOT NULL,
        actor_ref text,
        occurred_at timestamptz NOT NULL DEFAULT now()
      );

      CREATE TABLE analysis.analysis_runs (
        analysis_run_id text PRIMARY KEY,
        status text NOT NULL,
        completed_at timestamptz
      );

      CREATE TABLE analysis.analysis_stage_runs (
        stage_run_id text PRIMARY KEY,
        status text NOT NULL,
        completed_at timestamptz
      );

      CREATE TABLE lifecycle.validation_runs (
        validation_run_id text PRIMARY KEY,
        status text NOT NULL
      );

      CREATE TABLE ops.jobs (
        job_id text PRIMARY KEY,
        status text NOT NULL,
        completed_at timestamptz
      );
    `);
    const pg = db.adapters.createPg();
    client = new pg.Client();
    await client.connect();
  });

  describe('1. State Registry and Metadata Catalog', () => {
    it('verifies all 9 entity kinds exist in the registry with correct state descriptors', () => {
      const entityKinds = [
        'ANALYSIS_RUN',
        'ANALYSIS_STAGE_RUN',
        'AGENT_VERSION',
        'VALIDATION_RUN',
        'MODIFICATION_WORKSPACE',
        'PACKAGE',
        'SHIPMENT',
        'WORKFLOW_RUN',
        'JOB',
      ] as const;

      expect(STATE_MACHINE_VERSION).toBe('2.0.1');

      for (const kind of entityKinds) {
        const catalog = getEntityCatalog(kind);
        expect(catalog.entityKind).toBe(kind);
        expect(catalog.initialState).toBeDefined();
        expect(catalog.terminalStates.size).toBeGreaterThan(0);
        expect(Object.keys(catalog.states).length).toBeGreaterThan(0);
      }
    });

    it('validates state classification helpers (terminal, review, failure, cancel)', () => {
      expect(isTerminalState('ANALYSIS_RUN', AnalysisRunStates.COMPLETED)).toBe(true);
      expect(isTerminalState('ANALYSIS_RUN', AnalysisRunStates.FAILED)).toBe(true);
      expect(isTerminalState('ANALYSIS_RUN', AnalysisRunStates.CANCELLED)).toBe(true);
      expect(isTerminalState('ANALYSIS_RUN', AnalysisRunStates.RUNNING)).toBe(false);

      expect(isReviewState('ANALYSIS_RUN', AnalysisRunStates.REQUIRES_REVIEW)).toBe(true);
      expect(isReviewState('ANALYSIS_RUN', AnalysisRunStates.IN_REVIEW)).toBe(true);
      expect(isReviewState('ANALYSIS_RUN', AnalysisRunStates.RUNNING)).toBe(false);

      expect(isFailureState('ANALYSIS_RUN', AnalysisRunStates.FAILED)).toBe(true);
      expect(isCancelState('ANALYSIS_RUN', AnalysisRunStates.CANCELLED)).toBe(true);

      expect(isTerminalState('AGENT_VERSION', AgentVersionStates.ARCHIVED)).toBe(true);
      expect(isTerminalState('AGENT_VERSION', AgentVersionStates.SUPERSEDED)).toBe(true);
      expect(isReviewState('AGENT_VERSION', AgentVersionStates.PENDING_REVIEW)).toBe(true);
      expect(isReviewState('AGENT_VERSION', AgentVersionStates.IN_REVIEW)).toBe(true);
      expect(isFailureState('AGENT_VERSION', AgentVersionStates.QUARANTINED)).toBe(true);
      expect(isFailureState('AGENT_VERSION', AgentVersionStates.REVOKED)).toBe(true);
    });

    it('throws StateRegistryLookupError for unregistered entity kinds or unknown states', () => {
      expect(() => getEntityCatalog('NON_EXISTENT_KIND' as any)).toThrow(StateRegistryLookupError);
      expect(() => getStateDescriptor('ANALYSIS_RUN', 'UNKNOWN_STATE')).toThrow(StateRegistryLookupError);
    });
  });

  describe('2. Exhaustive Legal Transition Tests', () => {
    describe('AnalysisRun transitions', () => {
      it('supports the full golden path: PENDING -> QUEUED -> RUNNING -> STAGE_EXECUTION -> EVALUATING_POLICIES -> COMPLETED', async () => {
        const runId = 'run-101';
        const actor = 'service:orchestrator';
        const corrId = 'corr-101';

        // 1. Genesis -> PENDING
        const res1 = await LifecycleStateEngine.validate({
          entityRefId: runId,
          entityKind: 'ANALYSIS_RUN',
          fromState: null,
          toState: 'PENDING',
          action: 'INITIALIZE',
          transitionReason: 'Analysis run requested',
          actorRef: actor,
          correlationId: corrId,
        });
        expect(res1.valid).toBe(true);

        // 2. PENDING -> QUEUED
        const res2 = await LifecycleStateEngine.validate({
          entityRefId: runId,
          entityKind: 'ANALYSIS_RUN',
          fromState: 'PENDING',
          toState: 'QUEUED',
          action: 'QUEUE',
          actorRef: actor,
          correlationId: corrId,
        });
        expect(res2.valid).toBe(true);

        // 3. QUEUED -> RUNNING
        const res3 = await LifecycleStateEngine.validate({
          entityRefId: runId,
          entityKind: 'ANALYSIS_RUN',
          fromState: 'QUEUED',
          toState: 'RUNNING',
          action: 'START',
          actorRef: actor,
          correlationId: corrId,
        });
        expect(res3.valid).toBe(true);

        // 4. RUNNING -> STAGE_EXECUTION
        const res4 = await LifecycleStateEngine.validate({
          entityRefId: runId,
          entityKind: 'ANALYSIS_RUN',
          fromState: 'RUNNING',
          toState: 'STAGE_EXECUTION',
          action: 'START_STAGES',
          actorRef: actor,
          correlationId: corrId,
        });
        expect(res4.valid).toBe(true);

        // 5. STAGE_EXECUTION -> EVALUATING_POLICIES
        const res5 = await LifecycleStateEngine.validate({
          entityRefId: runId,
          entityKind: 'ANALYSIS_RUN',
          fromState: 'STAGE_EXECUTION',
          toState: 'EVALUATING_POLICIES',
          action: 'STAGES_COMPLETE',
          actorRef: actor,
          correlationId: corrId,
        });
        expect(res5.valid).toBe(true);

        // 6. EVALUATING_POLICIES -> COMPLETED (policy gate pass)
        const res6 = await LifecycleStateEngine.validate({
          entityRefId: runId,
          entityKind: 'ANALYSIS_RUN',
          fromState: 'EVALUATING_POLICIES',
          toState: 'COMPLETED',
          action: 'COMPLETE',
          actorRef: actor,
          correlationId: corrId,
          gateContext: {
            policyDecisions: [{ decision: 'PASS', policyName: 'Zero Critical Vulnerabilities' }],
          },
        });
        expect(res6.valid).toBe(true);
      });

      it('supports review, approval, and reanalysis loops', async () => {
        const runId = 'run-102';
        const actor = 'principal:auditor-1';
        const corrId = 'corr-102';

        // EVALUATING_POLICIES -> REQUIRES_REVIEW
        const toReview = await LifecycleStateEngine.validate({
          entityRefId: runId,
          entityKind: 'ANALYSIS_RUN',
          fromState: 'EVALUATING_POLICIES',
          toState: 'REQUIRES_REVIEW',
          action: 'FLAG_REVIEW',
          transitionReason: 'High risk finding detected; human review needed',
          actorRef: 'engine:policy-evaluator',
          correlationId: corrId,
        });
        expect(toReview.valid).toBe(true);

        // REQUIRES_REVIEW -> IN_REVIEW
        const inReview = await LifecycleStateEngine.validate({
          entityRefId: runId,
          entityKind: 'ANALYSIS_RUN',
          fromState: 'REQUIRES_REVIEW',
          toState: 'IN_REVIEW',
          action: 'START_REVIEW',
          transitionReason: 'Auditor opened investigation',
          actorRef: actor,
          correlationId: corrId,
          actorRoles: ['security_auditor'],
        });
        expect(inReview.valid).toBe(true);

        // IN_REVIEW -> REANALYZING (request reanalysis with new rules)
        const reanalyze = await LifecycleStateEngine.validate({
          entityRefId: runId,
          entityKind: 'ANALYSIS_RUN',
          fromState: 'IN_REVIEW',
          toState: 'REANALYZING',
          action: 'REQUEST_REANALYSIS',
          transitionReason: 'Requested reanalysis with deeper AST call graph depth',
          actorRef: actor,
          correlationId: corrId,
          actorRoles: ['security_auditor'],
        });
        expect(reanalyze.valid).toBe(true);

        // REANALYZING -> STAGE_EXECUTION -> EVALUATING_POLICIES
        const reExecute = await LifecycleStateEngine.validate({
          entityRefId: runId,
          entityKind: 'ANALYSIS_RUN',
          fromState: 'REANALYZING',
          toState: 'STAGE_EXECUTION',
          action: 'RESTART_STAGES',
          transitionReason: 'Re-running static stage',
          actorRef: 'service:orchestrator',
          correlationId: corrId,
        });
        expect(reExecute.valid).toBe(true);
      });
    });

    describe('AgentVersion full lifecycle & quarantine recovery', () => {
      it('supports quarantine and unquarantine path with administrative sign-off', async () => {
        const verId = 'ver-201';
        const corrId = 'corr-201';

        // 1. DISCOVERED -> QUARANTINED
        const quarantineRes = await LifecycleStateEngine.validate({
          entityRefId: verId,
          entityKind: 'AGENT_VERSION',
          fromState: 'DISCOVERED',
          toState: 'QUARANTINED',
          action: 'QUARANTINE_DIRECT',
          transitionReason: 'Suspicious payload detected at discovery',
          actorRef: 'service:discovery',
          correlationId: corrId,
        });
        expect(quarantineRes.valid).toBe(true);

        // 2. QUARANTINED -> IN_REVIEW (requires platform_admin role and admin approval record)
        const unquarantinePass = await LifecycleStateEngine.validate({
          entityRefId: verId,
          entityKind: 'AGENT_VERSION',
          fromState: 'QUARANTINED',
          toState: 'IN_REVIEW',
          action: 'UNQUARANTINE_REVIEW',
          transitionReason: 'Security lead authorized controlled review of payload',
          actorRef: 'principal:admin-lead',
          correlationId: corrId,
          actorRoles: ['platform_admin'],
          gateContext: {
            actorRoles: ['platform_admin'],
            approvals: [{
              approverId: 'admin-lead',
              approverRole: 'platform_admin',
              decision: 'APPROVED',
              reason: 'Confirmed false positive signature after sandbox analysis',
            }],
          },
        });
        expect(unquarantinePass.valid).toBe(true);

        // 3. IN_REVIEW -> APPROVED -> PROMOTED -> RELEASED
        const approvePass = await LifecycleStateEngine.validate({
          entityRefId: verId,
          entityKind: 'AGENT_VERSION',
          fromState: 'IN_REVIEW',
          toState: 'APPROVED',
          action: 'APPROVE_SIGN_OFF',
          transitionReason: 'Formal security clearance sign-off',
          actorRef: 'principal:admin-lead',
          correlationId: corrId,
          actorRoles: ['security_auditor'],
          gateContext: {
            approvals: [{
              approverId: 'admin-lead',
              approverRole: 'security_auditor',
              decision: 'APPROVED',
            }],
          },
        });
        expect(approvePass.valid).toBe(true);
      });
    });

    describe('AnalysisStageRun, Job, WorkflowRun, Package & Shipment', () => {
      it('validates StageRun timeout, retry, and cancellation paths', async () => {
        const stageId = 'stage-301';
        const corrId = 'corr-301';

        // PENDING -> RUNNING
        expect((await LifecycleStateEngine.validate({
          entityRefId: stageId,
          entityKind: 'ANALYSIS_STAGE_RUN',
          fromState: 'PENDING',
          toState: 'RUNNING',
          action: 'START',
          actorRef: 'worker:static',
          correlationId: corrId,
        })).valid).toBe(true);

        // RUNNING -> TIMED_OUT
        expect((await LifecycleStateEngine.validate({
          entityRefId: stageId,
          entityKind: 'ANALYSIS_STAGE_RUN',
          fromState: 'RUNNING',
          toState: 'TIMED_OUT',
          action: 'TIMEOUT',
          transitionReason: 'Stage exceeded 30000ms deadline',
          actorRef: 'service:watchdog',
          correlationId: corrId,
        })).valid).toBe(true);
      });

      it('validates Job retry loop: RUNNING -> RETRYING -> QUEUED -> RUNNING -> COMPLETED', async () => {
        const jobId = 'job-401';
        const corrId = 'corr-401';

        // RUNNING -> RETRYING
        expect((await LifecycleStateEngine.validate({
          entityRefId: jobId,
          entityKind: 'JOB',
          fromState: 'RUNNING',
          toState: 'RETRYING',
          action: 'SCHEDULE_RETRY',
          transitionReason: 'Database transient timeout, backing off for 2000ms',
          actorRef: 'worker:node-1',
          correlationId: corrId,
        })).valid).toBe(true);

        // RETRYING -> QUEUED
        expect((await LifecycleStateEngine.validate({
          entityRefId: jobId,
          entityKind: 'JOB',
          fromState: 'RETRYING',
          toState: 'QUEUED',
          action: 'RE_ENQUEUE',
          actorRef: 'service:scheduler',
          correlationId: corrId,
        })).valid).toBe(true);
      });

      it('validates Package signing, shipping, and revocation', async () => {
        const pkgId = 'pkg-501';
        const corrId = 'corr-501';

        // SIGNED -> SHIPPED
        expect((await LifecycleStateEngine.validate({
          entityRefId: pkgId,
          entityKind: 'PACKAGE',
          fromState: 'SIGNED',
          toState: 'SHIPPED',
          action: 'DISPATCH',
          transitionReason: 'Package dispatched to customer deployment registry',
          actorRef: 'service:shipping',
          correlationId: corrId,
          gateContext: {
            risks: [],
          },
        })).valid).toBe(true);

        // SHIPPED -> REVOKED (emergency revocation)
        expect((await LifecycleStateEngine.validate({
          entityRefId: pkgId,
          entityKind: 'PACKAGE',
          fromState: 'SHIPPED',
          toState: 'REVOKED',
          action: 'REVOKE',
          transitionReason: 'CVE-2026-9999 zero-day disclosed in upstream dependency',
          actorRef: 'principal:cso-officer',
          correlationId: corrId,
        })).valid).toBe(true);
      });
    });
  });

  describe('3. Illegal Transition & Jump Tests', () => {
    it('rejects illegal jumps skipping intermediate mandatory states', async () => {
      // PENDING -> COMPLETED directly for AnalysisRun (illegal jump)
      await expect(LifecycleStateEngine.assertLegalTransition({
        entityRefId: 'run-999',
        entityKind: 'ANALYSIS_RUN',
        fromState: 'PENDING',
        toState: 'COMPLETED',
        action: 'COMPLETE',
        transitionReason: 'Illegal skip',
        actorRef: 'attacker',
        correlationId: 'corr-illegal',
      })).rejects.toThrow(InvalidStateTransitionError);

      // DRAFT -> RELEASED directly for AgentVersion (illegal jump)
      await expect(LifecycleStateEngine.assertLegalTransition({
        entityRefId: 'ver-999',
        entityKind: 'AGENT_VERSION',
        fromState: 'DRAFT',
        toState: 'RELEASED',
        action: 'RELEASE',
        transitionReason: 'Illegal fast track',
        actorRef: 'attacker',
        correlationId: 'corr-illegal',
      })).rejects.toThrow(InvalidStateTransitionError);
    });

    it('rejects transitions originating from immutable terminal states', async () => {
      // Attempting to transition from COMPLETED -> RUNNING
      await expect(LifecycleStateEngine.assertLegalTransition({
        entityRefId: 'run-888',
        entityKind: 'ANALYSIS_RUN',
        fromState: 'COMPLETED',
        toState: 'RUNNING',
        action: 'START',
        transitionReason: 'Attempted resume of completed run',
        actorRef: 'service:orchestrator',
        correlationId: 'corr-term',
      })).rejects.toThrow(TerminalStateError);

      // Attempting to transition from CANCELLED -> STAGE_EXECUTION
      await expect(LifecycleStateEngine.assertLegalTransition({
        entityRefId: 'run-889',
        entityKind: 'ANALYSIS_RUN',
        fromState: 'CANCELLED',
        toState: 'STAGE_EXECUTION',
        action: 'START_STAGES',
        transitionReason: 'Attempted stage execution after cancel',
        actorRef: 'service:orchestrator',
        correlationId: 'corr-term',
      })).rejects.toThrow(TerminalStateError);
    });
  });

  describe('4. Policy Gate Enforcement Tests', () => {
    it('blocks EVALUATING_POLICIES -> COMPLETED when policy decisions contain FAIL', async () => {
      await expect(LifecycleStateEngine.assertLegalTransition({
        entityRefId: 'run-777',
        entityKind: 'ANALYSIS_RUN',
        fromState: 'EVALUATING_POLICIES',
        toState: 'COMPLETED',
        action: 'COMPLETE',
        actorRef: 'engine:policy-evaluator',
        correlationId: 'corr-gate',
        gateContext: {
          policyDecisions: [
            { decision: 'PASS', policyName: 'License Compliance' },
            { decision: 'FAIL', policyName: 'Hardcoded Secret Detection', outcomeReason: 'AWS Secret Key detected in prompt template' },
          ],
        },
      })).rejects.toThrow(PolicyGateFailedError);
    });

    it('blocks AGENT_VERSION promotion when unmitigated CRITICAL risks exist', async () => {
      await expect(LifecycleStateEngine.assertLegalTransition({
        entityRefId: 'ver-777',
        entityKind: 'AGENT_VERSION',
        fromState: 'ANALYZED',
        toState: 'APPROVED',
        action: 'AUTO_APPROVE',
        transitionReason: 'Attempting auto-approval',
        actorRef: 'service:orchestrator',
        correlationId: 'corr-risk',
        gateContext: {
          risks: [
            { severity: 'CRITICAL', title: 'Remote Code Execution via Eval Injection', mitigated: false },
          ],
        },
      })).rejects.toThrow(PolicyGateFailedError);
    });

    it('blocks VALIDATION_RUN pass when validation status is FAILED', async () => {
      await expect(LifecycleStateEngine.assertLegalTransition({
        entityRefId: 'val-777',
        entityKind: 'VALIDATION_RUN',
        fromState: 'RUNNING',
        toState: 'PASSED',
        action: 'PASS',
        actorRef: 'worker:validator',
        correlationId: 'corr-val',
        gateContext: {
          validationRunStatus: 'FAILED',
        },
      })).rejects.toThrow(PolicyGateFailedError);
    });

    it('blocks quarantine unquarantine when admin approval is missing', async () => {
      // Has role but missing admin approval
      await expect(LifecycleStateEngine.assertLegalTransition({
        entityRefId: 'ver-666',
        entityKind: 'AGENT_VERSION',
        fromState: 'QUARANTINED',
        toState: 'IN_REVIEW',
        action: 'UNQUARANTINE_REVIEW',
        transitionReason: 'Admin attempting unquarantine without formal sign-off record',
        actorRef: 'principal:admin-joe',
        correlationId: 'corr-quar',
        actorRoles: ['platform_admin'],
        gateContext: {
          actorRoles: ['platform_admin'],
          approvals: [], // Empty approvals
        },
      })).rejects.toThrow(PolicyGateFailedError);
    });
  });

  describe('5. Mandatory Reason & Role Restriction Tests', () => {
    it('throws MissingTransitionReasonError when mandatory transition reason is empty or omitted', async () => {
      await expect(LifecycleStateEngine.assertLegalTransition({
        entityRefId: 'run-555',
        entityKind: 'ANALYSIS_RUN',
        fromState: 'RUNNING',
        toState: 'FAILED',
        action: 'FAIL',
        transitionReason: '   ', // Empty/whitespace only
        actorRef: 'service:orchestrator',
        correlationId: 'corr-reason',
      })).rejects.toThrow(MissingTransitionReasonError);
    });

    it('throws UnauthorizedTransitionActorError when actor lacks rule-restricted roles', async () => {
      await expect(LifecycleStateEngine.assertLegalTransition({
        entityRefId: 'run-444',
        entityKind: 'ANALYSIS_RUN',
        fromState: 'REQUIRES_REVIEW',
        toState: 'IN_REVIEW',
        action: 'START_REVIEW',
        transitionReason: 'Standard developer attempting to open security review',
        actorRef: 'principal:dev-bob',
        correlationId: 'corr-role',
        actorRoles: ['developer', 'viewer'], // Missing 'security_auditor'
      })).rejects.toThrow(UnauthorizedTransitionActorError);
    });
  });

  describe('6. Append-Only Persistence & Database Invariant Enforcement', () => {
    it('persists transition event in ops.lifecycle_state_transitions and updates entity table status', async () => {
      const runId = 'run-db-101';
      const actor = 'service:orchestrator';
      const corrId = 'corr-db-101';

      // Insert initial record in analysis.analysis_runs
      await client.query(`
        INSERT INTO analysis.analysis_runs (analysis_run_id, status)
        VALUES ($1, 'PENDING');
      `, [runId]);

      // 1. Execute transition to RUNNING
      const res1 = await LifecycleStateMachineService.transitionState({
        entityRefId: runId,
        entityKind: 'ANALYSIS_RUN',
        fromState: 'PENDING',
        toState: 'RUNNING',
        action: 'START_DIRECT',
        actorRef: actor,
        correlationId: corrId,
      }, {
        dbClient: client,
        expectedFromState: 'PENDING',
      });

      expect(res1.transitionRecord.to_state).toBe('RUNNING');

      // Verify row in database
      const dbRun1 = await client.query(`SELECT status FROM analysis.analysis_runs WHERE analysis_run_id = $1`, [runId]);
      expect(dbRun1.rows[0].status).toBe('RUNNING');

      const transitions1 = await client.query(`SELECT * FROM ops.lifecycle_state_transitions WHERE entity_ref_id = $1`, [runId]);
      expect(transitions1.rows.length).toBe(1);
      expect(transitions1.rows[0].from_state).toBe('PENDING');
      expect(transitions1.rows[0].to_state).toBe('RUNNING');

      // 2. Concurrency Conflict Check: expectedFromState mismatch
      await expect(LifecycleStateMachineService.transitionState({
        entityRefId: runId,
        entityKind: 'ANALYSIS_RUN',
        fromState: 'PENDING', // Mismatched since current is RUNNING
        toState: 'FAILED',
        action: 'FAIL',
        transitionReason: 'Fail attempt with stale state',
        actorRef: actor,
        correlationId: corrId,
      }, {
        dbClient: client,
        expectedFromState: 'RUNNING', // Mismatched with fromState
      })).rejects.toThrow(StateTransitionConflictError);
    });
  });

  describe('7. Current-State Projection and Sequence Integrity', () => {
    it('projects authoritative current state, time in states, and metrics from historical records', () => {
      const now = Date.now();
      const transitions = [
        {
          state_transition_id: 't-1',
          entity_ref_id: 'run-proj-1',
          from_state: null,
          to_state: 'PENDING',
          transition_reason: 'Created',
          actor_ref: 'service:api',
          occurred_at: new Date(now - 10000).toISOString(),
          state_machine_version: '2.0.1',
        },
        {
          state_transition_id: 't-2',
          entity_ref_id: 'run-proj-1',
          from_state: 'PENDING',
          to_state: 'RUNNING',
          transition_reason: 'Started',
          actor_ref: 'service:orchestrator',
          occurred_at: new Date(now - 8000).toISOString(),
          state_machine_version: '2.0.1',
        },
        {
          state_transition_id: 't-3',
          entity_ref_id: 'run-proj-1',
          from_state: 'RUNNING',
          to_state: 'STAGE_EXECUTION',
          transition_reason: 'Executing stages',
          actor_ref: 'service:orchestrator',
          occurred_at: new Date(now - 4000).toISOString(),
          state_machine_version: '2.0.1',
        },
        {
          state_transition_id: 't-4',
          entity_ref_id: 'run-proj-1',
          from_state: 'STAGE_EXECUTION',
          to_state: 'COMPLETED',
          transition_reason: 'Finished all stages',
          actor_ref: 'service:orchestrator',
          occurred_at: new Date(now - 1000).toISOString(),
          state_machine_version: '2.0.1',
        },
      ];

      const projection = StateProjector.project('ANALYSIS_RUN', transitions);
      expect(projection.entityRefId).toBe('run-proj-1');
      expect(projection.currentState).toBe('COMPLETED');
      expect(projection.previousState).toBe('STAGE_EXECUTION');
      expect(projection.transitionCount).toBe(4);
      expect(projection.isTerminal).toBe(true);
      expect(projection.timeInStatesMs['PENDING']).toBe(2000);
      expect(projection.timeInStatesMs['RUNNING']).toBe(4000);
      expect(projection.timeInStatesMs['STAGE_EXECUTION']).toBe(3000);
    });

    it('detects history corruption or non-linear sequences and throws StateProjectionIntegrityError', () => {
      const now = Date.now();
      const corruptedTransitions = [
        {
          state_transition_id: 't-1',
          entity_ref_id: 'run-corrupt',
          from_state: null,
          to_state: 'PENDING',
          transition_reason: 'Created',
          occurred_at: new Date(now - 5000).toISOString(),
        },
        {
          state_transition_id: 't-2',
          entity_ref_id: 'run-corrupt',
          from_state: 'STAGE_EXECUTION', // BROKEN CONTINUITY: previous was PENDING, not STAGE_EXECUTION
          to_state: 'COMPLETED',
          transition_reason: 'Broken jump',
          occurred_at: new Date(now - 1000).toISOString(),
        },
      ];

      expect(() => StateProjector.project('ANALYSIS_RUN', corruptedTransitions)).toThrow(StateProjectionIntegrityError);

      const check = StateProjector.verifyIntegrity('ANALYSIS_RUN', corruptedTransitions);
      expect(check.intact).toBe(false);
      expect(check.error).toBeDefined();
    });
  });

  describe('8. Lifecycle Worker Integration (workers/lifecycle)', () => {
    it('executes lifecycle jobs successfully when valid and handles policy rejection cleanly', async () => {
      const jobSuccess = {
        entityRefId: 'job-run-101',
        entityKind: 'ANALYSIS_RUN' as const,
        fromState: 'PENDING',
        toState: 'RUNNING',
        action: 'START_DIRECT',
        transitionReason: 'Worker executing run',
        actorRef: 'worker:lifecycle',
        correlationId: 'corr-worker-1',
      };

      const result1 = await runLifecycleJob(jobSuccess);
      expect(result1.status).toBe('SUCCESS');
      expect(result1.transitionValid).toBe(true);
      expect(result1.transitionRecord?.to_state).toBe('RUNNING');

      // Policy rejection case
      const jobPolicyFail = {
        entityRefId: 'job-run-102',
        entityKind: 'ANALYSIS_RUN' as const,
        fromState: 'EVALUATING_POLICIES',
        toState: 'COMPLETED',
        action: 'COMPLETE',
        transitionReason: 'Completing with bad policy',
        actorRef: 'worker:lifecycle',
        correlationId: 'corr-worker-2',
        gateContext: {
          policyDecisions: [{ decision: 'FAIL' as const, policyName: 'Critical Bug' }],
        },
      };

      const result2 = await runLifecycleJob(jobPolicyFail);
      expect(result2.status).toBe('REJECTED_BY_POLICY');
      expect(result2.transitionValid).toBe(false);
      expect(result2.error).toContain('Policy gate');
    });
  });
});
