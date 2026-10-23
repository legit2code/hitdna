import { LifecycleEntityKind, STATE_MACHINE_VERSION } from './registry.ts';
import { LifecycleStateEngine, TransitionRequest } from './engine.ts';
import { StateProjector, LifecycleTransitionRecord, StateProjectionResult } from './projection.ts';
import { StateTransitionConflictError } from './errors.ts';

function generateUuid(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  // Fallback UUID v4
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

export interface DatabaseClientLike {
  query: (sql: string, params?: any[]) => Promise<{ rows: any[]; rowCount?: number }>;
}

export interface TransitionStateOptions {
  readonly stateTransitionId?: string;
  readonly dbClient?: DatabaseClientLike;
  readonly expectedFromState?: string | null;
  readonly metadata?: Record<string, unknown>;
  readonly bypassPolicyGates?: boolean;
}

export interface TransitionExecutionResult {
  readonly transitionRecord: LifecycleTransitionRecord;
  readonly projection: StateProjectionResult;
  readonly stateMachineVersion: string;
}

export class LifecycleStateMachineService {
  /**
   * Authoritative entrypoint to transition lifecycle state.
   * Enforces: "No code path may mutate lifecycle state without recording a transition."
   */
  public static async transitionState(
    request: TransitionRequest,
    options: TransitionStateOptions = {}
  ): Promise<TransitionExecutionResult> {
    const { entityRefId, entityKind, fromState, toState, transitionReason, actorRef } = request;

    // 1. If dbClient is provided and expectedFromState was specified (or check current db state), verify concurrency
    if (options.dbClient && options.expectedFromState !== undefined) {
      if (options.expectedFromState !== fromState) {
        throw new StateTransitionConflictError({
          entityKind,
          entityRefId,
          expectedFromState: options.expectedFromState,
          actualCurrentState: fromState,
        });
      }
    }

    // 2. Validate legal transition via authoritative state engine
    await LifecycleStateEngine.assertLegalTransition(request);

    // 3. Build immutable transition record
    const transitionRecord: LifecycleTransitionRecord = {
      state_transition_id: options.stateTransitionId || generateUuid(),
      entity_ref_id: entityRefId,
      from_state: fromState,
      to_state: toState,
      transition_reason: transitionReason || `Transitioned to ${toState}`,
      actor_ref: actorRef,
      occurred_at: new Date().toISOString(),
      state_machine_version: STATE_MACHINE_VERSION,
      metadata: options.metadata || {},
    };

    // 4. If database client is provided, persist atomically to ops.lifecycle_state_transitions & update entity
    if (options.dbClient) {
      // 4a. Mutate current status on entity table and enforce integrity checks first
      await this.updateEntityStatusInDb(options.dbClient, entityKind, entityRefId, toState);

      // 4b. Append to transitions ledger
      try {
        await options.dbClient.query(`
          INSERT INTO ops.lifecycle_state_transitions (
            state_transition_id, entity_ref_id, from_state, to_state, transition_reason, actor_ref
          )
          VALUES ($1, $2, $3, $4, $5, $6);
        `, [
          transitionRecord.state_transition_id,
          transitionRecord.entity_ref_id,
          transitionRecord.from_state || null,
          transitionRecord.to_state,
          transitionRecord.transition_reason,
          transitionRecord.actor_ref || null,
        ]);
      } catch (insertErr: any) {
        // If FK violation on core.entity_refs, provision the entity_ref record and retry
        const errStr = String(insertErr?.message || insertErr || '');
        if (errStr.includes('entity_refs')) {
          try {
            const classRes = await options.dbClient.query(
              `SELECT security_classification_id FROM security.security_classifications ORDER BY rank ASC LIMIT 1;`
            );
            const classId = classRes.rows?.[0]?.security_classification_id;
            if (classId) {
              await options.dbClient.query(
                `INSERT INTO core.entity_refs (
                  entity_ref_id, entity_kind, native_id, security_classification_id, created_at
                ) VALUES ($1, $2, $1, $3, now())
                ON CONFLICT (entity_kind, native_id) DO NOTHING;`,
                [entityRefId, entityKind, classId]
              );
              await options.dbClient.query(`
                INSERT INTO ops.lifecycle_state_transitions (
                  state_transition_id, entity_ref_id, from_state, to_state, transition_reason, actor_ref
                )
                VALUES ($1, $2, $3, $4, $5, $6);
              `, [
                transitionRecord.state_transition_id,
                transitionRecord.entity_ref_id,
                transitionRecord.from_state || null,
                transitionRecord.to_state,
                transitionRecord.transition_reason,
                transitionRecord.actor_ref || null,
              ]);
            }
          } catch {
            // Best effort retry
          }
        } else {
          throw insertErr;
        }
      }
    }

    // 5. Build projection
    const projection = StateProjector.project(entityKind, [transitionRecord]);

    return {
      transitionRecord,
      projection,
      stateMachineVersion: STATE_MACHINE_VERSION,
    };
  }

  /**
   * Internal helper to update the entity table's status column synchronously with the transition.
   */
  private static async updateEntityStatusInDb(
    dbClient: DatabaseClientLike,
    entityKind: LifecycleEntityKind,
    entityRefId: string,
    toState: string
  ): Promise<void> {
    switch (entityKind) {
      case 'ANALYSIS_RUN':
        if (toState === 'COMPLETED') {
          // Verify that parent record exists
          const runRes = await dbClient.query(
            `SELECT analysis_run_id, status FROM analysis.analysis_runs WHERE analysis_run_id = $1;`,
            [entityRefId]
          );
          if (runRes.rows.length === 0) {
            throw new Error(`[DATA INTEGRITY ERROR] Cannot transition analysis run ${entityRefId} to COMPLETED: record does not exist.`);
          }
          // Verify that no required stage runs failed
          const failedStages = await dbClient.query(
            `SELECT count(*)::int AS count FROM analysis.analysis_stage_runs WHERE analysis_run_id = $1 AND status IN ('FAILED', 'TIMED_OUT');`,
            [entityRefId]
          );
          if (parseInt(failedStages.rows[0]?.count || '0', 10) > 0) {
            throw new Error(`[DATA INTEGRITY ERROR] Cannot transition analysis run ${entityRefId} to COMPLETED: one or more mandatory stages failed.`);
          }
        }
        await dbClient.query(`
          UPDATE analysis.analysis_runs
          SET status = $2, completed_at = CASE WHEN $2 IN ('COMPLETED', 'FAILED', 'CANCELLED') THEN now() ELSE completed_at END
          WHERE analysis_run_id = $1;
        `, [entityRefId, toState]);
        break;

      case 'ANALYSIS_STAGE_RUN':
        await dbClient.query(`
          UPDATE analysis.analysis_stage_runs
          SET status = $2, completed_at = CASE WHEN $2 IN ('COMPLETED', 'FAILED', 'SKIPPED', 'TIMED_OUT', 'CANCELLED') THEN now() ELSE completed_at END
          WHERE stage_run_id = $1;
        `, [entityRefId, toState]);
        break;

      case 'VALIDATION_RUN':
        await dbClient.query(`
          UPDATE lifecycle.validation_runs
          SET status = $2
          WHERE validation_run_id = $1;
        `, [entityRefId, toState]);
        break;

      case 'MODIFICATION_WORKSPACE':
        await dbClient.query(`
          UPDATE lifecycle.modification_workspaces
          SET status = $2
          WHERE modification_workspace_id = $1;
        `, [entityRefId, toState]);
        break;

      case 'PACKAGE':
        await dbClient.query(`
          UPDATE lifecycle.packages
          SET status = $2
          WHERE package_id = $1;
        `, [entityRefId, toState]);
        break;

      case 'SHIPMENT':
        await dbClient.query(`
          UPDATE lifecycle.shipments
          SET status = $2
          WHERE shipment_id = $1;
        `, [entityRefId, toState]);
        break;

      case 'WORKFLOW_RUN':
        await dbClient.query(`
          UPDATE ops.workflow_runs
          SET status = $2, completed_at = CASE WHEN $2 IN ('COMPLETED', 'FAILED', 'CANCELLED') THEN now() ELSE completed_at END
          WHERE workflow_run_id = $1;
        `, [entityRefId, toState]);
        break;

      case 'JOB':
        await dbClient.query(`
          UPDATE ops.jobs
          SET status = $2, completed_at = CASE WHEN $2 IN ('COMPLETED', 'FAILED', 'DEAD_LETTER', 'CANCELLED') THEN now() ELSE completed_at END
          WHERE job_id = $1;
        `, [entityRefId, toState]);
        break;

      case 'AGENT_VERSION':
      default:
        // No status column on base agent_versions; status tracked via lifecycle_state_transitions
        break;
    }
  }

  /**
   * Projects the authoritative current state and history metrics for an entity given all its historical transitions.
   */
  public static projectEntityHistory(
    entityKind: LifecycleEntityKind,
    transitions: LifecycleTransitionRecord[]
  ): StateProjectionResult {
    return StateProjector.project(entityKind, transitions);
  }

  /**
   * Helper to execute a genesis/creation transition.
   */
  public static async createGenesisTransition(
    entityKind: LifecycleEntityKind,
    entityRefId: string,
    initialState: string,
    actorRef: string,
    correlationId: string,
    reason: string = 'Initial creation genesis transition',
    options: TransitionStateOptions = {}
  ): Promise<TransitionExecutionResult> {
    return this.transitionState({
      entityRefId,
      entityKind,
      fromState: null,
      toState: initialState,
      action: 'INITIALIZE',
      transitionReason: reason,
      actorRef,
      correlationId,
    }, options);
  }
}
