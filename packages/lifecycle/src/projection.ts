import { LifecycleEntityKind, STATE_MACHINE_VERSION, isTerminalState } from './registry.ts';
import { StateProjectionIntegrityError } from './errors.ts';

export interface LifecycleTransitionRecord {
  readonly state_transition_id: string;
  readonly entity_ref_id: string;
  readonly from_state: string | null;
  readonly to_state: string;
  readonly transition_reason: string;
  readonly actor_ref?: string | null;
  readonly occurred_at: string | Date;
  readonly state_machine_version?: string;
  readonly metadata?: Record<string, unknown>;
}

export interface StateProjectionResult {
  readonly entityRefId: string;
  readonly entityKind: LifecycleEntityKind;
  readonly currentState: string;
  readonly previousState: string | null;
  readonly transitionCount: number;
  readonly isTerminal: boolean;
  readonly genesisAt: string;
  readonly lastTransitionAt: string;
  readonly stateMachineVersion: string;
  readonly timeInStatesMs: Record<string, number>;
  readonly history: LifecycleTransitionRecord[];
  readonly reviewCount: number;
  readonly quarantineCount: number;
  readonly reanalysisCount: number;
}

export class StateProjector {
  /**
   * Projects the authoritative current state and history metrics from an append-only sequence of transition records.
   */
  public static project(
    entityKind: LifecycleEntityKind,
    transitions: LifecycleTransitionRecord[]
  ): StateProjectionResult {
    if (!transitions || transitions.length === 0) {
      throw new StateProjectionIntegrityError({
        entityKind,
        entityRefId: 'UNKNOWN',
        sequenceError: 'Cannot project state from an empty transition history.',
      });
    }

    // Sort transitions chronologically by occurred_at
    const sorted = [...transitions].sort((a, b) => {
      const timeA = new Date(a.occurred_at).getTime();
      const timeB = new Date(b.occurred_at).getTime();
      return timeA - timeB;
    });

    const entityRefId = sorted[0].entity_ref_id;
    let currentState: string = sorted[0].to_state;
    let previousState: string | null = sorted[0].from_state;
    let reviewCount = 0;
    let quarantineCount = 0;
    let reanalysisCount = 0;

    const timeInStatesMs: Record<string, number> = {};

    // Validate linear sequence continuity
    for (let i = 0; i < sorted.length; i++) {
      const current = sorted[i];

      // Check entity id consistency
      if (current.entity_ref_id !== entityRefId) {
        throw new StateProjectionIntegrityError({
          entityKind,
          entityRefId,
          sequenceError: `Transition sequence contains mismatched entityRefId '${current.entity_ref_id}' at index ${i}.`,
        });
      }

      if (i > 0) {
        const prev = sorted[i - 1];
        
        // Continuity check: current.from_state must equal prev.to_state
        if (current.from_state !== prev.to_state) {
          throw new StateProjectionIntegrityError({
            entityKind,
            entityRefId,
            sequenceError: `Non-linear sequence at step ${i}: transition from_state '${current.from_state}' does not match preceding to_state '${prev.to_state}'.`,
          });
        }

        // Check if previous state was terminal
        if (isTerminalState(entityKind, prev.to_state)) {
          throw new StateProjectionIntegrityError({
            entityKind,
            entityRefId,
            sequenceError: `History contains transition out of terminal state '${prev.to_state}' to '${current.to_state}' at step ${i}.`,
          });
        }

        // Calculate time in state
        const duration = new Date(current.occurred_at).getTime() - new Date(prev.occurred_at).getTime();
        if (duration >= 0) {
          timeInStatesMs[prev.to_state] = (timeInStatesMs[prev.to_state] || 0) + duration;
        }
      }

      // Track domain metrics
      if (current.to_state.includes('REVIEW')) {
        reviewCount++;
      }
      if (current.to_state.includes('QUARANTINE')) {
        quarantineCount++;
      }
      if (current.to_state.includes('REANALYZ')) {
        reanalysisCount++;
      }

      currentState = current.to_state;
      previousState = current.from_state;
    }

    const genesisAt = new Date(sorted[0].occurred_at).toISOString();
    const lastTransitionAt = new Date(sorted[sorted.length - 1].occurred_at).toISOString();
    const isTerminal = isTerminalState(entityKind, currentState);

    return {
      entityRefId,
      entityKind,
      currentState,
      previousState,
      transitionCount: sorted.length,
      isTerminal,
      genesisAt,
      lastTransitionAt,
      stateMachineVersion: sorted[sorted.length - 1].state_machine_version || STATE_MACHINE_VERSION,
      timeInStatesMs,
      history: sorted,
      reviewCount,
      quarantineCount,
      reanalysisCount,
    };
  }

  /**
   * Verifies whether a transition sequence is mathematically and logically intact without throwing.
   */
  public static verifyIntegrity(
    entityKind: LifecycleEntityKind,
    transitions: LifecycleTransitionRecord[]
  ): { intact: boolean; error?: string } {
    try {
      this.project(entityKind, transitions);
      return { intact: true };
    } catch (err) {
      return {
        intact: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }
}
